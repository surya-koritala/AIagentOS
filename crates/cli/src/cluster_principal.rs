//! Caller-owned signing for replicated membership administration.

use std::collections::BTreeMap;
use std::path::PathBuf;

use agent_sdk::{
    AuthorityCommand, AuthorityResponse, ClusterCertificateRollout, ClusterMember,
    ClusterMemberRegistration, SdkError, WireErrorCode,
};
use chrono::Utc;
use ring::signature::Ed25519KeyPair;
use uuid::Uuid;

use super::Join;
use crate::OperatorClient;

pub(super) struct PrincipalOptions {
    cluster_id: String,
    id: String,
    generation: u64,
    key_path: PathBuf,
}

impl PrincipalOptions {
    pub(super) fn parse(options: &mut BTreeMap<String, String>) -> Result<Option<Self>, String> {
        let id = options.remove("--principal-id");
        let generation = options.remove("--principal-generation");
        let key_path = options.remove("--principal-key");
        let cluster_id = options.remove("--principal-cluster-id");
        if id.is_none() && generation.is_none() && key_path.is_none() && cluster_id.is_none() {
            return Ok(None);
        }
        let id = id.ok_or("missing --principal-id")?;
        let cluster_id = cluster_id.ok_or("missing --principal-cluster-id")?;
        if Uuid::parse_str(&cluster_id).ok().is_none_or(|uuid| uuid.to_string() != cluster_id) {
            return Err("principal cluster ID must be a canonical UUID".into());
        }
        if Uuid::parse_str(&id).ok().is_none_or(|uuid| uuid.to_string() != id) {
            return Err("principal ID must be a canonical UUID".into());
        }
        let generation = generation
            .ok_or("missing --principal-generation")?
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or("principal generation must be positive")?;
        let key_path = key_path.filter(|value| !value.is_empty()).ok_or("missing --principal-key")?;
        Ok(Some(Self { cluster_id, id, generation, key_path: key_path.into() }))
    }
}

pub(super) struct PrincipalSigner {
    options: PrincipalOptions,
    key: Ed25519KeyPair,
    cluster_id: Option<String>,
    actor: Option<String>,
}

impl PrincipalSigner {
    pub(super) fn load(options: PrincipalOptions) -> Result<Self, SdkError> {
        let bytes = kernel::config::read_private_principal_key(&options.key_path)
            .map_err(|_| SdkError::Configuration("principal key requires a bounded current-owner-only regular file without links".into()))?;
        let key = Ed25519KeyPair::from_pkcs8(&bytes)
            .map_err(|_| SdkError::Configuration("principal key must be Ed25519 PKCS#8 DER".into()))?;
        Ok(Self { options, key, cluster_id: None, actor: None })
    }

    pub(super) async fn actor(&mut self, client: &mut OperatorClient) -> Result<String, SdkError> {
        if self.actor.is_none() {
            let identity = client.node_info().await?.control.ok_or_else(||
                SdkError::Configuration("signed authority requires durable node identity".into()))?.identity;
            self.actor = Some(format!("system-node:{}", identity.node_id));
        }
        Ok(self.actor.as_ref().expect("loaded actor").clone())
    }

    pub(super) async fn submit(&mut self, client: &mut OperatorClient, command: AuthorityCommand) -> Result<AuthorityResponse, SdkError> {
        if self.cluster_id.is_none() {
            let actual = client.cluster_membership().await?.cluster_id;
            if actual != self.options.cluster_id {
                return Err(SdkError::Configuration("authority cluster does not match the explicit principal signing profile".into()));
            }
            self.cluster_id = Some(actual);
        }
        client.submit_authority_command_with_signer(
            command,
            self.cluster_id.as_ref().expect("loaded cluster"),
            &self.options.id,
            self.options.generation,
            |payload| Ok(self.key.sign(payload).as_ref().to_vec()),
        ).await
    }

    async fn challenged_registration(&mut self, authority: &mut OperatorClient, node: &mut OperatorClient, join: &Join, candidate: Option<String>) -> Result<(ClusterMemberRegistration, String, String), SdkError> {
        let mut material = b"AIagentOS replicated join challenge v1".to_vec();
        material.extend_from_slice(join.ids.challenge.to_string().as_bytes());
        let challenge_hex = ring::digest::digest(&ring::digest::SHA256, &material)
            .as_ref().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let challenge = match self.submit(authority, AuthorityCommand::IssueJoinChallenge {
            operation_id: join.ids.challenge.to_string(), challenge_hex,
            ttl_seconds: 30, proposed_at: Utc::now(),
        }).await? {
            AuthorityResponse::JoinChallengeIssued {challenge, ..} => challenge,
            _ => return Err(SdkError::Kernel("unexpected signed challenge response".into())),
        };
        let identity = node.node_info().await?.control.ok_or_else(||
            SdkError::Kernel("cluster membership requires durable node identity support".into()))?.identity;
        let protocol = node.hello().await?;
        let registration = ClusterMemberRegistration {
            node_id: identity.node_id, fingerprint: identity.fingerprint, public_key: identity.public_key,
            tls_server_certificate_fingerprint: candidate.or_else(|| node.tls_peer_certificate_fingerprint().map(str::to_string)),
            endpoint: join.node.clone(), server_version: protocol.server_version,
            min_protocol_version: protocol.min_protocol_version, protocol_version: protocol.protocol_version,
        };
        let payload = kernel::cluster_control::membership_join_payload(&challenge.cluster_id, &challenge.challenge_hex, &registration)
            .map_err(|_| SdkError::Kernel("membership challenge payload is invalid".into()))?;
        let nonce = payload.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let proof = node.prove_node_identity(nonce).await?;
        if proof.node_id != registration.node_id || proof.fingerprint != registration.fingerprint || proof.public_key != registration.public_key {
            return Err(SdkError::Wire {code: WireErrorCode::Conflict, message: "node identity changed while completing signed cluster admission".into(), retryable: false});
        }
        Ok((registration, challenge.challenge_hex, proof.signature_hex))
    }

    pub(super) async fn admit(&mut self, authority: &mut OperatorClient, node: &mut OperatorClient, join: &Join) -> Result<ClusterMember, SdkError> {
        let (registration, challenge_hex, signature_hex) = self.challenged_registration(authority, node, join, None).await?;
        let protocol = authority.hello().await?;
        let actor = self.actor(authority).await?;
        self.member(authority, AuthorityCommand::RegisterMember {
            operation_id: join.ids.mutation.to_string(), registration, challenge_hex, signature_hex,
            expected_generation: join.generation, authority_min_protocol_version: protocol.min_protocol_version,
            authority_protocol_version: protocol.protocol_version, actor, reason: join.reason.clone(), proposed_at: Utc::now(),
        }).await
    }

    pub(super) async fn member(&mut self, authority: &mut OperatorClient, command: AuthorityCommand) -> Result<ClusterMember, SdkError> {
        match self.submit(authority, command).await? {
            AuthorityResponse::MemberUpdated {member, ..} => Ok(member),
            _ => Err(SdkError::Kernel("unexpected signed membership response".into())),
        }
    }

    pub(super) async fn prepare(&mut self, authority: &mut OperatorClient, node: &mut OperatorClient, join: &Join, fingerprint: String, bounds: (u64, u64)) -> Result<(ClusterMember, ClusterCertificateRollout), SdkError> {
        let (registration, challenge_hex, signature_hex) = self.challenged_registration(authority, node, join, Some(fingerprint)).await?;
        let actor = self.actor(authority).await?;
        match self.submit(authority, AuthorityCommand::PrepareMemberCertificateRollout {
            operation_id: join.ids.mutation.to_string(), registration, challenge_hex, signature_hex,
            expected_generation: join.generation.expect("certificate generation"), prepare_ttl_seconds: bounds.0,
            minimum_overlap_seconds: bounds.1, actor, reason: join.reason.clone(), proposed_at: Utc::now(),
        }).await? {
            AuthorityResponse::CertificateRolloutUpdated {member, rollout: Some(rollout), ..} => Ok((member, rollout)),
            _ => Err(SdkError::Kernel("unexpected signed certificate prepare response".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(path: PathBuf) -> PrincipalOptions {
        PrincipalOptions { cluster_id: "00000000-0000-0000-0000-000000000100".into(), id: "00000000-0000-0000-0000-000000000900".into(), generation: 1, key_path: path }
    }

    #[test]
    fn principal_key_loading_is_bounded_private_and_never_echoes_material() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("principal.pk8");
        let document = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        kernel::config::write_owner_only_atomic(&path, document.as_ref()).unwrap();
        assert!(PrincipalSigner::load(options(path.clone())).is_ok());
        kernel::config::write_owner_only_atomic(&path, &vec![0; 4097]).unwrap();
        let Err(error) = PrincipalSigner::load(options(path.clone())) else { panic!("oversized principal key accepted") };
        assert_eq!(error.to_string(), "client configuration error: principal key requires a bounded current-owner-only regular file without links");
        kernel::config::write_owner_only_atomic(&path, b"private-invalid-material").unwrap();
        let Err(error) = PrincipalSigner::load(options(path.clone())) else { panic!("invalid principal key accepted") };
        assert!(!error.to_string().contains("private-invalid-material"));
        assert!(PrincipalSigner::load(options(root.path().into())).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(PrincipalSigner::load(options(path.clone())).is_err());
            let link = root.path().join("linked.pk8");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(PrincipalSigner::load(options(link)).is_err());
        }
    }

    #[test]
    fn principal_options_require_one_complete_canonical_explicit_profile() {
        assert!(PrincipalOptions::parse(&mut BTreeMap::new()).unwrap().is_none());
        assert!(PrincipalOptions::parse(&mut BTreeMap::from([("--principal-key".into(), "key.pk8".into())])).is_err());
        for generation in ["0", "-1", "invalid"] {
            assert!(PrincipalOptions::parse(&mut BTreeMap::from([
                ("--principal-id".into(), "00000000-0000-0000-0000-000000000900".into()),
                ("--principal-key".into(), "key.pk8".into()),
                ("--principal-generation".into(), generation.into()),
                ("--principal-cluster-id".into(), "00000000-0000-0000-0000-000000000100".into()),
            ])).is_err());
        }
    }
}
