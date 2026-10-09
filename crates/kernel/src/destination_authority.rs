//! Caller-bound destination admission against a fresh online quorum view.
//!
//! The request binding is derived from the actual syscall, never accepted from
//! the caller's proof. This verifier does not obtain its own quorum barrier;
//! dispatch must supply the view read for this admission and retain the existing
//! destination mutation barrier through the admitted operation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cluster_consensus::ReplicatedAuthorityView;
use crate::cluster_control::{ClusterMemberState, ClusterOwnershipState};
use crate::cluster_principal::{AuthorityCommandClass, AuthorityPrincipal, AuthorityPrincipalKind};

pub const FEATURE: &str = "destination-authority-online-v1";
const DOMAIN: &[u8] = b"AIagentOS independent destination admission v1\0";
const MAX_PROOF_TTL_SECONDS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationAuthorityMode {
    OnlineQuorumV1,
}

/// Every ownership field and the full actual mutation are part of the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationRequestBinding {
    pub mode: DestinationAuthorityMode,
    pub cluster_id: String,
    pub agent_id: String,
    pub tenant_id: Option<String>,
    pub owner_node_id: String,
    pub authority_term: u64,
    pub authority_generation: u64,
    pub fencing_token: u64,
    pub lease_expires_at: DateTime<Utc>,
    pub operation_id: String,
    pub command_sha256: String,
}

/// Derive the signed request identity from the actual command, not proof fields.
pub fn request_binding(
    call: &crate::syscall_server::Syscall,
    operation_id: &str,
    tenant_id: &str,
) -> Result<DestinationRequestBinding, DestinationAdmissionError> {
    use crate::syscall_server::{AgentMutationFenceProof, Syscall};
    let (agent_id, fence) = match call {
        Syscall::InstallAgentMutationFence {
            operation_id: Some(command_id), agent_id, cluster_id, owner_node_id,
            authority_term, authority_generation, fencing_token, proof_expires_at, ..
        } | Syscall::RetireAgentMutationFence {
            operation_id: Some(command_id), agent_id, cluster_id, owner_node_id,
            authority_term, authority_generation, fencing_token, proof_expires_at, ..
        } if command_id == operation_id => (agent_id, AgentMutationFenceProof {
            cluster_id: cluster_id.clone(), owner_node_id: owner_node_id.clone(),
            authority_term: *authority_term, authority_generation: *authority_generation,
            fencing_token: *fencing_token, proof_expires_at: *proof_expires_at,
        }),
        Syscall::FencedAgentMutation { agent_id, proof, mutation }
            if crate::syscall_server::mutable_agent_target(mutation) == Some(agent_id.as_str())
                => (agent_id, proof.clone()),
        Syscall::CreateAgent { agent_id: Some(agent_id), ownership_proof: Some(proof), .. }
            => (agent_id, proof.clone()),
        Syscall::CloneAgent { child_agent_id, child_ownership_proof: Some(proof), .. }
            => (child_agent_id, proof.clone()),
        _ => return Err(DestinationAdmissionError::InvalidProof),
    };
    let value = serde_json::to_value(call).map_err(|_| DestinationAdmissionError::InvalidProof)?;
    let mut canonical = Vec::new();
    crate::cluster_principal::encode_canonical_json(&value, &mut canonical)
        .map_err(|_| DestinationAdmissionError::InvalidProof)?;
    let binding = DestinationRequestBinding {
        mode: DestinationAuthorityMode::OnlineQuorumV1,
        cluster_id: fence.cluster_id,
        agent_id: agent_id.clone(),
        tenant_id: Some(tenant_id.to_owned()),
        owner_node_id: fence.owner_node_id,
        authority_term: fence.authority_term,
        authority_generation: fence.authority_generation,
        fencing_token: fence.fencing_token,
        lease_expires_at: fence.proof_expires_at,
        operation_id: operation_id.to_owned(),
        command_sha256: crate::cluster_control::sha256_hex(&canonical),
    };
    binding.validate()?;
    Ok(binding)
}

impl DestinationRequestBinding {
    fn validate(&self) -> Result<(), DestinationAdmissionError> {
        if !canonical_uuid(&self.cluster_id)
            || !canonical_uuid(&self.agent_id)
            || !canonical_uuid(&self.owner_node_id)
            || !canonical_uuid(&self.operation_id)
            || self
                .tenant_id
                .as_deref()
                .is_some_and(|id| id != crate::context::DEFAULT_TENANT && !canonical_uuid(id))
            || self.authority_term == 0
            || self.authority_generation == 0
            || self.fencing_token == 0
            || !canonical_hex(&self.command_sha256, 32)
        {
            return Err(DestinationAdmissionError::InvalidProof);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationPrincipalProof {
    pub version: u16,
    pub binding: DestinationRequestBinding,
    pub principal_id: String,
    pub principal_generation: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DestinationAdmissionError {
    #[error("destination principal proof is invalid")]
    InvalidProof,
    #[error("destination principal signature is invalid")]
    InvalidSignature,
    #[error("destination principal is not currently authorized")]
    Unauthorized,
    #[error("destination tenant scope does not match current ownership")]
    TenantScope,
    #[error("destination proof is not the exact active quorum ownership revision")]
    Ownership,
    #[error("destination proof is expired or outside its validity window")]
    Expired,
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn payload(proof: &DestinationPrincipalProof) -> Result<Vec<u8>, DestinationAdmissionError> {
    proof.binding.validate()?;
    if proof.version != 1 || !canonical_uuid(&proof.principal_id) || proof.principal_generation == 0
    {
        return Err(DestinationAdmissionError::InvalidProof);
    }
    let mut unsigned = proof.clone();
    unsigned.signature_hex.clear();
    let mut output = DOMAIN.to_vec();
    output.extend(
        serde_json::to_vec(&unsigned).map_err(|_| DestinationAdmissionError::InvalidProof)?,
    );
    Ok(output)
}

/// The signing callback belongs to the caller; the runtime never receives keys.
pub fn sign_destination_request(
    binding: DestinationRequestBinding,
    principal_id: &str,
    principal_generation: u64,
    issued_at: DateTime<Utc>,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, DestinationAdmissionError>,
) -> Result<DestinationPrincipalProof, DestinationAdmissionError> {
    let expires_at = issued_at
        .checked_add_signed(chrono::Duration::seconds(MAX_PROOF_TTL_SECONDS))
        .ok_or(DestinationAdmissionError::InvalidProof)?
        .min(binding.lease_expires_at);
    if expires_at <= issued_at {
        return Err(DestinationAdmissionError::Expired);
    }
    let mut proof = DestinationPrincipalProof {
        version: 1,
        binding,
        principal_id: principal_id.to_owned(),
        principal_generation,
        issued_at,
        expires_at,
        signature_hex: String::new(),
    };
    let signature = sign(&payload(&proof)?)?;
    if signature.len() != 64 {
        return Err(DestinationAdmissionError::InvalidSignature);
    }
    proof.signature_hex = crate::cluster_control::hex_encode(&signature);
    Ok(proof)
}

/// Current principal and exact ownership are checked before admitting effects.
pub fn verify_destination_request<'a>(
    proof: &DestinationPrincipalProof,
    actual: &DestinationRequestBinding,
    view: &'a ReplicatedAuthorityView,
    authenticated_tenant: Option<&str>,
    destination_node_id: &str,
    now: DateTime<Utc>,
) -> Result<&'a AuthorityPrincipal, DestinationAdmissionError> {
    actual.validate()?;
    let signed_payload = payload(proof)?;
    if &proof.binding != actual
        || actual.cluster_id != view.genesis.cluster_id
        || actual.cluster_id != view.membership.cluster_id
        || actual.owner_node_id != destination_node_id
    {
        return Err(DestinationAdmissionError::Ownership);
    }
    let at = now.max(view.logical_time);
    if proof.issued_at > at
        || proof.expires_at <= at
        || proof.expires_at <= proof.issued_at
        || proof.expires_at > actual.lease_expires_at
        || proof.expires_at
            > proof
                .issued_at
                .checked_add_signed(chrono::Duration::seconds(MAX_PROOF_TTL_SECONDS))
                .ok_or(DestinationAdmissionError::InvalidProof)?
    {
        return Err(DestinationAdmissionError::Expired);
    }
    let principal = view
        .principals
        .get(&proof.principal_id)
        .ok_or(DestinationAdmissionError::Unauthorized)?;
    principal
        .validate()
        .map_err(|_| DestinationAdmissionError::Unauthorized)?;
    if principal.revoked
        || principal.generation != proof.principal_generation
        || principal.expires_at.is_some_and(|expiry| expiry <= at)
        || !principal
            .allowed_command_classes
            .contains(&AuthorityCommandClass::Ownership)
    {
        return Err(DestinationAdmissionError::Unauthorized);
    }
    let scope = view
        .ownership_tenant_scopes
        .get(&actual.agent_id)
        .map(String::as_str);
    if scope.is_none()
        || scope != actual.tenant_id.as_deref()
        || authenticated_tenant.is_some_and(|tenant| scope != Some(tenant))
        || (principal.kind == AuthorityPrincipalKind::Tenant
            && (principal.tenant_id.as_deref() != scope || authenticated_tenant != scope))
    {
        return Err(DestinationAdmissionError::TenantScope);
    }
    let ownership = view
        .ownerships
        .iter()
        .find(|row| row.agent_id == actual.agent_id)
        .ok_or(DestinationAdmissionError::Ownership)?;
    if ownership.owner_node_id != actual.owner_node_id
        || ownership.authority_term != actual.authority_term
        || ownership.generation != actual.authority_generation
        || ownership.fencing_token != actual.fencing_token
        || ownership.lease_expires_at != actual.lease_expires_at
        || ownership.state != ClusterOwnershipState::Active
        || ownership.updated_at > at
        || ownership.lease_expires_at <= at
        || !view.membership.members.iter().any(|member| {
            member.node_id == actual.owner_node_id && member.state == ClusterMemberState::Active
        })
    {
        return Err(DestinationAdmissionError::Ownership);
    }
    if !canonical_hex(&proof.signature_hex, 64) {
        return Err(DestinationAdmissionError::InvalidSignature);
    }
    let signature = crate::cluster_control::hex_decode(&proof.signature_hex)
        .ok_or(DestinationAdmissionError::InvalidSignature)?;
    if !crate::cluster_control::ClusterControl::verify_challenge(
        &principal.public_key,
        &signed_payload,
        &signature,
    ) {
        return Err(DestinationAdmissionError::InvalidSignature);
    }
    Ok(principal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_consensus::AuthorityGenesis;
    use crate::cluster_control::{ClusterAgentOwnership, ClusterMember, ClusterMembershipSnapshot};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::{BTreeMap, BTreeSet};

    struct Fixture {
        key: Ed25519KeyPair,
        binding: DestinationRequestBinding,
        view: ReplicatedAuthorityView,
    }

    impl Fixture {
        fn new() -> Self {
            let document =
                Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
            let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
            let now = Utc::now();
            let binding = DestinationRequestBinding {
                mode: DestinationAuthorityMode::OnlineQuorumV1,
                cluster_id: uuid::Uuid::new_v4().to_string(),
                agent_id: uuid::Uuid::new_v4().to_string(),
                tenant_id: Some(uuid::Uuid::new_v4().to_string()),
                owner_node_id: uuid::Uuid::new_v4().to_string(),
                authority_term: 7,
                authority_generation: 11,
                fencing_token: 13,
                lease_expires_at: now + chrono::Duration::seconds(60),
                operation_id: uuid::Uuid::new_v4().to_string(),
                command_sha256: crate::cluster_control::sha256_hex(b"exact actual mutation"),
            };
            let principal = AuthorityPrincipal {
                principal_id: uuid::Uuid::new_v4().to_string(),
                public_key: crate::cluster_control::hex_encode(key.public_key().as_ref()),
                kind: AuthorityPrincipalKind::Tenant,
                tenant_id: binding.tenant_id.clone(),
                allowed_command_classes: BTreeSet::from([AuthorityCommandClass::Ownership]),
                generation: 1,
                revoked: false,
                expires_at: None,
            };
            let owner_document =
                Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
            let owner_key = Ed25519KeyPair::from_pkcs8(owner_document.as_ref()).unwrap();
            let owner = ClusterMember {
                node_id: binding.owner_node_id.clone(),
                public_key: crate::cluster_control::hex_encode(owner_key.public_key().as_ref()),
                fingerprint: crate::cluster_control::sha256_hex(owner_key.public_key().as_ref()),
                tls_server_certificate_fingerprint: None,
                endpoint: "127.0.0.1:1".into(),
                server_version: "destination-proof-fixture".into(),
                min_protocol_version: 2,
                protocol_version: 2,
                state: ClusterMemberState::Active,
                generation: 1,
                joined_at: now,
                updated_at: now,
                reason: "independent owner identity".into(),
            };
            let ownership = ClusterAgentOwnership {
                agent_id: binding.agent_id.clone(),
                owner_node_id: binding.owner_node_id.clone(),
                authority_term: binding.authority_term,
                fencing_token: binding.fencing_token,
                generation: binding.authority_generation,
                state: ClusterOwnershipState::Active,
                lease_expires_at: binding.lease_expires_at,
                updated_at: now,
                reason: "exact quorum fixture ownership".into(),
            };
            let view = ReplicatedAuthorityView {
                genesis: AuthorityGenesis {
                    cluster_id: binding.cluster_id.clone(),
                    members: Vec::new(),
                    operator_principals: Vec::new(),
                },
                principals: BTreeMap::from([(principal.principal_id.clone(), principal)]),
                principal_audit: Vec::new(),
                ownership_tenant_scopes: BTreeMap::from([(
                    binding.agent_id.clone(),
                    binding.tenant_id.clone().unwrap(),
                )]),
                membership: ClusterMembershipSnapshot {
                    cluster_id: binding.cluster_id.clone(),
                    generation: 1,
                    authority_time: Some(now),
                    tls_trust_generation: 0,
                    certificate_rollouts: Vec::new(),
                    members: vec![owner],
                },
                membership_audit: Vec::new(),
                certificate_rollout_audit: Vec::new(),
                ownerships: vec![ownership],
                ownership_audit: Vec::new(),
                logical_time: now,
            };
            Self { key, binding, view }
        }

        fn signed(&self) -> DestinationPrincipalProof {
            let principal = self.view.principals.values().next().unwrap();
            sign_destination_request(
                self.binding.clone(),
                &principal.principal_id,
                principal.generation,
                self.view.logical_time,
                |bytes| Ok(self.key.sign(bytes).as_ref().to_vec()),
            )
            .unwrap()
        }

        fn verify(
            &self,
            proof: &DestinationPrincipalProof,
        ) -> Result<(), DestinationAdmissionError> {
            verify_destination_request(
                proof,
                &self.binding,
                &self.view,
                self.binding.tenant_id.as_deref(),
                &self.binding.owner_node_id,
                self.view.logical_time,
            )
            .map(|_| ())
        }
    }

    #[test]
    fn exact_signed_admission_rejects_tampered_command_identity_and_signature() {
        let fixture = Fixture::new();
        let proof = fixture.signed();
        assert_eq!(fixture.verify(&proof), Ok(()));
        let mut wrong = proof.clone();
        wrong.binding.command_sha256 = crate::cluster_control::sha256_hex(b"other mutation");
        assert_eq!(
            fixture.verify(&wrong),
            Err(DestinationAdmissionError::Ownership)
        );
        wrong = proof.clone();
        wrong.binding.agent_id = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            fixture.verify(&wrong),
            Err(DestinationAdmissionError::Ownership)
        );
        wrong = proof.clone();
        wrong.binding.cluster_id = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            fixture.verify(&wrong),
            Err(DestinationAdmissionError::Ownership)
        );
        wrong = proof;
        wrong.signature_hex = "00".repeat(64);
        assert_eq!(
            fixture.verify(&wrong),
            Err(DestinationAdmissionError::InvalidSignature)
        );
    }

    #[test]
    fn admission_rechecks_current_principal_tenant_and_ownership_state() {
        let mut fixture = Fixture::new();
        let proof = fixture.signed();
        let id = proof.principal_id.clone();
        fixture.view.principals.get_mut(&id).unwrap().revoked = true;
        assert_eq!(
            fixture.verify(&proof),
            Err(DestinationAdmissionError::Unauthorized)
        );
        fixture.view.principals.get_mut(&id).unwrap().revoked = false;
        fixture.view.principals.get_mut(&id).unwrap().generation += 1;
        assert_eq!(
            fixture.verify(&proof),
            Err(DestinationAdmissionError::Unauthorized)
        );
        fixture.view.principals.get_mut(&id).unwrap().generation -= 1;
        fixture.view.ownerships[0].state = ClusterOwnershipState::Released;
        assert_eq!(
            fixture.verify(&proof),
            Err(DestinationAdmissionError::Ownership)
        );
        fixture.view.ownerships[0].state = ClusterOwnershipState::Active;
        fixture.view.ownerships[0].authority_term += 1;
        assert_eq!(
            fixture.verify(&proof),
            Err(DestinationAdmissionError::Ownership)
        );
        fixture.view.ownerships[0].authority_term -= 1;
        fixture.view.membership.members[0].state = ClusterMemberState::Revoked;
        assert_eq!(
            fixture.verify(&proof),
            Err(DestinationAdmissionError::Ownership)
        );
        fixture.view.membership.members[0].state = ClusterMemberState::Active;
        fixture
            .view
            .ownership_tenant_scopes
            .remove(&fixture.binding.agent_id);
        assert_eq!(
            fixture.verify(&proof),
            Err(DestinationAdmissionError::TenantScope)
        );
    }

    #[test]
    fn admission_rejects_missing_foreign_tenant_expiry_and_future_proofs() {
        let fixture = Fixture::new();
        let proof = fixture.signed();
        for tenant in [None, Some("00000000-0000-0000-0000-000000000001")] {
            assert!(verify_destination_request(
                &proof,
                &fixture.binding,
                &fixture.view,
                tenant,
                &fixture.binding.owner_node_id,
                fixture.view.logical_time,
            )
            .is_err());
        }
        let mut wrong = proof.clone();
        wrong.issued_at = fixture.view.logical_time + chrono::Duration::seconds(1);
        assert_eq!(
            fixture.verify(&wrong),
            Err(DestinationAdmissionError::Expired)
        );
        wrong = proof.clone();
        wrong.expires_at = fixture.view.logical_time;
        assert_eq!(
            fixture.verify(&wrong),
            Err(DestinationAdmissionError::Expired)
        );
        wrong = proof;
        wrong.expires_at = wrong.issued_at + chrono::Duration::seconds(31);
        assert_eq!(
            fixture.verify(&wrong),
            Err(DestinationAdmissionError::Expired)
        );
        let unknown = serde_json::from_str::<DestinationAuthorityMode>("\"offline_legacy\"");
        assert!(unknown.is_err());
    }

    #[test]
    fn system_scope_requires_explicit_committed_binding_and_an_operator_key() {
        let mut fixture = Fixture::new();
        fixture.binding.tenant_id = Some(crate::context::DEFAULT_TENANT.to_owned());
        fixture.view.ownership_tenant_scopes.insert(
            fixture.binding.agent_id.clone(), crate::context::DEFAULT_TENANT.to_owned(),
        );
        let principal = fixture.view.principals.values_mut().next().unwrap();
        principal.kind = AuthorityPrincipalKind::Operator;
        principal.tenant_id = None;
        let proof = fixture.signed();
        assert!(verify_destination_request(
            &proof, &fixture.binding, &fixture.view, None,
            &fixture.binding.owner_node_id, fixture.view.logical_time,
        ).is_ok());
        fixture.view.ownership_tenant_scopes.clear();
        assert_eq!(fixture.verify(&proof), Err(DestinationAdmissionError::TenantScope));
    }

    #[test]
    fn actual_mutation_binding_is_order_independent_and_rejects_target_substitution() {
        use crate::syscall_server::{AgentMutationFenceProof, Syscall};
        let fixture = Fixture::new();
        let b = &fixture.binding;
        let fence = AgentMutationFenceProof {
            cluster_id: b.cluster_id.clone(), owner_node_id: b.owner_node_id.clone(),
            authority_term: b.authority_term, authority_generation: b.authority_generation,
            fencing_token: b.fencing_token, proof_expires_at: b.lease_expires_at,
        };
        let make = |args| Syscall::FencedAgentMutation {
            agent_id: b.agent_id.clone(), proof: fence.clone(),
            mutation: Box::new(Syscall::CallTool {
                agent_id: b.agent_id.clone(), tool: "write_file".into(), args,
            }),
        };
        let a = make(serde_json::from_str(r#"{"path":"one","content":"two"}"#).unwrap());
        let c = make(serde_json::from_str(r#"{"content":"two","path":"one"}"#).unwrap());
        let tenant = b.tenant_id.as_deref().unwrap();
        assert_eq!(request_binding(&a, &b.operation_id, tenant).unwrap(),
            request_binding(&c, &b.operation_id, tenant).unwrap());
        let mut substitution = a.clone();
        if let Syscall::FencedAgentMutation { mutation, .. } = &mut substitution {
            *mutation = Box::new(Syscall::PauseAgent { agent_id: uuid::Uuid::new_v4().to_string() });
        }
        assert!(request_binding(&substitution, &b.operation_id, tenant).is_err());
        assert!(request_binding(&Syscall::ListAgents, &b.operation_id, tenant).is_err());
    }
}
