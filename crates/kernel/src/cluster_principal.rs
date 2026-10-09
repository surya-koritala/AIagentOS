//! Independent, public-key authorization for replicated cluster commands.
//!
//! Node transport/delegation keys identify the forwarding machine. They are
//! never accepted as a substitute for an enrolled operator or tenant key.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cluster_consensus::AuthorityCommand;

pub const MAX_AUTHORITY_PRINCIPALS: usize = 256;
pub const PRINCIPAL_PROOF_TTL_SECONDS: i64 = 30;
const PRINCIPAL_PROOF_CLOCK_SKEW_SECONDS: i64 = 5;
const PRINCIPAL_PROOF_VERSION: u16 = 1;

/// Closed command classes; principals cannot introduce new permission labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCommandClass {
    Membership,
    Ownership,
    PrincipalAdmin,
    TransportAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityPrincipalKind {
    Operator,
    Tenant,
}

/// Public replicated authorization record. Revoked records remain tombstones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPrincipal {
    pub principal_id: String,
    pub public_key: String,
    pub kind: AuthorityPrincipalKind,
    pub tenant_id: Option<String>,
    pub allowed_command_classes: BTreeSet<AuthorityCommandClass>,
    pub generation: u64,
    pub revoked: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

impl AuthorityPrincipal {
    pub fn validate(&self) -> Result<(), PrincipalProofError> {
        if !canonical_uuid(&self.principal_id)
            || !canonical_hex(&self.public_key, 32)
            || self.generation == 0
            || self.allowed_command_classes.is_empty()
            || self.allowed_command_classes.len() > 4
        {
            return Err(PrincipalProofError::InvalidPrincipal);
        }
        match (self.kind, self.tenant_id.as_deref()) {
            (AuthorityPrincipalKind::Operator, None) => {}
            (AuthorityPrincipalKind::Tenant, Some(tenant))
                if canonical_uuid(tenant)
                    && self.allowed_command_classes
                        == BTreeSet::from([AuthorityCommandClass::Ownership]) => {}
            _ => return Err(PrincipalProofError::InvalidPrincipal),
        }
        Ok(())
    }
}

pub(crate) fn genesis_principal_registry(
    seeds: &[AuthorityPrincipal],
    node_public_keys: impl Iterator<Item = String>,
    required: bool,
) -> Result<BTreeMap<String, AuthorityPrincipal>, PrincipalProofError> {
    if seeds.len() > 31 || (required && seeds.is_empty()) {
        return Err(PrincipalProofError::InvalidPrincipal);
    }
    let node_keys: BTreeSet<_> = node_public_keys.collect();
    let mut principals = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for seed in seeds {
        seed.validate()?;
        if seed.kind != AuthorityPrincipalKind::Operator
            || seed.generation != 1
            || seed.revoked
            || seed.expires_at.is_some()
            || !seed
                .allowed_command_classes
                .contains(&AuthorityCommandClass::PrincipalAdmin)
            || node_keys.contains(&seed.public_key)
            || !keys.insert(seed.public_key.clone())
            || principals
                .insert(seed.principal_id.clone(), seed.clone())
                .is_some()
        {
            return Err(PrincipalProofError::InvalidPrincipal);
        }
    }
    Ok(principals)
}

/// Caller-signed authorization, independent of the source node delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPrincipalProof {
    pub version: u16,
    pub cluster_id: String,
    pub principal_id: String,
    pub principal_generation: u64,
    pub operation_id: String,
    pub command_sha256: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature_hex: String,
}

/// Stable redacted failures: no command, key, target or account data is echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalProofError {
    #[error("cluster principal proof is required")]
    Missing,
    #[error("cluster principal is not enrolled")]
    Unknown,
    #[error("cluster principal is revoked")]
    Revoked,
    #[error("cluster principal proof is expired or outside its validity window")]
    Expired,
    #[error("cluster principal command class is not authorized")]
    WrongCommandClass,
    #[error("cluster principal command digest does not match")]
    WrongDigest,
    #[error("cluster principal generation does not match")]
    WrongGeneration,
    #[error("cluster principal signature is invalid")]
    InvalidSignature,
    #[error("cluster principal proof identity is invalid")]
    InvalidProof,
    #[error("cluster principal record is invalid")]
    InvalidPrincipal,
    #[error("cluster principal tenant scope is not authorized")]
    TenantScope,
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

/// Remove exactly one authorization envelope. Nested envelopes fail closed.
pub fn unsigned_authority_command(
    command: &AuthorityCommand,
) -> Result<&AuthorityCommand, PrincipalProofError> {
    match command {
        AuthorityCommand::Authorized { command, .. } => {
            if matches!(command.as_ref(), AuthorityCommand::Authorized { .. }) {
                Err(PrincipalProofError::InvalidProof)
            } else {
                Ok(command)
            }
        }
        _ => Ok(command),
    }
}

pub fn authority_command_class(
    command: &AuthorityCommand,
) -> Result<AuthorityCommandClass, PrincipalProofError> {
    match unsigned_authority_command(command)? {
        AuthorityCommand::IssueJoinChallenge { .. }
        | AuthorityCommand::RegisterMember { .. }
        | AuthorityCommand::PrepareMemberCertificateRollout { .. }
        | AuthorityCommand::AbortMemberCertificateRollout { .. }
        | AuthorityCommand::FinalizeMemberCertificateRollout { .. }
        | AuthorityCommand::SetMemberState { .. } => Ok(AuthorityCommandClass::Membership),
        AuthorityCommand::ClaimOwnership { .. }
        | AuthorityCommand::RenewOwnership { .. }
        | AuthorityCommand::ReleaseOwnership { .. } => Ok(AuthorityCommandClass::Ownership),
        AuthorityCommand::EnrollPrincipal { .. } | AuthorityCommand::RevokePrincipal { .. } => {
            Ok(AuthorityCommandClass::PrincipalAdmin)
        }
        AuthorityCommand::Initialize { .. }
        | AuthorityCommand::Barrier { .. }
        | AuthorityCommand::AdvanceTime { .. }
        | AuthorityCommand::Authorized { .. } => Err(PrincipalProofError::WrongCommandClass),
    }
}

/// The same semantic digest used by node delegation and durable retry receipts.
/// Only the leader-controlled clock and authenticated envelope are excluded.
pub fn authority_command_semantic_sha256(
    command: &AuthorityCommand,
) -> Result<String, PrincipalProofError> {
    let mut value = serde_json::to_value(unsigned_authority_command(command)?)
        .map_err(|_| PrincipalProofError::InvalidProof)?;
    let fields = value
        .as_object_mut()
        .and_then(|outer| outer.values_mut().next())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(PrincipalProofError::InvalidProof)?;
    fields.remove("proposed_at");
    let mut canonical = Vec::new();
    encode_canonical_json(&value, &mut canonical)?;
    Ok(crate::cluster_control::sha256_hex(&canonical))
}

fn encode_canonical_json(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<(), PrincipalProofError> {
    match value {
        serde_json::Value::Object(fields) => {
            output.push(b'{');
            let ordered = fields.iter().collect::<BTreeMap<_, _>>();
            for (index, (key, value)) in ordered.into_iter().enumerate() {
                if index > 0 { output.push(b','); }
                serde_json::to_writer(&mut *output, key).map_err(|_| PrincipalProofError::InvalidProof)?;
                output.push(b':');
                encode_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 { output.push(b','); }
                encode_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        _ => serde_json::to_writer(output, value).map_err(|_| PrincipalProofError::InvalidProof)?,
    }
    Ok(())
}

#[cfg(test)]
mod canonical_tests {
    use super::*;

    #[test]
    fn canonical_bytes_sort_nested_objects_and_preserve_array_order() {
        let value: serde_json::Value = serde_json::from_str(r#"{"z":{"b":1,"a":2},"a":[{"y":true,"x":"quoted"},3]}"#).unwrap();
        let mut encoded = Vec::new();
        encode_canonical_json(&value, &mut encoded).unwrap();
        assert_eq!(encoded, br#"{"a":[{"x":"quoted","y":true},3],"z":{"a":2,"b":1}}"#);
        let reordered: serde_json::Value = serde_json::from_str(r#"{"a":[3,{"x":"quoted","y":true}],"z":{"a":2,"b":1}}"#).unwrap();
        let mut other = Vec::new();
        encode_canonical_json(&reordered, &mut other).unwrap();
        assert_ne!(encoded, other);
    }
}

fn append_field(payload: &mut Vec<u8>, value: &str) -> Result<(), PrincipalProofError> {
    let length = u32::try_from(value.len()).map_err(|_| PrincipalProofError::InvalidProof)?;
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(value.as_bytes());
    Ok(())
}

fn proof_payload(proof: &AuthorityPrincipalProof) -> Result<Vec<u8>, PrincipalProofError> {
    let mut payload = b"AIagentOS independent authority principal v1".to_vec();
    payload.extend_from_slice(&proof.version.to_be_bytes());
    for value in [
        &proof.cluster_id,
        &proof.principal_id,
        &proof.operation_id,
        &proof.command_sha256,
    ] {
        append_field(&mut payload, value)?;
    }
    payload.extend_from_slice(&proof.principal_generation.to_be_bytes());
    append_field(&mut payload, &proof.issued_at.to_rfc3339())?;
    append_field(&mut payload, &proof.expires_at.to_rfc3339())?;
    Ok(payload)
}

/// Sign on the caller side. The callback owns the independent private key;
/// no runtime configuration or replicated state contains that key.
pub fn sign_authority_principal(
    command: AuthorityCommand,
    cluster_id: &str,
    principal_id: &str,
    principal_generation: u64,
    now: DateTime<Utc>,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, PrincipalProofError>,
) -> Result<AuthorityCommand, PrincipalProofError> {
    if matches!(command, AuthorityCommand::Authorized { .. })
        || !canonical_uuid(cluster_id)
        || !canonical_uuid(principal_id)
        || !canonical_uuid(command.operation_id())
        || principal_generation == 0
    {
        return Err(PrincipalProofError::InvalidProof);
    }
    authority_command_class(&command)?;
    let mut proof = AuthorityPrincipalProof {
        version: PRINCIPAL_PROOF_VERSION,
        cluster_id: cluster_id.into(),
        principal_id: principal_id.into(),
        principal_generation,
        operation_id: command.operation_id().into(),
        command_sha256: authority_command_semantic_sha256(&command)?,
        issued_at: now,
        expires_at: now
            .checked_add_signed(chrono::Duration::seconds(PRINCIPAL_PROOF_TTL_SECONDS))
            .ok_or(PrincipalProofError::InvalidProof)?,
        signature_hex: String::new(),
    };
    let signature = sign(&proof_payload(&proof)?)?;
    if signature.len() != 64 {
        return Err(PrincipalProofError::InvalidSignature);
    }
    proof.signature_hex = crate::cluster_control::hex_encode(&signature);
    Ok(AuthorityCommand::Authorized {
        command: Box::new(command),
        principal_proof: proof,
    })
}

/// Verify current replicated authorization before either new writes or replay.
pub fn verify_authority_principal<'a>(
    command: &AuthorityCommand,
    cluster_id: &str,
    principals: &'a BTreeMap<String, AuthorityPrincipal>,
    now: DateTime<Utc>,
) -> Result<&'a AuthorityPrincipal, PrincipalProofError> {
    let AuthorityCommand::Authorized {
        principal_proof: proof,
        ..
    } = command
    else {
        return Err(PrincipalProofError::Missing);
    };
    let inner = unsigned_authority_command(command)?;
    if proof.version != PRINCIPAL_PROOF_VERSION
        || proof.cluster_id != cluster_id
        || !canonical_uuid(&proof.cluster_id)
        || !canonical_uuid(&proof.principal_id)
        || proof.operation_id != inner.operation_id()
        || !canonical_uuid(&proof.operation_id)
        || !canonical_hex(&proof.command_sha256, 32)
    {
        return Err(PrincipalProofError::InvalidProof);
    }
    let principal = principals
        .get(&proof.principal_id)
        .ok_or(PrincipalProofError::Unknown)?;
    principal.validate()?;
    if principal.revoked {
        return Err(PrincipalProofError::Revoked);
    }
    if proof.principal_generation != principal.generation {
        return Err(PrincipalProofError::WrongGeneration);
    }
    if principal.expires_at.is_some_and(|expiry| expiry <= now)
        || proof.expires_at <= now
        || proof.expires_at <= proof.issued_at
        || proof.issued_at
            > now
                .checked_add_signed(chrono::Duration::seconds(
                    PRINCIPAL_PROOF_CLOCK_SKEW_SECONDS,
                ))
                .ok_or(PrincipalProofError::InvalidProof)?
        || proof.expires_at
            > proof
                .issued_at
                .checked_add_signed(chrono::Duration::seconds(PRINCIPAL_PROOF_TTL_SECONDS))
                .ok_or(PrincipalProofError::InvalidProof)?
    {
        return Err(PrincipalProofError::Expired);
    }
    if !principal
        .allowed_command_classes
        .contains(&authority_command_class(inner)?)
    {
        return Err(PrincipalProofError::WrongCommandClass);
    }
    if proof.command_sha256 != authority_command_semantic_sha256(inner)? {
        return Err(PrincipalProofError::WrongDigest);
    }
    if !canonical_hex(&proof.signature_hex, 64) {
        return Err(PrincipalProofError::InvalidSignature);
    }
    let signature = crate::cluster_control::hex_decode(&proof.signature_hex)
        .ok_or(PrincipalProofError::InvalidSignature)?;
    if !crate::cluster_control::ClusterControl::verify_challenge(
        &principal.public_key,
        &proof_payload(proof)?,
        &signature,
    ) {
        return Err(PrincipalProofError::InvalidSignature);
    }
    Ok(principal)
}

pub(crate) fn ownership_agent(command: &AuthorityCommand) -> Option<&str> {
    match command {
        AuthorityCommand::ClaimOwnership { agent_id, .. }
        | AuthorityCommand::RenewOwnership { agent_id, .. }
        | AuthorityCommand::ReleaseOwnership { agent_id, .. } => Some(agent_id),
        _ => None,
    }
}

pub(crate) fn command_proposed_at(command: &AuthorityCommand) -> Option<DateTime<Utc>> {
    match command {
        AuthorityCommand::IssueJoinChallenge { proposed_at, .. }
        | AuthorityCommand::RegisterMember { proposed_at, .. }
        | AuthorityCommand::PrepareMemberCertificateRollout { proposed_at, .. }
        | AuthorityCommand::AbortMemberCertificateRollout { proposed_at, .. }
        | AuthorityCommand::FinalizeMemberCertificateRollout { proposed_at, .. }
        | AuthorityCommand::SetMemberState { proposed_at, .. }
        | AuthorityCommand::ClaimOwnership { proposed_at, .. }
        | AuthorityCommand::RenewOwnership { proposed_at, .. }
        | AuthorityCommand::ReleaseOwnership { proposed_at, .. }
        | AuthorityCommand::EnrollPrincipal { proposed_at, .. }
        | AuthorityCommand::RevokePrincipal { proposed_at, .. } => Some(*proposed_at),
        _ => None,
    }
}

pub(crate) fn set_committed_command_time(command: &mut AuthorityCommand, at: DateTime<Utc>) {
    let command = match command {
        AuthorityCommand::Authorized { command, .. } => command.as_mut(),
        command => command,
    };
    match command {
        AuthorityCommand::IssueJoinChallenge { proposed_at, .. }
        | AuthorityCommand::RegisterMember { proposed_at, .. }
        | AuthorityCommand::PrepareMemberCertificateRollout { proposed_at, .. }
        | AuthorityCommand::AbortMemberCertificateRollout { proposed_at, .. }
        | AuthorityCommand::FinalizeMemberCertificateRollout { proposed_at, .. }
        | AuthorityCommand::SetMemberState { proposed_at, .. }
        | AuthorityCommand::ClaimOwnership { proposed_at, .. }
        | AuthorityCommand::RenewOwnership { proposed_at, .. }
        | AuthorityCommand::ReleaseOwnership { proposed_at, .. }
        | AuthorityCommand::EnrollPrincipal { proposed_at, .. }
        | AuthorityCommand::RevokePrincipal { proposed_at, .. } => *proposed_at = at,
        _ => {}
    }
}

pub(crate) fn set_verified_audit_actor(command: &mut AuthorityCommand, principal_id: &str) {
    match command {
        AuthorityCommand::RegisterMember { actor, .. }
        | AuthorityCommand::PrepareMemberCertificateRollout { actor, .. }
        | AuthorityCommand::AbortMemberCertificateRollout { actor, .. }
        | AuthorityCommand::FinalizeMemberCertificateRollout { actor, .. }
        | AuthorityCommand::SetMemberState { actor, .. }
        | AuthorityCommand::ClaimOwnership { actor, .. }
        | AuthorityCommand::RenewOwnership { actor, .. }
        | AuthorityCommand::ReleaseOwnership { actor, .. }
        | AuthorityCommand::EnrollPrincipal { actor, .. }
        | AuthorityCommand::RevokePrincipal { actor, .. } => {
            *actor = format!("principal:{principal_id}")
        }
        _ => {}
    }
}

/// Origin, leader, and public replay admission share the same current-state check.
pub fn verify_authority_principal_view(
    command: &AuthorityCommand,
    view: &crate::cluster_consensus::ReplicatedAuthorityView,
    now: DateTime<Utc>,
) -> Result<AuthorityPrincipal, PrincipalProofError> {
    let principal = verify_authority_principal(
        command,
        &view.genesis.cluster_id,
        &view.principals,
        now.max(view.logical_time),
    )?;
    let inner = unsigned_authority_command(command)?;
    let existing = ownership_agent(inner)
        .is_some_and(|agent| view.ownerships.iter().any(|row| row.agent_id == agent));
    verify_tenant_ownership_scope(principal, inner, &view.ownership_tenant_scopes, existing)?;
    verify_member_key_separation(inner, &view.principals)?;
    Ok(principal.clone())
}

pub(crate) fn verify_member_key_separation(
    command: &AuthorityCommand,
    principals: &BTreeMap<String, AuthorityPrincipal>,
) -> Result<(), PrincipalProofError> {
    let registration = match command {
        AuthorityCommand::RegisterMember { registration, .. }
        | AuthorityCommand::PrepareMemberCertificateRollout { registration, .. } => {
            Some(registration)
        }
        _ => None,
    };
    if registration.is_some_and(|registration| {
        principals
            .values()
            .any(|principal| principal.public_key == registration.public_key)
    }) {
        return Err(PrincipalProofError::InvalidPrincipal);
    }
    Ok(())
}

/// Tenant ownership uses immutable scope retained after lease expiry/release.
pub(crate) fn verify_tenant_ownership_scope(
    principal: &AuthorityPrincipal,
    command: &AuthorityCommand,
    tenant_scopes: &BTreeMap<String, String>,
    existing_ownership: bool,
) -> Result<(), PrincipalProofError> {
    if principal.kind == AuthorityPrincipalKind::Operator {
        return Ok(());
    }
    let agent = ownership_agent(command).ok_or(PrincipalProofError::TenantScope)?;
    let tenant = principal
        .tenant_id
        .as_deref()
        .ok_or(PrincipalProofError::TenantScope)?;
    match tenant_scopes.get(agent) {
        Some(owner) if owner == tenant => Ok(()),
        None if !existing_ownership
            && matches!(command, AuthorityCommand::ClaimOwnership { .. }) =>
        {
            Ok(())
        }
        _ => Err(PrincipalProofError::TenantScope),
    }
}

#[cfg(test)]
pub(crate) const FIXTURE_CLUSTER_ID: &str = "00000000-0000-0000-0000-000000000100";

#[cfg(test)]
fn fixture_key() -> &'static ring::signature::Ed25519KeyPair {
    static KEY: std::sync::OnceLock<ring::signature::Ed25519KeyPair> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let document =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .expect("generate ephemeral CI principal");
        ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref())
            .expect("parse ephemeral CI principal")
    })
}

#[cfg(test)]
pub(crate) fn fixture_operator() -> AuthorityPrincipal {
    use ring::signature::KeyPair;
    AuthorityPrincipal {
        principal_id: "00000000-0000-0000-0000-000000000900".into(),
        public_key: crate::cluster_control::hex_encode(fixture_key().public_key().as_ref()),
        kind: AuthorityPrincipalKind::Operator,
        tenant_id: None,
        allowed_command_classes: BTreeSet::from([
            AuthorityCommandClass::Membership,
            AuthorityCommandClass::Ownership,
            AuthorityCommandClass::PrincipalAdmin,
            AuthorityCommandClass::TransportAdmin,
        ]),
        generation: 1,
        revoked: false,
        expires_at: None,
    }
}

#[cfg(test)]
pub(crate) fn fixture_registry() -> BTreeMap<String, AuthorityPrincipal> {
    let principal = fixture_operator();
    BTreeMap::from([(principal.principal_id.clone(), principal)])
}

#[cfg(test)]
pub(crate) fn fixture_signed(command: AuthorityCommand, cluster_id: &str) -> AuthorityCommand {
    fixture_signed_generation(command, cluster_id, 1)
}

#[cfg(test)]
pub(crate) fn fixture_signed_generation(
    command: AuthorityCommand,
    cluster_id: &str,
    generation: u64,
) -> AuthorityCommand {
    let principal = fixture_operator();
    let now = command_proposed_at(&command).unwrap_or_else(Utc::now);
    sign_authority_principal(
        command,
        cluster_id,
        &principal.principal_id,
        generation,
        now,
        |payload| Ok(fixture_key().sign(payload).as_ref().to_vec()),
    )
    .expect("sign explicit CI command fixture")
}
