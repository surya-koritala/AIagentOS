//! Immutable quorum identities and exact destination creation evidence.
//!
//! A reservation commits identity and initial placement in the authority store.
//! Destination creation is a separate SQLite transaction. Publication requires
//! its exact signed receipt; neither a matching UUID nor an ownership lease is
//! evidence that the reserved identity was created.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cluster_control::{hex_decode, sha256_hex, ClusterControl};
use crate::cluster_principal::{AuthorityPrincipal, AuthorityPrincipalKind, PrincipalProofError};

pub const FEATURE: &str = "quorum-agent-identity-v1";
pub const IDENTITY_VERSION: u16 = 1;
pub(crate) const IDENTITY_SCHEMA_VERSION: i64 = 16;
pub(crate) const DESTINATION_IDENTITY_TRIGGERS: &[(&str, &str)] = &[
    ("cluster_agent_creation_identity_immutable",
        "CREATE TRIGGER IF NOT EXISTS cluster_agent_creation_identity_immutable
         BEFORE UPDATE OF agent_id, reservation_json, reservation_sha256,
             creation_operation_id, installation_id, local_receipt_id ON cluster_agent_creation_journal
         BEGIN SELECT RAISE(ABORT, 'immutable destination identity cannot be replaced'); END;"),
    ("cluster_agent_creation_tombstone_retained",
        "CREATE TRIGGER IF NOT EXISTS cluster_agent_creation_tombstone_retained
         BEFORE DELETE ON cluster_agent_creation_journal
         BEGIN SELECT RAISE(ABORT, 'destination identity tombstones must be retained'); END;"),
];
pub const MAX_AGENT_IDENTITIES: usize = 100_000;
pub const MAX_IDENTITY_REVISION: u64 = i64::MAX as u64;
const RECEIPT_DOMAIN: &[u8] = b"AIagentOS exact destination creation v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentIdentityScope {
    System,
    Tenant { tenant_id: String },
}

impl AgentIdentityScope {
    pub fn validate(&self) -> Result<(), AgentIdentityError> {
        match self {
            Self::System => Ok(()),
            Self::Tenant { tenant_id } if canonical_uuid(tenant_id) => Ok(()),
            _ => Err(AgentIdentityError::InvalidIdentity),
        }
    }

    /// The legacy storage sentinel never selects system authority. Only this
    /// explicitly committed enum variant may select it.
    pub fn storage_tenant(&self) -> &str {
        match self {
            Self::System => crate::context::DEFAULT_TENANT,
            Self::Tenant { tenant_id } => tenant_id,
        }
    }

    pub fn authorize(&self, principal: &AuthorityPrincipal) -> Result<(), PrincipalProofError> {
        match (self, principal.kind, principal.tenant_id.as_deref()) {
            (Self::System, AuthorityPrincipalKind::Operator, None) => Ok(()),
            (Self::Tenant { .. }, AuthorityPrincipalKind::Operator, None) => Ok(()),
            (Self::Tenant { tenant_id }, AuthorityPrincipalKind::Tenant, Some(actual))
                if tenant_id == actual =>
            {
                Ok(())
            }
            _ => Err(PrincipalProofError::TenantScope),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentityReservation {
    pub version: u16,
    pub cluster_id: String,
    pub agent_id: String,
    pub scope: AgentIdentityScope,
    pub creator_principal_id: String,
    pub creation_operation_id: String,
    pub creation_sha256: String,
    pub initial_owner_node_id: String,
    pub initial_authority_term: u64,
    pub initial_authority_generation: u64,
    pub initial_fencing_token: u64,
    pub initial_lease_expires_at: DateTime<Utc>,
    pub prepared_at: DateTime<Utc>,
    pub reservation_revision: u64,
}

impl AgentIdentityReservation {
    pub fn validate(&self) -> Result<(), AgentIdentityError> {
        self.scope.validate()?;
        if self.version != IDENTITY_VERSION
            || !canonical_uuid(&self.cluster_id)
            || !canonical_uuid(&self.agent_id)
            || !canonical_uuid(&self.creator_principal_id)
            || !canonical_uuid(&self.creation_operation_id)
            || !canonical_uuid(&self.initial_owner_node_id)
            || !canonical_hex(&self.creation_sha256, 32)
            || self.initial_authority_term == 0
            || self.initial_authority_generation == 0
            || self.initial_fencing_token == 0
            || self.initial_lease_expires_at <= self.prepared_at
            || self.reservation_revision != 1
        {
            return Err(AgentIdentityError::InvalidIdentity);
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String, AgentIdentityError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| AgentIdentityError::InvalidIdentity)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentIdentityState {
    Prepared,
    Created,
    Published,
    Aborted,
    Deleted,
}

/// The destination signs this complete attestation with its admitted node key.
/// Installation and local receipt identities survive retry, restart and backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationCreationReceipt {
    pub version: u16,
    pub cluster_id: String,
    pub agent_id: String,
    pub scope: AgentIdentityScope,
    pub creator_principal_id: String,
    pub creation_operation_id: String,
    pub creation_sha256: String,
    pub reservation_revision: u64,
    pub reservation_sha256: String,
    pub destination_node_id: String,
    pub destination_installation_id: String,
    pub local_receipt_id: String,
    pub created_agent_id: String,
    pub created_row_sha256: String,
    pub schema_version: i64,
    pub min_reader_schema_version: i64,
    pub protocol_version: u32,
    pub created_at: DateTime<Utc>,
    pub signature_hex: String,
}

impl DestinationCreationReceipt {
    pub fn sha256(&self) -> Result<String, AgentIdentityError> {
        serde_json::to_vec(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| AgentIdentityError::ReceiptMismatch)
    }
    pub fn validate(
        &self,
        reservation: &AgentIdentityReservation,
    ) -> Result<(), AgentIdentityError> {
        self.validate_binding(reservation)?;
        if !canonical_hex(&self.signature_hex, 64) {
            return Err(AgentIdentityError::InvalidReceiptSignature);
        }
        Ok(())
    }

    pub(crate) fn validate_binding(
        &self,
        reservation: &AgentIdentityReservation,
    ) -> Result<(), AgentIdentityError> {
        reservation.validate()?;
        if self.version != IDENTITY_VERSION
            || self.cluster_id != reservation.cluster_id
            || self.agent_id != reservation.agent_id
            || self.scope != reservation.scope
            || self.creator_principal_id != reservation.creator_principal_id
            || self.creation_operation_id != reservation.creation_operation_id
            || self.creation_sha256 != reservation.creation_sha256
            || self.reservation_revision != reservation.reservation_revision
            || self.reservation_sha256 != reservation.sha256()?
            || self.destination_node_id != reservation.initial_owner_node_id
            || !canonical_uuid(&self.destination_installation_id)
            || !canonical_uuid(&self.local_receipt_id)
            || self.created_agent_id != reservation.agent_id
            || !canonical_hex(&self.created_row_sha256, 32)
            || self.schema_version < IDENTITY_SCHEMA_VERSION
            || self.min_reader_schema_version < IDENTITY_SCHEMA_VERSION
            || self.min_reader_schema_version > self.schema_version
            || self.protocol_version < 2
            || self.created_at < reservation.prepared_at
            || self.created_at >= reservation.initial_lease_expires_at
        {
            return Err(AgentIdentityError::ReceiptMismatch);
        }
        Ok(())
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>, AgentIdentityError> {
        let mut unsigned = self.clone();
        unsigned.signature_hex.clear();
        let mut payload = RECEIPT_DOMAIN.to_vec();
        payload.extend(
            serde_json::to_vec(&unsigned).map_err(|_| AgentIdentityError::ReceiptMismatch)?,
        );
        Ok(payload)
    }

    pub fn verify_signature(&self, public_key: &str) -> Result<(), AgentIdentityError> {
        let signature = hex_decode(&self.signature_hex)
            .filter(|bytes| bytes.len() == 64)
            .ok_or(AgentIdentityError::InvalidReceiptSignature)?;
        if !ClusterControl::verify_challenge(public_key, &self.signing_payload()?, &signature) {
            return Err(AgentIdentityError::InvalidReceiptSignature);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentityRecord {
    pub reservation: AgentIdentityReservation,
    pub state: AgentIdentityState,
    pub revision: u64,
    pub creation_receipt: Option<DestinationCreationReceipt>,
    pub changed_at: DateTime<Utc>,
    pub last_operation_id: String,
    pub changed_by_principal_id: String,
    pub tombstone_reason: Option<String>,
}

impl AgentIdentityRecord {
    pub fn validate(&self) -> Result<(), AgentIdentityError> {
        self.reservation.validate()?;
        if self.revision == 0
            || self.revision > MAX_IDENTITY_REVISION
            || !canonical_uuid(&self.last_operation_id)
            || !canonical_uuid(&self.changed_by_principal_id)
            || self.changed_at < self.reservation.prepared_at
        {
            return Err(AgentIdentityError::InvalidIdentity);
        }
        let has_receipt = self.creation_receipt.is_some();
        let legal = match self.state {
            AgentIdentityState::Prepared => self.revision == 1 && !has_receipt,
            AgentIdentityState::Created => self.revision == 2 && has_receipt,
            AgentIdentityState::Published => self.revision == 3 && has_receipt,
            AgentIdentityState::Aborted => {
                (self.revision == 2 && !has_receipt) || (self.revision == 3 && has_receipt)
            }
            AgentIdentityState::Deleted => self.revision == 4 && has_receipt,
        };
        let tombstone = matches!(
            self.state,
            AgentIdentityState::Aborted | AgentIdentityState::Deleted
        );
        if !legal
            || matches!(
                self.state,
                AgentIdentityState::Prepared
                    | AgentIdentityState::Created
                    | AgentIdentityState::Published
            ) && self.changed_by_principal_id != self.reservation.creator_principal_id
            || self.state == AgentIdentityState::Prepared
                && self.last_operation_id != self.reservation.creation_operation_id
            || tombstone != self.tombstone_reason.is_some()
            || self.tombstone_reason.as_ref().is_some_and(|reason| {
                reason.is_empty() || reason.len() > 1024 || reason.chars().any(char::is_control)
            })
        {
            return Err(AgentIdentityError::InvalidTransition);
        }
        if let Some(receipt) = &self.creation_receipt {
            receipt.validate(&self.reservation)?;
            if receipt.created_at > self.changed_at {
                return Err(AgentIdentityError::ReceiptMismatch);
            }
        }
        Ok(())
    }

    pub fn authorize_creator(
        &self,
        principal: &AuthorityPrincipal,
    ) -> Result<(), PrincipalProofError> {
        self.reservation.scope.authorize(principal)?;
        if principal.principal_id != self.reservation.creator_principal_id {
            return Err(PrincipalProofError::TenantScope);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum AgentIdentityError {
    #[error("agent identity reservation is invalid")]
    InvalidIdentity,
    #[error("agent identity transition conflicts with its committed revision")]
    InvalidTransition,
    #[error("destination creation receipt does not match the immutable reservation")]
    ReceiptMismatch,
    #[error("destination creation receipt signature is invalid")]
    InvalidReceiptSignature,
    #[error("destination contains conflicting or incomplete creation evidence")]
    DestinationConflict,
    #[error("agent identity is not published")]
    Unpublished,
}

pub(crate) fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

pub(crate) fn identity_command_agent(
    command: &crate::cluster_consensus::AuthorityCommand,
) -> Option<&str> {
    use crate::cluster_consensus::AuthorityCommand;
    match command {
        AuthorityCommand::PrepareAgentIdentity { agent_id, .. }
        | AuthorityCommand::RecordAgentCreation { agent_id, .. }
        | AuthorityCommand::PublishAgentIdentity { agent_id, .. }
        | AuthorityCommand::AbortAgentIdentity { agent_id, .. }
        | AuthorityCommand::DeleteAgentIdentity { agent_id, .. } => Some(agent_id),
        _ => None,
    }
}

pub(crate) fn verify_identity_command_scope(
    principal: &AuthorityPrincipal,
    command: &crate::cluster_consensus::AuthorityCommand,
    identities: &std::collections::BTreeMap<String, AgentIdentityRecord>,
) -> Result<(), PrincipalProofError> {
    use crate::cluster_consensus::AuthorityCommand;
    match command {
        AuthorityCommand::PrepareAgentIdentity {
            scope,
            creator_principal_id,
            ..
        } => {
            scope.authorize(principal)?;
            if creator_principal_id != &principal.principal_id {
                return Err(PrincipalProofError::TenantScope);
            }
        }
        AuthorityCommand::RecordAgentCreation { agent_id, .. }
        | AuthorityCommand::PublishAgentIdentity { agent_id, .. } => {
            identities
                .get(agent_id)
                .ok_or(PrincipalProofError::TenantScope)?
                .authorize_creator(principal)?;
        }
        AuthorityCommand::AbortAgentIdentity { agent_id, .. }
        | AuthorityCommand::DeleteAgentIdentity { agent_id, .. } => {
            let record = identities
                .get(agent_id)
                .ok_or(PrincipalProofError::TenantScope)?;
            record.reservation.scope.authorize(principal)?;
            if principal.kind != AuthorityPrincipalKind::Operator {
                record.authorize_creator(principal)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Hash only the exact creation arguments, excluding renewable fence proofs.
/// All IDs remain bound by the immutable reservation and receipt.
pub fn creation_command_sha256(
    call: &crate::syscall_server::Syscall,
) -> Result<String, AgentIdentityError> {
    use crate::syscall_server::Syscall;
    let value = match call {
        Syscall::CreateAgent {
            agent_id: Some(agent_id),
            name,
            task,
            provider,
            profile,
            priority,
            ..
        } if canonical_uuid(agent_id) => serde_json::json!({
            "create": { "agent_id": agent_id, "name": name, "task": task,
            "provider": provider, "profile": profile, "priority": priority }
        }),
        Syscall::CloneAgent {
            agent_id,
            child_agent_id,
            name,
            drop_capabilities,
            ..
        } if canonical_uuid(agent_id)
            && canonical_uuid(child_agent_id)
            && agent_id != child_agent_id =>
        {
            let drops = crate::cloning::clone_attenuation(drop_capabilities)
                .map_err(|_| AgentIdentityError::InvalidIdentity)?;
            return clone_creation_sha256(agent_id, child_agent_id, name, &drops);
        }
        _ => return Err(AgentIdentityError::InvalidIdentity),
    };
    serde_json::to_vec(&value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| AgentIdentityError::InvalidIdentity)
}

pub(crate) fn clone_creation_sha256(
    parent: &str,
    child: &str,
    name: &str,
    drops: &std::collections::BTreeSet<u64>,
) -> Result<String, AgentIdentityError> {
    let value = serde_json::json!({ "clone": { "agent_id": parent,
        "child_agent_id": child, "name": name, "drop_capabilities": drops } });
    serde_json::to_vec(&value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| AgentIdentityError::InvalidIdentity)
}

#[path = "cluster_agent_identity_store.rs"]
mod destination_store;

pub use destination_store::{
    begin_destination_creation, destination_agent_is_published, destination_creation_receipt,
    publish_destination_identity, DestinationCreationAdmission,
};
pub(crate) use destination_store::{
    commit_agent_creation_evidence, crash_identity_after_step_for_test, retain_identity_tombstones,
    validate_creation_write, validate_destination_identity_store,
};
