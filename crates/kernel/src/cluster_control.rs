//! Durable node identity and local control-plane admission state.
//!
//! A cluster node must not derive its identity from a dial address: addresses
//! change across restarts and can be reused by a different process. This module
//! creates one Ed25519 identity inside the kernel's durable SQLite boundary,
//! exposes only its public fingerprint, and persists generation-fenced
//! active/draining/quarantined transitions with an audit trail.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::context::SqliteContextManager;
use crate::ContextError;

const SINGLETON: i64 = 1;
pub(crate) const MAX_REASON_BYTES: usize = 1024;
const MAX_PROFILE_BYTES: usize = 64 * 1024;
const MAX_PROFILE_VALUES: usize = 256;
const MAX_PROFILE_LABELS: usize = 128;
const MAX_PROFILE_TEXT_BYTES: usize = 256;
const MAX_MEMBER_ENDPOINT_BYTES: usize = 2048;
const MAX_MEMBER_VERSION_BYTES: usize = 256;
pub(crate) const MIN_JOIN_CHALLENGE_TTL_SECONDS: u64 = 5;
pub(crate) const MAX_JOIN_CHALLENGE_TTL_SECONDS: u64 = 300;
pub(crate) const MIN_CERTIFICATE_ROLLOUT_SECONDS: u64 = 5;
pub(crate) const MAX_CERTIFICATE_ROLLOUT_SECONDS: u64 = 3_600;
pub(crate) const MIN_OWNERSHIP_LEASE_TTL_SECONDS: u64 = 5;
pub(crate) const MAX_OWNERSHIP_LEASE_TTL_SECONDS: u64 = 300;

#[cfg(test)]
thread_local! {
    static CLUSTER_MUTATION_STEP_FOR_TEST: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn crash_cluster_mutation_after_step_for_test(statement: &str) {
    let target = std::env::var("AIAGENTOS_TEST_EXIT_CLUSTER_AFTER_STEP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    CLUSTER_MUTATION_STEP_FOR_TEST.with(|counter| {
        let step = counter.get().saturating_add(1);
        counter.set(step);
        if target == Some(step) {
            eprintln!("terminating after cluster mutation {step}: {statement}");
            std::process::exit(86);
        }
    });
}

#[cfg(not(test))]
#[inline]
fn crash_cluster_mutation_after_step_for_test(_statement: &str) {}

/// Whether a node can receive new placement or mutable workload traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeAvailability {
    /// Accept normal placement and workload traffic.
    #[default]
    Active,
    /// Reject new placement while existing work is drained or migrated.
    Draining,
    /// Fail closed for mutable workload traffic until an operator restores it.
    Quarantined,
}

impl NodeAvailability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Quarantined => "quarantined",
        }
    }
}

impl TryFrom<&str> for NodeAvailability {
    type Error = ContextError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "active" => Ok(Self::Active),
            "draining" => Ok(Self::Draining),
            "quarantined" => Ok(Self::Quarantined),
            other => Err(storage_error(format!(
                "invalid persisted node availability {other:?}"
            ))),
        }
    }
}

/// Operator-declared placement constraints for one node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_residency: Option<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub sandbox_profiles: Vec<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Stable public identity for a kernel node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: String,
    /// SHA-256 of the Ed25519 public key, hex encoded.
    pub fingerprint: String,
    /// Ed25519 public key, hex encoded, for signed discovery challenges.
    pub public_key: String,
    pub created_at: DateTime<Utc>,
}

/// Complete placement/control view returned by the public node-info path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeControlStatus {
    pub identity: NodeIdentity,
    pub availability: NodeAvailability,
    pub generation: u64,
    pub profile: NodeProfile,
    pub reason: String,
    pub updated_at: DateTime<Utc>,
}

/// Durable evidence for one node-control mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeControlAudit {
    pub generation: u64,
    pub previous: NodeAvailability,
    pub current: NodeAvailability,
    pub actor: String,
    pub reason: String,
    pub changed_at: DateTime<Utc>,
}

/// Authoritative lifecycle of a node admitted to one cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterMemberState {
    /// Identity, endpoint, and protocol window are admitted for discovery.
    Active,
    /// The node left cleanly and must complete a fresh challenged join to return.
    Left,
    /// The identity is denied permanently by this authority.
    Revoked,
}

impl ClusterMemberState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Left => "left",
            Self::Revoked => "revoked",
        }
    }
}

impl TryFrom<&str> for ClusterMemberState {
    type Error = ContextError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "active" => Ok(Self::Active),
            "left" => Ok(Self::Left),
            "revoked" => Ok(Self::Revoked),
            other => Err(storage_error(format!(
                "invalid persisted cluster member state {other:?}"
            ))),
        }
    }
}

/// One-time authority challenge used to admit a cryptographically proven node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterJoinChallenge {
    pub cluster_id: String,
    pub challenge_hex: String,
    pub expires_at: DateTime<Utc>,
}

/// Candidate fields covered by the node's challenged join signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterMemberRegistration {
    pub node_id: String,
    pub fingerprint: String,
    pub public_key: String,
    /// SHA-256 of the node listener's verified TLS leaf certificate. `None`
    /// preserves explicitly plaintext legacy membership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_certificate_fingerprint: Option<String>,
    pub endpoint: String,
    pub server_version: String,
    pub min_protocol_version: u32,
    pub protocol_version: u32,
}

/// Durable membership record published by the designated authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterMember {
    pub node_id: String,
    pub fingerprint: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_certificate_fingerprint: Option<String>,
    pub endpoint: String,
    pub server_version: String,
    pub min_protocol_version: u32,
    pub protocol_version: u32,
    pub state: ClusterMemberState,
    pub generation: u64,
    pub joined_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub reason: String,
}

/// Quorum-coordinated application-listener certificate rollout phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterCertificateRolloutPhase {
    /// The current leaf remains authoritative while a bounded candidate leaf
    /// is staged for publication.
    Prepared,
    /// The replacement is current while the previous leaf drains for a
    /// bounded overlap interval.
    Activated,
}

/// Replicated, time-bounded application-listener certificate rollout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterCertificateRollout {
    pub node_id: String,
    pub trust_generation: u64,
    pub member_generation: u64,
    pub phase: ClusterCertificateRolloutPhase,
    pub previous_tls_server_certificate_fingerprint: String,
    pub next_tls_server_certificate_fingerprint: String,
    pub minimum_overlap_seconds: u64,
    /// Candidate authorization expires if activation never completes.
    pub prepare_expires_at: DateTime<Utc>,
    /// Present only after activation. The previous leaf is unauthorized at or
    /// after this replicated authority-clock instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retire_previous_after: Option<DateTime<Utc>>,
    pub prepared_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub reason: String,
}

impl ClusterCertificateRollout {
    /// Evaluate one verified leaf against this rollout using replicated
    /// authority time. Expiry always narrows trust without requiring another
    /// mutation to be available.
    pub fn accepts_fingerprint(&self, fingerprint: &str, authority_time: DateTime<Utc>) -> bool {
        match self.phase {
            ClusterCertificateRolloutPhase::Prepared => {
                fingerprint == self.previous_tls_server_certificate_fingerprint
                    || (authority_time < self.prepare_expires_at
                        && fingerprint == self.next_tls_server_certificate_fingerprint)
            }
            ClusterCertificateRolloutPhase::Activated => {
                fingerprint == self.next_tls_server_certificate_fingerprint
                    || (self
                        .retire_previous_after
                        .is_some_and(|deadline| authority_time < deadline)
                        && fingerprint == self.previous_tls_server_certificate_fingerprint)
            }
        }
    }
}

/// One transactionally consistent authority view used for discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterMembershipSnapshot {
    pub cluster_id: String,
    pub generation: u64,
    /// Replicated authority time used to evaluate certificate overlap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tls_trust_generation: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_rollouts: Vec<ClusterCertificateRollout>,
    pub members: Vec<ClusterMember>,
}

/// Durable evidence for one authority membership mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterMembershipAudit {
    pub membership_generation: u64,
    pub node_id: String,
    pub member_generation: u64,
    pub previous: Option<ClusterMemberState>,
    pub current: ClusterMemberState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_tls_server_certificate_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_tls_server_certificate_fingerprint: Option<String>,
    pub actor: String,
    pub reason: String,
    pub changed_at: DateTime<Utc>,
}

/// Durable evidence for one certificate-rollout transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterCertificateRolloutAudit {
    pub trust_generation: u64,
    pub node_id: String,
    pub member_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_phase: Option<ClusterCertificateRolloutPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_phase: Option<ClusterCertificateRolloutPhase>,
    pub previous_tls_server_certificate_fingerprint: String,
    pub next_tls_server_certificate_fingerprint: String,
    pub actor: String,
    pub reason: String,
    pub changed_at: DateTime<Utc>,
}

/// Durable state of one authority-issued agent ownership record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterOwnershipState {
    /// The exact owner and fencing token may be renewed until expiry.
    Active,
    /// The token is a permanent tombstone and can never become active again.
    Released,
}

impl ClusterOwnershipState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Released => "released",
        }
    }
}

impl TryFrom<&str> for ClusterOwnershipState {
    type Error = ContextError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "active" => Ok(Self::Active),
            "released" => Ok(Self::Released),
            other => Err(storage_error(format!(
                "invalid persisted cluster ownership state {other:?}"
            ))),
        }
    }
}

/// Authority-issued ownership lease. The fencing token never decreases for an
/// agent, including after release or expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterAgentOwnership {
    pub agent_id: String,
    pub owner_node_id: String,
    pub fencing_token: u64,
    pub generation: u64,
    pub state: ClusterOwnershipState,
    pub lease_expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub reason: String,
}

/// Durable evidence for an ownership claim, transfer, renewal, or release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterAgentOwnershipAudit {
    pub agent_id: String,
    pub generation: u64,
    pub previous_owner_node_id: Option<String>,
    pub owner_node_id: String,
    pub fencing_token: u64,
    pub operation: String,
    pub actor: String,
    pub reason: String,
    pub changed_at: DateTime<Utc>,
}

/// Destination-side state for the highest ownership token ever accepted for
/// one local agent. Retired fences remain as tombstones so an old owner cannot
/// become writable again after a restart or partition heals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMutationFenceState {
    Active,
    Retired,
}

impl AgentMutationFenceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

impl TryFrom<&str> for AgentMutationFenceState {
    type Error = ContextError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "active" => Ok(Self::Active),
            "retired" => Ok(Self::Retired),
            other => Err(storage_error(format!(
                "invalid persisted agent mutation fence state {other:?}"
            ))),
        }
    }
}

/// Durable destination admission record for fenced agent mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMutationFence {
    pub agent_id: String,
    pub cluster_id: String,
    pub owner_node_id: String,
    pub authority_generation: u64,
    pub fencing_token: u64,
    pub state: AgentMutationFenceState,
    pub installed_at: DateTime<Utc>,
    pub reason: String,
}

/// Durable evidence for installation or retirement of a destination fence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMutationFenceAudit {
    pub agent_id: String,
    pub cluster_id: String,
    pub owner_node_id: String,
    pub authority_generation: u64,
    pub fencing_token: u64,
    pub state: AgentMutationFenceState,
    pub actor: String,
    pub reason: String,
    pub changed_at: DateTime<Utc>,
}

/// Persistent local node-control state.
pub struct ClusterControl {
    store: Arc<SqliteContextManager>,
    identity: NodeIdentity,
}

impl ClusterControl {
    pub fn new(store: Arc<SqliteContextManager>) -> Result<Self, ContextError> {
        let identity = {
            let mut connection = store
                .conn
                .lock()
                .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| storage_error(format!("cluster identity transaction: {error}")))?;
            let existing = load_identity(&transaction)?;
            let identity = match existing {
                Some(identity) => identity,
                None => {
                    let random = SystemRandom::new();
                    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).map_err(|_| {
                        storage_error("failed to generate durable Ed25519 node identity")
                    })?;
                    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| {
                        storage_error("generated Ed25519 node identity could not be parsed")
                    })?;
                    let public_key = pair.public_key().as_ref().to_vec();
                    let created_at = Utc::now();
                    let identity = NodeIdentity {
                        node_id: uuid::Uuid::new_v4().to_string(),
                        fingerprint: sha256_hex(&public_key),
                        public_key: hex_encode(&public_key),
                        created_at,
                    };
                    transaction
                        .execute(
                            "INSERT INTO cluster_node_identity
                             (singleton, node_id, private_key, public_key, fingerprint, created_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            params![
                                SINGLETON,
                                identity.node_id,
                                pkcs8.as_ref(),
                                public_key,
                                identity.fingerprint,
                                identity.created_at.to_rfc3339(),
                            ],
                        )
                        .map_err(|error| {
                            storage_error(format!("persist cluster identity: {error}"))
                        })?;
                    crash_cluster_mutation_after_step_for_test("identity.insert");
                    identity
                }
            };
            let now = Utc::now().to_rfc3339();
            let initialized_control = transaction
                .execute(
                    "INSERT OR IGNORE INTO cluster_node_control
                     (singleton, availability, generation, profile_json, reason, updated_at)
                     VALUES (?1, 'active', 0, ?2, 'initial registration', ?3)",
                    params![
                        SINGLETON,
                        serde_json::to_string(&NodeProfile::default())
                            .map_err(|error| storage_error(error.to_string()))?,
                        now,
                    ],
                )
                .map_err(|error| {
                    storage_error(format!("initialize cluster node control: {error}"))
                })?;
            if initialized_control == 1 {
                crash_cluster_mutation_after_step_for_test("node_control.initialize");
            }
            let initialized_authority = transaction
                .execute(
                    "INSERT OR IGNORE INTO cluster_membership_authority
                     (singleton, cluster_id, generation, created_at)
                     VALUES (?1, ?2, 0, ?3)",
                    params![SINGLETON, uuid::Uuid::new_v4().to_string(), now],
                )
                .map_err(|error| {
                    storage_error(format!("initialize cluster membership authority: {error}"))
                })?;
            if initialized_authority == 1 {
                crash_cluster_mutation_after_step_for_test("membership_authority.initialize");
            }
            transaction
                .commit()
                .map_err(|error| storage_error(format!("commit cluster identity: {error}")))?;
            identity
        };
        Ok(Self { store, identity })
    }

    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    pub fn status(&self) -> Result<NodeControlStatus, ContextError> {
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        connection
            .query_row(
                "SELECT availability, generation, profile_json, reason, updated_at
                 FROM cluster_node_control WHERE singleton = ?1",
                [SINGLETON],
                |row| {
                    let availability: String = row.get(0)?;
                    let generation: i64 = row.get(1)?;
                    let profile_json: String = row.get(2)?;
                    let reason: String = row.get(3)?;
                    let updated_at: String = row.get(4)?;
                    Ok((availability, generation, profile_json, reason, updated_at))
                },
            )
            .map_err(|error| storage_error(format!("read node control: {error}")))
            .and_then(
                |(availability, generation, profile_json, reason, updated_at)| {
                    Ok(NodeControlStatus {
                        identity: self.identity.clone(),
                        availability: NodeAvailability::try_from(availability.as_str())?,
                        generation: u64::try_from(generation).map_err(|_| {
                            storage_error("node-control generation is outside the u64 range")
                        })?,
                        profile: serde_json::from_str(&profile_json)
                            .map_err(|error| {
                                storage_error(format!("invalid persisted node profile: {error}"))
                            })
                            .and_then(|profile| {
                                validate_profile(&profile)?;
                                Ok(profile)
                            })?,
                        reason,
                        updated_at: parse_timestamp(&updated_at)?,
                    })
                },
            )
    }

    /// Replace placement metadata using the same generation fence as state
    /// transitions. This prevents a stale operator from silently overwriting a
    /// concurrent region/model/security update.
    pub fn set_profile(
        &self,
        profile: NodeProfile,
        expected_generation: u64,
        actor: &str,
        reason: &str,
    ) -> Result<NodeControlStatus, ContextError> {
        validate_profile(&profile)?;
        self.mutate(None, Some(profile), expected_generation, actor, reason)
    }

    /// Transition active/draining/quarantined state with compare-and-set
    /// generation fencing and a durable audit entry.
    pub fn transition(
        &self,
        availability: NodeAvailability,
        expected_generation: u64,
        actor: &str,
        reason: &str,
    ) -> Result<NodeControlStatus, ContextError> {
        self.mutate(Some(availability), None, expected_generation, actor, reason)
    }

    fn mutate(
        &self,
        availability: Option<NodeAvailability>,
        profile: Option<NodeProfile>,
        expected_generation: u64,
        actor: &str,
        reason: &str,
    ) -> Result<NodeControlStatus, ContextError> {
        validate_text(actor, "cluster-control actor")?;
        validate_reason(reason)?;
        let mut connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error(format!("node-control transaction: {error}")))?;
        let (previous_text, current_generation, profile_json): (String, i64, String) = transaction
            .query_row(
                "SELECT availability, generation, profile_json
                 FROM cluster_node_control WHERE singleton = ?1",
                [SINGLETON],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| storage_error(format!("read node-control revision: {error}")))?;
        let current_generation = u64::try_from(current_generation)
            .map_err(|_| storage_error("node-control generation is outside the u64 range"))?;
        if current_generation != expected_generation {
            return Err(storage_error(format!(
                "node-control revision conflict: expected {expected_generation}, current {current_generation}"
            )));
        }
        let previous = NodeAvailability::try_from(previous_text.as_str())?;
        let next = availability.unwrap_or(previous);
        let next_profile = match profile {
            Some(profile) => profile,
            None => serde_json::from_str(&profile_json).map_err(|error| {
                storage_error(format!("invalid persisted node profile: {error}"))
            })?,
        };
        let next_generation = current_generation
            .checked_add(1)
            .ok_or_else(|| storage_error("node-control generation overflow"))?;
        let next_generation_i64 = i64::try_from(next_generation)
            .map_err(|_| storage_error("node-control generation exceeds SQLite integer range"))?;
        let now = Utc::now();
        let changed = transaction
            .execute(
                "UPDATE cluster_node_control
                 SET availability = ?1, generation = ?2, profile_json = ?3,
                     reason = ?4, updated_at = ?5
                 WHERE singleton = ?6 AND generation = ?7",
                params![
                    next.as_str(),
                    next_generation_i64,
                    serde_json::to_string(&next_profile)
                        .map_err(|error| storage_error(error.to_string()))?,
                    reason,
                    now.to_rfc3339(),
                    SINGLETON,
                    i64::try_from(expected_generation).map_err(|_| {
                        storage_error("expected generation exceeds SQLite integer range")
                    })?,
                ],
            )
            .map_err(|error| storage_error(format!("update node control: {error}")))?;
        if changed != 1 {
            return Err(storage_error("node-control revision conflict"));
        }
        crash_cluster_mutation_after_step_for_test("node_control.update");
        transaction
            .execute(
                "INSERT INTO cluster_node_control_audit
                 (generation, previous_availability, current_availability, actor, reason, changed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    next_generation_i64,
                    previous.as_str(),
                    next.as_str(),
                    actor,
                    reason,
                    now.to_rfc3339(),
                ],
            )
            .map_err(|error| storage_error(format!("audit node control: {error}")))?;
        crash_cluster_mutation_after_step_for_test("node_control.audit");
        transaction
            .commit()
            .map_err(|error| storage_error(format!("commit node control: {error}")))?;
        drop(connection);
        self.status()
    }

    pub fn audit(&self, limit: usize) -> Result<Vec<NodeControlAudit>, ContextError> {
        let limit = limit.clamp(1, 1_000);
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let mut statement = connection
            .prepare(
                "SELECT generation, previous_availability, current_availability,
                        actor, reason, changed_at
                 FROM cluster_node_control_audit
                 ORDER BY generation DESC LIMIT ?1",
            )
            .map_err(|error| storage_error(format!("prepare node-control audit: {error}")))?;
        let rows = statement
            .query_map([limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|error| storage_error(format!("query node-control audit: {error}")))?;
        let mut audit = Vec::new();
        for row in rows {
            let (generation, previous, current, actor, reason, changed_at) =
                row.map_err(|error| storage_error(format!("read node-control audit: {error}")))?;
            audit.push(NodeControlAudit {
                generation: u64::try_from(generation)
                    .map_err(|_| storage_error("negative node-control audit generation"))?,
                previous: NodeAvailability::try_from(previous.as_str())?,
                current: NodeAvailability::try_from(current.as_str())?,
                actor,
                reason,
                changed_at: parse_timestamp(&changed_at)?,
            });
        }
        Ok(audit)
    }

    /// Create a one-time, short-lived challenge for an authorized join.
    pub fn issue_join_challenge(
        &self,
        ttl_seconds: u64,
    ) -> Result<ClusterJoinChallenge, ContextError> {
        if !(MIN_JOIN_CHALLENGE_TTL_SECONDS..=MAX_JOIN_CHALLENGE_TTL_SECONDS).contains(&ttl_seconds)
        {
            return Err(storage_error(format!(
                "invalid join challenge ttl (expected {MIN_JOIN_CHALLENGE_TTL_SECONDS}..={MAX_JOIN_CHALLENGE_TTL_SECONDS} seconds)"
            )));
        }
        let mut challenge = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut challenge)
            .map_err(|_| storage_error("failed to generate cluster join challenge"))?;
        let challenge_hex = hex_encode(&challenge);
        let challenge_hash = sha256_hex(&challenge);
        let expires_at = Utc::now()
            + chrono::Duration::seconds(
                i64::try_from(ttl_seconds)
                    .map_err(|_| storage_error("join challenge ttl is outside the i64 range"))?,
            );
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let now = Utc::now().to_rfc3339();
        connection
            .execute(
                "DELETE FROM cluster_join_challenges
                 WHERE expires_at <= ?1",
                [&now],
            )
            .map_err(|error| storage_error(format!("prune cluster join challenges: {error}")))?;
        connection
            .execute(
                "INSERT INTO cluster_join_challenges
                 (challenge_hash, expires_at, consumed_at) VALUES (?1, ?2, NULL)",
                params![challenge_hash, expires_at.to_rfc3339()],
            )
            .map_err(|error| storage_error(format!("persist cluster join challenge: {error}")))?;
        let cluster_id: String = connection
            .query_row(
                "SELECT cluster_id FROM cluster_membership_authority WHERE singleton = ?1",
                [SINGLETON],
                |row| row.get(0),
            )
            .map_err(|error| storage_error(format!("read cluster authority id: {error}")))?;
        Ok(ClusterJoinChallenge {
            cluster_id,
            challenge_hex,
            expires_at,
        })
    }

    /// Admit or re-admit a node after a fresh authority challenge.
    ///
    /// The signed payload binds the cluster id, nonce, durable node identity,
    /// advertised endpoint, software version, and supported protocol window.
    /// Re-admission is compare-and-set fenced; revoked identities are terminal.
    #[allow(clippy::too_many_arguments)]
    pub fn register_member(
        &self,
        registration: ClusterMemberRegistration,
        challenge_hex: &str,
        signature_hex: &str,
        expected_generation: Option<u64>,
        authority_min_protocol_version: u32,
        authority_protocol_version: u32,
        actor: &str,
        reason: &str,
    ) -> Result<ClusterMember, ContextError> {
        validate_member_registration(&registration)?;
        validate_text(actor, "cluster-membership actor")?;
        validate_reason(reason)?;
        if authority_min_protocol_version == 0
            || authority_min_protocol_version > authority_protocol_version
        {
            return Err(storage_error("invalid authority protocol window"));
        }
        if registration.protocol_version < authority_min_protocol_version
            || registration.min_protocol_version > authority_protocol_version
        {
            return Err(storage_error(format!(
                "incompatible wire-protocol cluster member window: authority v{authority_min_protocol_version}..=v{authority_protocol_version}, member v{}..=v{}",
                registration.min_protocol_version, registration.protocol_version
            )));
        }
        let challenge = hex_decode(challenge_hex)
            .filter(|value| value.len() == 32)
            .ok_or_else(|| storage_error("invalid cluster join challenge"))?;
        let signature = hex_decode(signature_hex)
            .ok_or_else(|| storage_error("invalid cluster join signature"))?;

        let mut connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error(format!("cluster join transaction: {error}")))?;
        let (cluster_id, membership_generation): (String, i64) = transaction
            .query_row(
                "SELECT cluster_id, generation
                 FROM cluster_membership_authority WHERE singleton = ?1",
                [SINGLETON],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| storage_error(format!("read cluster authority: {error}")))?;
        let payload = membership_join_payload(&cluster_id, challenge_hex, &registration)?;
        if !Self::verify_challenge(&registration.public_key, &payload, &signature) {
            return Err(storage_error(
                "cluster member challenged identity proof denied",
            ));
        }

        let challenge_hash = sha256_hex(&challenge);
        let challenge_row: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT expires_at, consumed_at FROM cluster_join_challenges
                 WHERE challenge_hash = ?1",
                [&challenge_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| storage_error(format!("read cluster join challenge: {error}")))?;
        let Some((expires_at, consumed_at)) = challenge_row else {
            return Err(storage_error("invalid cluster join challenge: unknown"));
        };
        if consumed_at.is_some() {
            return Err(storage_error("cluster join challenge was already consumed"));
        }
        if parse_timestamp(&expires_at)? <= Utc::now() {
            return Err(storage_error("invalid cluster join challenge: expired"));
        }

        let existing = load_member(&transaction, &registration.node_id)?;
        let duplicate: Option<String> = transaction
            .query_row(
                "SELECT node_id FROM cluster_members
                 WHERE (fingerprint = ?1 OR endpoint = ?2) AND node_id <> ?3
                 LIMIT 1",
                params![
                    registration.fingerprint,
                    registration.endpoint,
                    registration.node_id
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| storage_error(format!("check duplicate cluster member: {error}")))?;
        if let Some(node_id) = duplicate {
            return Err(storage_error(format!(
                "cluster member identity or endpoint already belongs to node {node_id}"
            )));
        }

        let now = Utc::now();
        let (previous, previous_tls_fingerprint, member_generation, joined_at) = match existing {
            Some(member) => {
                let Some(expected) = expected_generation else {
                    return Err(storage_error(format!(
                        "cluster member revision conflict: expected generation is required, current {}",
                        member.generation
                    )));
                };
                if expected != member.generation {
                    return Err(storage_error(format!(
                        "cluster member revision conflict: expected {expected}, current {}",
                        member.generation
                    )));
                }
                if member.state == ClusterMemberState::Revoked {
                    return Err(storage_error(
                        "revoked cluster member conflict: cannot rejoin",
                    ));
                }
                if member.fingerprint != registration.fingerprint
                    || member.public_key != registration.public_key
                {
                    return Err(storage_error(
                        "cluster member durable identity cannot change during rejoin",
                    ));
                }
                if member.tls_server_certificate_fingerprint.is_some()
                    && registration.tls_server_certificate_fingerprint.is_none()
                {
                    return Err(storage_error(
                        "cluster member TLS certificate binding cannot be removed during rejoin",
                    ));
                }
                (
                    Some(member.state),
                    member.tls_server_certificate_fingerprint,
                    member
                        .generation
                        .checked_add(1)
                        .ok_or_else(|| storage_error("cluster member generation overflow"))?,
                    member.joined_at,
                )
            }
            None => {
                if expected_generation.is_some() {
                    return Err(storage_error(
                        "cluster member revision conflict: node does not exist",
                    ));
                }
                (None, None, 1, now)
            }
        };
        let membership_generation = u64::try_from(membership_generation)
            .map_err(|_| storage_error("negative membership generation"))?
            .checked_add(1)
            .ok_or_else(|| storage_error("membership generation overflow"))?;
        let member_generation_i64 = sqlite_generation(member_generation, "cluster member")?;
        let membership_generation_i64 =
            sqlite_generation(membership_generation, "cluster membership")?;

        transaction
            .execute(
                "INSERT INTO cluster_members
                 (node_id, fingerprint, public_key, tls_server_certificate_fingerprint,
                  endpoint, server_version,
                  min_protocol_version, protocol_version, state, generation,
                  joined_at, updated_at, reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?10, ?11, ?12)
                 ON CONFLICT(node_id) DO UPDATE SET
                   tls_server_certificate_fingerprint =
                       excluded.tls_server_certificate_fingerprint,
                   endpoint = excluded.endpoint,
                   server_version = excluded.server_version,
                   min_protocol_version = excluded.min_protocol_version,
                   protocol_version = excluded.protocol_version,
                   state = excluded.state,
                   generation = excluded.generation,
                   updated_at = excluded.updated_at,
                   reason = excluded.reason",
                params![
                    registration.node_id,
                    registration.fingerprint,
                    registration.public_key,
                    registration.tls_server_certificate_fingerprint,
                    registration.endpoint,
                    registration.server_version,
                    i64::from(registration.min_protocol_version),
                    i64::from(registration.protocol_version),
                    member_generation_i64,
                    joined_at.to_rfc3339(),
                    now.to_rfc3339(),
                    reason,
                ],
            )
            .map_err(|error| storage_error(format!("persist cluster member: {error}")))?;
        crash_cluster_mutation_after_step_for_test("membership.member");
        let consumed = transaction
            .execute(
                "UPDATE cluster_join_challenges SET consumed_at = ?1
                 WHERE challenge_hash = ?2 AND consumed_at IS NULL",
                params![now.to_rfc3339(), challenge_hash],
            )
            .map_err(|error| storage_error(format!("consume cluster join challenge: {error}")))?;
        if consumed != 1 {
            return Err(storage_error("cluster join challenge was already consumed"));
        }
        crash_cluster_mutation_after_step_for_test("membership.challenge");
        let advanced = transaction
            .execute(
                "UPDATE cluster_membership_authority SET generation = ?1
                 WHERE singleton = ?2 AND generation = ?3",
                params![
                    membership_generation_i64,
                    SINGLETON,
                    membership_generation_i64 - 1
                ],
            )
            .map_err(|error| storage_error(format!("advance membership generation: {error}")))?;
        if advanced != 1 {
            return Err(storage_error("cluster membership revision conflict"));
        }
        crash_cluster_mutation_after_step_for_test("membership.authority");
        transaction
            .execute(
                "INSERT INTO cluster_membership_audit
                 (membership_generation, node_id, member_generation, previous_state,
                  current_state, previous_tls_server_certificate_fingerprint,
                  current_tls_server_certificate_fingerprint, actor, reason, changed_at)
                 VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8, ?9)",
                params![
                    membership_generation_i64,
                    registration.node_id,
                    member_generation_i64,
                    previous.map(ClusterMemberState::as_str),
                    previous_tls_fingerprint,
                    registration.tls_server_certificate_fingerprint,
                    actor,
                    reason,
                    now.to_rfc3339(),
                ],
            )
            .map_err(|error| storage_error(format!("audit cluster member join: {error}")))?;
        crash_cluster_mutation_after_step_for_test("membership.audit");
        transaction
            .commit()
            .map_err(|error| storage_error(format!("commit cluster join: {error}")))?;
        drop(connection);
        self.member(&registration.node_id)?
            .ok_or_else(|| storage_error("joined cluster member disappeared"))
    }

    /// Generation-fenced clean leave or terminal identity revocation.
    pub fn set_member_state(
        &self,
        node_id: &str,
        state: ClusterMemberState,
        expected_generation: u64,
        actor: &str,
        reason: &str,
    ) -> Result<ClusterMember, ContextError> {
        if state == ClusterMemberState::Active {
            return Err(storage_error(
                "invalid active membership transition: a fresh challenged join is required",
            ));
        }
        uuid::Uuid::parse_str(node_id)
            .map_err(|_| storage_error("invalid cluster member node id"))?;
        validate_text(actor, "cluster-membership actor")?;
        validate_reason(reason)?;
        let mut connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error(format!("cluster member state transaction: {error}")))?;
        let member = load_member(&transaction, node_id)?
            .ok_or_else(|| storage_error("cluster member not found"))?;
        if member.generation != expected_generation {
            return Err(storage_error(format!(
                "cluster member revision conflict: expected {expected_generation}, current {}",
                member.generation
            )));
        }
        if member.state == ClusterMemberState::Revoked {
            return Err(storage_error(
                "revoked cluster member state conflict: revocation is terminal",
            ));
        }
        if member.state == state {
            return Err(storage_error(
                "cluster member is already in the requested state",
            ));
        }
        let member_generation = member
            .generation
            .checked_add(1)
            .ok_or_else(|| storage_error("cluster member generation overflow"))?;
        let current_membership_generation: i64 = transaction
            .query_row(
                "SELECT generation FROM cluster_membership_authority WHERE singleton = ?1",
                [SINGLETON],
                |row| row.get(0),
            )
            .map_err(|error| storage_error(format!("read membership generation: {error}")))?;
        let membership_generation = u64::try_from(current_membership_generation)
            .map_err(|_| storage_error("negative membership generation"))?
            .checked_add(1)
            .ok_or_else(|| storage_error("membership generation overflow"))?;
        let member_generation_i64 = sqlite_generation(member_generation, "cluster member")?;
        let membership_generation_i64 =
            sqlite_generation(membership_generation, "cluster membership")?;
        let now = Utc::now();
        if state == ClusterMemberState::Left {
            let active_leases: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM cluster_agent_ownership
                     WHERE owner_node_id = ?1 AND state = 'active'
                       AND lease_expires_at > ?2",
                    params![node_id, now.to_rfc3339()],
                    |row| row.get(0),
                )
                .map_err(|error| storage_error(format!("inspect member ownership: {error}")))?;
            if active_leases != 0 {
                return Err(storage_error(
                    "cluster member leave conflict: active ownership leases must be released first",
                ));
            }
        } else {
            let owned = {
                let mut statement = transaction
                    .prepare(
                        "SELECT agent_id, fencing_token, generation
                         FROM cluster_agent_ownership
                         WHERE owner_node_id = ?1 AND state = 'active'
                         ORDER BY agent_id",
                    )
                    .map_err(|error| {
                        storage_error(format!("prepare revoked member ownership: {error}"))
                    })?;
                let rows = statement
                    .query_map([node_id], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .map_err(|error| {
                        storage_error(format!("query revoked member ownership: {error}"))
                    })?;
                rows.collect::<Result<Vec<_>, _>>().map_err(|error| {
                    storage_error(format!("read revoked member ownership: {error}"))
                })?
            };
            for (agent_id, fencing_token, generation) in owned {
                let fencing_token = u64::try_from(fencing_token)
                    .map_err(|_| storage_error("negative ownership fencing token"))?;
                let generation = u64::try_from(generation)
                    .map_err(|_| storage_error("negative ownership generation"))?
                    .checked_add(1)
                    .ok_or_else(|| storage_error("agent ownership generation overflow"))?;
                write_ownership(
                    &transaction,
                    &agent_id,
                    node_id,
                    fencing_token,
                    generation,
                    ClusterOwnershipState::Released,
                    now,
                    now,
                    reason,
                )?;
                write_ownership_audit(
                    &transaction,
                    &agent_id,
                    generation,
                    Some(node_id),
                    node_id,
                    fencing_token,
                    "release",
                    actor,
                    reason,
                    now,
                )?;
            }
        }
        let changed = transaction
            .execute(
                "UPDATE cluster_members SET state = ?1, generation = ?2,
                 updated_at = ?3, reason = ?4
                 WHERE node_id = ?5 AND generation = ?6",
                params![
                    state.as_str(),
                    member_generation_i64,
                    now.to_rfc3339(),
                    reason,
                    node_id,
                    sqlite_generation(expected_generation, "expected cluster member")?,
                ],
            )
            .map_err(|error| storage_error(format!("update cluster member state: {error}")))?;
        if changed != 1 {
            return Err(storage_error("cluster member revision conflict"));
        }
        crash_cluster_mutation_after_step_for_test("member_state.member");
        let authority_changed = transaction
            .execute(
                "UPDATE cluster_membership_authority SET generation = ?1
                 WHERE singleton = ?2 AND generation = ?3",
                params![
                    membership_generation_i64,
                    SINGLETON,
                    current_membership_generation
                ],
            )
            .map_err(|error| storage_error(format!("advance membership generation: {error}")))?;
        if authority_changed != 1 {
            return Err(storage_error("cluster membership revision conflict"));
        }
        crash_cluster_mutation_after_step_for_test("member_state.authority");
        transaction
            .execute(
                "INSERT INTO cluster_membership_audit
                 (membership_generation, node_id, member_generation, previous_state,
                  current_state, previous_tls_server_certificate_fingerprint,
                  current_tls_server_certificate_fingerprint, actor, reason, changed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    membership_generation_i64,
                    node_id,
                    member_generation_i64,
                    member.state.as_str(),
                    state.as_str(),
                    member.tls_server_certificate_fingerprint,
                    member.tls_server_certificate_fingerprint,
                    actor,
                    reason,
                    now.to_rfc3339(),
                ],
            )
            .map_err(|error| storage_error(format!("audit cluster member state: {error}")))?;
        crash_cluster_mutation_after_step_for_test("member_state.audit");
        transaction
            .commit()
            .map_err(|error| storage_error(format!("commit cluster member state: {error}")))?;
        drop(connection);
        self.member(node_id)?
            .ok_or_else(|| storage_error("updated cluster member disappeared"))
    }

    pub fn membership_snapshot(&self) -> Result<ClusterMembershipSnapshot, ContextError> {
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let (cluster_id, generation): (String, i64) = connection
            .query_row(
                "SELECT cluster_id, generation
                 FROM cluster_membership_authority WHERE singleton = ?1",
                [SINGLETON],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| storage_error(format!("read cluster membership snapshot: {error}")))?;
        let mut statement = connection
            .prepare(
                "SELECT node_id, fingerprint, public_key,
                        tls_server_certificate_fingerprint, endpoint, server_version,
                        min_protocol_version, protocol_version, state, generation,
                        joined_at, updated_at, reason
                 FROM cluster_members ORDER BY node_id",
            )
            .map_err(|error| storage_error(format!("prepare cluster members: {error}")))?;
        let rows = statement
            .query_map([], member_from_row)
            .map_err(|error| storage_error(format!("query cluster members: {error}")))?;
        let mut members = Vec::new();
        for row in rows {
            members.push(
                row.map_err(|error| storage_error(format!("read cluster member: {error}")))?
                    .try_into()?,
            );
        }
        Ok(ClusterMembershipSnapshot {
            cluster_id,
            generation: u64::try_from(generation)
                .map_err(|_| storage_error("negative membership generation"))?,
            authority_time: None,
            tls_trust_generation: 0,
            certificate_rollouts: Vec::new(),
            members,
        })
    }

    pub fn membership_audit(
        &self,
        limit: usize,
    ) -> Result<Vec<ClusterMembershipAudit>, ContextError> {
        let limit = limit.clamp(1, 1_000);
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let mut statement = connection
            .prepare(
                "SELECT membership_generation, node_id, member_generation,
                        previous_state, current_state,
                        previous_tls_server_certificate_fingerprint,
                        current_tls_server_certificate_fingerprint,
                        actor, reason, changed_at
                 FROM cluster_membership_audit
                 ORDER BY membership_generation DESC LIMIT ?1",
            )
            .map_err(|error| storage_error(format!("prepare membership audit: {error}")))?;
        let rows = statement
            .query_map([limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .map_err(|error| storage_error(format!("query membership audit: {error}")))?;
        let mut audit = Vec::new();
        for row in rows {
            let (
                membership_generation,
                node_id,
                member_generation,
                previous,
                current,
                previous_tls_server_certificate_fingerprint,
                current_tls_server_certificate_fingerprint,
                actor,
                reason,
                changed_at,
            ) = row.map_err(|error| storage_error(format!("read membership audit: {error}")))?;
            audit.push(ClusterMembershipAudit {
                membership_generation: u64::try_from(membership_generation)
                    .map_err(|_| storage_error("negative membership audit generation"))?,
                node_id,
                member_generation: u64::try_from(member_generation)
                    .map_err(|_| storage_error("negative member audit generation"))?,
                previous: previous
                    .as_deref()
                    .map(ClusterMemberState::try_from)
                    .transpose()?,
                current: ClusterMemberState::try_from(current.as_str())?,
                previous_tls_server_certificate_fingerprint,
                current_tls_server_certificate_fingerprint,
                actor,
                reason,
                changed_at: parse_timestamp(&changed_at)?,
            });
        }
        Ok(audit)
    }

    /// Claim an unowned, released, or expired agent record for one active
    /// member. Replacing any previous record requires its exact fencing token;
    /// every successful replacement receives a strictly greater token.
    pub fn claim_agent_ownership(
        &self,
        agent_id: &str,
        owner_node_id: &str,
        ttl_seconds: u64,
        expected_fencing_token: Option<u64>,
        actor: &str,
        reason: &str,
    ) -> Result<ClusterAgentOwnership, ContextError> {
        validate_ownership_request(agent_id, owner_node_id, ttl_seconds, actor, reason)?;
        let mut connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error(format!("agent ownership transaction: {error}")))?;
        require_active_member(&transaction, owner_node_id)?;
        let previous = load_ownership(&transaction, agent_id)?;
        let now = Utc::now();
        let (fencing_token, generation, operation, previous_owner_node_id) =
            match previous.as_ref() {
                None => {
                    if expected_fencing_token.is_some() {
                        return Err(storage_error(
                            "agent ownership conflict: no previous fencing token exists",
                        ));
                    }
                    (1, 1, "claim", None)
                }
                Some(previous) => {
                    if expected_fencing_token != Some(previous.fencing_token) {
                        return Err(storage_error(format!(
                            "agent ownership fencing conflict: expected {:?}, current {}",
                            expected_fencing_token, previous.fencing_token
                        )));
                    }
                    if previous.state == ClusterOwnershipState::Active
                        && previous.lease_expires_at > now
                    {
                        return Err(storage_error(
                            "agent ownership conflict: current lease has not expired",
                        ));
                    }
                    (
                        previous.fencing_token.checked_add(1).ok_or_else(|| {
                            storage_error("agent ownership fencing token overflow")
                        })?,
                        previous
                            .generation
                            .checked_add(1)
                            .ok_or_else(|| storage_error("agent ownership generation overflow"))?,
                        "transfer",
                        Some(previous.owner_node_id.clone()),
                    )
                }
            };
        let lease_expires_at = ownership_expiry(now, ttl_seconds)?;
        write_ownership(
            &transaction,
            agent_id,
            owner_node_id,
            fencing_token,
            generation,
            ClusterOwnershipState::Active,
            lease_expires_at,
            now,
            reason,
        )?;
        write_ownership_audit(
            &transaction,
            agent_id,
            generation,
            previous_owner_node_id.as_deref(),
            owner_node_id,
            fencing_token,
            operation,
            actor,
            reason,
            now,
        )?;
        transaction
            .commit()
            .map_err(|error| storage_error(format!("commit agent ownership: {error}")))?;
        drop(connection);
        self.agent_ownership(agent_id)?
            .ok_or_else(|| storage_error("claimed agent ownership disappeared"))
    }

    /// Renew only the exact active, unexpired owner/token pair. Renewal keeps
    /// the fencing token stable and advances the audit generation.
    pub fn renew_agent_ownership(
        &self,
        agent_id: &str,
        owner_node_id: &str,
        fencing_token: u64,
        ttl_seconds: u64,
        actor: &str,
        reason: &str,
    ) -> Result<ClusterAgentOwnership, ContextError> {
        validate_ownership_request(agent_id, owner_node_id, ttl_seconds, actor, reason)?;
        let mut connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error(format!("agent ownership renewal: {error}")))?;
        require_active_member(&transaction, owner_node_id)?;
        let previous = load_ownership(&transaction, agent_id)?
            .ok_or_else(|| storage_error("agent ownership not found"))?;
        let now = Utc::now();
        if previous.state != ClusterOwnershipState::Active
            || previous.owner_node_id != owner_node_id
            || previous.fencing_token != fencing_token
        {
            return Err(storage_error("agent ownership fencing conflict"));
        }
        if previous.lease_expires_at <= now {
            return Err(storage_error(
                "agent ownership lease expired before renewal",
            ));
        }
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or_else(|| storage_error("agent ownership generation overflow"))?;
        let lease_expires_at = ownership_expiry(now, ttl_seconds)?;
        write_ownership(
            &transaction,
            agent_id,
            owner_node_id,
            fencing_token,
            generation,
            ClusterOwnershipState::Active,
            lease_expires_at,
            now,
            reason,
        )?;
        write_ownership_audit(
            &transaction,
            agent_id,
            generation,
            Some(owner_node_id),
            owner_node_id,
            fencing_token,
            "renew",
            actor,
            reason,
            now,
        )?;
        transaction
            .commit()
            .map_err(|error| storage_error(format!("commit ownership renewal: {error}")))?;
        drop(connection);
        self.agent_ownership(agent_id)?
            .ok_or_else(|| storage_error("renewed agent ownership disappeared"))
    }

    /// Release only the exact active owner/token pair. The retained tombstone
    /// prevents the fencing token from ever being reused.
    pub fn release_agent_ownership(
        &self,
        agent_id: &str,
        owner_node_id: &str,
        fencing_token: u64,
        actor: &str,
        reason: &str,
    ) -> Result<ClusterAgentOwnership, ContextError> {
        validate_ownership_identity(agent_id, owner_node_id)?;
        validate_text(actor, "cluster-ownership actor")?;
        validate_reason(reason)?;
        let mut connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error(format!("agent ownership release: {error}")))?;
        let previous = load_ownership(&transaction, agent_id)?
            .ok_or_else(|| storage_error("agent ownership not found"))?;
        if previous.state != ClusterOwnershipState::Active
            || previous.owner_node_id != owner_node_id
            || previous.fencing_token != fencing_token
        {
            return Err(storage_error("agent ownership fencing conflict"));
        }
        let now = Utc::now();
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or_else(|| storage_error("agent ownership generation overflow"))?;
        write_ownership(
            &transaction,
            agent_id,
            owner_node_id,
            fencing_token,
            generation,
            ClusterOwnershipState::Released,
            now,
            now,
            reason,
        )?;
        write_ownership_audit(
            &transaction,
            agent_id,
            generation,
            Some(owner_node_id),
            owner_node_id,
            fencing_token,
            "release",
            actor,
            reason,
            now,
        )?;
        transaction
            .commit()
            .map_err(|error| storage_error(format!("commit ownership release: {error}")))?;
        drop(connection);
        self.agent_ownership(agent_id)?
            .ok_or_else(|| storage_error("released agent ownership disappeared"))
    }

    pub fn agent_ownership(
        &self,
        agent_id: &str,
    ) -> Result<Option<ClusterAgentOwnership>, ContextError> {
        uuid::Uuid::parse_str(agent_id)
            .map_err(|_| storage_error("invalid cluster ownership agent id"))?;
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        load_ownership(&connection, agent_id)
    }

    /// Page through the complete durable ownership directory in stable agent-id
    /// order. Released and expired records are intentionally included so
    /// reconciliation can distinguish tombstones, live routes, and abandoned
    /// pre-creation reservations without guessing from local node state.
    pub fn agent_ownerships(
        &self,
        after_agent_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ClusterAgentOwnership>, ContextError> {
        if let Some(agent_id) = after_agent_id {
            uuid::Uuid::parse_str(agent_id)
                .map_err(|_| storage_error("invalid ownership page cursor"))?;
        }
        let limit = limit.clamp(1, 1_000);
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let mut statement = connection
            .prepare(
                "SELECT agent_id, owner_node_id, fencing_token, generation, state,
                        lease_expires_at, updated_at, reason
                 FROM cluster_agent_ownership
                 WHERE (?1 IS NULL OR agent_id > ?1)
                 ORDER BY agent_id ASC
                 LIMIT ?2",
            )
            .map_err(|error| storage_error(format!("prepare ownership directory: {error}")))?;
        let rows = statement
            .query_map(
                rusqlite::params![after_agent_id, i64::try_from(limit).unwrap_or(i64::MAX)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .map_err(|error| storage_error(format!("query ownership directory: {error}")))?;
        let mut ownerships = Vec::new();
        for row in rows {
            let (
                agent_id,
                owner_node_id,
                fencing_token,
                generation,
                state,
                lease_expires_at,
                updated_at,
                reason,
            ) = row.map_err(|error| storage_error(format!("read ownership directory: {error}")))?;
            ownerships.push(ClusterAgentOwnership {
                agent_id,
                owner_node_id,
                fencing_token: u64::try_from(fencing_token)
                    .map_err(|_| storage_error("negative ownership fencing token"))?,
                generation: u64::try_from(generation)
                    .map_err(|_| storage_error("negative ownership generation"))?,
                state: ClusterOwnershipState::try_from(state.as_str())?,
                lease_expires_at: parse_timestamp(&lease_expires_at)?,
                updated_at: parse_timestamp(&updated_at)?,
                reason,
            });
        }
        Ok(ownerships)
    }

    /// Read one ownership record and, when requested, have the authority
    /// validate active state and expiry against its own clock.
    pub fn agent_ownership_with_active_requirement(
        &self,
        agent_id: &str,
        require_active: bool,
    ) -> Result<Option<ClusterAgentOwnership>, ContextError> {
        let ownership = self.agent_ownership(agent_id)?;
        if require_active {
            let Some(current) = ownership.as_ref() else {
                return Err(storage_error("agent ownership conflict: record not found"));
            };
            if current.state != ClusterOwnershipState::Active
                || current.lease_expires_at <= Utc::now()
            {
                return Err(storage_error(
                    "agent ownership conflict: lease is released or expired",
                ));
            }
        }
        Ok(ownership)
    }

    pub fn agent_ownership_audit(
        &self,
        agent_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ClusterAgentOwnershipAudit>, ContextError> {
        if let Some(agent_id) = agent_id {
            uuid::Uuid::parse_str(agent_id)
                .map_err(|_| storage_error("invalid cluster ownership agent id"))?;
        }
        let limit = limit.clamp(1, 1_000);
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let sql = if agent_id.is_some() {
            "SELECT agent_id, generation, previous_owner_node_id, owner_node_id,
                    fencing_token, operation, actor, reason, changed_at
             FROM cluster_agent_ownership_audit
             WHERE agent_id = ?1
             ORDER BY generation DESC LIMIT ?2"
        } else {
            "SELECT agent_id, generation, previous_owner_node_id, owner_node_id,
                    fencing_token, operation, actor, reason, changed_at
             FROM cluster_agent_ownership_audit
             ORDER BY changed_at DESC, agent_id, generation DESC LIMIT ?2"
        };
        let mut statement = connection
            .prepare(sql)
            .map_err(|error| storage_error(format!("prepare ownership audit: {error}")))?;
        let mut rows = statement
            .query(params![agent_id, limit as i64])
            .map_err(|error| storage_error(format!("query ownership audit: {error}")))?;
        let mut audit = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|error| storage_error(format!("read ownership audit: {error}")))?
        {
            audit.push(ClusterAgentOwnershipAudit {
                agent_id: row
                    .get(0)
                    .map_err(|error| storage_error(error.to_string()))?,
                generation: u64::try_from(
                    row.get::<_, i64>(1)
                        .map_err(|error| storage_error(error.to_string()))?,
                )
                .map_err(|_| storage_error("negative ownership audit generation"))?,
                previous_owner_node_id: row
                    .get(2)
                    .map_err(|error| storage_error(error.to_string()))?,
                owner_node_id: row
                    .get(3)
                    .map_err(|error| storage_error(error.to_string()))?,
                fencing_token: u64::try_from(
                    row.get::<_, i64>(4)
                        .map_err(|error| storage_error(error.to_string()))?,
                )
                .map_err(|_| storage_error("negative ownership audit fencing token"))?,
                operation: row
                    .get(5)
                    .map_err(|error| storage_error(error.to_string()))?,
                actor: row
                    .get(6)
                    .map_err(|error| storage_error(error.to_string()))?,
                reason: row
                    .get(7)
                    .map_err(|error| storage_error(error.to_string()))?,
                changed_at: parse_timestamp(
                    &row.get::<_, String>(8)
                        .map_err(|error| storage_error(error.to_string()))?,
                )?,
            });
        }
        Ok(audit)
    }

    /// Install the highest authority-issued token accepted by this workload
    /// node for one local or authority-reserved agent identity. Preinstalling
    /// the fence lets exact-ID creation prove that its reservation is still
    /// current. Older tokens and foreign-node records fail closed; a retired
    /// token can never be reactivated.
    #[allow(clippy::too_many_arguments)]
    pub fn install_agent_mutation_fence(
        &self,
        agent_id: &str,
        cluster_id: &str,
        owner_node_id: &str,
        authority_generation: u64,
        fencing_token: u64,
        actor: &str,
        reason: &str,
    ) -> Result<AgentMutationFence, ContextError> {
        validate_mutation_fence_input(
            agent_id,
            cluster_id,
            owner_node_id,
            authority_generation,
            fencing_token,
            actor,
            reason,
        )?;
        if owner_node_id != self.identity.node_id {
            return Err(storage_error(
                "agent mutation fence owner does not match this destination node",
            ));
        }
        let mut connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error(format!("agent mutation fence transaction: {error}")))?;
        let previous = load_mutation_fence(&transaction, agent_id)?;
        if let Some(previous) = &previous {
            if previous.cluster_id != cluster_id || previous.owner_node_id != owner_node_id {
                return Err(storage_error(
                    "agent mutation fence conflicts with the durable cluster or destination",
                ));
            }
            if fencing_token < previous.fencing_token
                || authority_generation < previous.authority_generation
            {
                return Err(storage_error(
                    "stale agent mutation fence rejected by destination",
                ));
            }
            if previous.state == AgentMutationFenceState::Retired
                && fencing_token == previous.fencing_token
            {
                return Err(storage_error(
                    "retired agent mutation fence cannot become active again",
                ));
            }
            if fencing_token == previous.fencing_token
                && authority_generation == previous.authority_generation
                && previous.state == AgentMutationFenceState::Active
            {
                return Ok(previous.clone());
            }
            if fencing_token > previous.fencing_token
                && authority_generation <= previous.authority_generation
            {
                return Err(storage_error(
                    "new agent mutation fence requires a newer authority generation",
                ));
            }
        }
        let now = Utc::now();
        write_mutation_fence(
            &transaction,
            agent_id,
            cluster_id,
            owner_node_id,
            authority_generation,
            fencing_token,
            AgentMutationFenceState::Active,
            actor,
            reason,
            now,
        )?;
        transaction
            .commit()
            .map_err(|error| storage_error(format!("commit agent mutation fence: {error}")))?;
        drop(connection);
        self.agent_mutation_fence(agent_id)?
            .ok_or_else(|| storage_error("installed agent mutation fence disappeared"))
    }

    /// Retire the exact active destination token. The retained maximum-token
    /// tombstone permanently rejects a delayed mutation from the old owner.
    #[allow(clippy::too_many_arguments)]
    pub fn retire_agent_mutation_fence(
        &self,
        agent_id: &str,
        cluster_id: &str,
        owner_node_id: &str,
        authority_generation: u64,
        fencing_token: u64,
        actor: &str,
        reason: &str,
    ) -> Result<AgentMutationFence, ContextError> {
        validate_mutation_fence_input(
            agent_id,
            cluster_id,
            owner_node_id,
            authority_generation,
            fencing_token,
            actor,
            reason,
        )?;
        if owner_node_id != self.identity.node_id {
            return Err(storage_error(
                "agent mutation fence owner does not match this destination node",
            ));
        }
        let mut connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                storage_error(format!("retire agent mutation fence transaction: {error}"))
            })?;
        let previous = load_mutation_fence(&transaction, agent_id)?
            .ok_or_else(|| storage_error("agent mutation fence not found"))?;
        if previous.cluster_id != cluster_id
            || previous.owner_node_id != owner_node_id
            || previous.authority_generation != authority_generation
            || previous.fencing_token != fencing_token
            || previous.state != AgentMutationFenceState::Active
        {
            return Err(storage_error(
                "agent mutation fence retirement requires the exact active record",
            ));
        }
        let now = Utc::now();
        write_mutation_fence(
            &transaction,
            agent_id,
            cluster_id,
            owner_node_id,
            authority_generation,
            fencing_token,
            AgentMutationFenceState::Retired,
            actor,
            reason,
            now,
        )?;
        transaction
            .commit()
            .map_err(|error| storage_error(format!("commit fence retirement: {error}")))?;
        drop(connection);
        self.agent_mutation_fence(agent_id)?
            .ok_or_else(|| storage_error("retired agent mutation fence disappeared"))
    }

    pub fn agent_mutation_fence(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentMutationFence>, ContextError> {
        uuid::Uuid::parse_str(agent_id)
            .map_err(|_| storage_error("invalid agent mutation fence agent id"))?;
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        load_mutation_fence(&connection, agent_id)
    }

    /// Validate the exact active destination record before any fenced mutation
    /// is admitted. Missing, retired, stale, foreign, or cross-cluster tokens
    /// are indistinguishable conflicts to remote callers.
    pub fn verify_agent_mutation_fence(
        &self,
        agent_id: &str,
        cluster_id: &str,
        owner_node_id: &str,
        authority_generation: u64,
        fencing_token: u64,
    ) -> Result<(), ContextError> {
        let record = self
            .agent_mutation_fence(agent_id)?
            .ok_or_else(|| storage_error("agent mutation fence is not installed"))?;
        if record.state != AgentMutationFenceState::Active
            || record.cluster_id != cluster_id
            || record.owner_node_id != owner_node_id
            || record.owner_node_id != self.identity.node_id
            || record.authority_generation != authority_generation
            || record.fencing_token != fencing_token
        {
            return Err(storage_error(
                "agent mutation rejected by destination ownership fence",
            ));
        }
        Ok(())
    }

    pub fn agent_mutation_fence_audit(
        &self,
        agent_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AgentMutationFenceAudit>, ContextError> {
        if let Some(agent_id) = agent_id {
            uuid::Uuid::parse_str(agent_id)
                .map_err(|_| storage_error("invalid agent mutation fence agent id"))?;
        }
        let limit = limit.clamp(1, 1_000);
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let sql = if agent_id.is_some() {
            "SELECT agent_id, cluster_id, owner_node_id, authority_generation,
                    fencing_token, state, actor, reason, changed_at
             FROM cluster_agent_mutation_fence_audit
             WHERE agent_id = ?1
             ORDER BY fencing_token DESC, authority_generation DESC LIMIT ?2"
        } else {
            "SELECT agent_id, cluster_id, owner_node_id, authority_generation,
                    fencing_token, state, actor, reason, changed_at
             FROM cluster_agent_mutation_fence_audit
             ORDER BY changed_at DESC, agent_id, fencing_token DESC LIMIT ?2"
        };
        let mut statement = connection
            .prepare(sql)
            .map_err(|error| storage_error(format!("prepare mutation fence audit: {error}")))?;
        let mut rows = statement
            .query(params![agent_id, limit as i64])
            .map_err(|error| storage_error(format!("query mutation fence audit: {error}")))?;
        let mut audit = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|error| storage_error(format!("read mutation fence audit: {error}")))?
        {
            audit.push(mutation_fence_audit_from_row(row)?);
        }
        Ok(audit)
    }

    fn member(&self, node_id: &str) -> Result<Option<ClusterMember>, ContextError> {
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        load_member(&connection, node_id)
    }

    /// Sign an operator-provided nonce so discovery can prove possession of the
    /// durable identity without exposing private key material.
    pub fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>, ContextError> {
        if challenge.is_empty() || challenge.len() > 4096 {
            return Err(storage_error(
                "invalid cluster identity challenge length (expected 1..=4096 bytes)",
            ));
        }
        let connection = self
            .store
            .conn
            .lock()
            .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
        let private_key: Vec<u8> = connection
            .query_row(
                "SELECT private_key FROM cluster_node_identity WHERE singleton = ?1",
                [SINGLETON],
                |row| row.get(0),
            )
            .map_err(|error| storage_error(format!("read cluster private key: {error}")))?;
        let pair = Ed25519KeyPair::from_pkcs8(&private_key)
            .map_err(|_| storage_error("persisted cluster private key is invalid"))?;
        Ok(pair.sign(challenge).as_ref().to_vec())
    }

    pub fn prove_challenge_hex(&self, challenge_hex: &str) -> Result<String, ContextError> {
        if challenge_hex.is_empty() || challenge_hex.len() > 8192 {
            return Err(storage_error(
                "invalid cluster identity challenge length (expected 2..=8192 hexadecimal bytes)",
            ));
        }
        let challenge = hex_decode(challenge_hex)
            .ok_or_else(|| storage_error("invalid hexadecimal cluster identity challenge"))?;
        self.sign_challenge(&challenge)
            .map(|signature| hex_encode(&signature))
    }

    pub fn verify_challenge(public_key_hex: &str, challenge: &[u8], signature: &[u8]) -> bool {
        let Some(public_key) = hex_decode(public_key_hex) else {
            return false;
        };
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(challenge, signature)
            .is_ok()
    }
}

type StoredMember = (
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    i64,
    i64,
    String,
    i64,
    String,
    String,
    String,
);

fn member_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMember> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

impl TryFrom<StoredMember> for ClusterMember {
    type Error = ContextError;

    fn try_from(value: StoredMember) -> Result<Self, Self::Error> {
        let (
            node_id,
            fingerprint,
            public_key,
            tls_server_certificate_fingerprint,
            endpoint,
            server_version,
            min_protocol_version,
            protocol_version,
            state,
            generation,
            joined_at,
            updated_at,
            reason,
        ) = value;
        let member = Self {
            node_id,
            fingerprint,
            public_key,
            tls_server_certificate_fingerprint,
            endpoint,
            server_version,
            min_protocol_version: u32::try_from(min_protocol_version)
                .map_err(|_| storage_error("invalid member minimum protocol version"))?,
            protocol_version: u32::try_from(protocol_version)
                .map_err(|_| storage_error("invalid member protocol version"))?,
            state: ClusterMemberState::try_from(state.as_str())?,
            generation: u64::try_from(generation)
                .map_err(|_| storage_error("negative cluster member generation"))?,
            joined_at: parse_timestamp(&joined_at)?,
            updated_at: parse_timestamp(&updated_at)?,
            reason,
        };
        validate_member_registration(&ClusterMemberRegistration {
            node_id: member.node_id.clone(),
            fingerprint: member.fingerprint.clone(),
            public_key: member.public_key.clone(),
            tls_server_certificate_fingerprint: member.tls_server_certificate_fingerprint.clone(),
            endpoint: member.endpoint.clone(),
            server_version: member.server_version.clone(),
            min_protocol_version: member.min_protocol_version,
            protocol_version: member.protocol_version,
        })?;
        Ok(member)
    }
}

fn load_member(
    connection: &rusqlite::Connection,
    node_id: &str,
) -> Result<Option<ClusterMember>, ContextError> {
    connection
        .query_row(
            "SELECT node_id, fingerprint, public_key,
                    tls_server_certificate_fingerprint, endpoint, server_version,
                    min_protocol_version, protocol_version, state, generation,
                    joined_at, updated_at, reason
             FROM cluster_members WHERE node_id = ?1",
            [node_id],
            member_from_row,
        )
        .optional()
        .map_err(|error| storage_error(format!("load cluster member: {error}")))?
        .map(ClusterMember::try_from)
        .transpose()
}

pub(crate) fn validate_ownership_identity(
    agent_id: &str,
    owner_node_id: &str,
) -> Result<(), ContextError> {
    uuid::Uuid::parse_str(agent_id)
        .map_err(|_| storage_error("invalid cluster ownership agent id"))?;
    uuid::Uuid::parse_str(owner_node_id)
        .map_err(|_| storage_error("invalid cluster ownership node id"))?;
    Ok(())
}

pub(crate) fn validate_ownership_request(
    agent_id: &str,
    owner_node_id: &str,
    ttl_seconds: u64,
    actor: &str,
    reason: &str,
) -> Result<(), ContextError> {
    validate_ownership_identity(agent_id, owner_node_id)?;
    if !(MIN_OWNERSHIP_LEASE_TTL_SECONDS..=MAX_OWNERSHIP_LEASE_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(storage_error(format!(
            "invalid agent ownership TTL: expected {MIN_OWNERSHIP_LEASE_TTL_SECONDS}..={MAX_OWNERSHIP_LEASE_TTL_SECONDS} seconds"
        )));
    }
    validate_text(actor, "cluster-ownership actor")?;
    validate_reason(reason)
}

pub(crate) fn ownership_expiry(
    now: DateTime<Utc>,
    ttl_seconds: u64,
) -> Result<DateTime<Utc>, ContextError> {
    let seconds = i64::try_from(ttl_seconds)
        .map_err(|_| storage_error("agent ownership TTL exceeds clock range"))?;
    now.checked_add_signed(chrono::Duration::seconds(seconds))
        .ok_or_else(|| storage_error("agent ownership expiry overflow"))
}

fn require_active_member(
    connection: &rusqlite::Connection,
    node_id: &str,
) -> Result<(), ContextError> {
    let state: Option<String> = connection
        .query_row(
            "SELECT state FROM cluster_members WHERE node_id = ?1",
            [node_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| storage_error(format!("read ownership member: {error}")))?;
    match state.as_deref() {
        Some("active") => Ok(()),
        Some(_) => Err(storage_error(
            "agent ownership denied: owner node is not an active cluster member",
        )),
        None => Err(storage_error(
            "agent ownership denied: owner node is not a cluster member",
        )),
    }
}

fn load_ownership(
    connection: &rusqlite::Connection,
    agent_id: &str,
) -> Result<Option<ClusterAgentOwnership>, ContextError> {
    let stored = connection
        .query_row(
            "SELECT agent_id, owner_node_id, fencing_token, generation, state,
                    lease_expires_at, updated_at, reason
             FROM cluster_agent_ownership WHERE agent_id = ?1",
            [agent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| storage_error(format!("load agent ownership: {error}")))?;
    stored
        .map(
            |(
                agent_id,
                owner_node_id,
                fencing_token,
                generation,
                state,
                lease_expires_at,
                updated_at,
                reason,
            )| {
                Ok(ClusterAgentOwnership {
                    agent_id,
                    owner_node_id,
                    fencing_token: u64::try_from(fencing_token)
                        .map_err(|_| storage_error("negative ownership fencing token"))?,
                    generation: u64::try_from(generation)
                        .map_err(|_| storage_error("negative ownership generation"))?,
                    state: ClusterOwnershipState::try_from(state.as_str())?,
                    lease_expires_at: parse_timestamp(&lease_expires_at)?,
                    updated_at: parse_timestamp(&updated_at)?,
                    reason,
                })
            },
        )
        .transpose()
}

#[allow(clippy::too_many_arguments)]
fn validate_mutation_fence_input(
    agent_id: &str,
    cluster_id: &str,
    owner_node_id: &str,
    authority_generation: u64,
    fencing_token: u64,
    actor: &str,
    reason: &str,
) -> Result<(), ContextError> {
    uuid::Uuid::parse_str(agent_id)
        .map_err(|_| storage_error("invalid agent mutation fence agent id"))?;
    uuid::Uuid::parse_str(cluster_id)
        .map_err(|_| storage_error("invalid agent mutation fence cluster id"))?;
    uuid::Uuid::parse_str(owner_node_id)
        .map_err(|_| storage_error("invalid agent mutation fence owner node id"))?;
    if authority_generation == 0 {
        return Err(storage_error(
            "agent mutation fence authority generation must be positive",
        ));
    }
    if fencing_token == 0 {
        return Err(storage_error("agent mutation fence token must be positive"));
    }
    validate_text(actor, "agent mutation fence actor")?;
    validate_reason(reason)
}

fn load_mutation_fence(
    connection: &rusqlite::Connection,
    agent_id: &str,
) -> Result<Option<AgentMutationFence>, ContextError> {
    connection
        .query_row(
            "SELECT agent_id, cluster_id, owner_node_id, authority_generation,
                    fencing_token, state, installed_at, reason
             FROM cluster_agent_mutation_fences WHERE agent_id = ?1",
            [agent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| storage_error(format!("load agent mutation fence: {error}")))?
        .map(
            |(
                agent_id,
                cluster_id,
                owner_node_id,
                authority_generation,
                fencing_token,
                state,
                installed_at,
                reason,
            )| {
                Ok(AgentMutationFence {
                    agent_id,
                    cluster_id,
                    owner_node_id,
                    authority_generation: u64::try_from(authority_generation)
                        .map_err(|_| storage_error("negative fence authority generation"))?,
                    fencing_token: u64::try_from(fencing_token)
                        .map_err(|_| storage_error("negative agent mutation fencing token"))?,
                    state: AgentMutationFenceState::try_from(state.as_str())?,
                    installed_at: parse_timestamp(&installed_at)?,
                    reason,
                })
            },
        )
        .transpose()
}

#[allow(clippy::too_many_arguments)]
fn write_mutation_fence(
    connection: &rusqlite::Connection,
    agent_id: &str,
    cluster_id: &str,
    owner_node_id: &str,
    authority_generation: u64,
    fencing_token: u64,
    state: AgentMutationFenceState,
    actor: &str,
    reason: &str,
    changed_at: DateTime<Utc>,
) -> Result<(), ContextError> {
    let authority_generation =
        sqlite_generation(authority_generation, "fence authority generation")?;
    let fencing_token = sqlite_generation(fencing_token, "agent mutation fencing token")?;
    connection
        .execute(
            "INSERT INTO cluster_agent_mutation_fences
             (agent_id, cluster_id, owner_node_id, authority_generation,
              fencing_token, state, installed_at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(agent_id) DO UPDATE SET
               cluster_id = excluded.cluster_id,
               owner_node_id = excluded.owner_node_id,
               authority_generation = excluded.authority_generation,
               fencing_token = excluded.fencing_token,
               state = excluded.state,
               installed_at = excluded.installed_at,
               reason = excluded.reason",
            params![
                agent_id,
                cluster_id,
                owner_node_id,
                authority_generation,
                fencing_token,
                state.as_str(),
                changed_at.to_rfc3339(),
                reason,
            ],
        )
        .map_err(|error| storage_error(format!("write agent mutation fence: {error}")))?;
    crash_cluster_mutation_after_step_for_test("agent_mutation_fence.record");
    connection
        .execute(
            "INSERT INTO cluster_agent_mutation_fence_audit
             (agent_id, fencing_token, cluster_id, owner_node_id,
              authority_generation, state, actor, reason, changed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                agent_id,
                fencing_token,
                cluster_id,
                owner_node_id,
                authority_generation,
                state.as_str(),
                actor,
                reason,
                changed_at.to_rfc3339(),
            ],
        )
        .map_err(|error| storage_error(format!("audit agent mutation fence: {error}")))?;
    crash_cluster_mutation_after_step_for_test("agent_mutation_fence.audit");
    Ok(())
}

fn mutation_fence_audit_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<AgentMutationFenceAudit, ContextError> {
    Ok(AgentMutationFenceAudit {
        agent_id: row
            .get(0)
            .map_err(|error| storage_error(error.to_string()))?,
        cluster_id: row
            .get(1)
            .map_err(|error| storage_error(error.to_string()))?,
        owner_node_id: row
            .get(2)
            .map_err(|error| storage_error(error.to_string()))?,
        authority_generation: u64::try_from(
            row.get::<_, i64>(3)
                .map_err(|error| storage_error(error.to_string()))?,
        )
        .map_err(|_| storage_error("negative fence audit authority generation"))?,
        fencing_token: u64::try_from(
            row.get::<_, i64>(4)
                .map_err(|error| storage_error(error.to_string()))?,
        )
        .map_err(|_| storage_error("negative fence audit token"))?,
        state: AgentMutationFenceState::try_from(
            row.get::<_, String>(5)
                .map_err(|error| storage_error(error.to_string()))?
                .as_str(),
        )?,
        actor: row
            .get(6)
            .map_err(|error| storage_error(error.to_string()))?,
        reason: row
            .get(7)
            .map_err(|error| storage_error(error.to_string()))?,
        changed_at: parse_timestamp(
            &row.get::<_, String>(8)
                .map_err(|error| storage_error(error.to_string()))?,
        )?,
    })
}

#[allow(clippy::too_many_arguments)]
fn write_ownership(
    connection: &rusqlite::Connection,
    agent_id: &str,
    owner_node_id: &str,
    fencing_token: u64,
    generation: u64,
    state: ClusterOwnershipState,
    lease_expires_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    reason: &str,
) -> Result<(), ContextError> {
    connection
        .execute(
            "INSERT INTO cluster_agent_ownership
             (agent_id, owner_node_id, fencing_token, generation, state,
              lease_expires_at, updated_at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(agent_id) DO UPDATE SET
               owner_node_id = excluded.owner_node_id,
               fencing_token = excluded.fencing_token,
               generation = excluded.generation,
               state = excluded.state,
               lease_expires_at = excluded.lease_expires_at,
               updated_at = excluded.updated_at,
               reason = excluded.reason",
            params![
                agent_id,
                owner_node_id,
                sqlite_generation(fencing_token, "ownership fencing token")?,
                sqlite_generation(generation, "ownership generation")?,
                state.as_str(),
                lease_expires_at.to_rfc3339(),
                updated_at.to_rfc3339(),
                reason,
            ],
        )
        .map_err(|error| storage_error(format!("write agent ownership: {error}")))?;
    crash_cluster_mutation_after_step_for_test("agent_ownership.record");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_ownership_audit(
    connection: &rusqlite::Connection,
    agent_id: &str,
    generation: u64,
    previous_owner_node_id: Option<&str>,
    owner_node_id: &str,
    fencing_token: u64,
    operation: &str,
    actor: &str,
    reason: &str,
    changed_at: DateTime<Utc>,
) -> Result<(), ContextError> {
    connection
        .execute(
            "INSERT INTO cluster_agent_ownership_audit
             (agent_id, generation, previous_owner_node_id, owner_node_id,
              fencing_token, operation, actor, reason, changed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                agent_id,
                sqlite_generation(generation, "ownership audit generation")?,
                previous_owner_node_id,
                owner_node_id,
                sqlite_generation(fencing_token, "ownership audit fencing token")?,
                operation,
                actor,
                reason,
                changed_at.to_rfc3339(),
            ],
        )
        .map_err(|error| storage_error(format!("audit agent ownership: {error}")))?;
    crash_cluster_mutation_after_step_for_test("agent_ownership.audit");
    Ok(())
}

/// Build the canonical, domain-separated bytes that a joining node signs.
pub fn membership_join_payload(
    cluster_id: &str,
    challenge_hex: &str,
    registration: &ClusterMemberRegistration,
) -> Result<Vec<u8>, ContextError> {
    uuid::Uuid::parse_str(cluster_id).map_err(|_| storage_error("invalid cluster authority id"))?;
    validate_member_registration(registration)?;
    let challenge = hex_decode(challenge_hex)
        .filter(|value| value.len() == 32)
        .ok_or_else(|| storage_error("invalid cluster join challenge"))?;
    let mut payload = b"AIagentOS cluster membership join v1".to_vec();
    let min_protocol_version = registration.min_protocol_version.to_string();
    let protocol_version = registration.protocol_version.to_string();
    for field in [
        cluster_id.as_bytes(),
        challenge.as_slice(),
        registration.node_id.as_bytes(),
        registration.fingerprint.as_bytes(),
        registration.public_key.as_bytes(),
        registration.endpoint.as_bytes(),
        registration.server_version.as_bytes(),
        min_protocol_version.as_bytes(),
        protocol_version.as_bytes(),
    ] {
        let length = u32::try_from(field.len())
            .map_err(|_| storage_error("cluster join payload field is too large"))?;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(field);
    }
    if let Some(fingerprint) = registration.tls_server_certificate_fingerprint.as_deref() {
        let length = u32::try_from(fingerprint.len())
            .map_err(|_| storage_error("cluster join payload field is too large"))?;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(fingerprint.as_bytes());
    }
    Ok(payload)
}

fn load_identity(connection: &rusqlite::Connection) -> Result<Option<NodeIdentity>, ContextError> {
    connection
        .query_row(
            "SELECT node_id, private_key, public_key, fingerprint, created_at
             FROM cluster_node_identity WHERE singleton = ?1",
            [SINGLETON],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|error| storage_error(format!("load cluster identity: {error}")))?
        .map(
            |(node_id, private_key, public_key, fingerprint, created_at)| {
                uuid::Uuid::parse_str(&node_id)
                    .map_err(|_| storage_error("persisted cluster node id is invalid"))?;
                let pair = Ed25519KeyPair::from_pkcs8(&private_key)
                    .map_err(|_| storage_error("persisted cluster private key is invalid"))?;
                if pair.public_key().as_ref() != public_key {
                    return Err(storage_error(
                        "persisted cluster private key does not match its public key",
                    ));
                }
                let actual_fingerprint = sha256_hex(&public_key);
                if actual_fingerprint != fingerprint {
                    return Err(storage_error(
                        "persisted cluster identity fingerprint does not match its public key",
                    ));
                }
                Ok(NodeIdentity {
                    node_id,
                    fingerprint,
                    public_key: hex_encode(&public_key),
                    created_at: parse_timestamp(&created_at)?,
                })
            },
        )
        .transpose()
}

pub(crate) fn validate_text(value: &str, field: &str) -> Result<(), ContextError> {
    if value.trim().is_empty() || value.len() > MAX_REASON_BYTES || value.contains('\0') {
        return Err(storage_error(format!("invalid {field}")));
    }
    Ok(())
}

pub(crate) fn validate_reason(reason: &str) -> Result<(), ContextError> {
    validate_text(reason, "cluster-control reason")
}

pub(crate) fn validate_member_registration(
    registration: &ClusterMemberRegistration,
) -> Result<(), ContextError> {
    uuid::Uuid::parse_str(&registration.node_id)
        .map_err(|_| storage_error("invalid cluster member node id"))?;
    let public_key = hex_decode(&registration.public_key)
        .filter(|value| value.len() == 32)
        .ok_or_else(|| storage_error("invalid cluster member Ed25519 public key"))?;
    if registration.fingerprint.len() != 64 || sha256_hex(&public_key) != registration.fingerprint {
        return Err(storage_error(
            "cluster member fingerprint does not match its public key",
        ));
    }
    if registration
        .tls_server_certificate_fingerprint
        .as_deref()
        .is_some_and(|fingerprint| {
            fingerprint.len() != 64
                || !fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        return Err(storage_error(
            "invalid cluster member TLS server certificate fingerprint",
        ));
    }
    validate_member_text(
        &registration.endpoint,
        MAX_MEMBER_ENDPOINT_BYTES,
        "cluster member endpoint",
    )?;
    validate_member_text(
        &registration.server_version,
        MAX_MEMBER_VERSION_BYTES,
        "cluster member server version",
    )?;
    if registration.min_protocol_version == 0
        || registration.min_protocol_version > registration.protocol_version
    {
        return Err(storage_error("invalid cluster member protocol window"));
    }
    Ok(())
}

fn validate_member_text(value: &str, max_bytes: usize, field: &str) -> Result<(), ContextError> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        return Err(storage_error(format!("invalid {field}")));
    }
    Ok(())
}

fn sqlite_generation(value: u64, field: &str) -> Result<i64, ContextError> {
    i64::try_from(value).map_err(|_| storage_error(format!("{field} generation exceeds SQLite")))
}

fn validate_profile(profile: &NodeProfile) -> Result<(), ContextError> {
    let encoded = serde_json::to_vec(profile)
        .map_err(|error| storage_error(format!("encode node profile: {error}")))?;
    if encoded.len() > MAX_PROFILE_BYTES
        || profile.models.len() > MAX_PROFILE_VALUES
        || profile.sandbox_profiles.len() > MAX_PROFILE_VALUES
        || profile.labels.len() > MAX_PROFILE_LABELS
    {
        return Err(storage_error("invalid node profile: size limit exceeded"));
    }
    let valid_value = |value: &str| {
        !value.trim().is_empty() && value.len() <= MAX_PROFILE_TEXT_BYTES && !value.contains('\0')
    };
    if profile
        .region
        .as_deref()
        .is_some_and(|value| !valid_value(value))
        || profile
            .data_residency
            .as_deref()
            .is_some_and(|value| !valid_value(value))
        || profile.models.iter().any(|value| !valid_value(value))
        || profile
            .sandbox_profiles
            .iter()
            .any(|value| !valid_value(value))
        || profile
            .labels
            .iter()
            .any(|(key, value)| !valid_value(key) || !valid_value(value))
    {
        return Err(storage_error("invalid node profile value"));
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, ContextError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| storage_error(format!("invalid cluster timestamp: {error}")))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

fn storage_error(message: impl Into<String>) -> ContextError {
    ContextError::StorageError(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER_CRASH_CASES: &[(&str, usize)] = &[
        ("initialize", 3),
        ("transition", 2),
        ("profile", 2),
        ("join", 4),
        ("rejoin", 4),
        ("leave", 3),
        ("revoke", 3),
        ("ownership_claim", 2),
        ("ownership_renew", 2),
        ("ownership_release", 2),
        ("revoke_owned", 5),
        ("fence_install", 2),
        ("fence_retire", 2),
    ];
    const CLUSTER_MUTATION_TABLES: &[&str] = &[
        "cluster_node_identity",
        "cluster_node_control",
        "cluster_node_control_audit",
        "cluster_membership_authority",
        "cluster_join_challenges",
        "cluster_members",
        "cluster_membership_audit",
        "cluster_agent_ownership",
        "cluster_agent_ownership_audit",
        "cluster_agent_mutation_fences",
        "cluster_agent_mutation_fence_audit",
    ];

    struct ClusterCrashDatabase {
        authority_path: std::path::PathBuf,
        member_path: std::path::PathBuf,
    }

    impl ClusterCrashDatabase {
        fn new(operation: &str, step: usize) -> Self {
            let id = uuid::Uuid::new_v4();
            Self {
                authority_path: std::env::temp_dir().join(format!(
                    "aiagentos-cluster-crash-authority-{operation}-{step}-{id}.db"
                )),
                member_path: std::env::temp_dir().join(format!(
                    "aiagentos-cluster-crash-member-{operation}-{step}-{id}.db"
                )),
            }
        }
    }

    impl Drop for ClusterCrashDatabase {
        fn drop(&mut self) {
            remove_cluster_crash_database(&self.authority_path);
            remove_cluster_crash_database(&self.member_path);
        }
    }

    #[derive(Debug, Default, Serialize, Deserialize)]
    struct ClusterCrashInput {
        challenge_hex: Option<String>,
        signature_hex: Option<String>,
        node_id: Option<String>,
        expected_generation: Option<u64>,
        agent_id: Option<String>,
        cluster_id: Option<String>,
        fencing_token: Option<u64>,
    }

    fn remove_cluster_crash_database(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(sidecar));
        }
    }

    fn reset_cluster_mutation_steps_for_test() {
        CLUSTER_MUTATION_STEP_FOR_TEST.with(|counter| counter.set(0));
    }

    fn cluster_mutation_steps_for_test() -> usize {
        CLUSTER_MUTATION_STEP_FOR_TEST.with(std::cell::Cell::get)
    }

    fn prepare_cluster_crash_join(
        authority: &ClusterControl,
        member: &ClusterControl,
        expected_generation: Option<u64>,
    ) -> ClusterCrashInput {
        let registration = member_registration(member, "member.internal:7443");
        let challenge = authority.issue_join_challenge(300).unwrap();
        let signature = sign_join(authority, member, &challenge, &registration);
        ClusterCrashInput {
            challenge_hex: Some(challenge.challenge_hex),
            signature_hex: Some(signature),
            node_id: Some(registration.node_id),
            expected_generation,
            ..ClusterCrashInput::default()
        }
    }

    fn register_cluster_crash_member(
        authority: &ClusterControl,
        member: &ClusterControl,
        input: &ClusterCrashInput,
        reason: &str,
    ) -> ClusterMember {
        let registration = member_registration(member, "member.internal:7443");
        authority
            .register_member(
                registration,
                input
                    .challenge_hex
                    .as_deref()
                    .expect("cluster crash join challenge"),
                input
                    .signature_hex
                    .as_deref()
                    .expect("cluster crash join signature"),
                input.expected_generation,
                1,
                2,
                "system",
                reason,
            )
            .unwrap()
    }

    fn seed_cluster_crash_operation(
        authority_path: &std::path::Path,
        member_path: &std::path::Path,
        operation: &str,
    ) -> ClusterCrashInput {
        let authority_store = Arc::new(open_cluster_crash_manager(authority_path));
        if operation == "initialize" {
            drop(authority_store);
            return ClusterCrashInput::default();
        }
        let authority = ClusterControl::new(authority_store).unwrap();
        match operation {
            "transition" | "profile" => ClusterCrashInput::default(),
            "join" => {
                let member =
                    ClusterControl::new(Arc::new(open_cluster_crash_manager(member_path))).unwrap();
                prepare_cluster_crash_join(&authority, &member, None)
            }
            "rejoin" => {
                let member =
                    ClusterControl::new(Arc::new(open_cluster_crash_manager(member_path))).unwrap();
                let first = prepare_cluster_crash_join(&authority, &member, None);
                let joined =
                    register_cluster_crash_member(&authority, &member, &first, "initial admission");
                let left = authority
                    .set_member_state(
                        &joined.node_id,
                        ClusterMemberState::Left,
                        joined.generation,
                        "system",
                        "maintenance",
                    )
                    .unwrap();
                prepare_cluster_crash_join(&authority, &member, Some(left.generation))
            }
            "leave" | "revoke" | "ownership_claim" | "ownership_renew" | "ownership_release"
            | "revoke_owned" => {
                let member =
                    ClusterControl::new(Arc::new(open_cluster_crash_manager(member_path))).unwrap();
                let first = prepare_cluster_crash_join(&authority, &member, None);
                let joined =
                    register_cluster_crash_member(&authority, &member, &first, "initial admission");
                let agent_id = uuid::Uuid::new_v4().to_string();
                let fencing_token = if operation == "ownership_renew"
                    || operation == "ownership_release"
                    || operation == "revoke_owned"
                {
                    Some(
                        authority
                            .claim_agent_ownership(
                                &agent_id,
                                &joined.node_id,
                                30,
                                None,
                                "system",
                                "ownership crash fixture",
                            )
                            .unwrap()
                            .fencing_token,
                    )
                } else {
                    None
                };
                ClusterCrashInput {
                    node_id: Some(joined.node_id),
                    expected_generation: Some(joined.generation),
                    agent_id: Some(agent_id),
                    fencing_token,
                    ..ClusterCrashInput::default()
                }
            }
            "fence_install" | "fence_retire" => {
                let agent_id = uuid::Uuid::new_v4().to_string();
                let node_id = authority.identity().node_id.clone();
                let cluster_id = uuid::Uuid::new_v4().to_string();
                let now = Utc::now().to_rfc3339();
                authority
                    .store
                    .conn
                    .lock()
                    .unwrap()
                    .execute(
                        "INSERT INTO agents
                         (id, session_id, name, task, llm_provider,
                          permission_profile, priority, status, created_at,
                          last_activity_at)
                         VALUES (?1, ?2, 'fence-crash', 'test', 'stub',
                                 'standard', 3, 'Running', ?3, ?3)",
                        params![&agent_id, uuid::Uuid::new_v4().to_string(), now],
                    )
                    .unwrap();
                if operation == "fence_retire" {
                    authority
                        .install_agent_mutation_fence(
                            &agent_id,
                            &cluster_id,
                            &node_id,
                            10,
                            5,
                            "system",
                            "fence crash fixture",
                        )
                        .unwrap();
                }
                ClusterCrashInput {
                    node_id: Some(node_id),
                    expected_generation: Some(10),
                    agent_id: Some(agent_id),
                    cluster_id: Some(cluster_id),
                    fencing_token: Some(5),
                    ..ClusterCrashInput::default()
                }
            }
            unknown => panic!("unknown cluster crash operation {unknown}"),
        }
    }

    fn open_cluster_crash_manager(path: &std::path::Path) -> SqliteContextManager {
        // This matrix exercises SQLite transaction recovery across a forced
        // process exit. The exclusive process-ownership lease is deliberately
        // omitted because fork/exec lease inheritance is qualified separately.
        SqliteContextManager::new_without_storage_lease(path).unwrap()
    }

    fn run_cluster_crash_operation(
        authority_path: &std::path::Path,
        member_path: &std::path::Path,
        operation: &str,
        input: &ClusterCrashInput,
    ) {
        let authority_store = Arc::new(open_cluster_crash_manager(authority_path));
        if operation == "initialize" {
            ClusterControl::new(authority_store).unwrap();
            return;
        }
        let authority = ClusterControl::new(authority_store).unwrap();
        match operation {
            "transition" => {
                authority
                    .transition(
                        NodeAvailability::Draining,
                        0,
                        "operator",
                        "crash-qualified transition",
                    )
                    .unwrap();
            }
            "profile" => {
                authority
                    .set_profile(
                        NodeProfile {
                            region: Some("ca-central-1".into()),
                            models: vec!["qualified-model".into()],
                            ..NodeProfile::default()
                        },
                        0,
                        "operator",
                        "crash-qualified profile",
                    )
                    .unwrap();
            }
            "join" | "rejoin" => {
                let member =
                    ClusterControl::new(Arc::new(open_cluster_crash_manager(member_path))).unwrap();
                register_cluster_crash_member(
                    &authority,
                    &member,
                    input,
                    if operation == "join" {
                        "crash-qualified join"
                    } else {
                        "crash-qualified rejoin"
                    },
                );
            }
            "leave" | "revoke" | "revoke_owned" => {
                authority
                    .set_member_state(
                        input.node_id.as_deref().expect("cluster crash node id"),
                        if operation == "leave" {
                            ClusterMemberState::Left
                        } else {
                            ClusterMemberState::Revoked
                        },
                        input
                            .expected_generation
                            .expect("cluster crash expected generation"),
                        "system",
                        if operation == "leave" {
                            "crash-qualified leave"
                        } else {
                            "crash-qualified revocation"
                        },
                    )
                    .unwrap();
            }
            "ownership_claim" => {
                authority
                    .claim_agent_ownership(
                        input.agent_id.as_deref().expect("cluster crash agent id"),
                        input.node_id.as_deref().expect("cluster crash node id"),
                        30,
                        None,
                        "system",
                        "crash-qualified ownership claim",
                    )
                    .unwrap();
            }
            "ownership_renew" => {
                authority
                    .renew_agent_ownership(
                        input.agent_id.as_deref().expect("cluster crash agent id"),
                        input.node_id.as_deref().expect("cluster crash node id"),
                        input
                            .fencing_token
                            .expect("cluster crash ownership fencing token"),
                        30,
                        "system",
                        "crash-qualified ownership renewal",
                    )
                    .unwrap();
            }
            "ownership_release" => {
                authority
                    .release_agent_ownership(
                        input.agent_id.as_deref().expect("cluster crash agent id"),
                        input.node_id.as_deref().expect("cluster crash node id"),
                        input
                            .fencing_token
                            .expect("cluster crash ownership fencing token"),
                        "system",
                        "crash-qualified ownership release",
                    )
                    .unwrap();
            }
            "fence_install" => {
                authority
                    .install_agent_mutation_fence(
                        input.agent_id.as_deref().expect("cluster crash agent id"),
                        input
                            .cluster_id
                            .as_deref()
                            .expect("cluster crash cluster id"),
                        input.node_id.as_deref().expect("cluster crash node id"),
                        input
                            .expected_generation
                            .expect("cluster crash authority generation"),
                        input
                            .fencing_token
                            .expect("cluster crash mutation fencing token"),
                        "system",
                        "crash-qualified mutation fence install",
                    )
                    .unwrap();
            }
            "fence_retire" => {
                authority
                    .retire_agent_mutation_fence(
                        input.agent_id.as_deref().expect("cluster crash agent id"),
                        input
                            .cluster_id
                            .as_deref()
                            .expect("cluster crash cluster id"),
                        input.node_id.as_deref().expect("cluster crash node id"),
                        input
                            .expected_generation
                            .expect("cluster crash authority generation"),
                        input
                            .fencing_token
                            .expect("cluster crash mutation fencing token"),
                        "system",
                        "crash-qualified mutation fence retirement",
                    )
                    .unwrap();
            }
            unknown => panic!("unknown cluster crash operation {unknown}"),
        }
    }

    fn cluster_table_fingerprints(
        database: &std::path::Path,
    ) -> std::collections::BTreeMap<String, String> {
        let manager = open_cluster_crash_manager(database);
        let connection = manager.conn.lock().unwrap();
        let fingerprints = CLUSTER_MUTATION_TABLES
            .iter()
            .map(|table| {
                let mut statement = connection
                    .prepare(&format!("SELECT * FROM {table}"))
                    .unwrap();
                let columns = statement.column_count();
                let mut query = statement.query([]).unwrap();
                let mut encoded_rows = Vec::new();
                while let Some(row) = query.next().unwrap() {
                    let mut encoded = Vec::new();
                    for index in 0..columns {
                        match row.get_ref(index).unwrap() {
                            rusqlite::types::ValueRef::Null => encoded.push(0),
                            rusqlite::types::ValueRef::Integer(value) => {
                                encoded.push(1);
                                encoded.extend_from_slice(&value.to_be_bytes());
                            }
                            rusqlite::types::ValueRef::Real(value) => {
                                encoded.push(2);
                                encoded.extend_from_slice(&value.to_bits().to_be_bytes());
                            }
                            rusqlite::types::ValueRef::Text(value) => {
                                encoded.push(3);
                                encoded.extend_from_slice(
                                    &u64::try_from(value.len()).unwrap().to_be_bytes(),
                                );
                                encoded.extend_from_slice(value);
                            }
                            rusqlite::types::ValueRef::Blob(value) => {
                                encoded.push(4);
                                encoded.extend_from_slice(
                                    &u64::try_from(value.len()).unwrap().to_be_bytes(),
                                );
                                encoded.extend_from_slice(value);
                            }
                        }
                    }
                    encoded_rows.push(encoded);
                }
                encoded_rows.sort();
                let mut material = Vec::new();
                for row in encoded_rows {
                    material.extend_from_slice(&u64::try_from(row.len()).unwrap().to_be_bytes());
                    material.extend_from_slice(&row);
                }
                (
                    (*table).to_string(),
                    hex_encode(ring::digest::digest(&ring::digest::SHA256, &material).as_ref()),
                )
            })
            .collect();
        drop(connection);
        drop(manager);
        fingerprints
    }

    fn assert_cluster_database_valid(database: &std::path::Path) {
        let manager = open_cluster_crash_manager(database);
        let connection = manager.conn.lock().unwrap();
        crate::schema::verify(&connection).unwrap();
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(quick_check, "ok");
    }

    fn assert_cluster_challenge_consumed(database: &std::path::Path, challenge_hex: &str) {
        let manager = open_cluster_crash_manager(database);
        let connection = manager.conn.lock().unwrap();
        let challenge = hex_decode(challenge_hex).unwrap();
        let consumed: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM cluster_join_challenges
                 WHERE challenge_hash = ?1 AND consumed_at IS NOT NULL",
                [sha256_hex(&challenge)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(consumed, 1);
    }

    fn assert_cluster_crash_operation_committed(
        database: &std::path::Path,
        operation: &str,
        input: &ClusterCrashInput,
    ) {
        let control = ClusterControl::new(Arc::new(open_cluster_crash_manager(database))).unwrap();
        match operation {
            "initialize" => {
                let status = control.status().unwrap();
                assert_eq!(status.generation, 0);
                assert_eq!(status.availability, NodeAvailability::Active);
                assert_eq!(control.membership_snapshot().unwrap().generation, 0);
                assert!(control.audit(10).unwrap().is_empty());
                assert!(control.membership_audit(10).unwrap().is_empty());
            }
            "transition" => {
                let status = control.status().unwrap();
                assert_eq!(status.generation, 1);
                assert_eq!(status.availability, NodeAvailability::Draining);
                let audit = control.audit(10).unwrap();
                assert_eq!(audit.len(), 1);
                assert_eq!(audit[0].generation, status.generation);
                assert_eq!(audit[0].current, status.availability);
            }
            "profile" => {
                let status = control.status().unwrap();
                assert_eq!(status.generation, 1);
                assert_eq!(status.availability, NodeAvailability::Active);
                assert_eq!(status.profile.region.as_deref(), Some("ca-central-1"));
                assert_eq!(status.profile.models, vec!["qualified-model"]);
                let audit = control.audit(10).unwrap();
                assert_eq!(audit.len(), 1);
                assert_eq!(audit[0].previous, NodeAvailability::Active);
                assert_eq!(audit[0].current, NodeAvailability::Active);
            }
            "join" | "rejoin" => {
                let expected_generation = if operation == "join" { 1 } else { 3 };
                let snapshot = control.membership_snapshot().unwrap();
                assert_eq!(snapshot.generation, expected_generation);
                assert_eq!(snapshot.members.len(), 1);
                assert_eq!(snapshot.members[0].state, ClusterMemberState::Active);
                assert_eq!(snapshot.members[0].generation, expected_generation);
                let audit = control.membership_audit(10).unwrap();
                assert_eq!(audit.len(), expected_generation as usize);
                assert_eq!(audit[0].membership_generation, expected_generation);
                assert_eq!(audit[0].member_generation, expected_generation);
                assert_eq!(audit[0].current, ClusterMemberState::Active);
                assert_cluster_challenge_consumed(
                    database,
                    input
                        .challenge_hex
                        .as_deref()
                        .expect("committed cluster challenge"),
                );
            }
            "leave" | "revoke" | "revoke_owned" => {
                let expected_state = if operation == "leave" {
                    ClusterMemberState::Left
                } else {
                    ClusterMemberState::Revoked
                };
                let snapshot = control.membership_snapshot().unwrap();
                assert_eq!(snapshot.generation, 2);
                assert_eq!(snapshot.members.len(), 1);
                assert_eq!(snapshot.members[0].state, expected_state);
                assert_eq!(snapshot.members[0].generation, 2);
                let audit = control.membership_audit(10).unwrap();
                assert_eq!(audit.len(), 2);
                assert_eq!(audit[0].membership_generation, 2);
                assert_eq!(audit[0].member_generation, 2);
                assert_eq!(audit[0].current, expected_state);
                if operation == "revoke_owned" {
                    let ownership = control
                        .agent_ownership(input.agent_id.as_deref().expect("cluster crash agent id"))
                        .unwrap()
                        .expect("released ownership tombstone");
                    assert_eq!(ownership.state, ClusterOwnershipState::Released);
                    assert_eq!(
                        ownership.fencing_token,
                        input
                            .fencing_token
                            .expect("cluster crash ownership fencing token")
                    );
                    let ownership_audit = control
                        .agent_ownership_audit(input.agent_id.as_deref(), 10)
                        .unwrap();
                    assert_eq!(ownership_audit.len(), 2);
                    assert_eq!(ownership_audit[0].operation, "release");
                }
            }
            "ownership_claim" | "ownership_renew" | "ownership_release" => {
                let ownership = control
                    .agent_ownership(input.agent_id.as_deref().expect("cluster crash agent id"))
                    .unwrap()
                    .expect("committed ownership");
                assert_eq!(
                    ownership.state,
                    if operation == "ownership_release" {
                        ClusterOwnershipState::Released
                    } else {
                        ClusterOwnershipState::Active
                    }
                );
                assert_eq!(ownership.fencing_token, 1);
                assert_eq!(
                    ownership.generation,
                    if operation == "ownership_claim" { 1 } else { 2 }
                );
                let audit = control
                    .agent_ownership_audit(input.agent_id.as_deref(), 10)
                    .unwrap();
                assert_eq!(
                    audit.len(),
                    if operation == "ownership_claim" { 1 } else { 2 }
                );
                assert_eq!(
                    audit[0].operation,
                    match operation {
                        "ownership_claim" => "claim",
                        "ownership_renew" => "renew",
                        _ => "release",
                    }
                );
            }
            "fence_install" | "fence_retire" => {
                let fence = control
                    .agent_mutation_fence(
                        input.agent_id.as_deref().expect("cluster crash agent id"),
                    )
                    .unwrap()
                    .expect("committed destination fence");
                assert_eq!(
                    fence.state,
                    if operation == "fence_install" {
                        AgentMutationFenceState::Active
                    } else {
                        AgentMutationFenceState::Retired
                    }
                );
                assert_eq!(
                    fence.fencing_token,
                    input
                        .fencing_token
                        .expect("cluster crash mutation fencing token")
                );
                let audit = control
                    .agent_mutation_fence_audit(input.agent_id.as_deref(), 10)
                    .unwrap();
                assert_eq!(
                    audit.len(),
                    if operation == "fence_install" { 1 } else { 2 }
                );
                assert_eq!(audit[0].state, fence.state);
            }
            unknown => panic!("unknown cluster crash operation {unknown}"),
        }
        assert_cluster_database_valid(database);
    }

    #[test]
    fn process_exit_at_every_cluster_multi_table_statement_preserves_atomicity() {
        for (operation, expected_steps) in CLUSTER_CRASH_CASES {
            for step in 1..=*expected_steps {
                let database = ClusterCrashDatabase::new(operation, step);
                let input = seed_cluster_crash_operation(
                    &database.authority_path,
                    &database.member_path,
                    operation,
                );
                let baseline = cluster_table_fingerprints(&database.authority_path);

                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--ignored")
                    .arg("cluster_multi_table_mutation_crash_child_only")
                    .env(
                        "AIAGENTOS_TEST_CLUSTER_CRASH_AUTHORITY_DB",
                        &database.authority_path,
                    )
                    .env(
                        "AIAGENTOS_TEST_CLUSTER_CRASH_MEMBER_DB",
                        &database.member_path,
                    )
                    .env("AIAGENTOS_TEST_CLUSTER_CRASH_OPERATION", operation)
                    .env(
                        "AIAGENTOS_TEST_CLUSTER_CRASH_INPUT",
                        serde_json::to_string(&input).unwrap(),
                    )
                    .env("AIAGENTOS_TEST_EXIT_CLUSTER_AFTER_STEP", step.to_string())
                    .status()
                    .unwrap();
                assert_eq!(
                    child.code(),
                    Some(86),
                    "{operation} child did not terminate at mutation {step}"
                );
                assert_cluster_database_valid(&database.authority_path);
                assert_eq!(
                    cluster_table_fingerprints(&database.authority_path),
                    baseline,
                    "process exit after {operation} mutation {step} left partial cluster state"
                );

                reset_cluster_mutation_steps_for_test();
                run_cluster_crash_operation(
                    &database.authority_path,
                    &database.member_path,
                    operation,
                    &input,
                );
                assert_eq!(
                    cluster_mutation_steps_for_test(),
                    *expected_steps,
                    "{operation} mutation inventory changed without updating the crash matrix"
                );
                assert_ne!(
                    cluster_table_fingerprints(&database.authority_path),
                    baseline,
                    "{operation} retry did not publish its complete transaction"
                );
                assert_cluster_crash_operation_committed(
                    &database.authority_path,
                    operation,
                    &input,
                );
            }
        }
    }

    #[test]
    #[ignore = "child-process helper for cluster multi-table crash regression"]
    fn cluster_multi_table_mutation_crash_child_only() {
        let Some(authority) = std::env::var_os("AIAGENTOS_TEST_CLUSTER_CRASH_AUTHORITY_DB") else {
            return;
        };
        let member = std::env::var_os("AIAGENTOS_TEST_CLUSTER_CRASH_MEMBER_DB")
            .expect("cluster crash helper requires a member database");
        let operation = std::env::var("AIAGENTOS_TEST_CLUSTER_CRASH_OPERATION")
            .expect("cluster crash helper requires an operation");
        let input: ClusterCrashInput = serde_json::from_str(
            &std::env::var("AIAGENTOS_TEST_CLUSTER_CRASH_INPUT")
                .expect("cluster crash helper requires operation input"),
        )
        .unwrap();
        run_cluster_crash_operation(
            std::path::Path::new(&authority),
            std::path::Path::new(&member),
            &operation,
            &input,
        );
        panic!("cluster crash helper did not terminate at the requested mutation");
    }

    #[test]
    fn identity_is_stable_and_proves_private_key_possession() {
        let store = Arc::new(SqliteContextManager::in_memory().unwrap());
        let first = ClusterControl::new(store.clone()).unwrap();
        let second = ClusterControl::new(store).unwrap();
        assert_eq!(first.identity(), second.identity());

        let challenge = b"cluster-discovery-nonce";
        let signature = first.sign_challenge(challenge).unwrap();
        assert!(ClusterControl::verify_challenge(
            &first.identity().public_key,
            challenge,
            &signature
        ));
        assert!(!ClusterControl::verify_challenge(
            &first.identity().public_key,
            b"different",
            &signature
        ));
    }

    #[test]
    fn destination_mutation_fences_are_monotonic_exact_and_durable() {
        let store = Arc::new(SqliteContextManager::in_memory().unwrap());
        let control = ClusterControl::new(store.clone()).unwrap();
        let agent_id = uuid::Uuid::new_v4().to_string();
        let cluster_id = uuid::Uuid::new_v4().to_string();
        let node_id = control.identity().node_id.clone();
        let now = Utc::now().to_rfc3339();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO agents
                 (id, session_id, name, task, llm_provider, permission_profile,
                  priority, status, created_at, last_activity_at)
                 VALUES (?1, ?2, 'fenced', 'test', 'stub', 'standard',
                         3, 'Running', ?3, ?3)",
                params![&agent_id, uuid::Uuid::new_v4().to_string(), now],
            )
            .unwrap();

        let foreign_node = uuid::Uuid::new_v4().to_string();
        assert!(control
            .install_agent_mutation_fence(
                &agent_id,
                &cluster_id,
                &foreign_node,
                10,
                5,
                "system",
                "foreign destination",
            )
            .unwrap_err()
            .to_string()
            .contains("destination node"));

        let installed = control
            .install_agent_mutation_fence(
                &agent_id,
                &cluster_id,
                &node_id,
                10,
                5,
                "system",
                "initial destination fence",
            )
            .unwrap();
        assert_eq!(installed.state, AgentMutationFenceState::Active);
        control
            .verify_agent_mutation_fence(&agent_id, &cluster_id, &node_id, 10, 5)
            .unwrap();
        assert_eq!(
            control
                .install_agent_mutation_fence(
                    &agent_id,
                    &cluster_id,
                    &node_id,
                    10,
                    5,
                    "system",
                    "idempotent retry",
                )
                .unwrap(),
            installed
        );
        assert!(control
            .install_agent_mutation_fence(
                &agent_id,
                &cluster_id,
                &node_id,
                9,
                4,
                "system",
                "stale route",
            )
            .unwrap_err()
            .to_string()
            .contains("stale"));
        assert!(control
            .install_agent_mutation_fence(
                &agent_id,
                &cluster_id,
                &node_id,
                10,
                6,
                "system",
                "token without generation",
            )
            .unwrap_err()
            .to_string()
            .contains("newer authority generation"));

        let transferred = control
            .install_agent_mutation_fence(
                &agent_id,
                &cluster_id,
                &node_id,
                11,
                6,
                "system",
                "ownership transfer",
            )
            .unwrap();
        assert_eq!(transferred.fencing_token, 6);
        assert!(control
            .verify_agent_mutation_fence(&agent_id, &cluster_id, &node_id, 10, 5)
            .unwrap_err()
            .to_string()
            .contains("destination ownership fence"));
        control
            .verify_agent_mutation_fence(&agent_id, &cluster_id, &node_id, 11, 6)
            .unwrap();

        let retired = control
            .retire_agent_mutation_fence(
                &agent_id,
                &cluster_id,
                &node_id,
                11,
                6,
                "system",
                "drained old owner",
            )
            .unwrap();
        assert_eq!(retired.state, AgentMutationFenceState::Retired);
        assert!(control
            .verify_agent_mutation_fence(&agent_id, &cluster_id, &node_id, 11, 6)
            .is_err());
        assert!(control
            .install_agent_mutation_fence(
                &agent_id,
                &cluster_id,
                &node_id,
                11,
                6,
                "system",
                "delayed replay",
            )
            .unwrap_err()
            .to_string()
            .contains("cannot become active"));

        let restarted = ClusterControl::new(store).unwrap();
        assert_eq!(
            restarted.agent_mutation_fence(&agent_id).unwrap(),
            Some(retired)
        );
        let audit = restarted
            .agent_mutation_fence_audit(Some(&agent_id), 10)
            .unwrap();
        assert_eq!(audit.len(), 3);
        assert_eq!(audit[0].state, AgentMutationFenceState::Retired);
        assert_eq!(audit[0].fencing_token, 6);
    }

    #[test]
    fn transitions_are_generation_fenced_and_audited() {
        let store = Arc::new(SqliteContextManager::in_memory().unwrap());
        let control = ClusterControl::new(store).unwrap();
        let initial = control.status().unwrap();
        assert_eq!(initial.availability, NodeAvailability::Active);

        let draining = control
            .transition(
                NodeAvailability::Draining,
                initial.generation,
                "operator",
                "rolling upgrade",
            )
            .unwrap();
        assert_eq!(draining.availability, NodeAvailability::Draining);
        assert!(control
            .transition(
                NodeAvailability::Active,
                initial.generation,
                "stale",
                "stale write",
            )
            .unwrap_err()
            .to_string()
            .contains("revision conflict"));

        let audit = control.audit(10).unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].previous, NodeAvailability::Active);
        assert_eq!(audit[0].current, NodeAvailability::Draining);

        let oversized = NodeProfile {
            models: vec!["model".into(); MAX_PROFILE_VALUES + 1],
            ..NodeProfile::default()
        };
        assert!(control
            .set_profile(
                oversized,
                draining.generation,
                "operator",
                "invalid profile",
            )
            .unwrap_err()
            .to_string()
            .contains("size limit"));
        assert_eq!(control.status().unwrap().generation, draining.generation);
    }

    #[test]
    fn persisted_identity_key_mismatch_fails_startup() {
        let store = Arc::new(SqliteContextManager::in_memory().unwrap());
        ClusterControl::new(store.clone()).unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE cluster_node_identity SET private_key = ?1 WHERE singleton = ?2",
                params![vec![0_u8; 32], SINGLETON],
            )
            .unwrap();
        assert!(ClusterControl::new(store)
            .err()
            .expect("corrupt private key must fail startup")
            .to_string()
            .contains("private key is invalid"));
    }

    fn member_registration(control: &ClusterControl, endpoint: &str) -> ClusterMemberRegistration {
        ClusterMemberRegistration {
            node_id: control.identity().node_id.clone(),
            fingerprint: control.identity().fingerprint.clone(),
            public_key: control.identity().public_key.clone(),
            tls_server_certificate_fingerprint: None,
            endpoint: endpoint.to_string(),
            server_version: "0.3.0-test".to_string(),
            min_protocol_version: 1,
            protocol_version: 2,
        }
    }

    fn sign_join(
        _authority: &ClusterControl,
        member: &ClusterControl,
        challenge: &ClusterJoinChallenge,
        registration: &ClusterMemberRegistration,
    ) -> String {
        let payload = membership_join_payload(
            &challenge.cluster_id,
            &challenge.challenge_hex,
            registration,
        )
        .unwrap();
        hex_encode(&member.sign_challenge(&payload).unwrap())
    }

    #[test]
    fn membership_join_leave_rejoin_and_revocation_are_fenced_and_audited() {
        let authority = ClusterControl::new(Arc::new(
            SqliteContextManager::in_memory().expect("authority store"),
        ))
        .expect("authority");
        let member = ClusterControl::new(Arc::new(
            SqliteContextManager::in_memory().expect("member store"),
        ))
        .expect("member");
        let registration = member_registration(&member, "127.0.0.1:7443");

        let challenge = authority.issue_join_challenge(30).unwrap();
        let signature = sign_join(&authority, &member, &challenge, &registration);
        let joined = authority
            .register_member(
                registration.clone(),
                &challenge.challenge_hex,
                &signature,
                None,
                1,
                2,
                "system",
                "initial admission",
            )
            .unwrap();
        assert_eq!(joined.state, ClusterMemberState::Active);
        assert_eq!(joined.generation, 1);
        let snapshot = authority.membership_snapshot().unwrap();
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.members, vec![joined.clone()]);

        let duplicate = ClusterControl::new(Arc::new(
            SqliteContextManager::in_memory().expect("duplicate store"),
        ))
        .expect("duplicate member");
        let duplicate_registration = member_registration(&duplicate, "127.0.0.1:7443");
        let duplicate_challenge = authority.issue_join_challenge(30).unwrap();
        let duplicate_signature = sign_join(
            &authority,
            &duplicate,
            &duplicate_challenge,
            &duplicate_registration,
        );
        assert!(authority
            .register_member(
                duplicate_registration,
                &duplicate_challenge.challenge_hex,
                &duplicate_signature,
                None,
                1,
                2,
                "system",
                "duplicate endpoint",
            )
            .unwrap_err()
            .to_string()
            .contains("already belongs"));

        assert!(authority
            .register_member(
                registration.clone(),
                &challenge.challenge_hex,
                &signature,
                Some(joined.generation),
                1,
                2,
                "system",
                "replay",
            )
            .unwrap_err()
            .to_string()
            .contains("already consumed"));

        let left = authority
            .set_member_state(
                &joined.node_id,
                ClusterMemberState::Left,
                joined.generation,
                "system",
                "maintenance",
            )
            .unwrap();
        assert_eq!(left.state, ClusterMemberState::Left);
        assert_eq!(left.generation, 2);
        assert!(authority
            .set_member_state(
                &joined.node_id,
                ClusterMemberState::Revoked,
                joined.generation,
                "stale",
                "stale write",
            )
            .unwrap_err()
            .to_string()
            .contains("revision conflict"));

        let rejoin_challenge = authority.issue_join_challenge(30).unwrap();
        let rejoin_signature = sign_join(&authority, &member, &rejoin_challenge, &registration);
        let rejoined = authority
            .register_member(
                registration.clone(),
                &rejoin_challenge.challenge_hex,
                &rejoin_signature,
                Some(left.generation),
                1,
                2,
                "system",
                "maintenance complete",
            )
            .unwrap();
        assert_eq!(rejoined.state, ClusterMemberState::Active);
        assert_eq!(rejoined.generation, 3);

        let revoked = authority
            .set_member_state(
                &rejoined.node_id,
                ClusterMemberState::Revoked,
                rejoined.generation,
                "security",
                "identity compromised",
            )
            .unwrap();
        assert_eq!(revoked.state, ClusterMemberState::Revoked);
        let revoked_challenge = authority.issue_join_challenge(30).unwrap();
        let revoked_signature = sign_join(&authority, &member, &revoked_challenge, &registration);
        assert!(authority
            .register_member(
                registration,
                &revoked_challenge.challenge_hex,
                &revoked_signature,
                Some(revoked.generation),
                1,
                2,
                "system",
                "attempt reactivation",
            )
            .unwrap_err()
            .to_string()
            .contains("cannot rejoin"));

        let audit = authority.membership_audit(10).unwrap();
        assert_eq!(audit.len(), 4);
        assert_eq!(audit[0].current, ClusterMemberState::Revoked);
        assert_eq!(audit[3].previous, None);
        assert_eq!(audit[3].current, ClusterMemberState::Active);
    }

    #[test]
    fn membership_rejects_expired_challenges_bad_proofs_and_version_skew() {
        let authority_store = Arc::new(SqliteContextManager::in_memory().unwrap());
        let authority = ClusterControl::new(authority_store.clone()).unwrap();
        let member = ClusterControl::new(Arc::new(SqliteContextManager::in_memory().unwrap()))
            .expect("member");
        let registration = member_registration(&member, "member.internal:7443");

        let challenge = authority.issue_join_challenge(30).unwrap();
        let signature = sign_join(&authority, &member, &challenge, &registration);
        authority_store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE cluster_join_challenges SET expires_at = ?1",
                [Utc::now()
                    .checked_sub_signed(chrono::Duration::seconds(1))
                    .unwrap()
                    .to_rfc3339()],
            )
            .unwrap();
        assert!(authority
            .register_member(
                registration.clone(),
                &challenge.challenge_hex,
                &signature,
                None,
                1,
                2,
                "system",
                "expired",
            )
            .unwrap_err()
            .to_string()
            .contains("expired"));

        let challenge = authority.issue_join_challenge(30).unwrap();
        assert!(authority
            .register_member(
                registration.clone(),
                &challenge.challenge_hex,
                &hex_encode(&[0_u8; 64]),
                None,
                1,
                2,
                "system",
                "bad proof",
            )
            .unwrap_err()
            .to_string()
            .contains("identity proof denied"));

        let challenge = authority.issue_join_challenge(30).unwrap();
        let mut incompatible = registration;
        incompatible.min_protocol_version = 3;
        incompatible.protocol_version = 4;
        let signature = sign_join(&authority, &member, &challenge, &incompatible);
        assert!(authority
            .register_member(
                incompatible,
                &challenge.challenge_hex,
                &signature,
                None,
                1,
                2,
                "system",
                "version skew",
            )
            .unwrap_err()
            .to_string()
            .contains("incompatible wire-protocol"));
        assert!(authority.membership_snapshot().unwrap().members.is_empty());
    }

    #[test]
    fn agent_ownership_tokens_are_monotonic_exact_and_audited() {
        let authority_store = Arc::new(SqliteContextManager::in_memory().unwrap());
        let authority = ClusterControl::new(authority_store.clone()).unwrap();
        let first = ClusterControl::new(Arc::new(SqliteContextManager::in_memory().unwrap()))
            .expect("first member");
        let second = ClusterControl::new(Arc::new(SqliteContextManager::in_memory().unwrap()))
            .expect("second member");
        for (member, endpoint) in [
            (&first, "first.internal:7443"),
            (&second, "second.internal:7443"),
        ] {
            let registration = member_registration(member, endpoint);
            let challenge = authority.issue_join_challenge(30).unwrap();
            let signature = sign_join(&authority, member, &challenge, &registration);
            authority
                .register_member(
                    registration,
                    &challenge.challenge_hex,
                    &signature,
                    None,
                    1,
                    2,
                    "system",
                    "ownership fixture member",
                )
                .unwrap();
        }

        let agent_id = uuid::Uuid::new_v4().to_string();
        assert!(authority
            .claim_agent_ownership(
                &agent_id,
                &first.identity().node_id,
                MIN_OWNERSHIP_LEASE_TTL_SECONDS - 1,
                None,
                "scheduler",
                "invalid TTL",
            )
            .unwrap_err()
            .to_string()
            .contains("ownership TTL"));

        let claimed = authority
            .claim_agent_ownership(
                &agent_id,
                &first.identity().node_id,
                30,
                None,
                "scheduler",
                "initial placement",
            )
            .unwrap();
        assert_eq!(claimed.fencing_token, 1);
        assert_eq!(claimed.generation, 1);
        assert_eq!(claimed.state, ClusterOwnershipState::Active);
        assert_eq!(
            authority
                .agent_ownership_with_active_requirement(&agent_id, true)
                .unwrap(),
            Some(claimed.clone())
        );
        assert!(authority
            .claim_agent_ownership(
                &agent_id,
                &second.identity().node_id,
                30,
                Some(claimed.fencing_token),
                "scheduler",
                "premature transfer",
            )
            .unwrap_err()
            .to_string()
            .contains("has not expired"));
        assert!(authority
            .renew_agent_ownership(
                &agent_id,
                &second.identity().node_id,
                claimed.fencing_token,
                30,
                "scheduler",
                "wrong owner",
            )
            .unwrap_err()
            .to_string()
            .contains("fencing conflict"));

        let renewed = authority
            .renew_agent_ownership(
                &agent_id,
                &first.identity().node_id,
                claimed.fencing_token,
                30,
                "scheduler",
                "heartbeat",
            )
            .unwrap();
        assert_eq!(renewed.fencing_token, claimed.fencing_token);
        assert_eq!(renewed.generation, 2);

        let released = authority
            .release_agent_ownership(
                &agent_id,
                &first.identity().node_id,
                renewed.fencing_token,
                "scheduler",
                "drained",
            )
            .unwrap();
        assert_eq!(released.state, ClusterOwnershipState::Released);
        assert_eq!(released.fencing_token, 1);
        assert_eq!(released.generation, 3);
        assert!(authority
            .agent_ownership_with_active_requirement(&agent_id, true)
            .unwrap_err()
            .to_string()
            .contains("released or expired"));
        assert!(authority
            .renew_agent_ownership(
                &agent_id,
                &first.identity().node_id,
                released.fencing_token,
                30,
                "scheduler",
                "stale renewal",
            )
            .unwrap_err()
            .to_string()
            .contains("fencing conflict"));

        let transferred = authority
            .claim_agent_ownership(
                &agent_id,
                &second.identity().node_id,
                30,
                Some(released.fencing_token),
                "scheduler",
                "placement transfer",
            )
            .unwrap();
        authority_store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE cluster_agent_ownership
                 SET lease_expires_at = ?1
                 WHERE agent_id = ?2",
                params![
                    (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339(),
                    agent_id
                ],
            )
            .unwrap();
        assert!(authority
            .agent_ownership_with_active_requirement(&agent_id, true)
            .unwrap_err()
            .to_string()
            .contains("released or expired"));
        assert!(authority.agent_ownership(&agent_id).unwrap().is_some());
        assert_eq!(transferred.fencing_token, 2);
        assert_eq!(transferred.generation, 4);
        let reclaimed = authority
            .claim_agent_ownership(
                &agent_id,
                &first.identity().node_id,
                30,
                Some(transferred.fencing_token),
                "recovery",
                "expired owner recovery",
            )
            .unwrap();
        assert_eq!(reclaimed.fencing_token, 3);
        assert_eq!(reclaimed.generation, 5);
        let mut directory_ids = vec![agent_id.clone()];
        for _ in 0..2 {
            let extra_agent_id = uuid::Uuid::new_v4().to_string();
            authority
                .claim_agent_ownership(
                    &extra_agent_id,
                    &first.identity().node_id,
                    30,
                    None,
                    "scheduler",
                    "directory pagination fixture",
                )
                .unwrap();
            directory_ids.push(extra_agent_id);
        }
        directory_ids.sort();
        let first_page = authority.agent_ownerships(None, 2).unwrap();
        assert_eq!(
            first_page
                .iter()
                .map(|ownership| ownership.agent_id.as_str())
                .collect::<Vec<_>>(),
            directory_ids[..2]
        );
        let second_page = authority
            .agent_ownerships(Some(&first_page[1].agent_id), 2)
            .unwrap();
        assert_eq!(
            second_page
                .iter()
                .map(|ownership| ownership.agent_id.as_str())
                .collect::<Vec<_>>(),
            vec![directory_ids[2].as_str()]
        );
        assert!(authority
            .agent_ownerships(Some("not-a-uuid"), 10)
            .unwrap_err()
            .to_string()
            .contains("invalid ownership page cursor"));
        let first_member = authority
            .membership_snapshot()
            .unwrap()
            .members
            .into_iter()
            .find(|member| member.node_id == first.identity().node_id)
            .unwrap();
        assert!(authority
            .set_member_state(
                &first_member.node_id,
                ClusterMemberState::Left,
                first_member.generation,
                "scheduler",
                "unsafe leave",
            )
            .unwrap_err()
            .to_string()
            .contains("ownership leases must be released"));
        authority
            .set_member_state(
                &first_member.node_id,
                ClusterMemberState::Revoked,
                first_member.generation,
                "security",
                "compromised owner",
            )
            .unwrap();
        let revoked_ownership = authority.agent_ownership(&agent_id).unwrap().unwrap();
        assert_eq!(revoked_ownership.state, ClusterOwnershipState::Released);
        assert_eq!(revoked_ownership.fencing_token, reclaimed.fencing_token);
        assert_eq!(revoked_ownership.generation, 6);

        let audit = authority
            .agent_ownership_audit(Some(&agent_id), 10)
            .unwrap();
        assert_eq!(audit.len(), 6);
        assert_eq!(
            authority
                .agent_ownership_audit(None, 10)
                .unwrap()
                .iter()
                .filter(|entry| entry.agent_id == agent_id)
                .count(),
            6
        );
        assert_eq!(
            audit
                .iter()
                .map(|entry| entry.operation.as_str())
                .collect::<Vec<_>>(),
            vec!["release", "transfer", "transfer", "release", "renew", "claim"]
        );
        assert_eq!(audit[0].fencing_token, revoked_ownership.fencing_token);
        assert_eq!(
            ClusterControl::new(authority_store)
                .unwrap()
                .agent_ownership(&agent_id)
                .unwrap(),
            Some(revoked_ownership)
        );
    }
}
