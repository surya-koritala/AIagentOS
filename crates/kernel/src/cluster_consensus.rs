//! Durable consensus storage for the distributed control plane.
//!
//! This module implements OpenRaft's storage-v2 contracts inside the kernel's
//! existing SQLite durability boundary. The authenticated peer transport and
//! executable election runtime live in `cluster_runtime`. When the operator
//! enables that runtime, this deterministic state machine is the authority for
//! public membership and ownership mutations and snapshots.

// OpenRaft's required StorageError is intentionally larger than Clippy's
// generic Result threshold. Storage-v2 implementations cannot replace or box
// that public trait error.
#![allow(clippy::result_large_err)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug};
use std::io::{self, Cursor};
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use openraft::storage::{LogFlushed, LogState, RaftLogStorage, RaftStateMachine, Snapshot};
use openraft::{
    AnyError, Entry, EntryPayload, LogId, OptionalSend, RaftLogReader, RaftSnapshotBuilder,
    SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cluster_control::{
    hex_decode, membership_join_payload, ownership_expiry, sha256_hex,
    validate_member_registration, validate_ownership_identity, validate_ownership_request,
    validate_reason, validate_text, ClusterAgentOwnership, ClusterAgentOwnershipAudit,
    ClusterCertificateRollout, ClusterCertificateRolloutAudit, ClusterCertificateRolloutPhase,
    ClusterControl, ClusterJoinChallenge, ClusterMember, ClusterMemberRegistration,
    ClusterMemberState, ClusterMembershipAudit, ClusterMembershipSnapshot, ClusterOwnershipState,
    MAX_CERTIFICATE_ROLLOUT_SECONDS, MAX_JOIN_CHALLENGE_TTL_SECONDS,
    MIN_CERTIFICATE_ROLLOUT_SECONDS, MIN_JOIN_CHALLENGE_TTL_SECONDS,
};
use crate::context::SqliteContextManager;

/// Stable numeric identifier used by the Raft protocol.
pub type ClusterRaftNodeId = u64;

/// Authenticated connection metadata that will be consumed by the peer
/// transport slice. Persisting it in membership entries makes endpoint and
/// identity changes quorum-versioned instead of out-of-band configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRaftNode {
    /// TLS endpoint advertised for Raft RPCs.
    pub endpoint: String,
    /// DNS name expected in the peer certificate.
    pub server_name: String,
    /// Lowercase SHA-256 fingerprint of the exact accepted server leaf.
    pub tls_certificate_sha256: String,
    /// Lowercase SHA-256 fingerprint of the exact accepted client leaf.
    ///
    /// This is separate from the server fingerprint so operators can use
    /// least-privilege certificates with distinct server-auth and client-auth
    /// extended key usages. Older durable membership values deserialize this
    /// as empty and remain valid storage, but the live peer runtime rejects an
    /// empty fingerprint.
    #[serde(default)]
    pub tls_client_certificate_sha256: String,
    /// Additional exact server leaves accepted during the current
    /// transport-trust overlap generation.
    #[serde(default)]
    pub tls_certificate_sha256_overlap: Vec<String>,
    /// Additional exact client leaves accepted during the current
    /// transport-trust overlap generation.
    #[serde(default)]
    pub tls_client_certificate_sha256_overlap: Vec<String>,
    /// Base64 or PEM encoded Ed25519 membership identity public key.
    pub identity_public_key: String,
    /// Lowercase SHA-256 digest of the complete, generation-fenced Raft
    /// transport catalog. This separates voter changes from peer trust
    /// changes: every voter generation must retain the same catalog digest,
    /// while a dedicated trust generation may replace it exactly once.
    ///
    /// Older durable memberships deserialize this as empty. The runtime
    /// accepts that legacy value only when the durable node map already
    /// exactly matches the operator catalog.
    #[serde(default)]
    pub transport_catalog_sha256: String,
    /// Monotonic generation of the peer catalog, leaf allowlists, and accepted
    /// CA roots. Generation zero is the legacy single-leaf catalog.
    #[serde(default)]
    pub transport_trust_generation: u64,
    /// Sorted exact fingerprints of every certificate accepted as a Raft trust
    /// anchor for this generation. Empty only for legacy generation zero.
    #[serde(default)]
    pub transport_peer_ca_sha256: Vec<String>,
    /// Absolute expiration for overlap leaves/roots in this trust generation.
    /// It is part of the catalog digest and is enforced on every connection.
    #[serde(default)]
    pub transport_trust_overlap_not_after: Option<chrono::DateTime<chrono::Utc>>,
    /// Monotonic voter-set generation carried by every node record while a
    /// quorum change is prepared or active. Generation zero and an empty
    /// digest preserve compatibility with memberships written before dynamic
    /// voter reconfiguration existed.
    #[serde(default)]
    pub voter_set_generation: u64,
    /// Lowercase SHA-256 digest of the exact target voter ids for
    /// `voter_set_generation`. Persisting the intent in OpenRaft membership
    /// lets a new leader resume a crash-interrupted joint-consensus change
    /// without accepting a conflicting operator target.
    #[serde(default)]
    pub voter_set_sha256: String,
}

/// Canonical application-level member seeded into a new authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityGenesisMember {
    pub node_id: String,
    pub fingerprint: String,
    pub public_key: String,
    #[serde(default)]
    pub tls_server_certificate_fingerprint: Option<String>,
    pub endpoint: String,
    pub server_version: String,
    pub min_protocol_version: u32,
    pub protocol_version: u32,
}

/// Identical immutable genesis document supplied at the first quorum bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityGenesis {
    pub cluster_id: String,
    pub members: Vec<AuthorityGenesisMember>,
}

/// Deterministic commands for the replicated membership and ownership
/// authority. Every command carries a caller-stable operation UUID. Mutations
/// also carry a proposed wall-clock value; the state machine converts it into
/// a monotonic replicated authority clock before evaluating expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityCommand {
    Initialize {
        operation_id: String,
        genesis: AuthorityGenesis,
        proposed_at: DateTime<Utc>,
    },
    /// Commit an idempotent sequencing barrier.
    Barrier {
        /// Canonical UUID identifying this logical operation across retries.
        operation_id: String,
        /// Optional compare-and-set against the current authority sequence.
        expected_sequence: Option<u64>,
    },
    /// Internal quorum-committed logical-clock advancement used before
    /// authority reads. It does not consume the bounded external-operation
    /// receipt map and is idempotent for an identical proposed timestamp.
    AdvanceTime {
        operation_id: String,
        proposed_at: DateTime<Utc>,
    },
    IssueJoinChallenge {
        operation_id: String,
        challenge_hex: String,
        ttl_seconds: u64,
        proposed_at: DateTime<Utc>,
    },
    RegisterMember {
        operation_id: String,
        registration: ClusterMemberRegistration,
        challenge_hex: String,
        signature_hex: String,
        expected_generation: Option<u64>,
        authority_min_protocol_version: u32,
        authority_protocol_version: u32,
        actor: String,
        reason: String,
        proposed_at: DateTime<Utc>,
    },
    PrepareMemberCertificateRollout {
        operation_id: String,
        registration: ClusterMemberRegistration,
        challenge_hex: String,
        signature_hex: String,
        expected_generation: u64,
        prepare_ttl_seconds: u64,
        minimum_overlap_seconds: u64,
        actor: String,
        reason: String,
        proposed_at: DateTime<Utc>,
    },
    AbortMemberCertificateRollout {
        operation_id: String,
        node_id: String,
        expected_generation: u64,
        actor: String,
        reason: String,
        proposed_at: DateTime<Utc>,
    },
    FinalizeMemberCertificateRollout {
        operation_id: String,
        node_id: String,
        expected_generation: u64,
        actor: String,
        reason: String,
        proposed_at: DateTime<Utc>,
    },
    SetMemberState {
        operation_id: String,
        node_id: String,
        state: ClusterMemberState,
        expected_generation: u64,
        actor: String,
        reason: String,
        proposed_at: DateTime<Utc>,
    },
    ClaimOwnership {
        operation_id: String,
        agent_id: String,
        owner_node_id: String,
        ttl_seconds: u64,
        expected_fencing_token: Option<u64>,
        actor: String,
        reason: String,
        proposed_at: DateTime<Utc>,
    },
    RenewOwnership {
        operation_id: String,
        agent_id: String,
        owner_node_id: String,
        fencing_token: u64,
        ttl_seconds: u64,
        actor: String,
        reason: String,
        proposed_at: DateTime<Utc>,
    },
    ReleaseOwnership {
        operation_id: String,
        agent_id: String,
        owner_node_id: String,
        fencing_token: u64,
        actor: String,
        reason: String,
        proposed_at: DateTime<Utc>,
    },
}

impl AuthorityCommand {
    fn operation_id(&self) -> &str {
        match self {
            Self::Initialize { operation_id, .. }
            | Self::Barrier { operation_id, .. }
            | Self::AdvanceTime { operation_id, .. }
            | Self::IssueJoinChallenge { operation_id, .. }
            | Self::RegisterMember { operation_id, .. }
            | Self::PrepareMemberCertificateRollout { operation_id, .. }
            | Self::AbortMemberCertificateRollout { operation_id, .. }
            | Self::FinalizeMemberCertificateRollout { operation_id, .. }
            | Self::SetMemberState { operation_id, .. }
            | Self::ClaimOwnership { operation_id, .. }
            | Self::RenewOwnership { operation_id, .. }
            | Self::ReleaseOwnership { operation_id, .. } => operation_id,
        }
    }
}

/// Deterministic state-machine rejection. Rejections are application results,
/// not Raft storage failures, and therefore remain identical on every replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRejection {
    InvalidOperationId,
    OperationIdConflict,
    SequenceMismatch,
    ReceiptCapacityReached,
    SequenceExhausted,
    NotInitialized,
    InvalidCommand,
    Conflict,
    CapacityReached,
}

/// Response returned when an authority log entry is applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityResponse {
    /// Blank and membership entries advance OpenRaft metadata only.
    MetadataApplied {
        sequence: u64,
        log_id: LogId<ClusterRaftNodeId>,
    },
    /// A new or idempotently replayed barrier is committed.
    BarrierCommitted {
        operation_id: String,
        sequence: u64,
        log_id: LogId<ClusterRaftNodeId>,
        replayed: bool,
    },
    /// The leader replicated a logical-clock floor before serving a read.
    AuthorityTimeAdvanced {
        operation_id: String,
        logical_time: DateTime<Utc>,
        log_id: LogId<ClusterRaftNodeId>,
    },
    ControlPlaneInitialized {
        operation_id: String,
        sequence: u64,
        log_id: LogId<ClusterRaftNodeId>,
        replayed: bool,
    },
    JoinChallengeIssued {
        operation_id: String,
        challenge: ClusterJoinChallenge,
        sequence: u64,
        log_id: LogId<ClusterRaftNodeId>,
        replayed: bool,
    },
    MemberUpdated {
        operation_id: String,
        member: ClusterMember,
        sequence: u64,
        log_id: LogId<ClusterRaftNodeId>,
        replayed: bool,
    },
    CertificateRolloutUpdated {
        operation_id: String,
        member: ClusterMember,
        rollout: Option<ClusterCertificateRollout>,
        sequence: u64,
        log_id: LogId<ClusterRaftNodeId>,
        replayed: bool,
    },
    OwnershipUpdated {
        operation_id: String,
        ownership: ClusterAgentOwnership,
        sequence: u64,
        log_id: LogId<ClusterRaftNodeId>,
        replayed: bool,
    },
    /// The command was committed by Raft but rejected by deterministic
    /// application validation.
    Rejected {
        operation_id: String,
        sequence: u64,
        log_id: LogId<ClusterRaftNodeId>,
        reason: AuthorityRejection,
        message: String,
    },
}

openraft::declare_raft_types!(
    /// OpenRaft type configuration for the cluster authority.
    pub ClusterRaftTypeConfig:
        D = AuthorityCommand,
        R = AuthorityResponse,
        NodeId = ClusterRaftNodeId,
        Node = ClusterRaftNode,
);

type ClusterEntry = Entry<ClusterRaftTypeConfig>;
type ClusterStorageResult<T> = Result<T, StorageError<ClusterRaftNodeId>>;
type SnapshotRecord = (SnapshotMeta<ClusterRaftNodeId, ClusterRaftNode>, Vec<u8>);

/// Maximum retained operation receipts in this first state-machine format.
///
/// Capacity exhaustion fails the application command closed. A later
/// replicated compaction command can advance a durable receipt floor without
/// allowing local replicas to prune independently.
pub const MAX_AUTHORITY_RECEIPTS: usize = 4_096;
const MAX_SNAPSHOT_ID_BYTES: usize = 255;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct AuthorityState {
    sequence: u64,
    receipts: BTreeMap<String, StoredAuthorityReceipt>,
    #[serde(default)]
    control_plane: Option<ReplicatedControlPlaneState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReplicatedJoinChallenge {
    challenge_hex: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReplicatedControlPlaneState {
    genesis: AuthorityGenesis,
    cluster_id: String,
    membership_generation: u64,
    members: BTreeMap<String, ClusterMember>,
    membership_audit: Vec<ClusterMembershipAudit>,
    #[serde(default)]
    tls_trust_generation: u64,
    #[serde(default)]
    certificate_rollouts: BTreeMap<String, ClusterCertificateRollout>,
    #[serde(default)]
    certificate_rollout_audit: Vec<ClusterCertificateRolloutAudit>,
    join_challenges: BTreeMap<String, ReplicatedJoinChallenge>,
    ownerships: BTreeMap<String, ClusterAgentOwnership>,
    ownership_audit: Vec<ClusterAgentOwnershipAudit>,
    logical_time: DateTime<Utc>,
}

type MembershipRevisionEvidence = (ClusterMemberState, Option<String>, DateTime<Utc>);
type CertificateRolloutAuditHead = (
    Option<ClusterCertificateRolloutPhase>,
    String,
    String,
    u64,
    u64,
    DateTime<Utc>,
    String,
);

/// Cloneable view read after an OpenRaft linearizability barrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicatedAuthorityView {
    pub genesis: AuthorityGenesis,
    pub membership: ClusterMembershipSnapshot,
    pub membership_audit: Vec<ClusterMembershipAudit>,
    pub certificate_rollout_audit: Vec<ClusterCertificateRolloutAudit>,
    pub ownerships: Vec<ClusterAgentOwnership>,
    pub ownership_audit: Vec<ClusterAgentOwnershipAudit>,
    pub logical_time: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredAuthorityReceipt {
    command: AuthorityCommand,
    response: AuthorityResponse,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PersistentState {
    last_applied: Option<LogId<ClusterRaftNodeId>>,
    membership: StoredMembership<ClusterRaftNodeId, ClusterRaftNode>,
    authority: AuthorityState,
    snapshot_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotState {
    last_applied: Option<LogId<ClusterRaftNodeId>>,
    membership: StoredMembership<ClusterRaftNodeId, ClusterRaftNode>,
    authority: AuthorityState,
}

impl From<&PersistentState> for SnapshotState {
    fn from(state: &PersistentState) -> Self {
        Self {
            last_applied: state.last_applied,
            membership: state.membership.clone(),
            authority: state.authority.clone(),
        }
    }
}

/// OpenRaft log/vote store backed by the shared kernel database.
#[derive(Clone)]
pub struct ClusterRaftLogStore {
    context: Arc<SqliteContextManager>,
}

/// OpenRaft state machine and snapshot store backed by the shared kernel
/// database.
#[derive(Clone)]
pub struct ClusterRaftStateMachine {
    context: Arc<SqliteContextManager>,
}

/// A frozen state-machine view used to create a consistent snapshot even if
/// later entries are applied concurrently.
pub struct ClusterRaftSnapshotBuilder {
    context: Arc<SqliteContextManager>,
    frozen: Result<PersistentState, String>,
}

/// Open and eagerly validate both halves of the durable consensus store.
///
/// Serialized corruption, an index/entry mismatch, or a malformed snapshot is
/// returned as a fatal OpenRaft storage error before a node can participate in
/// an election.
pub fn open_cluster_raft_storage(
    context: Arc<SqliteContextManager>,
) -> ClusterStorageResult<(ClusterRaftLogStore, ClusterRaftStateMachine)> {
    validate_store(&context)?;
    Ok((
        ClusterRaftLogStore {
            context: context.clone(),
        },
        ClusterRaftStateMachine { context },
    ))
}

/// Read the locally applied durable Raft membership before the network factory
/// is constructed. Callers use this only to preserve exact prior-catalog
/// identity checks during a generation-fenced transport-trust transition.
pub(crate) fn read_cluster_raft_membership(
    context: &SqliteContextManager,
) -> io::Result<StoredMembership<ClusterRaftNodeId, ClusterRaftNode>> {
    let connection = context
        .conn
        .lock()
        .map_err(|error| io::Error::other(format!("lock durable Raft membership: {error}")))?;
    let state = load_persistent_state(&connection)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    Ok(state.membership)
}

/// Read the locally applied replicated control-plane projection.
///
/// Callers serving external reads must first complete
/// `Raft::ensure_linearizable`; this function intentionally performs no
/// network operation and is also used to observe follower catch-up at startup.
pub fn read_replicated_authority_view(
    context: &SqliteContextManager,
) -> io::Result<Option<ReplicatedAuthorityView>> {
    let connection = context
        .conn
        .lock()
        .map_err(|error| io::Error::other(format!("lock replicated authority state: {error}")))?;
    let state = load_persistent_state(&connection)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let Some(control) = state.authority.control_plane else {
        return Ok(None);
    };
    Ok(Some(ReplicatedAuthorityView {
        genesis: control.genesis,
        membership: ClusterMembershipSnapshot {
            cluster_id: control.cluster_id,
            generation: control.membership_generation,
            authority_time: Some(control.logical_time),
            tls_trust_generation: control.tls_trust_generation,
            certificate_rollouts: control.certificate_rollouts.into_values().collect(),
            members: control.members.into_values().collect(),
        },
        membership_audit: control.membership_audit,
        certificate_rollout_audit: control.certificate_rollout_audit,
        ownerships: control.ownerships.into_values().collect(),
        ownership_audit: control.ownership_audit,
        logical_time: control.logical_time,
    }))
}

fn read_io(message: impl Into<String>) -> AnyError {
    AnyError::error(message.into())
}

fn index_blob(index: u64) -> [u8; 8] {
    index.to_be_bytes()
}

fn decode_index(bytes: &[u8]) -> Result<u64, AnyError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| read_io(format!("invalid Raft log index width {}", bytes.len())))?;
    Ok(u64::from_be_bytes(bytes))
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, AnyError> {
    serde_json::to_vec(value).map_err(|error| read_io(format!("serialize Raft value: {error}")))
}

fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, AnyError> {
    serde_json::from_slice(bytes)
        .map_err(|error| read_io(format!("decode durable {label}: {error}")))
}

fn read_meta<T: for<'de> Deserialize<'de>>(
    connection: &Connection,
    key: &str,
) -> Result<Option<T>, AnyError> {
    let bytes = connection
        .query_row(
            "SELECT value FROM cluster_raft_meta WHERE key = ?1",
            [key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|error| read_io(format!("read Raft metadata {key}: {error}")))?;
    bytes
        .map(|value| deserialize(&value, &format!("Raft metadata {key}")))
        .transpose()
}

fn write_meta<T: Serialize>(
    transaction: &Transaction<'_>,
    key: &str,
    value: &T,
) -> Result<(), AnyError> {
    let value = serialize(value)?;
    transaction
        .execute(
            "INSERT INTO cluster_raft_meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|error| read_io(format!("write Raft metadata {key}: {error}")))?;
    Ok(())
}

fn load_persistent_state(connection: &Connection) -> Result<PersistentState, AnyError> {
    let row = connection
        .query_row(
            "SELECT last_applied_json, membership_json, authority_state_json,
                    snapshot_sequence
             FROM cluster_raft_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|error| read_io(format!("read Raft state machine: {error}")))?;

    let Some((last_applied, membership, authority, snapshot_sequence)) = row else {
        return Ok(PersistentState::default());
    };
    let state = PersistentState {
        last_applied: last_applied
            .map(|value| deserialize(&value, "last applied log id"))
            .transpose()?,
        membership: deserialize(&membership, "stored membership")?,
        authority: deserialize(&authority, "authority state")?,
        snapshot_sequence: decode_index(&snapshot_sequence)?,
    };
    validate_persistent_state(&state)?;
    Ok(state)
}

fn write_persistent_state(
    transaction: &Transaction<'_>,
    state: &PersistentState,
) -> Result<(), AnyError> {
    validate_persistent_state(state)?;
    let last_applied = state.last_applied.as_ref().map(serialize).transpose()?;
    let membership = serialize(&state.membership)?;
    let authority = serialize(&state.authority)?;
    transaction
        .execute(
            "INSERT INTO cluster_raft_state(
                 singleton, last_applied_json, membership_json,
                 authority_state_json, snapshot_sequence
             ) VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET
                 last_applied_json = excluded.last_applied_json,
                 membership_json = excluded.membership_json,
                 authority_state_json = excluded.authority_state_json,
                 snapshot_sequence = excluded.snapshot_sequence",
            params![
                last_applied,
                membership,
                authority,
                index_blob(state.snapshot_sequence).as_slice()
            ],
        )
        .map_err(|error| read_io(format!("write Raft state machine: {error}")))?;
    Ok(())
}

fn validate_authority_state(state: &AuthorityState) -> Result<(), AnyError> {
    if state.receipts.len() > MAX_AUTHORITY_RECEIPTS {
        return Err(read_io(format!(
            "authority receipt count {} exceeds maximum {MAX_AUTHORITY_RECEIPTS}",
            state.receipts.len()
        )));
    }
    if state.sequence != state.receipts.len() as u64 {
        return Err(read_io(format!(
            "authority sequence {} does not match {} retained receipts",
            state.sequence,
            state.receipts.len()
        )));
    }
    let mut sequences = BTreeSet::new();
    let mut log_ids = BTreeSet::new();
    for (operation_id, receipt) in &state.receipts {
        let command_id = receipt.command.operation_id();
        if operation_id != command_id || canonical_operation_id(operation_id).is_none() {
            return Err(read_io(format!(
                "authority receipt key {operation_id:?} does not match a canonical command id"
            )));
        }
        let Some((response_id, sequence, log_id, replayed)) =
            successful_response_metadata(&receipt.response)
        else {
            return Err(read_io(format!(
                "authority receipt {operation_id} does not contain a successful response"
            )));
        };
        let expected_sequence_matches = match &receipt.command {
            AuthorityCommand::Barrier {
                expected_sequence, ..
            } => expected_sequence.is_none_or(|expected| expected == sequence - 1),
            _ => true,
        };
        if response_id != operation_id
            || replayed
            || sequence == 0
            || sequence > state.sequence
            || !expected_sequence_matches
            || !response_matches_command(&receipt.command, &receipt.response)
            || !sequences.insert(sequence)
            || !log_ids.insert(log_id)
        {
            return Err(read_io(format!(
                "authority receipt {operation_id} contains an inconsistent response"
            )));
        }
    }
    if let Some(control) = &state.control_plane {
        validate_control_plane_state(control)?;
    }
    Ok(())
}

fn successful_response_metadata(
    response: &AuthorityResponse,
) -> Option<(&str, u64, LogId<ClusterRaftNodeId>, bool)> {
    match response {
        AuthorityResponse::BarrierCommitted {
            operation_id,
            sequence,
            log_id,
            replayed,
        }
        | AuthorityResponse::ControlPlaneInitialized {
            operation_id,
            sequence,
            log_id,
            replayed,
        }
        | AuthorityResponse::JoinChallengeIssued {
            operation_id,
            sequence,
            log_id,
            replayed,
            ..
        }
        | AuthorityResponse::MemberUpdated {
            operation_id,
            sequence,
            log_id,
            replayed,
            ..
        }
        | AuthorityResponse::CertificateRolloutUpdated {
            operation_id,
            sequence,
            log_id,
            replayed,
            ..
        }
        | AuthorityResponse::OwnershipUpdated {
            operation_id,
            sequence,
            log_id,
            replayed,
            ..
        } => Some((operation_id, *sequence, *log_id, *replayed)),
        AuthorityResponse::MetadataApplied { .. }
        | AuthorityResponse::AuthorityTimeAdvanced { .. }
        | AuthorityResponse::Rejected { .. } => None,
    }
}

fn response_matches_command(command: &AuthorityCommand, response: &AuthorityResponse) -> bool {
    matches!(
        (command, response),
        (
            AuthorityCommand::Initialize { .. },
            AuthorityResponse::ControlPlaneInitialized { .. }
        ) | (
            AuthorityCommand::Barrier { .. },
            AuthorityResponse::BarrierCommitted { .. }
        ) | (
            AuthorityCommand::AdvanceTime { .. },
            AuthorityResponse::AuthorityTimeAdvanced { .. }
        ) | (
            AuthorityCommand::IssueJoinChallenge { .. },
            AuthorityResponse::JoinChallengeIssued { .. }
        ) | (
            AuthorityCommand::RegisterMember { .. } | AuthorityCommand::SetMemberState { .. },
            AuthorityResponse::MemberUpdated { .. }
        ) | (
            AuthorityCommand::PrepareMemberCertificateRollout { .. }
                | AuthorityCommand::AbortMemberCertificateRollout { .. }
                | AuthorityCommand::FinalizeMemberCertificateRollout { .. },
            AuthorityResponse::CertificateRolloutUpdated { .. }
        ) | (
            AuthorityCommand::ClaimOwnership { .. }
                | AuthorityCommand::RenewOwnership { .. }
                | AuthorityCommand::ReleaseOwnership { .. },
            AuthorityResponse::OwnershipUpdated { .. }
        )
    )
}

fn validate_control_plane_state(control: &ReplicatedControlPlaneState) -> Result<(), AnyError> {
    validate_and_build_genesis(&control.genesis, control.logical_time).map_err(
        |(_, message)| read_io(format!("invalid immutable authority genesis: {message}")),
    )?;
    if control.genesis.cluster_id != control.cluster_id {
        return Err(read_io(
            "immutable authority genesis cluster id differs from live authority state",
        ));
    }
    let cluster_id = Uuid::parse_str(&control.cluster_id)
        .map_err(|_| read_io("replicated authority cluster id is invalid"))?;
    if cluster_id.to_string() != control.cluster_id {
        return Err(read_io("replicated authority cluster id is not canonical"));
    }
    if control.membership_generation != control.membership_audit.len() as u64 {
        return Err(read_io(
            "replicated membership generation does not match its audit length",
        ));
    }
    if control.join_challenges.len() > 4_096
        || control.members.len() > 100_000
        || control.certificate_rollouts.len() > control.members.len()
        || control.ownerships.len() > 1_000_000
        || control.membership_audit.len() > 100_000
        || control.certificate_rollout_audit.len() > 100_000
        || control.ownership_audit.len() > 100_000
    {
        return Err(read_io(
            "replicated authority state exceeds a configured hard capacity",
        ));
    }
    let authority_started_at = control
        .membership_audit
        .first()
        .map(|audit| audit.changed_at)
        .ok_or_else(|| read_io("replicated authority has no genesis audit"))?;
    for (challenge_hash, challenge) in &control.join_challenges {
        let challenge_bytes = hex_decode(&challenge.challenge_hex)
            .filter(|bytes| bytes.len() == 32)
            .ok_or_else(|| read_io("replicated join challenge is invalid"))?;
        if sha256_hex(&challenge_bytes) != *challenge_hash
            || challenge.expires_at <= authority_started_at
            || challenge.consumed_at.is_some_and(|consumed| {
                consumed > control.logical_time || consumed >= challenge.expires_at
            })
        {
            return Err(read_io(
                "replicated join challenge contains invalid hash or timestamps",
            ));
        }
    }
    let valid_tls_fingerprint = |fingerprint: &str| {
        fingerprint.len() == 64
            && fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    };
    let mut historical_tls_owners = BTreeMap::<String, String>::new();
    let mut latest_membership_audit: BTreeMap<String, (u64, ClusterMemberState, Option<String>)> =
        BTreeMap::new();
    let mut membership_revision_audit: BTreeMap<(String, u64), MembershipRevisionEvidence> =
        BTreeMap::new();
    let mut first_membership_tls_revision = BTreeMap::<String, (String, u64, DateTime<Utc>)>::new();
    for (index, audit) in control.membership_audit.iter().enumerate() {
        let expected_global_generation = index as u64 + 1;
        if audit.membership_generation != expected_global_generation
            || audit.member_generation == 0
            || audit.changed_at > control.logical_time
            || Uuid::parse_str(&audit.node_id).is_err()
            || validate_text(&audit.actor, "replicated membership audit actor").is_err()
            || validate_reason(&audit.reason).is_err()
        {
            return Err(read_io("replicated membership audit entry is invalid"));
        }
        let previous = latest_membership_audit.get(&audit.node_id);
        let transition_is_valid = match previous {
            None => {
                audit.member_generation == 1
                    && audit.previous.is_none()
                    && audit.current == ClusterMemberState::Active
                    && audit.previous_tls_server_certificate_fingerprint.is_none()
            }
            Some((generation, state, tls_fingerprint)) => {
                *state != ClusterMemberState::Revoked
                    && generation.checked_add(1) == Some(audit.member_generation)
                    && audit.previous == Some(*state)
                    && audit.previous_tls_server_certificate_fingerprint == *tls_fingerprint
                    && !(tls_fingerprint.is_some()
                        && audit.current_tls_server_certificate_fingerprint.is_none())
            }
        };
        if !transition_is_valid {
            return Err(read_io(
                "replicated membership audit history is not consecutive",
            ));
        }
        for fingerprint in [
            audit.previous_tls_server_certificate_fingerprint.as_deref(),
            audit.current_tls_server_certificate_fingerprint.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !valid_tls_fingerprint(fingerprint)
                || historical_tls_owners
                    .insert(fingerprint.to_owned(), audit.node_id.clone())
                    .is_some_and(|owner| owner != audit.node_id)
            {
                return Err(read_io(
                    "replicated membership audit reuses an invalid or foreign TLS binding",
                ));
            }
        }
        latest_membership_audit.insert(
            audit.node_id.clone(),
            (
                audit.member_generation,
                audit.current,
                audit.current_tls_server_certificate_fingerprint.clone(),
            ),
        );
        if let Some(fingerprint) = &audit.current_tls_server_certificate_fingerprint {
            first_membership_tls_revision
                .entry(fingerprint.clone())
                .or_insert_with(|| {
                    (
                        audit.node_id.clone(),
                        audit.member_generation,
                        audit.changed_at,
                    )
                });
        }
        membership_revision_audit.insert(
            (audit.node_id.clone(), audit.member_generation),
            (
                audit.current,
                audit.current_tls_server_certificate_fingerprint.clone(),
                audit.changed_at,
            ),
        );
    }
    let mut member_fingerprints = BTreeSet::new();
    let mut member_endpoints = BTreeSet::new();
    let mut member_tls_fingerprints = BTreeSet::new();
    for (node_id, member) in &control.members {
        if node_id != &member.node_id {
            return Err(read_io("replicated member map key does not match node id"));
        }
        validate_member_registration(&ClusterMemberRegistration {
            node_id: member.node_id.clone(),
            fingerprint: member.fingerprint.clone(),
            public_key: member.public_key.clone(),
            tls_server_certificate_fingerprint: member.tls_server_certificate_fingerprint.clone(),
            endpoint: member.endpoint.clone(),
            server_version: member.server_version.clone(),
            min_protocol_version: member.min_protocol_version,
            protocol_version: member.protocol_version,
        })
        .map_err(|error| read_io(error.to_string()))?;
        if !member_fingerprints.insert(member.fingerprint.as_str())
            || !member_endpoints.insert(member.endpoint.as_str())
            || member
                .tls_server_certificate_fingerprint
                .as_deref()
                .is_some_and(|fingerprint| !member_tls_fingerprints.insert(fingerprint))
        {
            return Err(read_io(
                "replicated membership contains a duplicate identity, endpoint, or TLS binding",
            ));
        }
        if member.generation == 0
            || member.joined_at > member.updated_at
            || member.updated_at > control.logical_time
        {
            return Err(read_io(
                "replicated member contains invalid generation or time",
            ));
        }
        if latest_membership_audit.get(node_id)
            != Some(&(
                member.generation,
                member.state,
                member.tls_server_certificate_fingerprint.clone(),
            ))
        {
            return Err(read_io(
                "replicated member does not match its latest audit evidence",
            ));
        }
    }
    if latest_membership_audit.len() != control.members.len() {
        return Err(read_io(
            "replicated membership audit references an unknown member",
        ));
    }
    if control.tls_trust_generation != control.certificate_rollout_audit.len() as u64 {
        return Err(read_io(
            "replicated TLS trust generation does not match its audit length",
        ));
    }
    let mut seen_rollout_candidates = BTreeSet::new();
    let mut first_rollout_activation = BTreeMap::<String, (String, u64, DateTime<Utc>)>::new();
    let mut latest_rollout_audit: BTreeMap<String, CertificateRolloutAuditHead> = BTreeMap::new();
    for (index, audit) in control.certificate_rollout_audit.iter().enumerate() {
        let expected_trust_generation = index as u64 + 1;
        let transition_is_valid = match latest_rollout_audit.get(&audit.node_id) {
            None | Some((None, ..)) => {
                audit.previous_phase.is_none()
                    && audit.current_phase == Some(ClusterCertificateRolloutPhase::Prepared)
                    && seen_rollout_candidates
                        .insert(audit.next_tls_server_certificate_fingerprint.clone())
            }
            Some((
                Some(ClusterCertificateRolloutPhase::Prepared),
                previous_fingerprint,
                next_fingerprint,
                ..,
            )) => {
                audit.previous_phase == Some(ClusterCertificateRolloutPhase::Prepared)
                    && matches!(
                        audit.current_phase,
                        Some(ClusterCertificateRolloutPhase::Activated) | None
                    )
                    && &audit.previous_tls_server_certificate_fingerprint == previous_fingerprint
                    && &audit.next_tls_server_certificate_fingerprint == next_fingerprint
            }
            Some((
                Some(ClusterCertificateRolloutPhase::Activated),
                previous_fingerprint,
                next_fingerprint,
                ..,
            )) => {
                audit.previous_phase == Some(ClusterCertificateRolloutPhase::Activated)
                    && audit.current_phase.is_none()
                    && &audit.previous_tls_server_certificate_fingerprint == previous_fingerprint
                    && &audit.next_tls_server_certificate_fingerprint == next_fingerprint
            }
        };
        let expected_member_tls = match (audit.previous_phase, audit.current_phase) {
            (_, Some(ClusterCertificateRolloutPhase::Prepared))
            | (Some(ClusterCertificateRolloutPhase::Prepared), None) => {
                Some(audit.previous_tls_server_certificate_fingerprint.as_str())
            }
            (_, Some(ClusterCertificateRolloutPhase::Activated))
            | (Some(ClusterCertificateRolloutPhase::Activated), None) => {
                Some(audit.next_tls_server_certificate_fingerprint.as_str())
            }
            _ => None,
        };
        let member_revision =
            membership_revision_audit.get(&(audit.node_id.clone(), audit.member_generation));
        let revision_matches = member_revision.is_some_and(|(state, tls, changed_at)| {
            (*state == ClusterMemberState::Active
                || (audit.current_phase.is_none() && *state == ClusterMemberState::Revoked))
                && tls.as_deref() == expected_member_tls
                && *changed_at == audit.changed_at
        });
        if audit.trust_generation != expected_trust_generation
            || audit.member_generation == 0
            || audit.changed_at > control.logical_time
            || Uuid::parse_str(&audit.node_id).is_err()
            || !valid_tls_fingerprint(&audit.previous_tls_server_certificate_fingerprint)
            || !valid_tls_fingerprint(&audit.next_tls_server_certificate_fingerprint)
            || audit.previous_tls_server_certificate_fingerprint
                == audit.next_tls_server_certificate_fingerprint
            || validate_text(&audit.actor, "replicated certificate rollout audit actor").is_err()
            || validate_reason(&audit.reason).is_err()
            || !transition_is_valid
            || !revision_matches
            || historical_tls_owners
                .get(&audit.previous_tls_server_certificate_fingerprint)
                .is_some_and(|owner| owner != &audit.node_id)
            || historical_tls_owners
                .get(&audit.next_tls_server_certificate_fingerprint)
                .is_some_and(|owner| owner != &audit.node_id)
        {
            return Err(read_io(
                "replicated certificate rollout audit history is invalid",
            ));
        }
        historical_tls_owners.insert(
            audit.previous_tls_server_certificate_fingerprint.clone(),
            audit.node_id.clone(),
        );
        historical_tls_owners.insert(
            audit.next_tls_server_certificate_fingerprint.clone(),
            audit.node_id.clone(),
        );
        if audit.current_phase == Some(ClusterCertificateRolloutPhase::Activated)
            && first_rollout_activation
                .insert(
                    audit.next_tls_server_certificate_fingerprint.clone(),
                    (
                        audit.node_id.clone(),
                        audit.member_generation,
                        audit.changed_at,
                    ),
                )
                .is_some()
        {
            return Err(read_io(
                "replicated certificate rollout candidate has multiple activations",
            ));
        }
        latest_rollout_audit.insert(
            audit.node_id.clone(),
            (
                audit.current_phase,
                audit.previous_tls_server_certificate_fingerprint.clone(),
                audit.next_tls_server_certificate_fingerprint.clone(),
                audit.member_generation,
                audit.trust_generation,
                audit.changed_at,
                audit.reason.clone(),
            ),
        );
    }
    if seen_rollout_candidates.iter().any(|candidate| {
        match (
            first_membership_tls_revision.get(candidate),
            first_rollout_activation.get(candidate),
        ) {
            (None, None) => false,
            (Some(first_authorized), Some(activated)) => first_authorized != activated,
            _ => true,
        }
    }) {
        return Err(read_io(
            "replicated certificate rollout candidate was authorized before its activation",
        ));
    }
    for (node_id, rollout) in &control.certificate_rollouts {
        let member = control.members.get(node_id);
        let latest = latest_rollout_audit.get(node_id);
        let prepare_window_is_valid = rollout
            .prepared_at
            .checked_add_signed(TimeDelta::seconds(MIN_CERTIFICATE_ROLLOUT_SECONDS as i64))
            .is_some_and(|minimum| rollout.prepare_expires_at >= minimum)
            && rollout
                .prepared_at
                .checked_add_signed(TimeDelta::seconds(MAX_CERTIFICATE_ROLLOUT_SECONDS as i64))
                .is_some_and(|maximum| rollout.prepare_expires_at <= maximum);
        let retirement_is_valid = match rollout.phase {
            ClusterCertificateRolloutPhase::Prepared => {
                rollout.retire_previous_after.is_none()
                    && rollout.updated_at == rollout.prepared_at
                    && member
                        .and_then(|member| member.tls_server_certificate_fingerprint.as_deref())
                        == Some(rollout.previous_tls_server_certificate_fingerprint.as_str())
            }
            ClusterCertificateRolloutPhase::Activated => {
                rollout.retire_previous_after.is_some_and(|deadline| {
                    rollout.updated_at.checked_add_signed(TimeDelta::seconds(
                        rollout.minimum_overlap_seconds as i64,
                    )) == Some(deadline)
                }) && member.and_then(|member| member.tls_server_certificate_fingerprint.as_deref())
                    == Some(rollout.next_tls_server_certificate_fingerprint.as_str())
            }
        };
        if node_id != &rollout.node_id
            || member.is_none_or(|member| {
                member.state != ClusterMemberState::Active
                    || member.generation != rollout.member_generation
            })
            || rollout.trust_generation == 0
            || rollout.minimum_overlap_seconds < MIN_CERTIFICATE_ROLLOUT_SECONDS
            || rollout.minimum_overlap_seconds > MAX_CERTIFICATE_ROLLOUT_SECONDS
            || !prepare_window_is_valid
            || rollout.prepared_at > rollout.updated_at
            || rollout.updated_at > control.logical_time
            || !valid_tls_fingerprint(&rollout.previous_tls_server_certificate_fingerprint)
            || !valid_tls_fingerprint(&rollout.next_tls_server_certificate_fingerprint)
            || rollout.previous_tls_server_certificate_fingerprint
                == rollout.next_tls_server_certificate_fingerprint
            || validate_reason(&rollout.reason).is_err()
            || !retirement_is_valid
            || latest
                != Some(&(
                    Some(rollout.phase),
                    rollout.previous_tls_server_certificate_fingerprint.clone(),
                    rollout.next_tls_server_certificate_fingerprint.clone(),
                    rollout.member_generation,
                    rollout.trust_generation,
                    rollout.updated_at,
                    rollout.reason.clone(),
                ))
        {
            return Err(read_io(
                "replicated certificate rollout does not match current member and audit state",
            ));
        }
    }
    if latest_rollout_audit.iter().any(|(node_id, (phase, ..))| {
        phase.is_some() != control.certificate_rollouts.contains_key(node_id)
    }) {
        return Err(read_io(
            "replicated certificate rollout audit references inconsistent live state",
        ));
    }
    let mut latest_ownership_audit: BTreeMap<
        String,
        (u64, String, u64, u64, ClusterOwnershipState),
    > = BTreeMap::new();
    for audit in &control.ownership_audit {
        if audit.generation == 0
            || audit.authority_term == 0
            || audit.fencing_token == 0
            || audit.changed_at > control.logical_time
            || validate_ownership_identity(&audit.agent_id, &audit.owner_node_id).is_err()
            || audit
                .previous_owner_node_id
                .as_deref()
                .is_some_and(|owner| Uuid::parse_str(owner).is_err())
            || validate_text(&audit.actor, "replicated ownership audit actor").is_err()
            || validate_reason(&audit.reason).is_err()
        {
            return Err(read_io("replicated ownership audit entry is invalid"));
        }
        let state = match audit.operation.as_str() {
            "claim" | "transfer" | "renew" => ClusterOwnershipState::Active,
            "release" => ClusterOwnershipState::Released,
            _ => return Err(read_io("replicated ownership audit operation is invalid")),
        };
        let previous = latest_ownership_audit.get(&audit.agent_id);
        let history_is_valid = match previous {
            None => {
                audit.operation == "claim"
                    && audit.generation == 1
                    && audit.fencing_token == 1
                    && audit.previous_owner_node_id.is_none()
            }
            Some((generation, owner, authority_term, fencing_token, previous_state)) => {
                let common = generation.checked_add(1) == Some(audit.generation)
                    && audit.previous_owner_node_id.as_ref() == Some(owner)
                    && audit.authority_term >= *authority_term;
                common
                    && match audit.operation.as_str() {
                        "renew" => {
                            *previous_state == ClusterOwnershipState::Active
                                && audit.owner_node_id == *owner
                                && audit.fencing_token == *fencing_token
                        }
                        "release" => {
                            *previous_state == ClusterOwnershipState::Active
                                && audit.owner_node_id == *owner
                                && audit.fencing_token == *fencing_token
                        }
                        "transfer" => fencing_token.checked_add(1) == Some(audit.fencing_token),
                        _ => false,
                    }
            }
        };
        if !history_is_valid {
            return Err(read_io(
                "replicated ownership audit history is not consecutive",
            ));
        }
        latest_ownership_audit.insert(
            audit.agent_id.clone(),
            (
                audit.generation,
                audit.owner_node_id.clone(),
                audit.authority_term,
                audit.fencing_token,
                state,
            ),
        );
    }
    for (agent_id, ownership) in &control.ownerships {
        if agent_id != &ownership.agent_id
            || ownership.generation == 0
            || ownership.authority_term == 0
            || ownership.fencing_token == 0
            || ownership.updated_at > control.logical_time
        {
            return Err(read_io(
                "replicated ownership map contains invalid identity, generation, or time",
            ));
        }
        if (ownership.state == ClusterOwnershipState::Active
            && ownership.lease_expires_at <= ownership.updated_at)
            || (ownership.state == ClusterOwnershipState::Released
                && ownership.lease_expires_at != ownership.updated_at)
        {
            return Err(read_io(
                "replicated ownership contains invalid lease timestamps",
            ));
        }
        validate_ownership_identity(&ownership.agent_id, &ownership.owner_node_id)
            .map_err(|error| read_io(error.to_string()))?;
        if latest_ownership_audit.get(agent_id)
            != Some(&(
                ownership.generation,
                ownership.owner_node_id.clone(),
                ownership.authority_term,
                ownership.fencing_token,
                ownership.state,
            ))
        {
            return Err(read_io(
                "replicated ownership does not match its latest audit evidence",
            ));
        }
    }
    if latest_ownership_audit.len() != control.ownerships.len() {
        return Err(read_io(
            "replicated ownership audit references an unknown ownership record",
        ));
    }
    Ok(())
}

fn validate_persistent_state(state: &PersistentState) -> Result<(), AnyError> {
    validate_authority_state(&state.authority)?;
    let membership_log_id = state.membership.log_id();
    if let Some(membership_log_id) = membership_log_id {
        validate_log_id_at_or_before(*membership_log_id, state.last_applied, "stored membership")?;
    }
    for receipt in state.authority.receipts.values() {
        let (_, _, log_id, _) = successful_response_metadata(&receipt.response)
            .expect("validated receipts contain successful responses");
        validate_log_id_at_or_before(log_id, state.last_applied, "authority receipt")?;
    }
    Ok(())
}

fn validate_log_id_at_or_before(
    candidate: LogId<ClusterRaftNodeId>,
    frontier: Option<LogId<ClusterRaftNodeId>>,
    label: &str,
) -> Result<(), AnyError> {
    let Some(frontier) = frontier else {
        return Err(read_io(format!(
            "{label} exists without a last-applied log id"
        )));
    };
    if candidate.index > frontier.index
        || (candidate.index == frontier.index && candidate != frontier)
    {
        return Err(read_io(format!(
            "{label} {candidate} is not at or before last-applied {frontier}"
        )));
    }
    Ok(())
}

fn canonical_operation_id(operation_id: &str) -> Option<String> {
    let parsed = Uuid::parse_str(operation_id).ok()?;
    let canonical = parsed.to_string();
    (canonical == operation_id).then_some(canonical)
}

fn read_snapshot_record(connection: &Connection) -> Result<Option<SnapshotRecord>, AnyError> {
    let row = connection
        .query_row(
            "SELECT snapshot_id, meta_json, data
             FROM cluster_raft_snapshot WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| read_io(format!("read current Raft snapshot: {error}")))?;
    row.map(|(snapshot_id, meta, data)| {
        let meta: SnapshotMeta<ClusterRaftNodeId, ClusterRaftNode> =
            deserialize(&meta, "snapshot metadata")?;
        if snapshot_id != meta.snapshot_id {
            return Err(read_io(format!(
                "snapshot row id {snapshot_id:?} does not match serialized metadata"
            )));
        }
        validate_snapshot_data(&meta, &data)?;
        Ok((meta, data))
    })
    .transpose()
}

fn validate_snapshot_data(
    meta: &SnapshotMeta<ClusterRaftNodeId, ClusterRaftNode>,
    data: &[u8],
) -> Result<SnapshotState, AnyError> {
    if meta.snapshot_id.is_empty() || meta.snapshot_id.len() > MAX_SNAPSHOT_ID_BYTES {
        return Err(read_io(format!(
            "snapshot id length {} is outside 1..={MAX_SNAPSHOT_ID_BYTES}",
            meta.snapshot_id.len()
        )));
    }
    let state: SnapshotState = deserialize(data, "snapshot state")?;
    validate_authority_state(&state.authority)?;
    let persistent = PersistentState {
        last_applied: state.last_applied,
        membership: state.membership.clone(),
        authority: state.authority.clone(),
        snapshot_sequence: 0,
    };
    validate_persistent_state(&persistent)?;
    if state.last_applied != meta.last_log_id || state.membership != meta.last_membership {
        return Err(read_io(format!(
            "snapshot {} metadata does not match its state payload",
            meta.snapshot_id
        )));
    }
    Ok(state)
}

fn write_snapshot_record(
    transaction: &Transaction<'_>,
    meta: &SnapshotMeta<ClusterRaftNodeId, ClusterRaftNode>,
    data: &[u8],
) -> Result<(), AnyError> {
    validate_snapshot_data(meta, data)?;
    transaction
        .execute(
            "INSERT INTO cluster_raft_snapshot(
                 singleton, snapshot_id, meta_json, data, created_at
             ) VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET
                 snapshot_id = excluded.snapshot_id,
                 meta_json = excluded.meta_json,
                 data = excluded.data,
                 created_at = excluded.created_at",
            params![
                meta.snapshot_id,
                serialize(meta)?,
                data,
                Utc::now().to_rfc3339()
            ],
        )
        .map_err(|error| read_io(format!("write current Raft snapshot: {error}")))?;
    Ok(())
}

fn validate_store(context: &SqliteContextManager) -> ClusterStorageResult<()> {
    let connection = context
        .conn
        .lock()
        .map_err(|error| StorageIOError::read(read_io(format!("lock Raft store: {error}"))))?;
    let state = load_persistent_state(&connection).map_err(StorageIOError::read_state_machine)?;
    let _: Option<Vote<ClusterRaftNodeId>> =
        read_meta(&connection, "vote").map_err(StorageIOError::read_vote)?;
    let _: Option<Option<LogId<ClusterRaftNodeId>>> =
        read_meta(&connection, "committed").map_err(StorageIOError::read)?;
    let last_purged: Option<LogId<ClusterRaftNodeId>> =
        read_meta(&connection, "last_purged").map_err(StorageIOError::read)?;
    if let Some(last_purged) = last_purged {
        validate_log_id_at_or_before(last_purged, state.last_applied, "last-purged pointer")
            .map_err(StorageIOError::read_logs)?;
    }

    let mut statement = connection
        .prepare("SELECT log_index, entry_json FROM cluster_raft_log ORDER BY log_index")
        .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;
    let mut rows = statement
        .query([])
        .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;
    let mut previous = None;
    while let Some(row) = rows
        .next()
        .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?
    {
        let index = row
            .get::<_, Vec<u8>>(0)
            .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;
        let index = decode_index(&index).map_err(StorageIOError::read_logs)?;
        let entry = row
            .get::<_, Vec<u8>>(1)
            .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;
        let entry: ClusterEntry =
            deserialize(&entry, "Raft log entry").map_err(StorageIOError::read_logs)?;
        if entry.log_id.index != index {
            return Err(StorageIOError::read_log_at_index(
                index,
                read_io(format!(
                    "stored index {index} contains entry {}",
                    entry.log_id.index
                )),
            )
            .into());
        }
        if last_purged.is_some_and(|purged| index <= purged.index) {
            return Err(StorageIOError::read_log_at_index(
                index,
                read_io(format!(
                    "durable Raft log index {index} is not after last-purged {last_purged:?}"
                )),
            )
            .into());
        }
        if previous.is_some_and(|previous| index != previous + 1) {
            return Err(StorageIOError::read_logs(read_io(format!(
                "durable Raft log contains a hole before index {index}"
            )))
            .into());
        }
        previous = Some(index);
    }
    let snapshot = read_snapshot_record(&connection)
        .map_err(|error| StorageIOError::read_snapshot(None, error))?;
    if let Some((meta, _)) = snapshot {
        if let Some(snapshot_log_id) = meta.last_log_id {
            validate_log_id_at_or_before(snapshot_log_id, state.last_applied, "current snapshot")
                .map_err(|error| StorageIOError::read_snapshot(Some(meta.signature()), error))?;
        } else if state.last_applied.is_some() {
            return Err(StorageIOError::read_snapshot(
                Some(meta.signature()),
                read_io("empty current snapshot cannot accompany applied state"),
            )
            .into());
        }
    }
    Ok(())
}

fn read_log_entries<RB>(
    connection: &Connection,
    range: RB,
) -> ClusterStorageResult<Vec<ClusterEntry>>
where
    RB: RangeBounds<u64>,
{
    let start = match range.start_bound() {
        Bound::Included(index) => *index,
        Bound::Excluded(index) => match index.checked_add(1) {
            Some(index) => index,
            None => return Ok(Vec::new()),
        },
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(index) => index.checked_add(1),
        Bound::Excluded(index) => Some(*index),
        Bound::Unbounded => None,
    };
    if end.is_some_and(|end| end <= start) {
        return Ok(Vec::new());
    }

    let sql = if end.is_some() {
        "SELECT log_index, entry_json FROM cluster_raft_log
         WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index"
    } else {
        "SELECT log_index, entry_json FROM cluster_raft_log
         WHERE log_index >= ?1 ORDER BY log_index"
    };
    let mut statement = connection
        .prepare(sql)
        .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;
    let start_blob = index_blob(start);
    let end_blob = end.map(index_blob);
    let mut rows = if let Some(end_blob) = end_blob {
        statement.query(params![start_blob.as_slice(), end_blob.as_slice()])
    } else {
        statement.query(params![start_blob.as_slice()])
    }
    .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;

    let mut entries = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?
    {
        let stored_index = row
            .get::<_, Vec<u8>>(0)
            .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;
        let stored_index = decode_index(&stored_index).map_err(StorageIOError::read_logs)?;
        let bytes = row
            .get::<_, Vec<u8>>(1)
            .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;
        let entry: ClusterEntry =
            deserialize(&bytes, "Raft log entry").map_err(StorageIOError::read_logs)?;
        if entry.log_id.index != stored_index {
            return Err(StorageIOError::read_log_at_index(
                stored_index,
                read_io(format!(
                    "stored index {stored_index} contains entry {}",
                    entry.log_id.index
                )),
            )
            .into());
        }
        entries.push(entry);
    }
    Ok(entries)
}

impl ClusterRaftLogStore {
    fn append_entries(&self, entries: &[ClusterEntry]) -> ClusterStorageResult<()> {
        for pair in entries.windows(2) {
            if pair[1].log_id.index != pair[0].log_id.index.saturating_add(1) {
                return Err(StorageIOError::write_logs(read_io(format!(
                    "non-consecutive Raft append {} then {}",
                    pair[0].log_id.index, pair[1].log_id.index
                )))
                .into());
            }
        }
        let mut connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::write_logs(read_io(format!("lock Raft log store: {error}")))
        })?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageIOError::write_logs(read_io(error.to_string())))?;
        let committed = read_meta::<Option<LogId<ClusterRaftNodeId>>>(&transaction, "committed")
            .map_err(StorageIOError::read_logs)?
            .flatten();
        let state =
            load_persistent_state(&transaction).map_err(StorageIOError::read_state_machine)?;
        let last_purged = read_meta::<LogId<ClusterRaftNodeId>>(&transaction, "last_purged")
            .map_err(StorageIOError::read_logs)?;
        let last_stored_index = transaction
            .query_row(
                "SELECT log_index FROM cluster_raft_log
                 ORDER BY log_index DESC LIMIT 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?
            .map(|value| decode_index(&value))
            .transpose()
            .map_err(StorageIOError::read_logs)?;
        let durable_frontier = [
            last_stored_index,
            state.last_applied.map(|log_id| log_id.index),
            last_purged.map(|log_id| log_id.index),
        ]
        .into_iter()
        .flatten()
        .max();
        if let (Some(frontier), Some(first)) = (durable_frontier, entries.first()) {
            if first.log_id.index > frontier.saturating_add(1) {
                return Err(StorageIOError::write_logs(read_io(format!(
                    "Raft append starts at {} after durable frontier {frontier}",
                    first.log_id.index
                )))
                .into());
            }
        }
        for entry in entries {
            let encoded = serialize(entry).map_err(StorageIOError::write_logs)?;
            let existing = transaction
                .query_row(
                    "SELECT entry_json FROM cluster_raft_log WHERE log_index = ?1",
                    params![index_blob(entry.log_id.index).as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;
            if existing.as_ref().is_some_and(|current| current != &encoded) {
                return Err(StorageIOError::write_logs(read_io(format!(
                    "refusing to overwrite conflicting Raft log index {} without truncation",
                    entry.log_id.index
                )))
                .into());
            }
            if committed.is_some_and(|committed| {
                entry.log_id.index <= committed.index && existing.is_none()
            }) {
                return Err(StorageIOError::write_logs(read_io(format!(
                    "refusing to recreate purged or missing committed Raft log index {}",
                    entry.log_id.index
                )))
                .into());
            }
            transaction
                .execute(
                    "INSERT INTO cluster_raft_log(log_index, entry_json)
                     VALUES (?1, ?2)
                     ON CONFLICT(log_index) DO UPDATE SET
                         entry_json = excluded.entry_json",
                    params![index_blob(entry.log_id.index).as_slice(), encoded],
                )
                .map_err(|error| StorageIOError::write_logs(read_io(error.to_string())))?;
        }
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_logs(read_io(error.to_string())))?;
        Ok(())
    }
}

impl RaftLogReader<ClusterRaftTypeConfig> for ClusterRaftLogStore {
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> ClusterStorageResult<Vec<ClusterEntry>>
    where
        RB: RangeBounds<u64> + Clone + Debug + OptionalSend,
    {
        let connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::read_logs(read_io(format!("lock Raft log reader: {error}")))
        })?;
        read_log_entries(&connection, range)
    }
}

impl RaftLogStorage<ClusterRaftTypeConfig> for ClusterRaftLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> ClusterStorageResult<LogState<ClusterRaftTypeConfig>> {
        let connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::read_logs(read_io(format!("lock Raft log state: {error}")))
        })?;
        let last_purged_log_id =
            read_meta(&connection, "last_purged").map_err(StorageIOError::read_logs)?;
        let last = connection
            .query_row(
                "SELECT log_index, entry_json FROM cluster_raft_log
                 ORDER BY log_index DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|error| StorageIOError::read_logs(read_io(error.to_string())))?;
        let last_log_id = match last {
            Some((index, entry)) => {
                let index = decode_index(&index).map_err(StorageIOError::read_logs)?;
                let entry: ClusterEntry = deserialize(&entry, "last Raft log entry")
                    .map_err(StorageIOError::read_logs)?;
                if entry.log_id.index != index {
                    return Err(StorageIOError::read_log_at_index(
                        index,
                        read_io(format!(
                            "stored index {index} contains entry {}",
                            entry.log_id.index
                        )),
                    )
                    .into());
                }
                Some(entry.log_id)
            }
            None => last_purged_log_id,
        };
        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<ClusterRaftNodeId>) -> ClusterStorageResult<()> {
        let mut connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::write_vote(read_io(format!("lock Raft vote store: {error}")))
        })?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageIOError::write_vote(read_io(error.to_string())))?;
        if let Some(current) = read_meta::<Vote<ClusterRaftNodeId>>(&transaction, "vote")
            .map_err(StorageIOError::read_vote)?
        {
            if !matches!(
                current.partial_cmp(vote),
                Some(Ordering::Less | Ordering::Equal)
            ) {
                return Err(StorageIOError::write_vote(read_io(format!(
                    "refusing to replace durable vote {current} with non-monotonic vote {vote}"
                )))
                .into());
            }
        }
        write_meta(&transaction, "vote", vote).map_err(StorageIOError::write_vote)?;
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_vote(read_io(error.to_string())))?;
        Ok(())
    }

    async fn read_vote(&mut self) -> ClusterStorageResult<Option<Vote<ClusterRaftNodeId>>> {
        let connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::read_vote(read_io(format!("lock Raft vote store: {error}")))
        })?;
        read_meta(&connection, "vote").map_err(|error| StorageIOError::read_vote(error).into())
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<ClusterRaftNodeId>>,
    ) -> ClusterStorageResult<()> {
        let mut connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::write(read_io(format!("lock Raft commit store: {error}")))
        })?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageIOError::write(read_io(error.to_string())))?;
        let current = read_meta::<Option<LogId<ClusterRaftNodeId>>>(&transaction, "committed")
            .map_err(StorageIOError::read)?
            .flatten();
        let regresses = match (current, committed) {
            (Some(_), None) => true,
            (Some(current), Some(next)) => {
                next.index < current.index || (next.index == current.index && next != current)
            }
            _ => false,
        };
        if regresses {
            return Err(StorageIOError::write(read_io(format!(
                "refusing to regress committed pointer from {current:?} to {committed:?}"
            )))
            .into());
        }
        write_meta(&transaction, "committed", &committed).map_err(StorageIOError::write)?;
        transaction
            .commit()
            .map_err(|error| StorageIOError::write(read_io(error.to_string())))?;
        Ok(())
    }

    async fn read_committed(&mut self) -> ClusterStorageResult<Option<LogId<ClusterRaftNodeId>>> {
        let connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::read(read_io(format!("lock Raft commit store: {error}")))
        })?;
        Ok(
            read_meta::<Option<LogId<ClusterRaftNodeId>>>(&connection, "committed")
                .map_err(StorageIOError::read)?
                .flatten(),
        )
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<ClusterRaftTypeConfig>,
    ) -> ClusterStorageResult<()>
    where
        I: IntoIterator<Item = ClusterEntry> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let result = self.append_entries(&entries);
        match &result {
            Ok(()) => callback.log_io_completed(Ok(())),
            Err(error) => callback.log_io_completed(Err(std::io::Error::other(error.to_string()))),
        }
        result
    }

    async fn truncate(&mut self, log_id: LogId<ClusterRaftNodeId>) -> ClusterStorageResult<()> {
        let mut connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::write_logs(read_io(format!("lock Raft log store: {error}")))
        })?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageIOError::write_logs(read_io(error.to_string())))?;
        let committed = read_meta::<Option<LogId<ClusterRaftNodeId>>>(&transaction, "committed")
            .map_err(StorageIOError::read_logs)?
            .flatten();
        if committed.is_some_and(|committed| log_id.index <= committed.index) {
            return Err(StorageIOError::write_logs(read_io(format!(
                "refusing to truncate committed log at {log_id}; committed pointer is {committed:?}"
            )))
            .into());
        }
        transaction
            .execute(
                "DELETE FROM cluster_raft_log WHERE log_index >= ?1",
                params![index_blob(log_id.index).as_slice()],
            )
            .map_err(|error| StorageIOError::write_logs(read_io(error.to_string())))?;
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_logs(read_io(error.to_string())))?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<ClusterRaftNodeId>) -> ClusterStorageResult<()> {
        let mut connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::write_logs(read_io(format!("lock Raft log store: {error}")))
        })?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageIOError::write_logs(read_io(error.to_string())))?;
        if let Some(current) = read_meta::<LogId<ClusterRaftNodeId>>(&transaction, "last_purged")
            .map_err(StorageIOError::read_logs)?
        {
            if log_id.index < current.index || (log_id.index == current.index && log_id != current)
            {
                return Err(StorageIOError::write_logs(read_io(format!(
                    "refusing to regress last-purged pointer from {current} to {log_id}"
                )))
                .into());
            }
        }
        write_meta(&transaction, "last_purged", &log_id).map_err(StorageIOError::write_logs)?;
        transaction
            .execute(
                "DELETE FROM cluster_raft_log WHERE log_index <= ?1",
                params![index_blob(log_id.index).as_slice()],
            )
            .map_err(|error| StorageIOError::write_logs(read_io(error.to_string())))?;
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_logs(read_io(error.to_string())))?;
        Ok(())
    }
}

fn apply_authority_command(
    state: &mut AuthorityState,
    command: AuthorityCommand,
    log_id: LogId<ClusterRaftNodeId>,
) -> AuthorityResponse {
    let supplied_id = command.operation_id();
    let Some(canonical_id) = canonical_operation_id(supplied_id) else {
        return rejected(
            supplied_id.to_owned(),
            state.sequence,
            log_id,
            AuthorityRejection::InvalidOperationId,
            "authority operation_id must be a canonical lowercase UUID",
        );
    };
    if let AuthorityCommand::AdvanceTime { proposed_at, .. } = &command {
        let Some(control) = state.control_plane.as_mut() else {
            return rejected(
                canonical_id,
                state.sequence,
                log_id,
                AuthorityRejection::NotInitialized,
                "replicated authority is not initialized",
            );
        };
        control.logical_time = control.logical_time.max(*proposed_at);
        return AuthorityResponse::AuthorityTimeAdvanced {
            operation_id: canonical_id,
            logical_time: control.logical_time,
            log_id,
        };
    }
    if let Some(receipt) = state.receipts.get(&canonical_id) {
        if commands_are_same_retry(&receipt.command, &command) {
            return replay_response(&receipt.response);
        }
        return rejected(
            canonical_id,
            state.sequence,
            log_id,
            AuthorityRejection::OperationIdConflict,
            "authority operation_id is already committed with a different command",
        );
    }
    if let AuthorityCommand::Barrier {
        expected_sequence, ..
    } = &command
    {
        if expected_sequence.is_some_and(|expected| expected != state.sequence) {
            return rejected(
                canonical_id,
                state.sequence,
                log_id,
                AuthorityRejection::SequenceMismatch,
                "authority sequence compare-and-set failed",
            );
        }
    }
    if state.receipts.len() >= MAX_AUTHORITY_RECEIPTS {
        return rejected(
            canonical_id,
            state.sequence,
            log_id,
            AuthorityRejection::ReceiptCapacityReached,
            "authority idempotency receipt capacity is exhausted",
        );
    }
    let Some(sequence) = state.sequence.checked_add(1) else {
        return rejected(
            canonical_id,
            state.sequence,
            log_id,
            AuthorityRejection::SequenceExhausted,
            "authority sequence is exhausted",
        );
    };
    let response = match apply_new_authority_command(state, &command, sequence, log_id) {
        Ok(response) => response,
        Err((reason, message)) => {
            return rejected(canonical_id, state.sequence, log_id, reason, message)
        }
    };
    state.sequence = sequence;
    state.receipts.insert(
        canonical_id,
        StoredAuthorityReceipt {
            command,
            response: response.clone(),
        },
    );
    response
}

fn rejected(
    operation_id: String,
    sequence: u64,
    log_id: LogId<ClusterRaftNodeId>,
    reason: AuthorityRejection,
    message: impl Into<String>,
) -> AuthorityResponse {
    AuthorityResponse::Rejected {
        operation_id,
        sequence,
        log_id,
        reason,
        message: message.into(),
    }
}

fn commands_are_same_retry(previous: &AuthorityCommand, current: &AuthorityCommand) -> bool {
    fn semantic_value(command: &AuthorityCommand) -> Option<serde_json::Value> {
        let mut value = serde_json::to_value(command).ok()?;
        let variant = value.as_object_mut()?.values_mut().next()?;
        if let Some(fields) = variant.as_object_mut() {
            fields.remove("proposed_at");
        }
        Some(value)
    }
    previous.operation_id() == current.operation_id()
        && semantic_value(previous)
            .is_some_and(|previous| Some(previous) == semantic_value(current))
}

fn replay_response(response: &AuthorityResponse) -> AuthorityResponse {
    match response {
        AuthorityResponse::BarrierCommitted {
            operation_id,
            sequence,
            log_id,
            ..
        } => AuthorityResponse::BarrierCommitted {
            operation_id: operation_id.clone(),
            sequence: *sequence,
            log_id: *log_id,
            replayed: true,
        },
        AuthorityResponse::ControlPlaneInitialized {
            operation_id,
            sequence,
            log_id,
            ..
        } => AuthorityResponse::ControlPlaneInitialized {
            operation_id: operation_id.clone(),
            sequence: *sequence,
            log_id: *log_id,
            replayed: true,
        },
        AuthorityResponse::JoinChallengeIssued {
            operation_id,
            challenge,
            sequence,
            log_id,
            ..
        } => AuthorityResponse::JoinChallengeIssued {
            operation_id: operation_id.clone(),
            challenge: challenge.clone(),
            sequence: *sequence,
            log_id: *log_id,
            replayed: true,
        },
        AuthorityResponse::MemberUpdated {
            operation_id,
            member,
            sequence,
            log_id,
            ..
        } => AuthorityResponse::MemberUpdated {
            operation_id: operation_id.clone(),
            member: member.clone(),
            sequence: *sequence,
            log_id: *log_id,
            replayed: true,
        },
        AuthorityResponse::CertificateRolloutUpdated {
            operation_id,
            member,
            rollout,
            sequence,
            log_id,
            ..
        } => AuthorityResponse::CertificateRolloutUpdated {
            operation_id: operation_id.clone(),
            member: member.clone(),
            rollout: rollout.clone(),
            sequence: *sequence,
            log_id: *log_id,
            replayed: true,
        },
        AuthorityResponse::OwnershipUpdated {
            operation_id,
            ownership,
            sequence,
            log_id,
            ..
        } => AuthorityResponse::OwnershipUpdated {
            operation_id: operation_id.clone(),
            ownership: ownership.clone(),
            sequence: *sequence,
            log_id: *log_id,
            replayed: true,
        },
        AuthorityResponse::MetadataApplied { .. }
        | AuthorityResponse::AuthorityTimeAdvanced { .. }
        | AuthorityResponse::Rejected { .. } => {
            unreachable!("only successful normal-command responses are retained")
        }
    }
}

fn apply_new_authority_command(
    state: &mut AuthorityState,
    command: &AuthorityCommand,
    sequence: u64,
    log_id: LogId<ClusterRaftNodeId>,
) -> Result<AuthorityResponse, (AuthorityRejection, String)> {
    let operation_id = command.operation_id().to_owned();
    let authority_term = log_id.leader_id.term;
    match command {
        AuthorityCommand::Initialize {
            genesis,
            proposed_at,
            ..
        } => {
            if state.control_plane.is_some() {
                return Err((
                    AuthorityRejection::Conflict,
                    "replicated authority is already initialized".into(),
                ));
            }
            let control_plane = validate_and_build_genesis(genesis, *proposed_at)?;
            state.control_plane = Some(control_plane);
            Ok(AuthorityResponse::ControlPlaneInitialized {
                operation_id,
                sequence,
                log_id,
                replayed: false,
            })
        }
        AuthorityCommand::Barrier { .. } => Ok(AuthorityResponse::BarrierCommitted {
            operation_id,
            sequence,
            log_id,
            replayed: false,
        }),
        AuthorityCommand::AdvanceTime { .. } => {
            unreachable!("logical-clock advancement is handled before receipt sequencing")
        }
        AuthorityCommand::IssueJoinChallenge {
            challenge_hex,
            ttl_seconds,
            proposed_at,
            ..
        } => {
            let control = control_plane_mut(state)?;
            let mut next = control.clone();
            if !(MIN_JOIN_CHALLENGE_TTL_SECONDS..=MAX_JOIN_CHALLENGE_TTL_SECONDS)
                .contains(ttl_seconds)
            {
                return Err((
                    AuthorityRejection::InvalidCommand,
                    format!(
                        "invalid join challenge ttl (expected {MIN_JOIN_CHALLENGE_TTL_SECONDS}..={MAX_JOIN_CHALLENGE_TTL_SECONDS} seconds)"
                    ),
                ));
            }
            let challenge = hex_decode(challenge_hex)
                .filter(|bytes| bytes.len() == 32)
                .ok_or_else(|| {
                    (
                        AuthorityRejection::InvalidCommand,
                        "invalid cluster join challenge".into(),
                    )
                })?;
            let now = advance_authority_time(&mut next, *proposed_at)?;
            next.join_challenges
                .retain(|_, record| record.expires_at > now && record.consumed_at.is_none());
            if next.join_challenges.len() >= 4_096 {
                return Err((
                    AuthorityRejection::CapacityReached,
                    "replicated join challenge capacity is exhausted".into(),
                ));
            }
            let challenge_hash = sha256_hex(&challenge);
            if next.join_challenges.contains_key(&challenge_hash) {
                return Err((
                    AuthorityRejection::Conflict,
                    "cluster join challenge already exists".into(),
                ));
            }
            let expires_at = now
                .checked_add_signed(TimeDelta::seconds(*ttl_seconds as i64))
                .ok_or_else(|| {
                    (
                        AuthorityRejection::InvalidCommand,
                        "cluster join challenge expiry overflow".into(),
                    )
                })?;
            next.join_challenges.insert(
                challenge_hash,
                ReplicatedJoinChallenge {
                    challenge_hex: challenge_hex.clone(),
                    expires_at,
                    consumed_at: None,
                },
            );
            let challenge = ClusterJoinChallenge {
                cluster_id: next.cluster_id.clone(),
                challenge_hex: challenge_hex.clone(),
                expires_at,
            };
            *control = next;
            Ok(AuthorityResponse::JoinChallengeIssued {
                operation_id,
                challenge,
                sequence,
                log_id,
                replayed: false,
            })
        }
        AuthorityCommand::RegisterMember {
            registration,
            challenge_hex,
            signature_hex,
            expected_generation,
            authority_min_protocol_version,
            authority_protocol_version,
            actor,
            reason,
            proposed_at,
            ..
        } => {
            let control = control_plane_mut(state)?;
            let mut next = control.clone();
            let member = apply_register_member(
                &mut next,
                registration,
                challenge_hex,
                signature_hex,
                *expected_generation,
                *authority_min_protocol_version,
                *authority_protocol_version,
                actor,
                reason,
                *proposed_at,
            )?;
            *control = next;
            Ok(AuthorityResponse::MemberUpdated {
                operation_id,
                member,
                sequence,
                log_id,
                replayed: false,
            })
        }
        AuthorityCommand::PrepareMemberCertificateRollout {
            registration,
            challenge_hex,
            signature_hex,
            expected_generation,
            prepare_ttl_seconds,
            minimum_overlap_seconds,
            actor,
            reason,
            proposed_at,
            ..
        } => {
            let control = control_plane_mut(state)?;
            let mut next = control.clone();
            let (member, rollout) = apply_prepare_member_certificate_rollout(
                &mut next,
                registration,
                challenge_hex,
                signature_hex,
                *expected_generation,
                *prepare_ttl_seconds,
                *minimum_overlap_seconds,
                actor,
                reason,
                *proposed_at,
            )?;
            *control = next;
            Ok(AuthorityResponse::CertificateRolloutUpdated {
                operation_id,
                member,
                rollout: Some(rollout),
                sequence,
                log_id,
                replayed: false,
            })
        }
        AuthorityCommand::AbortMemberCertificateRollout {
            node_id,
            expected_generation,
            actor,
            reason,
            proposed_at,
            ..
        } => {
            let control = control_plane_mut(state)?;
            let mut next = control.clone();
            let member = apply_finish_member_certificate_rollout(
                &mut next,
                node_id,
                *expected_generation,
                CertificateRolloutFinish::Abort,
                actor,
                reason,
                *proposed_at,
            )?;
            *control = next;
            Ok(AuthorityResponse::CertificateRolloutUpdated {
                operation_id,
                member,
                rollout: None,
                sequence,
                log_id,
                replayed: false,
            })
        }
        AuthorityCommand::FinalizeMemberCertificateRollout {
            node_id,
            expected_generation,
            actor,
            reason,
            proposed_at,
            ..
        } => {
            let control = control_plane_mut(state)?;
            let mut next = control.clone();
            let member = apply_finish_member_certificate_rollout(
                &mut next,
                node_id,
                *expected_generation,
                CertificateRolloutFinish::Finalize,
                actor,
                reason,
                *proposed_at,
            )?;
            *control = next;
            Ok(AuthorityResponse::CertificateRolloutUpdated {
                operation_id,
                member,
                rollout: None,
                sequence,
                log_id,
                replayed: false,
            })
        }
        AuthorityCommand::SetMemberState {
            node_id,
            state: requested_state,
            expected_generation,
            actor,
            reason,
            proposed_at,
            ..
        } => {
            let control = control_plane_mut(state)?;
            let mut next = control.clone();
            let member = apply_set_member_state(
                &mut next,
                node_id,
                *requested_state,
                *expected_generation,
                actor,
                reason,
                *proposed_at,
                authority_term,
            )?;
            *control = next;
            Ok(AuthorityResponse::MemberUpdated {
                operation_id,
                member,
                sequence,
                log_id,
                replayed: false,
            })
        }
        AuthorityCommand::ClaimOwnership {
            agent_id,
            owner_node_id,
            ttl_seconds,
            expected_fencing_token,
            actor,
            reason,
            proposed_at,
            ..
        } => {
            let control = control_plane_mut(state)?;
            let mut next = control.clone();
            let ownership = apply_claim_ownership(
                &mut next,
                agent_id,
                owner_node_id,
                *ttl_seconds,
                *expected_fencing_token,
                actor,
                reason,
                *proposed_at,
                authority_term,
            )?;
            *control = next;
            Ok(AuthorityResponse::OwnershipUpdated {
                operation_id,
                ownership,
                sequence,
                log_id,
                replayed: false,
            })
        }
        AuthorityCommand::RenewOwnership {
            agent_id,
            owner_node_id,
            fencing_token,
            ttl_seconds,
            actor,
            reason,
            proposed_at,
            ..
        } => {
            let control = control_plane_mut(state)?;
            let mut next = control.clone();
            let ownership = apply_renew_ownership(
                &mut next,
                agent_id,
                owner_node_id,
                *fencing_token,
                *ttl_seconds,
                actor,
                reason,
                *proposed_at,
                authority_term,
            )?;
            *control = next;
            Ok(AuthorityResponse::OwnershipUpdated {
                operation_id,
                ownership,
                sequence,
                log_id,
                replayed: false,
            })
        }
        AuthorityCommand::ReleaseOwnership {
            agent_id,
            owner_node_id,
            fencing_token,
            actor,
            reason,
            proposed_at,
            ..
        } => {
            let control = control_plane_mut(state)?;
            let mut next = control.clone();
            let ownership = apply_release_ownership(
                &mut next,
                agent_id,
                owner_node_id,
                *fencing_token,
                actor,
                reason,
                *proposed_at,
                authority_term,
            )?;
            *control = next;
            Ok(AuthorityResponse::OwnershipUpdated {
                operation_id,
                ownership,
                sequence,
                log_id,
                replayed: false,
            })
        }
    }
}

fn control_plane_mut(
    state: &mut AuthorityState,
) -> Result<&mut ReplicatedControlPlaneState, (AuthorityRejection, String)> {
    state.control_plane.as_mut().ok_or_else(|| {
        (
            AuthorityRejection::NotInitialized,
            "replicated authority is not initialized".into(),
        )
    })
}

fn advance_authority_time(
    control: &mut ReplicatedControlPlaneState,
    proposed_at: DateTime<Utc>,
) -> Result<DateTime<Utc>, (AuthorityRejection, String)> {
    let minimum = control
        .logical_time
        .checked_add_signed(TimeDelta::microseconds(1))
        .ok_or_else(|| {
            (
                AuthorityRejection::InvalidCommand,
                "replicated authority clock is exhausted".into(),
            )
        })?;
    let effective = proposed_at.max(minimum);
    control.logical_time = effective;
    Ok(effective)
}

fn validate_and_build_genesis(
    genesis: &AuthorityGenesis,
    proposed_at: DateTime<Utc>,
) -> Result<ReplicatedControlPlaneState, (AuthorityRejection, String)> {
    let cluster_id = Uuid::parse_str(&genesis.cluster_id).map_err(|_| {
        (
            AuthorityRejection::InvalidCommand,
            "authority genesis cluster_id must be a UUID".into(),
        )
    })?;
    if cluster_id.to_string() != genesis.cluster_id {
        return Err((
            AuthorityRejection::InvalidCommand,
            "authority genesis cluster_id must be canonical".into(),
        ));
    }
    if genesis.members.is_empty() || genesis.members.len() > 31 {
        return Err((
            AuthorityRejection::InvalidCommand,
            "authority genesis must contain 1 to 31 members".into(),
        ));
    }
    let mut members = BTreeMap::new();
    let mut fingerprints = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    let mut tls_fingerprints = BTreeSet::new();
    for seed in &genesis.members {
        let registration = ClusterMemberRegistration {
            node_id: seed.node_id.clone(),
            fingerprint: seed.fingerprint.clone(),
            public_key: seed.public_key.clone(),
            tls_server_certificate_fingerprint: seed.tls_server_certificate_fingerprint.clone(),
            endpoint: seed.endpoint.clone(),
            server_version: seed.server_version.clone(),
            min_protocol_version: seed.min_protocol_version,
            protocol_version: seed.protocol_version,
        };
        validate_member_registration(&registration).map_err(invalid_command)?;
        if !fingerprints.insert(seed.fingerprint.clone())
            || !endpoints.insert(seed.endpoint.clone())
            || seed
                .tls_server_certificate_fingerprint
                .as_ref()
                .is_some_and(|fingerprint| !tls_fingerprints.insert(fingerprint.clone()))
        {
            return Err((
                AuthorityRejection::InvalidCommand,
                "authority genesis contains a duplicate identity, endpoint, or TLS binding".into(),
            ));
        }
        let member = ClusterMember {
            node_id: seed.node_id.clone(),
            fingerprint: seed.fingerprint.clone(),
            public_key: seed.public_key.clone(),
            tls_server_certificate_fingerprint: seed.tls_server_certificate_fingerprint.clone(),
            endpoint: seed.endpoint.clone(),
            server_version: seed.server_version.clone(),
            min_protocol_version: seed.min_protocol_version,
            protocol_version: seed.protocol_version,
            state: ClusterMemberState::Active,
            generation: 1,
            joined_at: proposed_at,
            updated_at: proposed_at,
            reason: "replicated authority genesis".into(),
        };
        if members.insert(seed.node_id.clone(), member).is_some() {
            return Err((
                AuthorityRejection::InvalidCommand,
                "authority genesis contains a duplicate application node id".into(),
            ));
        }
    }
    let membership_generation = members.len() as u64;
    let membership_audit = members
        .values()
        .enumerate()
        .map(|(index, member)| ClusterMembershipAudit {
            membership_generation: index as u64 + 1,
            node_id: member.node_id.clone(),
            member_generation: 1,
            previous: None,
            current: ClusterMemberState::Active,
            previous_tls_server_certificate_fingerprint: None,
            current_tls_server_certificate_fingerprint: member
                .tls_server_certificate_fingerprint
                .clone(),
            actor: "system:raft-genesis".into(),
            reason: "replicated authority genesis".into(),
            changed_at: proposed_at,
        })
        .collect();
    Ok(ReplicatedControlPlaneState {
        genesis: genesis.clone(),
        cluster_id: genesis.cluster_id.clone(),
        membership_generation,
        members,
        membership_audit,
        tls_trust_generation: 0,
        certificate_rollouts: BTreeMap::new(),
        certificate_rollout_audit: Vec::new(),
        join_challenges: BTreeMap::new(),
        ownerships: BTreeMap::new(),
        ownership_audit: Vec::new(),
        logical_time: proposed_at,
    })
}

fn invalid_command(error: impl fmt::Display) -> (AuthorityRejection, String) {
    (AuthorityRejection::InvalidCommand, error.to_string())
}

fn conflict(error: impl Into<String>) -> (AuthorityRejection, String) {
    (AuthorityRejection::Conflict, error.into())
}

fn validate_challenged_registration(
    control: &mut ReplicatedControlPlaneState,
    registration: &ClusterMemberRegistration,
    challenge_hex: &str,
    signature_hex: &str,
    proposed_at: DateTime<Utc>,
) -> Result<(DateTime<Utc>, String), (AuthorityRejection, String)> {
    validate_member_registration(registration).map_err(invalid_command)?;
    let challenge = hex_decode(challenge_hex)
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| invalid_command("invalid cluster join challenge"))?;
    let signature = hex_decode(signature_hex)
        .ok_or_else(|| invalid_command("invalid cluster join signature"))?;
    let payload = membership_join_payload(&control.cluster_id, challenge_hex, registration)
        .map_err(invalid_command)?;
    if !ClusterControl::verify_challenge(&registration.public_key, &payload, &signature) {
        return Err(conflict("cluster member challenged identity proof denied"));
    }
    let now = advance_authority_time(control, proposed_at)?;
    let challenge_hash = sha256_hex(&challenge);
    let challenge_record = control
        .join_challenges
        .get(&challenge_hash)
        .ok_or_else(|| conflict("invalid cluster join challenge: unknown"))?;
    if challenge_record.challenge_hex != challenge_hex {
        return Err(conflict("invalid cluster join challenge: hash mismatch"));
    }
    if challenge_record.consumed_at.is_some() {
        return Err(conflict("cluster join challenge was already consumed"));
    }
    if challenge_record.expires_at <= now {
        return Err(conflict("invalid cluster join challenge: expired"));
    }
    Ok((now, challenge_hash))
}

fn consume_join_challenge(
    control: &mut ReplicatedControlPlaneState,
    challenge_hash: &str,
    now: DateTime<Utc>,
) {
    control
        .join_challenges
        .get_mut(challenge_hash)
        .expect("validated challenge remains present")
        .consumed_at = Some(now);
}

fn require_membership_audit_capacity(
    control: &ReplicatedControlPlaneState,
) -> Result<(), (AuthorityRejection, String)> {
    if control.membership_audit.len() >= 100_000 {
        return Err((
            AuthorityRejection::CapacityReached,
            "replicated membership audit capacity is exhausted".into(),
        ));
    }
    Ok(())
}

fn require_certificate_rollout_audit_capacity(
    control: &ReplicatedControlPlaneState,
) -> Result<(), (AuthorityRejection, String)> {
    if control.certificate_rollout_audit.len() >= 100_000 {
        return Err((
            AuthorityRejection::CapacityReached,
            "replicated certificate rollout audit capacity is exhausted".into(),
        ));
    }
    Ok(())
}

fn append_member_revision(
    control: &mut ReplicatedControlPlaneState,
    previous: &ClusterMember,
    state: ClusterMemberState,
    tls_server_certificate_fingerprint: Option<String>,
    actor: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<ClusterMember, (AuthorityRejection, String)> {
    require_membership_audit_capacity(control)?;
    let generation = previous
        .generation
        .checked_add(1)
        .ok_or_else(|| conflict("cluster member generation overflow"))?;
    let membership_generation = control
        .membership_generation
        .checked_add(1)
        .ok_or_else(|| conflict("membership generation overflow"))?;
    let updated = ClusterMember {
        state,
        generation,
        tls_server_certificate_fingerprint: tls_server_certificate_fingerprint.clone(),
        updated_at: now,
        reason: reason.to_owned(),
        ..previous.clone()
    };
    control
        .members
        .insert(previous.node_id.clone(), updated.clone());
    control.membership_generation = membership_generation;
    control.membership_audit.push(ClusterMembershipAudit {
        membership_generation,
        node_id: previous.node_id.clone(),
        member_generation: generation,
        previous: Some(previous.state),
        current: state,
        previous_tls_server_certificate_fingerprint: previous
            .tls_server_certificate_fingerprint
            .clone(),
        current_tls_server_certificate_fingerprint: tls_server_certificate_fingerprint,
        actor: actor.to_owned(),
        reason: reason.to_owned(),
        changed_at: now,
    });
    Ok(updated)
}

#[allow(clippy::too_many_arguments)]
fn append_certificate_rollout_audit(
    control: &mut ReplicatedControlPlaneState,
    node_id: &str,
    member_generation: u64,
    previous_phase: Option<ClusterCertificateRolloutPhase>,
    current_phase: Option<ClusterCertificateRolloutPhase>,
    previous_tls_server_certificate_fingerprint: &str,
    next_tls_server_certificate_fingerprint: &str,
    actor: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<u64, (AuthorityRejection, String)> {
    require_certificate_rollout_audit_capacity(control)?;
    let trust_generation = control
        .tls_trust_generation
        .checked_add(1)
        .ok_or_else(|| conflict("cluster TLS trust generation overflow"))?;
    control.tls_trust_generation = trust_generation;
    control
        .certificate_rollout_audit
        .push(ClusterCertificateRolloutAudit {
            trust_generation,
            node_id: node_id.to_owned(),
            member_generation,
            previous_phase,
            current_phase,
            previous_tls_server_certificate_fingerprint:
                previous_tls_server_certificate_fingerprint.to_owned(),
            next_tls_server_certificate_fingerprint: next_tls_server_certificate_fingerprint
                .to_owned(),
            actor: actor.to_owned(),
            reason: reason.to_owned(),
            changed_at: now,
        });
    Ok(trust_generation)
}

fn certificate_fingerprint_was_previously_authorized(
    control: &ReplicatedControlPlaneState,
    fingerprint: &str,
) -> bool {
    control.membership_audit.iter().any(|audit| {
        audit.previous_tls_server_certificate_fingerprint.as_deref() == Some(fingerprint)
            || audit.current_tls_server_certificate_fingerprint.as_deref() == Some(fingerprint)
    }) || control.certificate_rollout_audit.iter().any(|audit| {
        audit.previous_tls_server_certificate_fingerprint == fingerprint
            || audit.next_tls_server_certificate_fingerprint == fingerprint
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_prepare_member_certificate_rollout(
    control: &mut ReplicatedControlPlaneState,
    registration: &ClusterMemberRegistration,
    challenge_hex: &str,
    signature_hex: &str,
    expected_generation: u64,
    prepare_ttl_seconds: u64,
    minimum_overlap_seconds: u64,
    actor: &str,
    reason: &str,
    proposed_at: DateTime<Utc>,
) -> Result<(ClusterMember, ClusterCertificateRollout), (AuthorityRejection, String)> {
    validate_text(actor, "cluster-certificate-rollout actor").map_err(invalid_command)?;
    validate_reason(reason).map_err(invalid_command)?;
    if !(MIN_CERTIFICATE_ROLLOUT_SECONDS..=MAX_CERTIFICATE_ROLLOUT_SECONDS)
        .contains(&prepare_ttl_seconds)
        || !(MIN_CERTIFICATE_ROLLOUT_SECONDS..=MAX_CERTIFICATE_ROLLOUT_SECONDS)
            .contains(&minimum_overlap_seconds)
    {
        return Err(invalid_command(format!(
            "invalid certificate rollout window (expected {MIN_CERTIFICATE_ROLLOUT_SECONDS}..={MAX_CERTIFICATE_ROLLOUT_SECONDS} seconds)"
        )));
    }
    require_membership_audit_capacity(control)?;
    require_certificate_rollout_audit_capacity(control)?;
    let (now, challenge_hash) = validate_challenged_registration(
        control,
        registration,
        challenge_hex,
        signature_hex,
        proposed_at,
    )?;
    let member = control
        .members
        .get(&registration.node_id)
        .cloned()
        .ok_or_else(|| conflict("cluster member not found"))?;
    if member.state != ClusterMemberState::Active {
        return Err(conflict(
            "certificate rollout requires an active cluster member",
        ));
    }
    if member.generation != expected_generation {
        return Err(conflict(format!(
            "cluster member revision conflict: expected {expected_generation}, current {}",
            member.generation
        )));
    }
    if control.certificate_rollouts.contains_key(&member.node_id) {
        return Err(conflict(
            "cluster member already has an unfinished certificate rollout",
        ));
    }
    if member.fingerprint != registration.fingerprint
        || member.public_key != registration.public_key
        || member.endpoint != registration.endpoint
        || member.server_version != registration.server_version
        || member.min_protocol_version != registration.min_protocol_version
        || member.protocol_version != registration.protocol_version
    {
        return Err(conflict(
            "certificate rollout registration may only change the TLS certificate fingerprint",
        ));
    }
    let previous_fingerprint = member
        .tls_server_certificate_fingerprint
        .as_deref()
        .ok_or_else(|| {
            conflict("certificate rollout requires an existing TLS-bound application listener")
        })?;
    let next_fingerprint = registration
        .tls_server_certificate_fingerprint
        .as_deref()
        .ok_or_else(|| invalid_command("certificate rollout candidate fingerprint is required"))?;
    if previous_fingerprint == next_fingerprint {
        return Err(conflict(
            "certificate rollout candidate must differ from the current fingerprint",
        ));
    }
    if certificate_fingerprint_was_previously_authorized(control, next_fingerprint)
        || control.members.values().any(|candidate| {
            candidate.tls_server_certificate_fingerprint.as_deref() == Some(next_fingerprint)
        })
    {
        return Err(conflict(
            "certificate rollout candidate was already authorized or assigned",
        ));
    }
    let prepare_expires_at = now
        .checked_add_signed(TimeDelta::seconds(prepare_ttl_seconds as i64))
        .ok_or_else(|| invalid_command("certificate rollout prepare expiry overflow"))?;
    let updated = append_member_revision(
        control,
        &member,
        member.state,
        member.tls_server_certificate_fingerprint.clone(),
        actor,
        reason,
        now,
    )?;
    let trust_generation = append_certificate_rollout_audit(
        control,
        &member.node_id,
        updated.generation,
        None,
        Some(ClusterCertificateRolloutPhase::Prepared),
        previous_fingerprint,
        next_fingerprint,
        actor,
        reason,
        now,
    )?;
    let rollout = ClusterCertificateRollout {
        node_id: member.node_id.clone(),
        trust_generation,
        member_generation: updated.generation,
        phase: ClusterCertificateRolloutPhase::Prepared,
        previous_tls_server_certificate_fingerprint: previous_fingerprint.to_owned(),
        next_tls_server_certificate_fingerprint: next_fingerprint.to_owned(),
        minimum_overlap_seconds,
        prepare_expires_at,
        retire_previous_after: None,
        prepared_at: now,
        updated_at: now,
        reason: reason.to_owned(),
    };
    control
        .certificate_rollouts
        .insert(member.node_id.clone(), rollout.clone());
    consume_join_challenge(control, &challenge_hash, now);
    Ok((updated, rollout))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateRolloutFinish {
    Abort,
    Finalize,
}

fn apply_finish_member_certificate_rollout(
    control: &mut ReplicatedControlPlaneState,
    node_id: &str,
    expected_generation: u64,
    finish: CertificateRolloutFinish,
    actor: &str,
    reason: &str,
    proposed_at: DateTime<Utc>,
) -> Result<ClusterMember, (AuthorityRejection, String)> {
    Uuid::parse_str(node_id)
        .map_err(|_| invalid_command("invalid certificate rollout cluster member node id"))?;
    validate_text(actor, "cluster-certificate-rollout actor").map_err(invalid_command)?;
    validate_reason(reason).map_err(invalid_command)?;
    require_membership_audit_capacity(control)?;
    require_certificate_rollout_audit_capacity(control)?;
    let member = control
        .members
        .get(node_id)
        .cloned()
        .ok_or_else(|| conflict("cluster member not found"))?;
    if member.state != ClusterMemberState::Active {
        return Err(conflict(
            "certificate rollout mutation requires an active cluster member",
        ));
    }
    if member.generation != expected_generation {
        return Err(conflict(format!(
            "cluster member revision conflict: expected {expected_generation}, current {}",
            member.generation
        )));
    }
    let rollout = control
        .certificate_rollouts
        .get(node_id)
        .cloned()
        .ok_or_else(|| conflict("cluster member has no unfinished certificate rollout"))?;
    if rollout.member_generation != member.generation {
        return Err(conflict(
            "certificate rollout revision differs from the current member revision",
        ));
    }
    let now = advance_authority_time(control, proposed_at)?;
    match finish {
        CertificateRolloutFinish::Abort
            if rollout.phase != ClusterCertificateRolloutPhase::Prepared =>
        {
            return Err(conflict(
                "activated certificate rollout cannot be aborted; wait and finalize it",
            ));
        }
        CertificateRolloutFinish::Finalize
            if rollout.phase != ClusterCertificateRolloutPhase::Activated =>
        {
            return Err(conflict(
                "prepared certificate rollout cannot be finalized before activation",
            ));
        }
        CertificateRolloutFinish::Finalize
            if rollout
                .retire_previous_after
                .is_none_or(|deadline| now < deadline) =>
        {
            return Err(conflict(
                "certificate rollout overlap has not reached its retirement deadline",
            ));
        }
        _ => {}
    }
    let updated = append_member_revision(
        control,
        &member,
        member.state,
        member.tls_server_certificate_fingerprint.clone(),
        actor,
        reason,
        now,
    )?;
    append_certificate_rollout_audit(
        control,
        node_id,
        updated.generation,
        Some(rollout.phase),
        None,
        &rollout.previous_tls_server_certificate_fingerprint,
        &rollout.next_tls_server_certificate_fingerprint,
        actor,
        reason,
        now,
    )?;
    control.certificate_rollouts.remove(node_id);
    Ok(updated)
}

#[allow(clippy::too_many_arguments)]
fn apply_register_member(
    control: &mut ReplicatedControlPlaneState,
    registration: &ClusterMemberRegistration,
    challenge_hex: &str,
    signature_hex: &str,
    expected_generation: Option<u64>,
    authority_min_protocol_version: u32,
    authority_protocol_version: u32,
    actor: &str,
    reason: &str,
    proposed_at: DateTime<Utc>,
) -> Result<ClusterMember, (AuthorityRejection, String)> {
    validate_text(actor, "cluster-membership actor").map_err(invalid_command)?;
    validate_reason(reason).map_err(invalid_command)?;
    if authority_min_protocol_version == 0
        || authority_min_protocol_version > authority_protocol_version
    {
        return Err(invalid_command("invalid authority protocol window"));
    }
    if registration.protocol_version < authority_min_protocol_version
        || registration.min_protocol_version > authority_protocol_version
    {
        return Err(conflict(format!(
            "incompatible wire-protocol cluster member window: authority v{authority_min_protocol_version}..=v{authority_protocol_version}, member v{}..=v{}",
            registration.min_protocol_version, registration.protocol_version
        )));
    }
    let (now, challenge_hash) = validate_challenged_registration(
        control,
        registration,
        challenge_hex,
        signature_hex,
        proposed_at,
    )?;
    if control.members.values().any(|member| {
        member.node_id != registration.node_id
            && (member.fingerprint == registration.fingerprint
                || member.endpoint == registration.endpoint
                || registration
                    .tls_server_certificate_fingerprint
                    .as_ref()
                    .is_some_and(|fingerprint| {
                        member.tls_server_certificate_fingerprint.as_ref() == Some(fingerprint)
                    }))
    }) {
        return Err(conflict(
            "cluster member identity, endpoint, or TLS binding already belongs to another node",
        ));
    }
    require_membership_audit_capacity(control)?;
    let existing = control.members.get(&registration.node_id).cloned();
    let mut activating_rollout = None;
    if let Some(member) = &existing {
        let changes_tls = member.tls_server_certificate_fingerprint
            != registration.tls_server_certificate_fingerprint;
        match control.certificate_rollouts.get(&member.node_id) {
            Some(rollout)
                if member.state == ClusterMemberState::Active
                    && changes_tls
                    && rollout.phase == ClusterCertificateRolloutPhase::Prepared
                    && rollout.member_generation == member.generation
                    && registration.tls_server_certificate_fingerprint.as_deref()
                        == Some(&rollout.next_tls_server_certificate_fingerprint)
                    && now < rollout.prepare_expires_at =>
            {
                if member.fingerprint != registration.fingerprint
                    || member.public_key != registration.public_key
                    || member.endpoint != registration.endpoint
                    || member.server_version != registration.server_version
                    || member.min_protocol_version != registration.min_protocol_version
                    || member.protocol_version != registration.protocol_version
                    || member.tls_server_certificate_fingerprint.as_deref()
                        != Some(&rollout.previous_tls_server_certificate_fingerprint)
                {
                    return Err(conflict(
                        "certificate rollout activation may only change the prepared TLS fingerprint",
                    ));
                }
                require_certificate_rollout_audit_capacity(control)?;
                activating_rollout = Some(rollout.clone());
            }
            Some(_) => {
                return Err(conflict(
                    "cluster member registration conflicts with its unfinished certificate rollout",
                ));
            }
            None if member.state == ClusterMemberState::Active && changes_tls => {
                return Err(conflict(
                    "active cluster member TLS changes require a prepared certificate rollout",
                ));
            }
            None => {}
        }
    }
    let (previous, previous_tls, generation, joined_at) = match existing {
        Some(member) => {
            let expected = expected_generation.ok_or_else(|| {
                conflict(format!(
                    "cluster member revision conflict: expected generation is required, current {}",
                    member.generation
                ))
            })?;
            if expected != member.generation {
                return Err(conflict(format!(
                    "cluster member revision conflict: expected {expected}, current {}",
                    member.generation
                )));
            }
            if member.state == ClusterMemberState::Revoked {
                return Err(conflict("revoked cluster member conflict: cannot rejoin"));
            }
            if member.fingerprint != registration.fingerprint
                || member.public_key != registration.public_key
            {
                return Err(conflict(
                    "cluster member durable identity cannot change during rejoin",
                ));
            }
            if member.tls_server_certificate_fingerprint.is_some()
                && registration.tls_server_certificate_fingerprint.is_none()
            {
                return Err(conflict(
                    "cluster member TLS certificate binding cannot be removed during rejoin",
                ));
            }
            (
                Some(member.state),
                member.tls_server_certificate_fingerprint,
                member
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| conflict("cluster member generation overflow"))?,
                member.joined_at,
            )
        }
        None => {
            if expected_generation.is_some() {
                return Err(conflict(
                    "cluster member revision conflict: no current member exists",
                ));
            }
            (None, None, 1, now)
        }
    };
    let membership_generation = control
        .membership_generation
        .checked_add(1)
        .ok_or_else(|| conflict("membership generation overflow"))?;
    let member = ClusterMember {
        node_id: registration.node_id.clone(),
        fingerprint: registration.fingerprint.clone(),
        public_key: registration.public_key.clone(),
        tls_server_certificate_fingerprint: registration.tls_server_certificate_fingerprint.clone(),
        endpoint: registration.endpoint.clone(),
        server_version: registration.server_version.clone(),
        min_protocol_version: registration.min_protocol_version,
        protocol_version: registration.protocol_version,
        state: ClusterMemberState::Active,
        generation,
        joined_at,
        updated_at: now,
        reason: reason.to_owned(),
    };
    control
        .members
        .insert(member.node_id.clone(), member.clone());
    control.membership_generation = membership_generation;
    control.membership_audit.push(ClusterMembershipAudit {
        membership_generation,
        node_id: member.node_id.clone(),
        member_generation: generation,
        previous,
        current: ClusterMemberState::Active,
        previous_tls_server_certificate_fingerprint: previous_tls,
        current_tls_server_certificate_fingerprint: member
            .tls_server_certificate_fingerprint
            .clone(),
        actor: actor.to_owned(),
        reason: reason.to_owned(),
        changed_at: now,
    });
    if let Some(mut rollout) = activating_rollout {
        let retire_previous_after = now
            .checked_add_signed(TimeDelta::seconds(rollout.minimum_overlap_seconds as i64))
            .ok_or_else(|| invalid_command("certificate rollout retirement deadline overflow"))?;
        let trust_generation = append_certificate_rollout_audit(
            control,
            &member.node_id,
            member.generation,
            Some(ClusterCertificateRolloutPhase::Prepared),
            Some(ClusterCertificateRolloutPhase::Activated),
            &rollout.previous_tls_server_certificate_fingerprint,
            &rollout.next_tls_server_certificate_fingerprint,
            actor,
            reason,
            now,
        )?;
        rollout.trust_generation = trust_generation;
        rollout.member_generation = member.generation;
        rollout.phase = ClusterCertificateRolloutPhase::Activated;
        rollout.retire_previous_after = Some(retire_previous_after);
        rollout.updated_at = now;
        rollout.reason = reason.to_owned();
        control
            .certificate_rollouts
            .insert(member.node_id.clone(), rollout);
    }
    consume_join_challenge(control, &challenge_hash, now);
    Ok(member)
}

#[allow(clippy::too_many_arguments)]
fn apply_set_member_state(
    control: &mut ReplicatedControlPlaneState,
    node_id: &str,
    state: ClusterMemberState,
    expected_generation: u64,
    actor: &str,
    reason: &str,
    proposed_at: DateTime<Utc>,
    authority_term: u64,
) -> Result<ClusterMember, (AuthorityRejection, String)> {
    if state == ClusterMemberState::Active {
        return Err(invalid_command(
            "invalid active membership transition: a fresh challenged join is required",
        ));
    }
    Uuid::parse_str(node_id).map_err(|_| invalid_command("invalid cluster member node id"))?;
    validate_text(actor, "cluster-membership actor").map_err(invalid_command)?;
    validate_reason(reason).map_err(invalid_command)?;
    let member = control
        .members
        .get(node_id)
        .cloned()
        .ok_or_else(|| conflict("cluster member not found"))?;
    if member.generation != expected_generation {
        return Err(conflict(format!(
            "cluster member revision conflict: expected {expected_generation}, current {}",
            member.generation
        )));
    }
    if member.state == ClusterMemberState::Revoked {
        return Err(conflict(
            "revoked cluster member state conflict: revocation is terminal",
        ));
    }
    if member.state == state {
        return Err(conflict("cluster member is already in the requested state"));
    }
    require_membership_audit_capacity(control)?;
    let certificate_rollout = control.certificate_rollouts.get(node_id).cloned();
    if state == ClusterMemberState::Left && certificate_rollout.is_some() {
        return Err(conflict(
            "cluster member leave conflict: finish its certificate rollout first",
        ));
    }
    if state == ClusterMemberState::Revoked && certificate_rollout.is_some() {
        require_certificate_rollout_audit_capacity(control)?;
    }
    let now = advance_authority_time(control, proposed_at)?;
    let active_owned = control
        .ownerships
        .values()
        .filter(|ownership| {
            ownership.owner_node_id == node_id
                && ownership.state == ClusterOwnershipState::Active
                && ownership.lease_expires_at > now
        })
        .cloned()
        .collect::<Vec<_>>();
    if state == ClusterMemberState::Left && !active_owned.is_empty() {
        return Err(conflict(
            "cluster member leave conflict: active ownership leases must be released first",
        ));
    }
    if state == ClusterMemberState::Revoked {
        if control
            .ownership_audit
            .len()
            .saturating_add(active_owned.len())
            > 100_000
        {
            return Err((
                AuthorityRejection::CapacityReached,
                "replicated ownership audit capacity is exhausted".into(),
            ));
        }
        for previous in active_owned {
            let generation = previous
                .generation
                .checked_add(1)
                .ok_or_else(|| conflict("agent ownership generation overflow"))?;
            let released = ClusterAgentOwnership {
                agent_id: previous.agent_id.clone(),
                owner_node_id: node_id.to_owned(),
                authority_term,
                fencing_token: previous.fencing_token,
                generation,
                state: ClusterOwnershipState::Released,
                lease_expires_at: now,
                updated_at: now,
                reason: reason.to_owned(),
            };
            control
                .ownerships
                .insert(released.agent_id.clone(), released);
            control.ownership_audit.push(ClusterAgentOwnershipAudit {
                agent_id: previous.agent_id,
                generation,
                previous_owner_node_id: Some(node_id.to_owned()),
                owner_node_id: node_id.to_owned(),
                authority_term,
                fencing_token: previous.fencing_token,
                operation: "release".into(),
                actor: actor.to_owned(),
                reason: reason.to_owned(),
                changed_at: now,
            });
        }
    }
    let generation = member
        .generation
        .checked_add(1)
        .ok_or_else(|| conflict("cluster member generation overflow"))?;
    let membership_generation = control
        .membership_generation
        .checked_add(1)
        .ok_or_else(|| conflict("membership generation overflow"))?;
    let updated = ClusterMember {
        state,
        generation,
        updated_at: now,
        reason: reason.to_owned(),
        ..member.clone()
    };
    control.members.insert(node_id.to_owned(), updated.clone());
    control.membership_generation = membership_generation;
    control.membership_audit.push(ClusterMembershipAudit {
        membership_generation,
        node_id: node_id.to_owned(),
        member_generation: generation,
        previous: Some(member.state),
        current: state,
        previous_tls_server_certificate_fingerprint: member
            .tls_server_certificate_fingerprint
            .clone(),
        current_tls_server_certificate_fingerprint: member.tls_server_certificate_fingerprint,
        actor: actor.to_owned(),
        reason: reason.to_owned(),
        changed_at: now,
    });
    if let Some(rollout) = certificate_rollout {
        append_certificate_rollout_audit(
            control,
            node_id,
            updated.generation,
            Some(rollout.phase),
            None,
            &rollout.previous_tls_server_certificate_fingerprint,
            &rollout.next_tls_server_certificate_fingerprint,
            actor,
            reason,
            now,
        )?;
        control.certificate_rollouts.remove(node_id);
    }
    Ok(updated)
}

fn require_replicated_active_member(
    control: &ReplicatedControlPlaneState,
    node_id: &str,
) -> Result<(), (AuthorityRejection, String)> {
    match control.members.get(node_id).map(|member| member.state) {
        Some(ClusterMemberState::Active) => Ok(()),
        Some(_) => Err(conflict(
            "agent ownership denied: owner node is not an active cluster member",
        )),
        None => Err(conflict(
            "agent ownership denied: owner node is not a cluster member",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_claim_ownership(
    control: &mut ReplicatedControlPlaneState,
    agent_id: &str,
    owner_node_id: &str,
    ttl_seconds: u64,
    expected_fencing_token: Option<u64>,
    actor: &str,
    reason: &str,
    proposed_at: DateTime<Utc>,
    authority_term: u64,
) -> Result<ClusterAgentOwnership, (AuthorityRejection, String)> {
    validate_ownership_request(agent_id, owner_node_id, ttl_seconds, actor, reason)
        .map_err(invalid_command)?;
    require_replicated_active_member(control, owner_node_id)?;
    if control.ownerships.len() >= 1_000_000 && !control.ownerships.contains_key(agent_id) {
        return Err((
            AuthorityRejection::CapacityReached,
            "replicated ownership directory capacity is exhausted".into(),
        ));
    }
    if control.ownership_audit.len() >= 100_000 {
        return Err((
            AuthorityRejection::CapacityReached,
            "replicated ownership audit capacity is exhausted".into(),
        ));
    }
    let now = advance_authority_time(control, proposed_at)?;
    let previous = control.ownerships.get(agent_id).cloned();
    let (fencing_token, generation, operation, previous_owner_node_id) = match previous {
        None => {
            if expected_fencing_token.is_some() {
                return Err(conflict(
                    "agent ownership conflict: no previous fencing token exists",
                ));
            }
            (1, 1, "claim", None)
        }
        Some(previous) => {
            if expected_fencing_token != Some(previous.fencing_token) {
                return Err(conflict(format!(
                    "agent ownership fencing conflict: expected {:?}, current {}",
                    expected_fencing_token, previous.fencing_token
                )));
            }
            if previous.state == ClusterOwnershipState::Active && previous.lease_expires_at > now {
                return Err(conflict(
                    "agent ownership conflict: current lease has not expired",
                ));
            }
            (
                previous
                    .fencing_token
                    .checked_add(1)
                    .ok_or_else(|| conflict("agent ownership fencing token overflow"))?,
                previous
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| conflict("agent ownership generation overflow"))?,
                "transfer",
                Some(previous.owner_node_id),
            )
        }
    };
    let lease_expires_at = ownership_expiry(now, ttl_seconds).map_err(invalid_command)?;
    let ownership = ClusterAgentOwnership {
        agent_id: agent_id.to_owned(),
        owner_node_id: owner_node_id.to_owned(),
        authority_term,
        fencing_token,
        generation,
        state: ClusterOwnershipState::Active,
        lease_expires_at,
        updated_at: now,
        reason: reason.to_owned(),
    };
    control
        .ownerships
        .insert(agent_id.to_owned(), ownership.clone());
    control.ownership_audit.push(ClusterAgentOwnershipAudit {
        agent_id: agent_id.to_owned(),
        generation,
        previous_owner_node_id,
        owner_node_id: owner_node_id.to_owned(),
        authority_term,
        fencing_token,
        operation: operation.into(),
        actor: actor.to_owned(),
        reason: reason.to_owned(),
        changed_at: now,
    });
    Ok(ownership)
}

#[allow(clippy::too_many_arguments)]
fn apply_renew_ownership(
    control: &mut ReplicatedControlPlaneState,
    agent_id: &str,
    owner_node_id: &str,
    fencing_token: u64,
    ttl_seconds: u64,
    actor: &str,
    reason: &str,
    proposed_at: DateTime<Utc>,
    authority_term: u64,
) -> Result<ClusterAgentOwnership, (AuthorityRejection, String)> {
    validate_ownership_request(agent_id, owner_node_id, ttl_seconds, actor, reason)
        .map_err(invalid_command)?;
    require_replicated_active_member(control, owner_node_id)?;
    if control.ownership_audit.len() >= 100_000 {
        return Err((
            AuthorityRejection::CapacityReached,
            "replicated ownership audit capacity is exhausted".into(),
        ));
    }
    let previous = control
        .ownerships
        .get(agent_id)
        .cloned()
        .ok_or_else(|| conflict("agent ownership not found"))?;
    let now = advance_authority_time(control, proposed_at)?;
    if previous.state != ClusterOwnershipState::Active
        || previous.owner_node_id != owner_node_id
        || previous.fencing_token != fencing_token
    {
        return Err(conflict("agent ownership fencing conflict"));
    }
    if previous.lease_expires_at <= now {
        return Err(conflict("agent ownership lease expired before renewal"));
    }
    let generation = previous
        .generation
        .checked_add(1)
        .ok_or_else(|| conflict("agent ownership generation overflow"))?;
    let ownership = ClusterAgentOwnership {
        authority_term,
        generation,
        lease_expires_at: ownership_expiry(now, ttl_seconds).map_err(invalid_command)?,
        updated_at: now,
        reason: reason.to_owned(),
        ..previous
    };
    control
        .ownerships
        .insert(agent_id.to_owned(), ownership.clone());
    control.ownership_audit.push(ClusterAgentOwnershipAudit {
        agent_id: agent_id.to_owned(),
        generation,
        previous_owner_node_id: Some(owner_node_id.to_owned()),
        owner_node_id: owner_node_id.to_owned(),
        authority_term,
        fencing_token,
        operation: "renew".into(),
        actor: actor.to_owned(),
        reason: reason.to_owned(),
        changed_at: now,
    });
    Ok(ownership)
}

#[allow(clippy::too_many_arguments)]
fn apply_release_ownership(
    control: &mut ReplicatedControlPlaneState,
    agent_id: &str,
    owner_node_id: &str,
    fencing_token: u64,
    actor: &str,
    reason: &str,
    proposed_at: DateTime<Utc>,
    authority_term: u64,
) -> Result<ClusterAgentOwnership, (AuthorityRejection, String)> {
    validate_ownership_identity(agent_id, owner_node_id).map_err(invalid_command)?;
    validate_text(actor, "cluster-ownership actor").map_err(invalid_command)?;
    validate_reason(reason).map_err(invalid_command)?;
    if control.ownership_audit.len() >= 100_000 {
        return Err((
            AuthorityRejection::CapacityReached,
            "replicated ownership audit capacity is exhausted".into(),
        ));
    }
    let previous = control
        .ownerships
        .get(agent_id)
        .cloned()
        .ok_or_else(|| conflict("agent ownership not found"))?;
    if previous.state != ClusterOwnershipState::Active
        || previous.owner_node_id != owner_node_id
        || previous.fencing_token != fencing_token
    {
        return Err(conflict("agent ownership fencing conflict"));
    }
    let now = advance_authority_time(control, proposed_at)?;
    let generation = previous
        .generation
        .checked_add(1)
        .ok_or_else(|| conflict("agent ownership generation overflow"))?;
    let ownership = ClusterAgentOwnership {
        authority_term,
        generation,
        state: ClusterOwnershipState::Released,
        lease_expires_at: now,
        updated_at: now,
        reason: reason.to_owned(),
        ..previous
    };
    control
        .ownerships
        .insert(agent_id.to_owned(), ownership.clone());
    control.ownership_audit.push(ClusterAgentOwnershipAudit {
        agent_id: agent_id.to_owned(),
        generation,
        previous_owner_node_id: Some(owner_node_id.to_owned()),
        owner_node_id: owner_node_id.to_owned(),
        authority_term,
        fencing_token,
        operation: "release".into(),
        actor: actor.to_owned(),
        reason: reason.to_owned(),
        changed_at: now,
    });
    Ok(ownership)
}

impl RaftStateMachine<ClusterRaftTypeConfig> for ClusterRaftStateMachine {
    type SnapshotBuilder = ClusterRaftSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> ClusterStorageResult<(
        Option<LogId<ClusterRaftNodeId>>,
        StoredMembership<ClusterRaftNodeId, ClusterRaftNode>,
    )> {
        let connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::read_state_machine(read_io(format!("lock Raft state machine: {error}")))
        })?;
        let state =
            load_persistent_state(&connection).map_err(StorageIOError::read_state_machine)?;
        Ok((state.last_applied, state.membership))
    }

    async fn apply<I>(&mut self, entries: I) -> ClusterStorageResult<Vec<AuthorityResponse>>
    where
        I: IntoIterator<Item = ClusterEntry> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        for pair in entries.windows(2) {
            if pair[1].log_id.index != pair[0].log_id.index.saturating_add(1) {
                return Err(StorageIOError::write_state_machine(read_io(format!(
                    "non-consecutive Raft state-machine apply {} then {}",
                    pair[0].log_id.index, pair[1].log_id.index
                )))
                .into());
            }
        }
        let mut connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::write_state_machine(read_io(format!(
                "lock Raft state machine: {error}"
            )))
        })?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageIOError::write_state_machine(read_io(error.to_string())))?;
        let mut state =
            load_persistent_state(&transaction).map_err(StorageIOError::read_state_machine)?;
        if let (Some(previous), Some(first)) = (state.last_applied, entries.first()) {
            if first.log_id.index <= previous.index {
                return Err(StorageIOError::write_state_machine(read_io(format!(
                    "refusing to reapply or regress from {previous} to {}",
                    first.log_id
                )))
                .into());
            }
        }
        let mut responses = Vec::with_capacity(entries.len());
        for entry in entries {
            state.last_applied = Some(entry.log_id);
            let response = match entry.payload {
                EntryPayload::Blank => AuthorityResponse::MetadataApplied {
                    sequence: state.authority.sequence,
                    log_id: entry.log_id,
                },
                EntryPayload::Membership(membership) => {
                    state.membership = StoredMembership::new(Some(entry.log_id), membership);
                    AuthorityResponse::MetadataApplied {
                        sequence: state.authority.sequence,
                        log_id: entry.log_id,
                    }
                }
                EntryPayload::Normal(command) => {
                    apply_authority_command(&mut state.authority, command, entry.log_id)
                }
            };
            responses.push(response);
        }
        write_persistent_state(&transaction, &state)
            .map_err(StorageIOError::write_state_machine)?;
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_state_machine(read_io(error.to_string())))?;
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        let frozen = self
            .context
            .conn
            .lock()
            .map_err(|error| format!("lock Raft state for snapshot: {error}"))
            .and_then(|connection| {
                load_persistent_state(&connection)
                    .map_err(|error| format!("freeze Raft snapshot state: {error}"))
            });
        ClusterRaftSnapshotBuilder {
            context: self.context.clone(),
            frozen,
        }
    }

    async fn begin_receiving_snapshot(&mut self) -> ClusterStorageResult<Box<Cursor<Vec<u8>>>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<ClusterRaftNodeId, ClusterRaftNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> ClusterStorageResult<()> {
        let data = snapshot.into_inner();
        let installed = validate_snapshot_data(meta, &data)
            .map_err(|error| StorageIOError::write_snapshot(Some(meta.signature()), error))?;
        let mut connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::write_snapshot(
                Some(meta.signature()),
                read_io(format!("lock Raft snapshot store: {error}")),
            )
        })?;
        let transaction = connection.transaction().map_err(|error| {
            StorageIOError::write_snapshot(Some(meta.signature()), read_io(error.to_string()))
        })?;
        let current =
            load_persistent_state(&transaction).map_err(StorageIOError::read_state_machine)?;
        match (current.last_applied, installed.last_applied) {
            (Some(current_log_id), Some(installed_log_id))
                if installed_log_id.index < current_log_id.index
                    || (installed_log_id.index == current_log_id.index
                        && installed_log_id != current_log_id) =>
            {
                return Err(StorageIOError::write_snapshot(
                    Some(meta.signature()),
                    read_io(format!(
                        "refusing to roll state machine back from {current_log_id} to \
                         {installed_log_id}"
                    )),
                )
                .into());
            }
            (Some(current_log_id), None) => {
                return Err(StorageIOError::write_snapshot(
                    Some(meta.signature()),
                    read_io(format!(
                        "refusing to replace applied state at {current_log_id} with an empty snapshot"
                    )),
                )
                .into());
            }
            _ => {}
        }
        if current.last_applied == installed.last_applied
            && SnapshotState::from(&current) != installed
        {
            return Err(StorageIOError::write_snapshot(
                Some(meta.signature()),
                read_io("snapshot conflicts with state already applied at the same log id"),
            )
            .into());
        }
        let state = PersistentState {
            last_applied: installed.last_applied,
            membership: installed.membership,
            authority: installed.authority,
            snapshot_sequence: current.snapshot_sequence,
        };
        write_persistent_state(&transaction, &state)
            .map_err(StorageIOError::write_state_machine)?;
        write_snapshot_record(&transaction, meta, &data)
            .map_err(|error| StorageIOError::write_snapshot(Some(meta.signature()), error))?;
        transaction.commit().map_err(|error| {
            StorageIOError::write_snapshot(Some(meta.signature()), read_io(error.to_string()))
        })?;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> ClusterStorageResult<Option<Snapshot<ClusterRaftTypeConfig>>> {
        let connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::read_snapshot(
                None,
                read_io(format!("lock Raft snapshot store: {error}")),
            )
        })?;
        let snapshot = read_snapshot_record(&connection)
            .map_err(|error| StorageIOError::read_snapshot(None, error))?;
        Ok(snapshot.map(|(meta, data)| Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        }))
    }
}

impl RaftSnapshotBuilder<ClusterRaftTypeConfig> for ClusterRaftSnapshotBuilder {
    async fn build_snapshot(&mut self) -> ClusterStorageResult<Snapshot<ClusterRaftTypeConfig>> {
        let frozen = self
            .frozen
            .as_ref()
            .map_err(|error| StorageIOError::read_state_machine(read_io(error.clone())))?;
        let data = serialize(&SnapshotState::from(frozen))
            .map_err(|error| StorageIOError::write_snapshot(None, error))?;
        let mut connection = self.context.conn.lock().map_err(|error| {
            StorageIOError::write_snapshot(
                None,
                read_io(format!("lock Raft snapshot store: {error}")),
            )
        })?;
        let transaction = connection
            .transaction()
            .map_err(|error| StorageIOError::write_snapshot(None, read_io(error.to_string())))?;
        let mut current =
            load_persistent_state(&transaction).map_err(StorageIOError::read_state_machine)?;
        current.snapshot_sequence = current.snapshot_sequence.checked_add(1).ok_or_else(|| {
            StorageIOError::write_snapshot(None, read_io("Raft snapshot sequence exhausted"))
        })?;
        let snapshot_id = match frozen.last_applied {
            Some(log_id) => format!(
                "{}-{}-{}",
                log_id.leader_id, log_id.index, current.snapshot_sequence
            ),
            None => format!("empty-{}", current.snapshot_sequence),
        };
        let meta = SnapshotMeta {
            last_log_id: frozen.last_applied,
            last_membership: frozen.membership.clone(),
            snapshot_id,
        };
        write_persistent_state(&transaction, &current)
            .map_err(StorageIOError::write_state_machine)?;

        let replace_current = transaction
            .query_row(
                "SELECT meta_json FROM cluster_raft_snapshot WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| StorageIOError::read_snapshot(None, read_io(error.to_string())))?
            .map(|bytes| {
                deserialize::<SnapshotMeta<ClusterRaftNodeId, ClusterRaftNode>>(
                    &bytes,
                    "snapshot metadata",
                )
                .map(|existing| {
                    meta.last_log_id.map(|id| id.index).unwrap_or(0)
                        >= existing.last_log_id.map(|id| id.index).unwrap_or(0)
                })
            })
            .transpose()
            .map_err(|error| StorageIOError::read_snapshot(None, error))?
            .unwrap_or(true);
        if replace_current {
            write_snapshot_record(&transaction, &meta, &data)
                .map_err(|error| StorageIOError::write_snapshot(Some(meta.signature()), error))?;
        }
        transaction.commit().map_err(|error| {
            StorageIOError::write_snapshot(Some(meta.signature()), read_io(error.to_string()))
        })?;
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openraft::storage::{RaftLogStorage, RaftStateMachine};
    use openraft::testing::{StoreBuilder, Suite};
    use openraft::{CommittedLeaderId, Entry, LogId, RaftSnapshotBuilder};

    use super::*;

    #[derive(Default)]
    struct SqliteStoreBuilder;

    impl StoreBuilder<ClusterRaftTypeConfig, ClusterRaftLogStore, ClusterRaftStateMachine>
        for SqliteStoreBuilder
    {
        async fn build(
            &self,
        ) -> ClusterStorageResult<((), ClusterRaftLogStore, ClusterRaftStateMachine)> {
            let context = Arc::new(
                SqliteContextManager::in_memory()
                    .map_err(|error| StorageIOError::write(read_io(error.to_string())))?,
            );
            let (log, state) = open_cluster_raft_storage(context)?;
            Ok(((), log, state))
        }
    }

    #[test]
    fn openraft_storage_v2_conformance_suite() {
        Suite::test_all(SqliteStoreBuilder).unwrap();
    }

    fn log_id(term: u64, index: u64) -> LogId<ClusterRaftNodeId> {
        LogId::new(CommittedLeaderId::new(term, 1), index)
    }

    fn barrier(operation_id: Uuid, expected_sequence: Option<u64>) -> AuthorityCommand {
        AuthorityCommand::Barrier {
            operation_id: operation_id.to_string(),
            expected_sequence,
        }
    }

    fn normal_entry(
        log_id: LogId<ClusterRaftNodeId>,
        command: AuthorityCommand,
    ) -> Entry<ClusterRaftTypeConfig> {
        Entry {
            log_id,
            payload: EntryPayload::Normal(command),
        }
    }

    #[tokio::test]
    async fn authority_barriers_are_sequenced_and_idempotent() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let (_, mut state) = open_cluster_raft_storage(context).unwrap();
        let operation_id = Uuid::new_v4();
        let first_command = barrier(operation_id, Some(0));
        let first = normal_entry(log_id(1, 1), first_command.clone());
        let response = state.apply([first]).await.unwrap();
        assert_eq!(
            response,
            vec![AuthorityResponse::BarrierCommitted {
                operation_id: operation_id.to_string(),
                sequence: 1,
                log_id: log_id(1, 1),
                replayed: false,
            }]
        );

        let replay = normal_entry(log_id(1, 2), first_command.clone());
        let response = state.apply([replay]).await.unwrap();
        assert_eq!(
            response,
            vec![AuthorityResponse::BarrierCommitted {
                operation_id: operation_id.to_string(),
                sequence: 1,
                log_id: log_id(1, 1),
                replayed: true,
            }]
        );

        let conflict = normal_entry(log_id(1, 3), barrier(operation_id, Some(1)));
        let response = state.apply([conflict]).await.unwrap();
        assert_eq!(
            response,
            vec![AuthorityResponse::Rejected {
                operation_id: operation_id.to_string(),
                sequence: 1,
                log_id: log_id(1, 3),
                reason: AuthorityRejection::OperationIdConflict,
                message: "authority operation_id is already committed with a different command"
                    .into(),
            }]
        );
    }

    fn test_identity() -> (ring::signature::Ed25519KeyPair, String, String) {
        use ring::signature::KeyPair as _;

        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = pair
            .public_key()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let fingerprint = sha256_hex(pair.public_key().as_ref());
        (pair, public_key, fingerprint)
    }

    fn sign_registration(
        pair: &ring::signature::Ed25519KeyPair,
        cluster_id: &str,
        challenge_hex: &str,
        registration: &ClusterMemberRegistration,
    ) -> String {
        let payload = membership_join_payload(cluster_id, challenge_hex, registration).unwrap();
        pair.sign(&payload)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn authority_genesis_rejects_a_tls_leaf_shared_by_two_identities() {
        let (_, first_public_key, first_fingerprint) = test_identity();
        let (_, second_public_key, second_fingerprint) = test_identity();
        let shared_tls = Some("a".repeat(64));
        let member = |node_id: String, public_key: String, fingerprint: String, endpoint: &str| {
            AuthorityGenesisMember {
                node_id,
                fingerprint,
                public_key,
                tls_server_certificate_fingerprint: shared_tls.clone(),
                endpoint: endpoint.into(),
                server_version: "0.3.0".into(),
                min_protocol_version: 1,
                protocol_version: 2,
            }
        };
        let genesis = AuthorityGenesis {
            cluster_id: Uuid::new_v4().to_string(),
            members: vec![
                member(
                    Uuid::new_v4().to_string(),
                    first_public_key,
                    first_fingerprint,
                    "127.0.0.1:7777",
                ),
                member(
                    Uuid::new_v4().to_string(),
                    second_public_key,
                    second_fingerprint,
                    "127.0.0.1:7778",
                ),
            ],
        };
        let error = validate_and_build_genesis(&genesis, Utc::now()).unwrap_err();
        assert_eq!(error.0, AuthorityRejection::InvalidCommand);
        assert!(error.1.contains("TLS binding"), "{}", error.1);
    }

    #[test]
    fn expired_join_challenges_are_reclaimed_before_capacity_is_enforced() {
        let (_, public_key, fingerprint) = test_identity();
        let cluster_id = Uuid::new_v4().to_string();
        let started_at = Utc::now();
        let mut state = AuthorityState::default();
        let initialized = apply_authority_command(
            &mut state,
            AuthorityCommand::Initialize {
                operation_id: cluster_id.clone(),
                genesis: AuthorityGenesis {
                    cluster_id,
                    members: vec![AuthorityGenesisMember {
                        node_id: Uuid::new_v4().to_string(),
                        fingerprint,
                        public_key,
                        tls_server_certificate_fingerprint: None,
                        endpoint: "127.0.0.1:7777".into(),
                        server_version: "0.3.0".into(),
                        min_protocol_version: 1,
                        protocol_version: 2,
                    }],
                },
                proposed_at: started_at,
            },
            log_id(1, 1),
        );
        assert!(matches!(
            initialized,
            AuthorityResponse::ControlPlaneInitialized { .. }
        ));
        let control = state.control_plane.as_mut().expect("initialized authority");
        for index in 0..4_096_u64 {
            let challenge_hex = format!("{index:064x}");
            let challenge = hex_decode(&challenge_hex).expect("fixed-width challenge");
            control.join_challenges.insert(
                sha256_hex(&challenge),
                ReplicatedJoinChallenge {
                    challenge_hex,
                    expires_at: started_at + TimeDelta::seconds(1),
                    consumed_at: None,
                },
            );
        }

        let replacement = apply_authority_command(
            &mut state,
            AuthorityCommand::IssueJoinChallenge {
                operation_id: Uuid::new_v4().to_string(),
                challenge_hex: "ff".repeat(32),
                ttl_seconds: 60,
                proposed_at: started_at + TimeDelta::seconds(2),
            },
            log_id(1, 2),
        );
        assert!(matches!(
            replacement,
            AuthorityResponse::JoinChallengeIssued { .. }
        ));
        assert_eq!(
            state
                .control_plane
                .as_ref()
                .expect("initialized authority")
                .join_challenges
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn replicated_membership_and_ownership_are_deterministic_and_replay_safe() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let (_, mut state) = open_cluster_raft_storage(context.clone()).unwrap();
        let (_, seed_public_key, seed_fingerprint) = test_identity();
        let seed_node_id = Uuid::new_v4().to_string();
        let cluster_id = Uuid::new_v4().to_string();
        let started_at = Utc::now();
        let genesis = AuthorityGenesis {
            cluster_id: cluster_id.clone(),
            members: vec![AuthorityGenesisMember {
                node_id: seed_node_id.clone(),
                fingerprint: seed_fingerprint,
                public_key: seed_public_key,
                tls_server_certificate_fingerprint: Some("a".repeat(64)),
                endpoint: "127.0.0.1:7777".into(),
                server_version: "0.3.0".into(),
                min_protocol_version: 1,
                protocol_version: 2,
            }],
        };
        let initialized = state
            .apply([normal_entry(
                log_id(1, 1),
                AuthorityCommand::Initialize {
                    operation_id: cluster_id.clone(),
                    genesis: genesis.clone(),
                    proposed_at: started_at,
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &initialized[0],
            AuthorityResponse::ControlPlaneInitialized {
                sequence: 1,
                replayed: false,
                ..
            }
        ));

        let challenge_operation = Uuid::new_v4();
        let challenge_hex = "bc".repeat(32);
        let challenge_response = state
            .apply([normal_entry(
                log_id(1, 2),
                AuthorityCommand::IssueJoinChallenge {
                    operation_id: challenge_operation.to_string(),
                    challenge_hex: challenge_hex.clone(),
                    ttl_seconds: 60,
                    proposed_at: started_at + TimeDelta::seconds(1),
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &challenge_response[0],
            AuthorityResponse::JoinChallengeIssued {
                sequence: 2,
                replayed: false,
                ..
            }
        ));

        let (joining_pair, joining_public_key, joining_fingerprint) = test_identity();
        let registration = ClusterMemberRegistration {
            node_id: Uuid::new_v4().to_string(),
            fingerprint: joining_fingerprint,
            public_key: joining_public_key,
            tls_server_certificate_fingerprint: Some("b".repeat(64)),
            endpoint: "127.0.0.1:7778".into(),
            server_version: "0.3.0".into(),
            min_protocol_version: 1,
            protocol_version: 2,
        };
        let payload = membership_join_payload(&cluster_id, &challenge_hex, &registration).unwrap();
        let signature_hex = joining_pair
            .sign(&payload)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let registered = state
            .apply([normal_entry(
                log_id(1, 3),
                AuthorityCommand::RegisterMember {
                    operation_id: Uuid::new_v4().to_string(),
                    registration: registration.clone(),
                    challenge_hex,
                    signature_hex,
                    expected_generation: None,
                    authority_min_protocol_version: 1,
                    authority_protocol_version: 2,
                    actor: "operator".into(),
                    reason: "admit workload node".into(),
                    proposed_at: started_at + TimeDelta::seconds(2),
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &registered[0],
            AuthorityResponse::MemberUpdated {
                member,
                sequence: 3,
                ..
            } if member.node_id == registration.node_id
        ));

        let agent_id = Uuid::new_v4().to_string();
        let claim_operation = Uuid::new_v4().to_string();
        let claim = AuthorityCommand::ClaimOwnership {
            operation_id: claim_operation,
            agent_id: agent_id.clone(),
            owner_node_id: seed_node_id.clone(),
            ttl_seconds: 60,
            expected_fencing_token: None,
            actor: "operator".into(),
            reason: "place agent".into(),
            proposed_at: started_at + TimeDelta::seconds(3),
        };
        let claimed = state
            .apply([normal_entry(log_id(1, 4), claim.clone())])
            .await
            .unwrap();
        let AuthorityResponse::OwnershipUpdated {
            ownership: claimed_ownership,
            sequence: 4,
            ..
        } = &claimed[0]
        else {
            panic!("expected replicated ownership claim");
        };
        assert_eq!(claimed_ownership.fencing_token, 1);
        assert_eq!(claimed_ownership.authority_term, 1);

        let mut replay = claim;
        if let AuthorityCommand::ClaimOwnership { proposed_at, .. } = &mut replay {
            *proposed_at = started_at + TimeDelta::seconds(10);
        }
        let replayed = state
            .apply([normal_entry(log_id(1, 5), replay)])
            .await
            .unwrap();
        assert!(matches!(
            &replayed[0],
            AuthorityResponse::OwnershipUpdated {
                sequence: 4,
                log_id: committed_log_id,
                replayed: true,
                ..
            } if *committed_log_id == log_id(1, 4)
        ));

        let renewed = state
            .apply([normal_entry(
                log_id(2, 6),
                AuthorityCommand::RenewOwnership {
                    operation_id: Uuid::new_v4().to_string(),
                    agent_id: agent_id.clone(),
                    owner_node_id: seed_node_id.clone(),
                    fencing_token: 1,
                    ttl_seconds: 60,
                    actor: "operator".into(),
                    reason: "renew agent".into(),
                    proposed_at: started_at + TimeDelta::seconds(4),
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &renewed[0],
            AuthorityResponse::OwnershipUpdated {
                ownership,
                sequence: 5,
                ..
            } if ownership.generation == 2
                && ownership.authority_term == 2
                && ownership.fencing_token == 1
        ));

        state
            .apply([normal_entry(
                log_id(2, 7),
                AuthorityCommand::ReleaseOwnership {
                    operation_id: Uuid::new_v4().to_string(),
                    agent_id: agent_id.clone(),
                    owner_node_id: seed_node_id,
                    fencing_token: 1,
                    actor: "operator".into(),
                    reason: "release agent".into(),
                    proposed_at: started_at + TimeDelta::seconds(5),
                },
            )])
            .await
            .unwrap();
        let advanced_to = started_at + TimeDelta::seconds(600);
        let advanced = state
            .apply([normal_entry(
                log_id(2, 8),
                AuthorityCommand::AdvanceTime {
                    operation_id: Uuid::new_v4().to_string(),
                    proposed_at: advanced_to,
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &advanced[0],
            AuthorityResponse::AuthorityTimeAdvanced {
                logical_time,
                ..
            } if *logical_time == advanced_to
        ));
        let view = read_replicated_authority_view(&context)
            .unwrap()
            .expect("initialized authority view");
        assert_eq!(view.genesis, genesis);
        assert_eq!(view.membership.generation, 2);
        assert_eq!(view.membership.members.len(), 2);
        assert_eq!(view.ownerships.len(), 1);
        assert_eq!(view.ownerships[0].agent_id, agent_id);
        assert_eq!(view.ownerships[0].state, ClusterOwnershipState::Released);
        assert_eq!(view.ownerships[0].authority_term, 2);
        assert_eq!(view.ownership_audit.len(), 3);
        assert_eq!(
            view.ownership_audit
                .iter()
                .map(|entry| entry.authority_term)
                .collect::<Vec<_>>(),
            [1, 2, 2]
        );
        assert_eq!(view.logical_time, advanced_to);
        let connection = context.conn.lock().unwrap();
        let persisted = load_persistent_state(&connection).unwrap();
        assert_eq!(persisted.authority.sequence, 6);
        assert_eq!(persisted.authority.receipts.len(), 6);
        let mut corrupted = persisted
            .authority
            .control_plane
            .expect("initialized authority");
        corrupted.ownership_audit[1].authority_term = 0;
        assert!(
            validate_control_plane_state(&corrupted).is_err(),
            "zero or corrupted authority terms must prevent participation"
        );
    }

    #[tokio::test]
    async fn certificate_rollout_is_bounded_replay_safe_and_never_reuses_retired_leaves() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let (_, mut state) = open_cluster_raft_storage(context.clone()).unwrap();
        let started_at = Utc::now();
        let cluster_id = Uuid::new_v4().to_string();
        let node_id = Uuid::new_v4().to_string();
        let (pair, public_key, fingerprint) = test_identity();
        let old_tls = "a".repeat(64);
        let new_tls = "b".repeat(64);
        let genesis = AuthorityGenesis {
            cluster_id: cluster_id.clone(),
            members: vec![AuthorityGenesisMember {
                node_id: node_id.clone(),
                fingerprint: fingerprint.clone(),
                public_key: public_key.clone(),
                tls_server_certificate_fingerprint: Some(old_tls.clone()),
                endpoint: "127.0.0.1:7777".into(),
                server_version: "0.3.0".into(),
                min_protocol_version: 1,
                protocol_version: 2,
            }],
        };
        state
            .apply([normal_entry(
                log_id(1, 1),
                AuthorityCommand::Initialize {
                    operation_id: Uuid::new_v4().to_string(),
                    genesis,
                    proposed_at: started_at,
                },
            )])
            .await
            .unwrap();

        let prepare_challenge = "c1".repeat(32);
        state
            .apply([normal_entry(
                log_id(1, 2),
                AuthorityCommand::IssueJoinChallenge {
                    operation_id: Uuid::new_v4().to_string(),
                    challenge_hex: prepare_challenge.clone(),
                    ttl_seconds: 60,
                    proposed_at: started_at + TimeDelta::seconds(1),
                },
            )])
            .await
            .unwrap();
        let candidate = ClusterMemberRegistration {
            node_id: node_id.clone(),
            fingerprint: fingerprint.clone(),
            public_key: public_key.clone(),
            tls_server_certificate_fingerprint: Some(new_tls.clone()),
            endpoint: "127.0.0.1:7777".into(),
            server_version: "0.3.0".into(),
            min_protocol_version: 1,
            protocol_version: 2,
        };
        let prepare = AuthorityCommand::PrepareMemberCertificateRollout {
            operation_id: Uuid::new_v4().to_string(),
            registration: candidate.clone(),
            challenge_hex: prepare_challenge.clone(),
            signature_hex: sign_registration(&pair, &cluster_id, &prepare_challenge, &candidate),
            expected_generation: 1,
            prepare_ttl_seconds: 5,
            minimum_overlap_seconds: 5,
            actor: "operator".into(),
            reason: "stage replacement leaf".into(),
            proposed_at: started_at + TimeDelta::seconds(1),
        };
        let prepared = state
            .apply([normal_entry(log_id(1, 3), prepare.clone())])
            .await
            .unwrap();
        let AuthorityResponse::CertificateRolloutUpdated {
            member,
            rollout: Some(rollout),
            sequence,
            replayed,
            ..
        } = &prepared[0]
        else {
            panic!("expected prepared certificate rollout");
        };
        assert_eq!(member.generation, 2);
        assert_eq!(*sequence, 3);
        assert!(!replayed);
        assert_eq!(rollout.phase, ClusterCertificateRolloutPhase::Prepared);
        assert!(rollout.accepts_fingerprint(
            &new_tls,
            rollout.prepare_expires_at - TimeDelta::nanoseconds(1)
        ));
        assert!(!rollout.accepts_fingerprint(&new_tls, rollout.prepare_expires_at));
        assert!(rollout.accepts_fingerprint(&old_tls, rollout.prepare_expires_at));
        {
            let connection = context.conn.lock().unwrap();
            let persisted = load_persistent_state(&connection).unwrap();
            let mut corrupted = persisted.authority.control_plane.unwrap();
            corrupted.tls_trust_generation += 1;
            assert!(
                validate_control_plane_state(&corrupted).is_err(),
                "rollout trust generation corruption must fail closed"
            );
        }

        let mut retry = prepare;
        if let AuthorityCommand::PrepareMemberCertificateRollout { proposed_at, .. } = &mut retry {
            *proposed_at = started_at + TimeDelta::seconds(20);
        }
        let replayed = state
            .apply([normal_entry(log_id(1, 4), retry)])
            .await
            .unwrap();
        assert!(matches!(
            &replayed[0],
            AuthorityResponse::CertificateRolloutUpdated {
                sequence: 3,
                replayed: true,
                ..
            }
        ));

        let activation_challenge = "c2".repeat(32);
        state
            .apply([normal_entry(
                log_id(1, 5),
                AuthorityCommand::IssueJoinChallenge {
                    operation_id: Uuid::new_v4().to_string(),
                    challenge_hex: activation_challenge.clone(),
                    ttl_seconds: 60,
                    proposed_at: started_at + TimeDelta::seconds(2),
                },
            )])
            .await
            .unwrap();
        let expired_activation = state
            .apply([normal_entry(
                log_id(1, 6),
                AuthorityCommand::RegisterMember {
                    operation_id: Uuid::new_v4().to_string(),
                    registration: candidate.clone(),
                    challenge_hex: activation_challenge.clone(),
                    signature_hex: sign_registration(
                        &pair,
                        &cluster_id,
                        &activation_challenge,
                        &candidate,
                    ),
                    expected_generation: Some(2),
                    authority_min_protocol_version: 1,
                    authority_protocol_version: 2,
                    actor: "operator".into(),
                    reason: "attempt expired candidate".into(),
                    proposed_at: rollout.prepare_expires_at,
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &expired_activation[0],
            AuthorityResponse::Rejected {
                reason: AuthorityRejection::Conflict,
                ..
            }
        ));
        let activated = state
            .apply([normal_entry(
                log_id(1, 7),
                AuthorityCommand::RegisterMember {
                    operation_id: Uuid::new_v4().to_string(),
                    registration: candidate.clone(),
                    challenge_hex: activation_challenge.clone(),
                    signature_hex: sign_registration(
                        &pair,
                        &cluster_id,
                        &activation_challenge,
                        &candidate,
                    ),
                    expected_generation: Some(2),
                    authority_min_protocol_version: 1,
                    authority_protocol_version: 2,
                    actor: "operator".into(),
                    reason: "activate replacement leaf".into(),
                    proposed_at: started_at + TimeDelta::seconds(3),
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &activated[0],
            AuthorityResponse::MemberUpdated { member, .. }
                if member.generation == 3
                    && member.tls_server_certificate_fingerprint.as_deref()
                        == Some(new_tls.as_str())
        ));
        let view = read_replicated_authority_view(&context).unwrap().unwrap();
        let rollout = &view.membership.certificate_rollouts[0];
        assert_eq!(rollout.phase, ClusterCertificateRolloutPhase::Activated);
        let retirement = rollout.retire_previous_after.unwrap();
        assert!(rollout.accepts_fingerprint(&old_tls, retirement - TimeDelta::nanoseconds(1)));
        assert!(!rollout.accepts_fingerprint(&old_tls, retirement));
        assert!(rollout.accepts_fingerprint(&new_tls, retirement));

        let early = state
            .apply([normal_entry(
                log_id(1, 8),
                AuthorityCommand::FinalizeMemberCertificateRollout {
                    operation_id: Uuid::new_v4().to_string(),
                    node_id: node_id.clone(),
                    expected_generation: 3,
                    actor: "operator".into(),
                    reason: "retire old leaf".into(),
                    proposed_at: started_at + TimeDelta::seconds(7),
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &early[0],
            AuthorityResponse::Rejected {
                reason: AuthorityRejection::Conflict,
                ..
            }
        ));
        let finalized = state
            .apply([normal_entry(
                log_id(1, 9),
                AuthorityCommand::FinalizeMemberCertificateRollout {
                    operation_id: Uuid::new_v4().to_string(),
                    node_id: node_id.clone(),
                    expected_generation: 3,
                    actor: "operator".into(),
                    reason: "retire old leaf".into(),
                    proposed_at: started_at + TimeDelta::seconds(8),
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &finalized[0],
            AuthorityResponse::CertificateRolloutUpdated {
                member,
                rollout: None,
                ..
            } if member.generation == 4
        ));
        let view = read_replicated_authority_view(&context).unwrap().unwrap();
        assert_eq!(view.membership.generation, 4);
        assert_eq!(view.membership.tls_trust_generation, 3);
        assert!(view.membership.certificate_rollouts.is_empty());
        assert_eq!(view.certificate_rollout_audit.len(), 3);
        drop(state);
        let (_, mut state) =
            open_cluster_raft_storage(context.clone()).expect("reopen qualified rollout state");

        let reuse_challenge = "c3".repeat(32);
        state
            .apply([normal_entry(
                log_id(1, 10),
                AuthorityCommand::IssueJoinChallenge {
                    operation_id: Uuid::new_v4().to_string(),
                    challenge_hex: reuse_challenge.clone(),
                    ttl_seconds: 60,
                    proposed_at: started_at + TimeDelta::seconds(9),
                },
            )])
            .await
            .unwrap();
        let retired_candidate = ClusterMemberRegistration {
            tls_server_certificate_fingerprint: Some(old_tls),
            ..candidate
        };
        let reuse = state
            .apply([normal_entry(
                log_id(1, 11),
                AuthorityCommand::PrepareMemberCertificateRollout {
                    operation_id: Uuid::new_v4().to_string(),
                    registration: retired_candidate.clone(),
                    challenge_hex: reuse_challenge.clone(),
                    signature_hex: sign_registration(
                        &pair,
                        &cluster_id,
                        &reuse_challenge,
                        &retired_candidate,
                    ),
                    expected_generation: 4,
                    prepare_ttl_seconds: 5,
                    minimum_overlap_seconds: 5,
                    actor: "operator".into(),
                    reason: "attempt retired leaf reuse".into(),
                    proposed_at: started_at + TimeDelta::seconds(10),
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &reuse[0],
            AuthorityResponse::Rejected {
                reason: AuthorityRejection::Conflict,
                ..
            }
        ));
        let direct_swap = state
            .apply([normal_entry(
                log_id(1, 12),
                AuthorityCommand::RegisterMember {
                    operation_id: Uuid::new_v4().to_string(),
                    registration: retired_candidate.clone(),
                    challenge_hex: reuse_challenge.clone(),
                    signature_hex: sign_registration(
                        &pair,
                        &cluster_id,
                        &reuse_challenge,
                        &retired_candidate,
                    ),
                    expected_generation: Some(4),
                    authority_min_protocol_version: 1,
                    authority_protocol_version: 2,
                    actor: "operator".into(),
                    reason: "attempt unprepared direct swap".into(),
                    proposed_at: started_at + TimeDelta::seconds(10),
                },
            )])
            .await
            .unwrap();
        assert!(matches!(
            &direct_swap[0],
            AuthorityResponse::Rejected {
                reason: AuthorityRejection::Conflict,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn corrupted_replicated_audit_history_fails_closed_on_open() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let (_, mut state) = open_cluster_raft_storage(context.clone()).unwrap();
        let (_, public_key, fingerprint) = test_identity();
        let cluster_id = Uuid::new_v4().to_string();
        state
            .apply([normal_entry(
                log_id(1, 1),
                AuthorityCommand::Initialize {
                    operation_id: cluster_id.clone(),
                    genesis: AuthorityGenesis {
                        cluster_id,
                        members: vec![AuthorityGenesisMember {
                            node_id: Uuid::new_v4().to_string(),
                            fingerprint,
                            public_key,
                            tls_server_certificate_fingerprint: None,
                            endpoint: "127.0.0.1:7777".into(),
                            server_version: "0.3.0".into(),
                            min_protocol_version: 1,
                            protocol_version: 2,
                        }],
                    },
                    proposed_at: Utc::now(),
                },
            )])
            .await
            .unwrap();
        {
            let connection = context.conn.lock().unwrap();
            let mut persisted = load_persistent_state(&connection).unwrap();
            persisted
                .authority
                .control_plane
                .as_mut()
                .unwrap()
                .membership_audit[0]
                .member_generation = 2;
            connection
                .execute(
                    "UPDATE cluster_raft_state SET authority_state_json = ?1 WHERE singleton = 1",
                    [serialize(&persisted.authority).unwrap()],
                )
                .unwrap();
        }
        assert!(
            open_cluster_raft_storage(context).is_err(),
            "corrupted replicated audit evidence must prevent participation"
        );
    }

    #[tokio::test]
    async fn vote_log_state_machine_and_snapshot_survive_restart() {
        let database = tempfile::NamedTempFile::new().unwrap();
        let path = database.path().to_path_buf();
        drop(database);
        let operation_id = Uuid::new_v4();
        let snapshot_meta;
        {
            let context = Arc::new(SqliteContextManager::new(&path).unwrap());
            let (mut log, mut state) = open_cluster_raft_storage(context).unwrap();
            let vote = Vote::new_committed(3, 7);
            log.save_vote(&vote).await.unwrap();
            let entry = normal_entry(log_id(3, 8), barrier(operation_id, Some(0)));
            log.append_entries(std::slice::from_ref(&entry)).unwrap();
            log.save_committed(Some(entry.log_id)).await.unwrap();
            state.apply([entry]).await.unwrap();
            let mut builder = state.get_snapshot_builder().await;
            snapshot_meta = builder.build_snapshot().await.unwrap().meta;
        }

        let context = Arc::new(SqliteContextManager::new(&path).unwrap());
        let (mut log, mut state) = open_cluster_raft_storage(context).unwrap();
        assert_eq!(
            log.read_vote().await.unwrap(),
            Some(Vote::new_committed(3, 7))
        );
        assert_eq!(
            log.get_log_state().await.unwrap().last_log_id,
            Some(log_id(3, 8))
        );
        assert_eq!(log.read_committed().await.unwrap(), Some(log_id(3, 8)));
        let (applied, _) = state.applied_state().await.unwrap();
        assert_eq!(applied, Some(log_id(3, 8)));
        assert_eq!(
            state.get_current_snapshot().await.unwrap().unwrap().meta,
            snapshot_meta
        );
    }

    #[test]
    fn malformed_durable_log_fails_closed_on_open() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        {
            let connection = context.conn.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO cluster_raft_log(log_index, entry_json)
                     VALUES (?1, ?2)",
                    params![index_blob(5).as_slice(), b"not-json".as_slice()],
                )
                .unwrap();
        }
        assert!(open_cluster_raft_storage(context).is_err());
    }

    #[tokio::test]
    async fn corrupted_snapshot_identity_and_receipt_sequence_fail_closed() {
        let snapshot_context = Arc::new(SqliteContextManager::in_memory().unwrap());
        {
            let (_, mut state) = open_cluster_raft_storage(snapshot_context.clone()).unwrap();
            state
                .apply([normal_entry(log_id(1, 1), barrier(Uuid::new_v4(), Some(0)))])
                .await
                .unwrap();
            state
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .unwrap();
        }
        {
            let connection = snapshot_context.conn.lock().unwrap();
            connection
                .execute(
                    "UPDATE cluster_raft_snapshot SET snapshot_id = 'tampered'",
                    [],
                )
                .unwrap();
        }
        assert!(open_cluster_raft_storage(snapshot_context).is_err());

        let receipt_context = Arc::new(SqliteContextManager::in_memory().unwrap());
        {
            let (_, mut state) = open_cluster_raft_storage(receipt_context.clone()).unwrap();
            state
                .apply([normal_entry(log_id(1, 1), barrier(Uuid::new_v4(), Some(0)))])
                .await
                .unwrap();
        }
        {
            let connection = receipt_context.conn.lock().unwrap();
            let mut state = load_persistent_state(&connection).unwrap();
            state.authority.sequence += 1;
            connection
                .execute(
                    "UPDATE cluster_raft_state SET authority_state_json = ?1
                     WHERE singleton = 1",
                    [serialize(&state.authority).unwrap()],
                )
                .unwrap();
        }
        assert!(open_cluster_raft_storage(receipt_context).is_err());
    }

    #[tokio::test]
    async fn durable_safety_pointers_cannot_regress_or_truncate_committed_logs() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let (mut log, _) = open_cluster_raft_storage(context).unwrap();
        log.save_vote(&Vote::new_committed(3, 7)).await.unwrap();
        assert!(log.save_vote(&Vote::new(2, 7)).await.is_err());

        log.save_committed(Some(log_id(3, 8))).await.unwrap();
        assert!(log.save_committed(Some(log_id(3, 7))).await.is_err());
        assert!(log.save_committed(None).await.is_err());
        assert!(log.truncate(log_id(3, 8)).await.is_err());
        log.truncate(log_id(3, 9)).await.unwrap();
    }

    #[test]
    fn conflicting_log_rewrites_and_holes_after_the_frontier_are_rejected() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let (log, _) = open_cluster_raft_storage(context).unwrap();
        let first = normal_entry(log_id(1, 1), barrier(Uuid::new_v4(), Some(0)));
        log.append_entries(std::slice::from_ref(&first)).unwrap();
        log.append_entries(std::slice::from_ref(&first)).unwrap();

        let conflicting = normal_entry(log_id(2, 1), barrier(Uuid::new_v4(), Some(0)));
        assert!(log.append_entries(&[conflicting]).is_err());
        let after_hole = normal_entry(log_id(2, 3), barrier(Uuid::new_v4(), Some(0)));
        assert!(log.append_entries(&[after_hole]).is_err());
    }

    #[tokio::test]
    async fn stale_snapshot_cannot_roll_back_applied_state() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let (_, mut state) = open_cluster_raft_storage(context).unwrap();
        state
            .apply([normal_entry(log_id(1, 1), barrier(Uuid::new_v4(), Some(0)))])
            .await
            .unwrap();
        let stale = state
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        state
            .apply([normal_entry(log_id(1, 2), barrier(Uuid::new_v4(), Some(1)))])
            .await
            .unwrap();

        assert!(state
            .install_snapshot(&stale.meta, stale.snapshot)
            .await
            .is_err());
        assert_eq!(state.applied_state().await.unwrap().0, Some(log_id(1, 2)));
    }
}
