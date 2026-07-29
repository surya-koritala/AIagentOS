//! Durable consensus storage for the distributed control plane.
//!
//! This module implements OpenRaft's storage-v2 contracts inside the kernel's
//! existing SQLite durability boundary. The authenticated peer transport and
//! executable election runtime live in `cluster_runtime`; routing production
//! membership and ownership mutations through that quorum remains a separate
//! integration stage.

// OpenRaft's required StorageError is intentionally larger than Clippy's
// generic Result threshold. Storage-v2 implementations cannot replace or box
// that public trait error.
#![allow(clippy::result_large_err)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use chrono::Utc;
use openraft::storage::{LogFlushed, LogState, RaftLogStorage, RaftStateMachine, Snapshot};
use openraft::{
    AnyError, Entry, EntryPayload, LogId, OptionalSend, RaftLogReader, RaftSnapshotBuilder,
    SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    /// Base64 or PEM encoded Ed25519 membership identity public key.
    pub identity_public_key: String,
}

/// First deterministic authority command supported by the substrate.
///
/// A barrier is useful for proving that a client operation reached the
/// replicated state machine. Production membership and ownership commands are
/// added only when their public syscall paths are switched to quorum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityCommand {
    /// Commit an idempotent sequencing barrier.
    Barrier {
        /// Canonical UUID identifying this logical operation across retries.
        operation_id: String,
        /// Optional compare-and-set against the current authority sequence.
        expected_sequence: Option<u64>,
    },
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
    /// The command was committed by Raft but rejected by deterministic
    /// application validation.
    Rejected {
        operation_id: String,
        sequence: u64,
        log_id: LogId<ClusterRaftNodeId>,
        reason: AuthorityRejection,
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
        let AuthorityCommand::Barrier {
            operation_id: command_id,
            expected_sequence,
        } = &receipt.command;
        if operation_id != command_id || canonical_operation_id(operation_id).is_none() {
            return Err(read_io(format!(
                "authority receipt key {operation_id:?} does not match a canonical command id"
            )));
        }
        match &receipt.response {
            AuthorityResponse::BarrierCommitted {
                operation_id: response_id,
                sequence,
                log_id,
                replayed: false,
            } if response_id == operation_id
                && *sequence > 0
                && *sequence <= state.sequence
                && expected_sequence.is_none_or(|expected| expected == sequence - 1)
                && sequences.insert(*sequence)
                && log_ids.insert(*log_id) => {}
            _ => {
                return Err(read_io(format!(
                    "authority receipt {operation_id} contains an inconsistent response"
                )));
            }
        }
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
        let AuthorityResponse::BarrierCommitted { log_id, .. } = &receipt.response else {
            unreachable!("authority validation accepts only committed barrier receipts")
        };
        validate_log_id_at_or_before(*log_id, state.last_applied, "authority receipt")?;
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
    let AuthorityCommand::Barrier {
        operation_id,
        expected_sequence,
    } = &command;
    let Some(canonical_id) = canonical_operation_id(operation_id) else {
        return AuthorityResponse::Rejected {
            operation_id: operation_id.clone(),
            sequence: state.sequence,
            log_id,
            reason: AuthorityRejection::InvalidOperationId,
        };
    };
    if let Some(receipt) = state.receipts.get(&canonical_id) {
        if receipt.command == command {
            let AuthorityResponse::BarrierCommitted {
                operation_id,
                sequence,
                log_id,
                ..
            } = &receipt.response
            else {
                unreachable!("validated receipts contain committed barrier responses")
            };
            return AuthorityResponse::BarrierCommitted {
                operation_id: operation_id.clone(),
                sequence: *sequence,
                log_id: *log_id,
                replayed: true,
            };
        }
        return AuthorityResponse::Rejected {
            operation_id: canonical_id,
            sequence: state.sequence,
            log_id,
            reason: AuthorityRejection::OperationIdConflict,
        };
    }
    if expected_sequence.is_some_and(|expected| expected != state.sequence) {
        return AuthorityResponse::Rejected {
            operation_id: canonical_id,
            sequence: state.sequence,
            log_id,
            reason: AuthorityRejection::SequenceMismatch,
        };
    }
    if state.receipts.len() >= MAX_AUTHORITY_RECEIPTS {
        return AuthorityResponse::Rejected {
            operation_id: canonical_id,
            sequence: state.sequence,
            log_id,
            reason: AuthorityRejection::ReceiptCapacityReached,
        };
    }
    let Some(sequence) = state.sequence.checked_add(1) else {
        return AuthorityResponse::Rejected {
            operation_id: canonical_id,
            sequence: state.sequence,
            log_id,
            reason: AuthorityRejection::SequenceExhausted,
        };
    };
    state.sequence = sequence;
    let response = AuthorityResponse::BarrierCommitted {
        operation_id: canonical_id.clone(),
        sequence,
        log_id,
        replayed: false,
    };
    state.receipts.insert(
        canonical_id,
        StoredAuthorityReceipt {
            command,
            response: response.clone(),
        },
    );
    response
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
            }]
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
