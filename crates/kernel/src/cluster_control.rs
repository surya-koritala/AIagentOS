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
const MAX_REASON_BYTES: usize = 1024;
const MAX_PROFILE_BYTES: usize = 64 * 1024;
const MAX_PROFILE_VALUES: usize = 256;
const MAX_PROFILE_LABELS: usize = 128;
const MAX_PROFILE_TEXT_BYTES: usize = 256;
const MAX_MEMBER_ENDPOINT_BYTES: usize = 2048;
const MAX_MEMBER_VERSION_BYTES: usize = 256;
const MIN_JOIN_CHALLENGE_TTL_SECONDS: u64 = 5;
const MAX_JOIN_CHALLENGE_TTL_SECONDS: u64 = 300;

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

/// One transactionally consistent authority view used for discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterMembershipSnapshot {
    pub cluster_id: String,
    pub generation: u64,
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
            connection
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS cluster_node_identity (
                         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                         node_id TEXT NOT NULL UNIQUE,
                         private_key BLOB NOT NULL,
                         public_key BLOB NOT NULL,
                         fingerprint TEXT NOT NULL UNIQUE,
                         created_at TEXT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS cluster_node_control (
                         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                         availability TEXT NOT NULL,
                         generation INTEGER NOT NULL CHECK (generation >= 0),
                         profile_json TEXT NOT NULL,
                         reason TEXT NOT NULL,
                         updated_at TEXT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS cluster_node_control_audit (
                         generation INTEGER PRIMARY KEY,
                         previous_availability TEXT NOT NULL,
                         current_availability TEXT NOT NULL,
                         actor TEXT NOT NULL,
                         reason TEXT NOT NULL,
                         changed_at TEXT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS cluster_membership_authority (
                         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                         cluster_id TEXT NOT NULL UNIQUE,
                         generation INTEGER NOT NULL CHECK (generation >= 0),
                         created_at TEXT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS cluster_join_challenges (
                         challenge_hash TEXT PRIMARY KEY,
                         expires_at TEXT NOT NULL,
                         consumed_at TEXT
                     );
                     CREATE TABLE IF NOT EXISTS cluster_members (
                         node_id TEXT PRIMARY KEY,
                         fingerprint TEXT NOT NULL UNIQUE,
                         public_key TEXT NOT NULL,
                         endpoint TEXT NOT NULL UNIQUE,
                         server_version TEXT NOT NULL,
                         min_protocol_version INTEGER NOT NULL CHECK (min_protocol_version >= 1),
                         protocol_version INTEGER NOT NULL CHECK (protocol_version >= min_protocol_version),
                         state TEXT NOT NULL,
                         generation INTEGER NOT NULL CHECK (generation >= 1),
                         joined_at TEXT NOT NULL,
                         updated_at TEXT NOT NULL,
                         reason TEXT NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS cluster_membership_audit (
                         membership_generation INTEGER PRIMARY KEY,
                         node_id TEXT NOT NULL,
                         member_generation INTEGER NOT NULL CHECK (member_generation >= 1),
                         previous_state TEXT,
                         current_state TEXT NOT NULL,
                         actor TEXT NOT NULL,
                         reason TEXT NOT NULL,
                         changed_at TEXT NOT NULL
                     );",
                )
                .map_err(|error| storage_error(format!("cluster schema: {error}")))?;

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
                    identity
                }
            };
            let now = Utc::now().to_rfc3339();
            transaction
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
            transaction
                .execute(
                    "INSERT OR IGNORE INTO cluster_membership_authority
                     (singleton, cluster_id, generation, created_at)
                     VALUES (?1, ?2, 0, ?3)",
                    params![SINGLETON, uuid::Uuid::new_v4().to_string(), now],
                )
                .map_err(|error| {
                    storage_error(format!("initialize cluster membership authority: {error}"))
                })?;
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
        let (previous, member_generation, joined_at) = match existing {
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
                (
                    Some(member.state),
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
                (None, 1, now)
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
                 (node_id, fingerprint, public_key, endpoint, server_version,
                  min_protocol_version, protocol_version, state, generation,
                  joined_at, updated_at, reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9, ?10, ?11)
                 ON CONFLICT(node_id) DO UPDATE SET
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
        transaction
            .execute(
                "INSERT INTO cluster_membership_audit
                 (membership_generation, node_id, member_generation, previous_state,
                  current_state, actor, reason, changed_at)
                 VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7)",
                params![
                    membership_generation_i64,
                    registration.node_id,
                    member_generation_i64,
                    previous.map(ClusterMemberState::as_str),
                    actor,
                    reason,
                    now.to_rfc3339(),
                ],
            )
            .map_err(|error| storage_error(format!("audit cluster member join: {error}")))?;
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
        transaction
            .execute(
                "INSERT INTO cluster_membership_audit
                 (membership_generation, node_id, member_generation, previous_state,
                  current_state, actor, reason, changed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    membership_generation_i64,
                    node_id,
                    member_generation_i64,
                    member.state.as_str(),
                    state.as_str(),
                    actor,
                    reason,
                    now.to_rfc3339(),
                ],
            )
            .map_err(|error| storage_error(format!("audit cluster member state: {error}")))?;
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
                "SELECT node_id, fingerprint, public_key, endpoint, server_version,
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
                        previous_state, current_state, actor, reason, changed_at
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
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
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
                actor,
                reason,
                changed_at: parse_timestamp(&changed_at)?,
            });
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
    ))
}

impl TryFrom<StoredMember> for ClusterMember {
    type Error = ContextError;

    fn try_from(value: StoredMember) -> Result<Self, Self::Error> {
        let (
            node_id,
            fingerprint,
            public_key,
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
            "SELECT node_id, fingerprint, public_key, endpoint, server_version,
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

fn validate_text(value: &str, field: &str) -> Result<(), ContextError> {
    if value.trim().is_empty() || value.len() > MAX_REASON_BYTES || value.contains('\0') {
        return Err(storage_error(format!("invalid {field}")));
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<(), ContextError> {
    validate_text(reason, "cluster-control reason")
}

fn validate_member_registration(
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
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
}
