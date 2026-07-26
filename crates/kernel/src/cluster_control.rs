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
use ring::rand::SystemRandom;
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
}
