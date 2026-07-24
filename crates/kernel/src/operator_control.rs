//! Durable operator tunables and the snapshot consistency barrier.
//!
//! Only settings that drive a live kernel path belong here. The legacy
//! [`crate::sysctl::Sysctl`] string map remains an internal prototype and is
//! deliberately not exposed as operator control.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::context::SqliteContextManager;
use crate::ContextError;

pub const MAX_AGENTS: &str = "kernel.max_agents";
pub const PROVIDER_PROBE_TIMEOUT_MS: &str = "operator.provider_probe_timeout_ms";
pub const SNAPSHOT_MAX_AGENTS: &str = "operator.snapshot_max_agents";

#[derive(Debug, Clone, Copy)]
struct TunableDefinition {
    name: &'static str,
    default: u64,
    min: u64,
    max: u64,
    description: &'static str,
}

const DEFINITIONS: [TunableDefinition; 3] = [
    TunableDefinition {
        name: MAX_AGENTS,
        default: 0,
        min: 0,
        max: 1_000_000,
        description: "Maximum durable agent identities admitted by this node; zero is unlimited.",
    },
    TunableDefinition {
        name: PROVIDER_PROBE_TIMEOUT_MS,
        default: 5_000,
        min: 50,
        max: 60_000,
        description: "Maximum wall-clock time allowed for one operator provider-health sample.",
    },
    TunableDefinition {
        name: SNAPSHOT_MAX_AGENTS,
        default: 10_000,
        min: 1,
        max: 100_000,
        description: "Maximum visible agent records returned in one operator snapshot.",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOperatorTunable {
    pub name: String,
    pub value: u64,
    pub revision: u64,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorTunable {
    pub name: String,
    pub value: u64,
    pub revision: u64,
    pub minimum: u64,
    pub maximum: u64,
    pub persisted: bool,
    pub updated_at: String,
    pub updated_by: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorTunableAudit {
    pub id: u64,
    pub name: String,
    pub revision: Option<u64>,
    pub previous_value: Option<u64>,
    pub requested_value: Option<u64>,
    pub effective_value: Option<u64>,
    pub action: String,
    pub outcome: String,
    pub actor: String,
    pub reason: Option<String>,
    pub created_at: String,
}

/// Non-sensitive record of an agent created from a package manifest.
///
/// This is intentionally an instance view, not the signed package registry
/// promised by issue #119. It lets operators distinguish package-created
/// workloads without exposing prompts, memory seeds, or manifest contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedPackageInstance {
    pub agent_id: String,
    pub tenant_id: String,
    pub name: String,
    pub provider: String,
    pub profile: String,
    pub loaded_at: String,
}

/// Live settings plus a reader/writer barrier around structural operator state.
///
/// Agent create/lifecycle mutations take the write side; snapshots take the
/// read side only while collecting subsystem-owned state. Provider probes run
/// after the guard is released, so a slow external health check cannot block
/// lifecycle progress.
pub struct OperatorControl {
    store: Arc<SqliteContextManager>,
    max_agents: AtomicU64,
    provider_probe_timeout_ms: AtomicU64,
    snapshot_max_agents: AtomicU64,
    snapshot_barrier: tokio::sync::RwLock<()>,
}

impl OperatorControl {
    pub fn new(store: Arc<SqliteContextManager>) -> Result<Self, ContextError> {
        for definition in DEFINITIONS {
            store.ensure_operator_tunable(definition.name, definition.default, "kernel-default")?;
        }
        let rows = store.list_operator_tunables()?;
        let value = |name: &str| -> Result<u64, ContextError> {
            let row = rows.iter().find(|row| row.name == name).ok_or_else(|| {
                ContextError::PersistenceFailed(format!(
                    "operator tunable {name:?} was not initialized"
                ))
            })?;
            validate_value(name, row.value)?;
            Ok(row.value)
        };
        Ok(Self {
            store,
            max_agents: AtomicU64::new(value(MAX_AGENTS)?),
            provider_probe_timeout_ms: AtomicU64::new(value(PROVIDER_PROBE_TIMEOUT_MS)?),
            snapshot_max_agents: AtomicU64::new(value(SNAPSHOT_MAX_AGENTS)?),
            snapshot_barrier: tokio::sync::RwLock::new(()),
        })
    }

    pub fn max_agents(&self) -> u64 {
        self.max_agents.load(Ordering::Acquire)
    }

    pub fn provider_probe_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.provider_probe_timeout_ms.load(Ordering::Acquire))
    }

    pub fn snapshot_max_agents(&self) -> usize {
        usize::try_from(self.snapshot_max_agents.load(Ordering::Acquire)).unwrap_or(usize::MAX)
    }

    pub(crate) async fn snapshot_guard(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.snapshot_barrier.read().await
    }

    pub(crate) async fn mutation_guard(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.snapshot_barrier.write().await
    }

    pub fn list(&self) -> Result<Vec<OperatorTunable>, ContextError> {
        self.store
            .list_operator_tunables()?
            .into_iter()
            .map(public_tunable)
            .collect()
    }

    pub fn audit(
        &self,
        name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<OperatorTunableAudit>, ContextError> {
        self.store
            .list_operator_tunable_audit(name, limit.clamp(1, 1_000))
    }

    pub async fn set(
        &self,
        name: &str,
        value: u64,
        expected_revision: u64,
        actor: &str,
    ) -> Result<OperatorTunable, ContextError> {
        if let Err(error) = validate_value(name, value) {
            let _ = self.store.record_operator_tunable_denial(
                name,
                Some(value),
                actor,
                &error.to_string(),
            );
            return Err(error);
        }
        let _guard = self.mutation_guard().await;
        let stored = match self
            .store
            .set_operator_tunable(name, value, expected_revision, actor)
        {
            Ok(stored) => stored,
            Err(error) => {
                let _ = self.store.record_operator_tunable_denial(
                    name,
                    Some(value),
                    actor,
                    &error.to_string(),
                );
                return Err(error);
            }
        };
        self.apply(&stored);
        public_tunable(stored)
    }

    pub async fn rollback(
        &self,
        name: &str,
        target_revision: u64,
        expected_revision: u64,
        actor: &str,
    ) -> Result<OperatorTunable, ContextError> {
        definition(name)?;
        let _guard = self.mutation_guard().await;
        let stored = match self.store.rollback_operator_tunable(
            name,
            target_revision,
            expected_revision,
            actor,
        ) {
            Ok(stored) => stored,
            Err(error) => {
                let _ = self.store.record_operator_tunable_denial(
                    name,
                    None,
                    actor,
                    &error.to_string(),
                );
                return Err(error);
            }
        };
        validate_value(name, stored.value)?;
        self.apply(&stored);
        public_tunable(stored)
    }

    pub fn record_denial(
        &self,
        name: &str,
        requested_value: Option<u64>,
        actor: &str,
        reason: &str,
    ) {
        let _ = self
            .store
            .record_operator_tunable_denial(name, requested_value, actor, reason);
    }

    fn apply(&self, stored: &StoredOperatorTunable) {
        let target = match stored.name.as_str() {
            MAX_AGENTS => &self.max_agents,
            PROVIDER_PROBE_TIMEOUT_MS => &self.provider_probe_timeout_ms,
            SNAPSHOT_MAX_AGENTS => &self.snapshot_max_agents,
            _ => unreachable!("validated operator tunable"),
        };
        target.store(stored.value, Ordering::Release);
    }
}

fn definition(name: &str) -> Result<TunableDefinition, ContextError> {
    DEFINITIONS
        .iter()
        .copied()
        .find(|definition| definition.name == name)
        .ok_or_else(|| {
            ContextError::StorageError(format!("invalid operator tunable name {name:?}"))
        })
}

fn validate_value(name: &str, value: u64) -> Result<(), ContextError> {
    let definition = definition(name)?;
    if !(definition.min..=definition.max).contains(&value) {
        return Err(ContextError::StorageError(format!(
            "invalid value {value} for operator tunable {name:?}; expected {}..={}",
            definition.min, definition.max
        )));
    }
    Ok(())
}

fn public_tunable(stored: StoredOperatorTunable) -> Result<OperatorTunable, ContextError> {
    let definition = definition(&stored.name)?;
    validate_value(&stored.name, stored.value)?;
    Ok(OperatorTunable {
        name: stored.name,
        value: stored.value,
        revision: stored.revision,
        minimum: definition.min,
        maximum: definition.max,
        persisted: true,
        updated_at: stored.updated_at,
        updated_by: stored.updated_by,
        description: definition.description.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn independent_sqlite_handles_cannot_both_win_the_same_revision() {
        let db_path = std::env::temp_dir().join(format!(
            "agentos-operator-cas-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let first_store = Arc::new(SqliteContextManager::new(&db_path).unwrap());
        let second_store = Arc::new(SqliteContextManager::new(&db_path).unwrap());
        let first = OperatorControl::new(first_store).unwrap();
        let second = OperatorControl::new(second_store).unwrap();

        let (left, right) = tokio::join!(
            first.set(MAX_AGENTS, 10, 1, "first"),
            second.set(MAX_AGENTS, 20, 1, "second")
        );
        assert_eq!(
            usize::from(left.is_ok()) + usize::from(right.is_ok()),
            1,
            "BEGIN IMMEDIATE + revision CAS must produce exactly one winner"
        );
        assert!(left
            .as_ref()
            .err()
            .or_else(|| right.as_ref().err())
            .unwrap()
            .to_string()
            .contains("conflict"));

        drop(first);
        drop(second);
        let verifier_store = Arc::new(SqliteContextManager::new(&db_path).unwrap());
        let verifier = OperatorControl::new(verifier_store).unwrap();
        let persisted = verifier
            .list()
            .unwrap()
            .into_iter()
            .find(|tunable| tunable.name == MAX_AGENTS)
            .unwrap();
        assert_eq!(persisted.revision, 2);
        assert!(matches!(persisted.value, 10 | 20));
        assert!(verifier
            .audit(Some(MAX_AGENTS), 10)
            .unwrap()
            .iter()
            .any(|entry| entry.outcome == "denied"));

        drop(verifier);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(format!("{}-wal", db_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", db_path.display()));
    }
}
