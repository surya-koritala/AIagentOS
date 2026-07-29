//! Context Manager — handles agent short-term and long-term memory.
//!
//! Provides SQLite-backed persistence for conversation history, working state,
//! tasks, results, and long-term facts with retry logic and summarization.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::memory_manager::Embedder;
use crate::{AgentId, ContextError};

/// A message in the agent's conversation history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub role: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

/// A task assigned to or created by an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task {
    pub id: uuid::Uuid,
    pub description: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Result of a completed task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskResult {
    pub task_id: uuid::Uuid,
    pub success: bool,
    pub output: serde_json::Value,
    pub completed_at: DateTime<Utc>,
}

/// Category for long-term memory facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactCategory {
    Preference,
    LearnedPattern,
    Fact,
    Instruction,
}

/// A fact stored in long-term memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fact {
    pub id: uuid::Uuid,
    pub content: String,
    pub category: FactCategory,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: DateTime<Utc>,
    pub embedding: Option<Vec<f32>>,
}

/// Durable usage record used for billing/metric reconciliation tests and
/// operator inspection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageRecord {
    pub tokens_used: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cached_tokens: u32,
    pub llm_requests: u32,
    pub retries: u32,
    pub provider_latency_ms: u64,
    pub provider_reported_requests: u32,
    pub estimated_requests: u32,
    pub provider: String,
    pub model: String,
    pub tool_calls: usize,
    pub estimated_cost_usd: f64,
    /// Exact charge applied by the budget enforcer, in micro-USD. This is the
    /// durable accounting source of truth; `estimated_cost_usd` is retained for
    /// operator display and backwards compatibility only.
    pub cost_micros: u64,
}

/// Restart-safe cumulative budget state reconstructed from durable usage rows.
///
/// Costs are summed row-by-row with saturating arithmetic so a corrupt or
/// extremely long-lived log cannot wrap a ceiling back to an apparently lower
/// spend. Agent-to-tenant mappings include zero-spend persisted agents as well
/// as legacy/orphaned usage rows (which map to [`DEFAULT_TENANT`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BudgetUsageSnapshot {
    pub global_micros: u64,
    pub per_agent_micros: HashMap<AgentId, u64>,
    pub per_tenant_micros: HashMap<String, u64>,
    pub agent_tenants: HashMap<AgentId, String>,
}

/// The durable subject boundary erased by a deletion transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionSubjectKind {
    Agent,
    User,
    Tenant,
}

impl DeletionSubjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::User => "user",
            Self::Tenant => "tenant",
        }
    }
}

/// Privacy-safe proof that one erasure transaction committed.
///
/// A receipt deliberately contains no subject id, tenant id, user id, actor,
/// free-form reason, or deleted content. The caller is responsible for keeping
/// the returned opaque receipt id alongside its external request record when
/// correlation is required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionReceipt {
    pub id: uuid::Uuid,
    pub subject_kind: DeletionSubjectKind,
    pub deleted_at: DateTime<Utc>,
    pub deleted_rows: BTreeMap<String, u64>,
    pub retained_records: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DurableDataClassification {
    pub table: &'static str,
    pub owner: &'static str,
    pub deletion: &'static str,
}

/// Canonical ownership/deletion catalog for every logical durable table.
///
/// The schema regression below compares this list with `sqlite_schema`, so a
/// new durable table cannot silently escape an explicit deletion decision.
pub const DURABLE_DATA_CATALOG: &[DurableDataClassification] = &[
    DurableDataClassification {
        table: "contexts",
        owner: "agent",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "facts",
        owner: "agent",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "conversations",
        owner: "agent",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "conversations_fts",
        owner: "agent",
        deletion: "erase-before-conversation",
    },
    DurableDataClassification {
        table: "usage_log",
        owner: "agent",
        deletion: "erase; shared quota ledger remains",
    },
    DurableDataClassification {
        table: "agent_kv",
        owner: "agent",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "context_spills",
        owner: "agent+tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "context_pressure",
        owner: "agent",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "context_snapshots",
        owner: "agent",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "generation_checkpoints",
        owner: "agent+tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "agents",
        owner: "agent+tenant",
        deletion: "erase-last",
    },
    DurableDataClassification {
        table: "loaded_package_instances",
        owner: "agent+tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "package_trust_keys",
        owner: "tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "package_artifacts",
        owner: "tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "package_installations",
        owner: "tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "package_install_history",
        owner: "tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "package_rate_limits",
        owner: "tenant+user-actor",
        deletion: "erase tenant; erase user actor limiter",
    },
    DurableDataClassification {
        table: "package_transparency",
        owner: "tenant; user is pseudonymous actor",
        deletion: "erase tenant; retain on user erasure",
    },
    DurableDataClassification {
        table: "package_audit",
        owner: "tenant; user is pseudonymous actor",
        deletion: "erase tenant; retain on user erasure",
    },
    DurableDataClassification {
        table: "operator_tunables",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "operator_tunable_audit",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "service_runtime",
        owner: "system; optional agent reference",
        deletion: "clear agent reference",
    },
    DurableDataClassification {
        table: "service_history",
        owner: "system; optional agent reference",
        deletion: "clear agent reference",
    },
    DurableDataClassification {
        table: "tenants",
        owner: "tenant",
        deletion: "erase-last",
    },
    DurableDataClassification {
        table: "users",
        owner: "user+tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "api_keys",
        owner: "user+tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "sessions",
        owner: "user+tenant",
        deletion: "erase",
    },
    DurableDataClassification {
        table: "quota_epoch_floor",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "quota_epochs",
        owner: "system+tenant+agent scopes",
        deletion: "erase subject cgroup scopes; retain shared scopes",
    },
    DurableDataClassification {
        table: "quota_receipts",
        owner: "system",
        deletion: "retain non-identifying accounting receipt",
    },
    DurableDataClassification {
        table: "quota_receipt_scopes",
        owner: "system+tenant+agent scopes",
        deletion: "erase subject cgroup scopes",
    },
    DurableDataClassification {
        table: "quota_refunded_receipts",
        owner: "system",
        deletion: "retain idempotency tombstone",
    },
    DurableDataClassification {
        table: "quota_migration_fence",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "accounting_integrity",
        owner: "system",
        deletion: "retain authenticated enforcement state",
    },
    DurableDataClassification {
        table: "accounting_events",
        owner: "system; record keys are keyed pseudonymous digests",
        deletion: "retain non-identifying integrity chain",
    },
    DurableDataClassification {
        table: "cluster_node_identity",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "cluster_node_control",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "cluster_node_control_audit",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "cluster_membership_authority",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "cluster_join_challenges",
        owner: "system",
        deletion: "retain until expiry/reconciliation",
    },
    DurableDataClassification {
        table: "cluster_members",
        owner: "system",
        deletion: "retain until membership removal",
    },
    DurableDataClassification {
        table: "cluster_membership_audit",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "cluster_agent_ownership",
        owner: "system",
        deletion: "retain fencing tombstone until cluster retirement",
    },
    DurableDataClassification {
        table: "cluster_agent_ownership_audit",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "storage_meta",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "schema_migrations",
        owner: "system",
        deletion: "retain",
    },
    DurableDataClassification {
        table: "deletion_receipts",
        owner: "system",
        deletion: "retain bounded non-identifying proof",
    },
];

/// Length of one fixed provider-rate accounting epoch.
///
/// Epoch identifiers accepted by the APIs below are Unix-minute numbers
/// (`unix_seconds / PROVIDER_RATE_EPOCH_SECONDS`), not process-relative
/// generations. This makes a boundary deterministic and restart-safe.
pub(crate) const PROVIDER_RATE_EPOCH_SECONDS: u64 = 60;

/// Durable lifecycle of one provider request reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderRateReceiptState {
    /// Capacity is committed, but provider I/O has not started.
    Reserved,
    /// Provider I/O may have happened, so the estimate must not be refunded.
    InFlight,
    /// Completion is unknown; the estimate is retained conservatively.
    Estimated,
    /// Provider-reported/derived actual usage replaced the estimate.
    Reconciled,
}

impl ProviderRateReceiptState {
    fn parse(value: &str) -> Result<Self, ContextError> {
        match value {
            "reserved" => Ok(Self::Reserved),
            "in_flight" => Ok(Self::InFlight),
            "estimated" => Ok(Self::Estimated),
            "reconciled" => Ok(Self::Reconciled),
            _ => Err(quota_error(format!(
                "invalid provider rate receipt state {value:?}"
            ))),
        }
    }
}

/// Affine identifier for one durable provider-rate reservation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProviderRateReservation {
    pub id: uuid::Uuid,
    pub epoch: u64,
    pub reserved_requests: u64,
    pub reserved_tokens: u64,
    pub state: ProviderRateReceiptState,
    /// Stable cgroup scope paths in root-to-leaf reservation order.
    pub cgroup_scopes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProviderRateRequest {
    pub receipt_id: uuid::Uuid,
    pub requested_epoch: u64,
    pub rpm: u32,
    pub tpm: u64,
    pub estimated_requests: u64,
    pub estimated_tokens: u64,
}

/// Durable usage and receipt-state counts for one effective provider epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProviderRateUsage {
    pub epoch: u64,
    pub requests: u64,
    pub tokens: u64,
    pub reserved_receipts: u64,
    pub in_flight_receipts: u64,
    pub estimated_receipts: u64,
    pub reconciled_receipts: u64,
}

/// Dimension that prevented a provider reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderRateLimitDimension {
    Requests,
    Tokens,
    /// A legacy database had process-local rate state that could not be
    /// reconstructed. It remains fail-closed for the rest of that one epoch.
    MigrationFence,
}

/// Stable durable quota namespace. Runtime cgroup ids must never be persisted:
/// only canonical semantic paths belong in [`QuotaScopeKind::Cgroup`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum QuotaScopeKind {
    Provider,
    Cgroup,
}

impl QuotaScopeKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Cgroup => "cgroup",
        }
    }

    fn parse(value: &str) -> Result<Self, ContextError> {
        match value {
            "provider" => Ok(Self::Provider),
            "cgroup" => Ok(Self::Cgroup),
            _ => Err(quota_error(format!("invalid quota scope kind {value:?}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct QuotaScopeKey {
    pub kind: QuotaScopeKind,
    pub id: String,
}

impl QuotaScopeKey {
    fn provider_global() -> Self {
        Self {
            kind: QuotaScopeKind::Provider,
            id: PROVIDER_QUOTA_SCOPE_ID.to_string(),
        }
    }

    fn cgroup(scope_id: &str) -> Self {
        Self {
            kind: QuotaScopeKind::Cgroup,
            id: scope_id.to_string(),
        }
    }
}

/// One root-to-leaf cgroup token constraint for a provider request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CgroupQuotaConstraint {
    pub scope_id: String,
    /// Zero means unlimited.
    pub token_limit: u64,
}

/// Durable aggregate and receipt states for one quota scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuotaScopeUsage {
    pub epoch: u64,
    pub scope: QuotaScopeKey,
    pub requests: u64,
    pub tokens: u64,
    pub reserved_receipts: u64,
    pub in_flight_receipts: u64,
    pub estimated_receipts: u64,
    pub reconciled_receipts: u64,
}

/// Result of an atomic provider-rate reservation attempt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProviderRateReserveOutcome {
    Reserved(ProviderRateReservation),
    Denied {
        epoch: u64,
        scope: QuotaScopeKey,
        dimension: ProviderRateLimitDimension,
        used: u64,
        requested: u64,
        limit: u64,
    },
}

/// Actions applied atomically while recovering provider reservations on boot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProviderRateRecovery {
    pub effective_epoch: u64,
    pub refunded_reserved: u64,
    pub retained_in_flight_estimates: u64,
}

const PROVIDER_QUOTA_SCOPE_KIND: &str = "provider";
const PROVIDER_QUOTA_SCOPE_ID: &str = "global";

#[cfg(test)]
thread_local! {
    /// Counts deliberate full receipt-ledger scans on the current test thread.
    /// Hot-path quota operations must stay at zero; recovery and integrity
    /// inspection intentionally increment it.
    static QUOTA_FULL_RECEIPT_SCANS: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredQuotaReceipt {
    id: uuid::Uuid,
    epoch: u64,
    state: ProviderRateReceiptState,
    reserved_requests: u64,
    reserved_tokens: u64,
    actual_requests: Option<u64>,
    actual_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredQuotaScope {
    key: QuotaScopeKey,
    order: u32,
    reserved_requests: u64,
    reserved_tokens: u64,
    actual_requests: Option<u64>,
    actual_tokens: Option<u64>,
}

fn quota_error(message: impl Into<String>) -> ContextError {
    ContextError::StorageError(format!(
        "durable quota accounting unavailable: {}",
        message.into()
    ))
}

fn u64_blob(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn parse_u64_blob(blob: Vec<u8>, field: &str) -> Result<u64, ContextError> {
    let bytes: [u8; 8] = blob.try_into().map_err(|blob: Vec<u8>| {
        quota_error(format!(
            "{field} is malformed: expected 8-byte unsigned integer, got {} bytes",
            blob.len()
        ))
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn validate_quota_scope_key(scope: &QuotaScopeKey) -> Result<(), ContextError> {
    if scope.id.is_empty() || scope.id.len() > 1024 || scope.id.contains('\0') {
        return Err(quota_error(format!(
            "invalid {:?} quota scope id",
            scope.kind
        )));
    }
    match scope.kind {
        QuotaScopeKind::Provider if scope.id != PROVIDER_QUOTA_SCOPE_ID => {
            Err(quota_error("only the provider/global scope is supported"))
        }
        QuotaScopeKind::Cgroup if !scope.id.starts_with('/') => Err(quota_error(
            "stable cgroup quota scopes must be absolute canonical paths",
        )),
        _ => Ok(()),
    }
}

/// The durable identity + config of a created agent, as stored in the `agents`
/// table. This is what lets a kernel rehydrate its agent registry after a
/// restart (graceful or crashed): the in-memory `AgentManager` is rebuilt from
/// these rows so a restored agent keeps its name, task, permission profile,
/// priority, and creation time — and the kernel can re-place it into the right
/// cgroup / namespaces / gate translation table so enforcement still applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedAgent {
    pub id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    /// The tenant this agent belongs to (the top-level isolation unit). Legacy
    /// rows / un-tenanted agents use [`DEFAULT_TENANT`]. Restored on rehydrate so
    /// the agent re-joins its tenant's namespace + cgroup after a restart.
    pub tenant_id: String,
    pub name: String,
    pub task: String,
    pub llm_provider: String,
    pub permission_profile: String,
    /// Scheduling priority as the raw 1..=5 value (see `Priority`).
    pub priority: u8,
    /// Serialized lifecycle state (`AgentState` as JSON).
    pub status: String,
    /// Serialized `SandboxConfig` (JSON), if the agent had one.
    pub sandbox_config_json: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
}

/// Public, non-sensitive metadata for a durable in-flight generation
/// checkpoint. The serialized prompt/messages remain inside the protected
/// SQLite store and are never returned by list APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationCheckpointMetadata {
    pub id: uuid::Uuid,
    pub agent_id: AgentId,
    pub version: u32,
    pub provider_id: String,
    pub model_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A claimed checkpoint plus the compatibility metadata needed by the kernel
/// before it restores a provider session.
#[derive(Debug, Clone)]
pub struct StoredGenerationCheckpoint {
    pub metadata: GenerationCheckpointMetadata,
    pub checkpoint: crate::execution::GenerationCheckpoint,
}

/// Durable operator view of context-pressure decisions for one agent. Spill
/// payloads remain in the protected per-agent KV namespace; this exposes only
/// counters and byte totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPressureStats {
    pub agent_id: AgentId,
    #[serde(default)]
    pub tenant_id: String,
    pub active_tokens: u32,
    pub budget_tokens: u32,
    #[serde(default)]
    pub agent_active_tokens: u64,
    #[serde(default)]
    pub agent_active_limit: u64,
    #[serde(default)]
    pub tenant_active_tokens: u64,
    #[serde(default)]
    pub tenant_active_limit: u64,
    #[serde(default)]
    pub global_active_tokens: u64,
    #[serde(default)]
    pub global_active_limit: u64,
    #[serde(default)]
    pub active_rejection_count: u64,
    pub spill_count: u64,
    pub evicted_messages: u64,
    pub stored_spills: u64,
    pub stored_spill_bytes: u64,
    #[serde(default)]
    pub agent_stored_bytes: u64,
    #[serde(default)]
    pub agent_storage_limit: u64,
    #[serde(default)]
    pub tenant_stored_bytes: u64,
    #[serde(default)]
    pub tenant_storage_limit: u64,
    #[serde(default)]
    pub global_stored_bytes: u64,
    #[serde(default)]
    pub global_storage_limit: u64,
    #[serde(default)]
    pub spill_retention_seconds: u64,
    pub error_count: u64,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextStorageLimits {
    pub per_agent_bytes: u64,
    pub per_tenant_bytes: u64,
    pub global_bytes: u64,
    pub spill_retention_seconds: u64,
}

impl Default for ContextStorageLimits {
    fn default() -> Self {
        Self {
            per_agent_bytes: 0,
            per_tenant_bytes: 0,
            global_bytes: 0,
            spill_retention_seconds: 30 * 24 * 60 * 60,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ContextStorageUsage {
    agent_bytes: u64,
    tenant_bytes: u64,
    global_bytes: u64,
}

pub const GENERATION_CHECKPOINT_VERSION: u32 = 1;
const MAX_GENERATION_CHECKPOINTS_PER_AGENT: usize = 8;

/// Agent's working context — short-term memory for the current session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentContext {
    pub conversation_history: Vec<Message>,
    pub working_state: serde_json::Value,
    pub active_tasks: Vec<Task>,
    pub intermediate_results: Vec<TaskResult>,
    pub token_count: u32,
}

impl Default for AgentContext {
    fn default() -> Self {
        Self {
            conversation_history: Vec::new(),
            working_state: serde_json::Value::Null,
            active_tasks: Vec::new(),
            intermediate_results: Vec::new(),
            token_count: 0,
        }
    }
}

/// The Context Manager trait.
#[async_trait::async_trait]
pub trait ContextManager: Send + Sync {
    async fn create_context(&self, agent_id: AgentId) -> Result<(), ContextError>;
    async fn get_context(&self, agent_id: AgentId) -> Result<AgentContext, ContextError>;
    async fn persist_context(
        &self,
        agent_id: AgentId,
        context: &AgentContext,
    ) -> Result<(), ContextError>;
    async fn restore_context(&self, agent_id: AgentId) -> Result<AgentContext, ContextError>;
    async fn summarize_overflow(
        &self,
        context: &AgentContext,
        token_limit: u32,
    ) -> Result<AgentContext, ContextError>;
    async fn store_fact(&self, agent_id: AgentId, fact: Fact) -> Result<(), ContextError>;
    async fn query_memory(&self, agent_id: AgentId, query: &str)
        -> Result<Vec<Fact>, ContextError>;
}

/// Maximum retry attempts for persistence operations.
const MAX_RETRIES: u32 = 3;

/// The implicit tenant assigned to agents that predate tenancy (or are created
/// through the un-tenanted `create_agent_full` path). Cross-tenant isolation is
/// still enforced relative to this id.
pub const DEFAULT_TENANT: &str = "default";

fn memory_content_hash(content: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, content.as_bytes());
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn quota_scope_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn record_deleted_rows(
    deleted_rows: &mut BTreeMap<String, u64>,
    key: impl Into<String>,
    count: usize,
) {
    if count > 0 {
        deleted_rows.insert(key.into(), u64::try_from(count).unwrap_or(u64::MAX));
    }
}

#[cfg(test)]
fn crash_erasure_after_step_for_test(step: &str) {
    if std::env::var("AIAGENTOS_TEST_EXIT_ERASURE_AFTER_STEP").as_deref() == Ok(step) {
        std::process::exit(87);
    }
}

#[cfg(not(test))]
#[inline]
fn crash_erasure_after_step_for_test(_step: &str) {}

#[cfg(test)]
fn crash_multi_table_mutation_after_step_for_test(step: &str) {
    if std::env::var("AIAGENTOS_TEST_EXIT_MULTI_TABLE_AFTER_STEP").as_deref() == Ok(step) {
        std::process::exit(86);
    }
}

#[cfg(not(test))]
#[inline]
fn crash_multi_table_mutation_after_step_for_test(_step: &str) {}

#[cfg(test)]
thread_local! {
    static QUOTA_MUTATION_STEP_FOR_TEST: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn crash_quota_mutation_after_step_for_test(statement: &str) {
    let target = std::env::var("AIAGENTOS_TEST_EXIT_QUOTA_AFTER_STEP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    QUOTA_MUTATION_STEP_FOR_TEST.with(|counter| {
        let step = counter.get().saturating_add(1);
        counter.set(step);
        if target == Some(step) {
            eprintln!("terminating after quota mutation {step}: {statement}");
            std::process::exit(87);
        }
    });
}

#[cfg(not(test))]
#[inline]
fn crash_quota_mutation_after_step_for_test(_statement: &str) {}

fn persist_deletion_receipt(
    transaction: &Transaction<'_>,
    subject_kind: DeletionSubjectKind,
    deleted_rows: BTreeMap<String, u64>,
    retained_records: Vec<String>,
) -> Result<DeletionReceipt, ContextError> {
    let receipt = DeletionReceipt {
        id: uuid::Uuid::new_v4(),
        subject_kind,
        deleted_at: Utc::now(),
        deleted_rows,
        retained_records,
    };
    let deleted_rows_json = serde_json::to_string(&receipt.deleted_rows)
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
    let retained_records_json = serde_json::to_string(&receipt.retained_records)
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO deletion_receipts
             (id, subject_kind, deleted_at, deleted_rows_json, retained_records_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                receipt.id.to_string(),
                receipt.subject_kind.as_str(),
                receipt.deleted_at.to_rfc3339(),
                deleted_rows_json,
                retained_records_json
            ],
        )
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
    Ok(receipt)
}

/// SQLite-backed context manager implementation.
pub struct SqliteContextManager {
    /// Shared durable store used by crate-owned subsystems. The connection is
    /// crate-visible so transactional modules such as the package supply chain
    /// can participate in the same backup, restore, and durability boundary.
    pub(crate) conn: Mutex<Connection>,
    /// Process-lifetime exclusive lease for the database path. Offline restore
    /// acquires the same lease and therefore cannot race a running kernel.
    _storage_lease: Option<crate::storage::StorageLease>,
    /// Operator-custodied whole-database key. The key identifier is public;
    /// bytes remain zeroized secret memory and are needed for encrypted online
    /// backups.
    encryption_key: Option<Arc<crate::storage_encryption::StorageEncryptionKey>>,
    /// Retired generations accepted only for historical backup maintenance.
    retired_encryption_keys: Vec<Arc<crate::storage_encryption::StorageEncryptionKey>>,
    storage_limits: RwLock<ContextStorageLimits>,
    /// Pluggable embedder used for the long-term-memory store/query/ranking
    /// path. Defaults to [`crate::memory_manager::default_embedder`]; swap it
    /// via [`SqliteContextManager::with_embedder`] to change embedding strategy
    /// without touching persistence.
    embedder: Arc<dyn Embedder>,
    #[cfg(test)]
    fail_next_agent_save: AtomicBool,
    #[cfg(test)]
    fail_agent_status_update_after: AtomicUsize,
}

impl SqliteContextManager {
    /// Create a new SqliteContextManager with the given database path.
    pub fn new(db_path: &Path) -> Result<Self, ContextError> {
        Self::open_file(db_path, true, None, Vec::new())
    }

    /// Exhaust the live SQLite connection's page budget for the checked-in
    /// resilience qualification. This seam is absent from normal kernel builds
    /// and deliberately operates on the same connection used by public storage
    /// syscalls, avoiding a mock or a second-connection approximation.
    #[cfg(feature = "qualification")]
    pub fn qualification_exhaust_storage(&self) -> Result<(i64, i64), ContextError> {
        let connection = self.conn.lock().map_err(|error| {
            ContextError::StorageError(format!("lock qualification database: {error}"))
        })?;
        connection
            .execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|error| {
                ContextError::StorageError(format!(
                    "prepare storage exhaustion qualification: {error}"
                ))
            })?;
        let page_count: i64 = connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let free_pages: i64 = connection
            .pragma_query_value(None, "freelist_count", |row| row.get(0))
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        connection
            .pragma_update(None, "max_page_count", page_count)
            .map_err(|error| {
                ContextError::StorageError(format!("set storage exhaustion page limit: {error}"))
            })?;
        Ok((page_count, free_pages))
    }

    /// Restore SQLite's supported maximum after
    /// [`qualification_exhaust_storage`](Self::qualification_exhaust_storage).
    #[cfg(feature = "qualification")]
    pub fn qualification_restore_storage_capacity(&self) -> Result<(), ContextError> {
        let connection = self.conn.lock().map_err(|error| {
            ContextError::StorageError(format!("lock qualification database: {error}"))
        })?;
        connection
            .pragma_update(None, "max_page_count", 2_147_483_646_i64)
            .map_err(|error| {
                ContextError::StorageError(format!(
                    "restore qualification database capacity: {error}"
                ))
            })
    }

    /// Create a manager for a SQLCipher-encrypted database.
    pub fn new_encrypted(
        db_path: &Path,
        key: crate::storage_encryption::StorageEncryptionKey,
    ) -> Result<Self, ContextError> {
        Self::open_file(db_path, true, Some(Arc::new(key)), Vec::new())
    }

    /// Create an encrypted manager that can also maintain backups made under
    /// explicitly retained previous key generations.
    pub fn new_encrypted_with_retired_keys(
        db_path: &Path,
        key: crate::storage_encryption::StorageEncryptionKey,
        retired_keys: Vec<crate::storage_encryption::StorageEncryptionKey>,
    ) -> Result<Self, ContextError> {
        Self::open_file(
            db_path,
            true,
            Some(Arc::new(key)),
            retired_keys.into_iter().map(Arc::new).collect(),
        )
    }

    fn open_file(
        db_path: &Path,
        acquire_lease: bool,
        encryption_key: Option<Arc<crate::storage_encryption::StorageEncryptionKey>>,
        retired_encryption_keys: Vec<Arc<crate::storage_encryption::StorageEncryptionKey>>,
    ) -> Result<Self, ContextError> {
        if encryption_key.is_none() && !retired_encryption_keys.is_empty() {
            return Err(ContextError::StorageError(
                "retired storage keys require a current database key".into(),
            ));
        }
        let mut key_ids = std::collections::BTreeSet::new();
        if let Some(key) = encryption_key.as_ref() {
            key_ids.insert(key.key_id());
        }
        for key in &retired_encryption_keys {
            if !key_ids.insert(key.key_id()) {
                return Err(ContextError::StorageError(format!(
                    "storage encryption key id {:?} is configured more than once",
                    key.key_id()
                )));
            }
        }
        let storage_lease = if acquire_lease {
            Some(crate::storage::acquire_storage_lease(db_path)?)
        } else {
            None
        };
        let conn =
            Connection::open(db_path).map_err(|e| ContextError::StorageError(e.to_string()))?;
        if let Some(key) = encryption_key.as_ref() {
            key.apply(&conn)?;
        }
        let schema_version = crate::schema::preflight(&conn)?;
        let accounting_integrity_exists = conn
            .query_row(
                "SELECT 1 FROM sqlite_schema
                 WHERE type = 'table' AND name = 'accounting_integrity'",
                [],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| {
                ContextError::StorageError(format!(
                    "failed to inspect accounting integrity schema: {error}"
                ))
            })?
            .is_some();
        if schema_version >= crate::accounting_integrity::SCHEMA_VERSION
            && !accounting_integrity_exists
        {
            return Err(ContextError::StorageError(
                "schema version requires accounting integrity state, but it is missing".into(),
            ));
        }
        if accounting_integrity_exists {
            crate::accounting_integrity::register_functions(&conn)?;
            crate::accounting_integrity::secure_existing_schema(&conn)?;
        }
        // Generation checkpoints contain prompts and tool results. Protect the
        // SQLite file with owner-only permissions on Unix before writing them.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(db_path, permissions)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
        }
        // Quota admission is committed before provider I/O. These durability
        // settings are therefore part of enforcement, not best-effort tuning:
        // startup fails closed if the filesystem/SQLite build cannot provide
        // WAL + FULL durability. A bounded busy timeout lets independent
        // kernel handles serialize BEGIN IMMEDIATE reservations under normal
        // contention while still surfacing prolonged lock failure.
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| quota_error(format!("failed to set SQLite busy timeout: {error}")))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| quota_error(format!("failed to enable SQLite WAL: {error}")))?;
        let journal_mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|error| quota_error(format!("failed to verify SQLite WAL: {error}")))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(quota_error(format!(
                "SQLite journal_mode is {journal_mode:?}, expected WAL"
            )));
        }
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|error| {
                quota_error(format!("failed to enable SQLite synchronous=FULL: {error}"))
            })?;
        let synchronous: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(|error| {
                quota_error(format!("failed to verify SQLite synchronous mode: {error}"))
            })?;
        if synchronous != 2 {
            return Err(quota_error(format!(
                "SQLite synchronous mode is {synchronous}, expected FULL (2)"
            )));
        }
        let mgr = Self {
            conn: Mutex::new(conn),
            _storage_lease: storage_lease,
            encryption_key,
            retired_encryption_keys,
            storage_limits: RwLock::new(ContextStorageLimits::default()),
            embedder: crate::memory_manager::default_embedder(),
            #[cfg(test)]
            fail_next_agent_save: AtomicBool::new(false),
            #[cfg(test)]
            fail_agent_status_update_after: AtomicUsize::new(0),
        };
        mgr.init_schema(schema_version)?;
        Ok(mgr)
    }

    pub(crate) fn new_without_storage_lease(db_path: &Path) -> Result<Self, ContextError> {
        Self::open_file(db_path, false, None, Vec::new())
    }

    pub(crate) fn new_without_storage_lease_encrypted(
        db_path: &Path,
        key: crate::storage_encryption::StorageEncryptionKey,
        retired_keys: Vec<crate::storage_encryption::StorageEncryptionKey>,
    ) -> Result<Self, ContextError> {
        Self::open_file(
            db_path,
            false,
            Some(Arc::new(key)),
            retired_keys.into_iter().map(Arc::new).collect(),
        )
    }

    /// Create an in-memory context manager (for testing).
    pub fn in_memory() -> Result<Self, ContextError> {
        let conn =
            Connection::open_in_memory().map_err(|e| ContextError::StorageError(e.to_string()))?;
        let schema_version = crate::schema::preflight(&conn)?;
        let mgr = Self {
            conn: Mutex::new(conn),
            _storage_lease: None,
            encryption_key: None,
            retired_encryption_keys: Vec::new(),
            storage_limits: RwLock::new(ContextStorageLimits::default()),
            embedder: crate::memory_manager::default_embedder(),
            #[cfg(test)]
            fail_next_agent_save: AtomicBool::new(false),
            #[cfg(test)]
            fail_agent_status_update_after: AtomicUsize::new(0),
        };
        mgr.init_schema(schema_version)?;
        Ok(mgr)
    }

    /// Non-secret identifier of the configured whole-database key.
    pub fn storage_encryption_key_id(&self) -> Option<&str> {
        self.encryption_key.as_deref().map(|key| key.key_id())
    }

    pub(crate) fn storage_encryption_key(
        &self,
    ) -> Option<Arc<crate::storage_encryption::StorageEncryptionKey>> {
        self.encryption_key.clone()
    }

    pub(crate) fn storage_backup_encryption_key(
        &self,
        key_id: &str,
    ) -> Option<Arc<crate::storage_encryption::StorageEncryptionKey>> {
        self.encryption_key
            .iter()
            .chain(&self.retired_encryption_keys)
            .find(|key| key.key_id() == key_id)
            .cloned()
    }

    pub fn retired_storage_encryption_key_count(&self) -> usize {
        self.retired_encryption_keys.len()
    }

    /// Swap the embedder used by the long-term-memory store/query path. Returns
    /// `self` for builder-style chaining. The seam where a different
    /// [`Embedder`] can drop in without changing persistence.
    pub fn with_embedder(mut self, embedder: Arc<dyn Embedder>) -> Self {
        self.embedder = embedder;
        self
    }

    fn init_schema(&self, schema_version: i64) -> Result<(), ContextError> {
        let mut connection = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|error| {
                quota_error(format!("failed to enable SQLite foreign keys: {error}"))
            })?;
        let foreign_keys: i64 = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .map_err(|error| {
                quota_error(format!("failed to verify SQLite foreign keys: {error}"))
            })?;
        if foreign_keys != 1 {
            return Err(quota_error(
                "SQLite foreign-key enforcement did not remain enabled",
            ));
        }
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                quota_error(format!(
                    "failed to start atomic schema migration transaction: {error}"
                ))
            })?;
        let conn = &transaction;
        let quota_schema_exists = conn
            .query_row(
                "SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'quota_epochs'",
                [],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| quota_error(format!("failed to inspect quota schema: {error}")))?
            .is_some();
        let quota_floor_initialized = if quota_schema_exists {
            let floor_table_exists = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master
                     WHERE type = 'table' AND name = 'quota_epoch_floor'",
                    [],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|error| {
                    quota_error(format!(
                        "failed to inspect quota epoch floor schema: {error}"
                    ))
                })?
                .is_some();
            if floor_table_exists {
                conn.query_row(
                    "SELECT 1 FROM quota_epoch_floor WHERE singleton = 1",
                    [],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|error| {
                    quota_error(format!(
                        "failed to inspect quota epoch floor state: {error}"
                    ))
                })?
                .is_some()
            } else {
                false
            }
        } else {
            false
        };
        let quota_receipt_scopes_exists = conn
            .query_row(
                "SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'quota_receipt_scopes'",
                [],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| {
                quota_error(format!(
                    "failed to inspect quota receipt-scope schema: {error}"
                ))
            })?
            .is_some();
        let hierarchy_schema_upgrade_needed = if quota_receipt_scopes_exists {
            let mut statement = conn
                .prepare("PRAGMA table_info(quota_receipt_scopes)")
                .map_err(|error| {
                    quota_error(format!(
                        "failed to inspect quota receipt scope schema: {error}"
                    ))
                })?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|error| {
                    quota_error(format!(
                        "failed to enumerate quota receipt scope columns: {error}"
                    ))
                })?;
            let mut has_scope_order = false;
            for row in rows {
                if row.map_err(|error| {
                    quota_error(format!(
                        "failed to read quota receipt scope column: {error}"
                    ))
                })? == "scope_order"
                {
                    has_scope_order = true;
                }
            }
            !has_scope_order
        } else {
            false
        };
        let mut legacy_database_has_rows = false;
        if !quota_schema_exists || !quota_floor_initialized || hierarchy_schema_upgrade_needed {
            // This list is deliberately static: table names never come from
            // persisted/user input, so the existence probes cannot become SQL
            // injection. A schema-only legacy database has no unknowable usage
            // to fence; any durable application row does. Recheck application
            // rows when the quota schema exists without its floor marker: that
            // is the recoverable signature of a crash between schema creation
            // and installing the legacy migration fence.
            for table in [
                "contexts",
                "facts",
                "conversations",
                "usage_log",
                "agent_kv",
                "context_spills",
                "context_pressure",
                "context_snapshots",
                "generation_checkpoints",
                "agents",
                "tenants",
                "users",
                "api_keys",
                "sessions",
            ] {
                let exists = conn
                    .query_row(
                        "SELECT 1 FROM sqlite_master
                         WHERE type = 'table' AND name = ?1",
                        [table],
                        |_| Ok(()),
                    )
                    .optional()
                    .map_err(|error| {
                        quota_error(format!("failed to inspect legacy table {table}: {error}"))
                    })?
                    .is_some();
                if exists {
                    let sql = format!("SELECT 1 FROM {table} LIMIT 1");
                    if conn
                        .query_row(&sql, [], |_| Ok(()))
                        .optional()
                        .map_err(|error| {
                            quota_error(format!("failed to inspect legacy table {table}: {error}"))
                        })?
                        .is_some()
                    {
                        legacy_database_has_rows = true;
                        break;
                    }
                }
            }
        }
        let mut hierarchy_database_has_rows = legacy_database_has_rows;
        if hierarchy_schema_upgrade_needed && !hierarchy_database_has_rows {
            // A PR140-era database can contain durable provider quota state
            // even if no application row remains. Its process-local cgroup
            // usage is still unattributable, so any quota row makes the
            // hierarchy migration live and requires a one-epoch fence.
            for table in ["quota_epochs", "quota_receipts", "quota_receipt_scopes"] {
                let exists = conn
                    .query_row(
                        "SELECT 1 FROM sqlite_master
                         WHERE type = 'table' AND name = ?1",
                        [table],
                        |_| Ok(()),
                    )
                    .optional()
                    .map_err(|error| {
                        quota_error(format!("failed to inspect quota table {table}: {error}"))
                    })?
                    .is_some();
                if exists {
                    let sql = format!("SELECT 1 FROM {table} LIMIT 1");
                    if conn
                        .query_row(&sql, [], |_| Ok(()))
                        .optional()
                        .map_err(|error| {
                            quota_error(format!("failed to inspect quota table {table}: {error}"))
                        })?
                        .is_some()
                    {
                        hierarchy_database_has_rows = true;
                        break;
                    }
                }
            }
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS contexts (
                agent_id TEXT PRIMARY KEY,
                context_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS facts (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_accessed_at TEXT NOT NULL,
                embedding_json TEXT,
                embedding_model TEXT NOT NULL DEFAULT 'legacy',
                embedding_version INTEGER NOT NULL DEFAULT 0,
                embedding_dim INTEGER NOT NULL DEFAULT 0,
                content_hash TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_facts_agent ON facts(agent_id);
            CREATE INDEX IF NOT EXISTS idx_facts_category ON facts(agent_id, category);
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                messages_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_conv_agent ON conversations(agent_id);
            CREATE INDEX IF NOT EXISTS idx_conv_updated ON conversations(updated_at);
            CREATE TABLE IF NOT EXISTS usage_log (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                tokens_used INTEGER NOT NULL,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                cached_tokens INTEGER NOT NULL DEFAULT 0,
                llm_requests INTEGER NOT NULL DEFAULT 0,
                retries INTEGER NOT NULL DEFAULT 0,
                provider_latency_ms INTEGER NOT NULL DEFAULT 0,
                provider_reported_requests INTEGER NOT NULL DEFAULT 0,
                estimated_requests INTEGER NOT NULL DEFAULT 0,
                model TEXT,
                estimated_cost_usd REAL,
                cost_micros INTEGER NOT NULL DEFAULT 0
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS conversations_fts USING fts5(conversation_id, content);
            CREATE TABLE IF NOT EXISTS agent_kv (
                agent_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(agent_id, key)
            );
            CREATE INDEX IF NOT EXISTS idx_agent_kv_agent ON agent_kv(agent_id);
            CREATE TABLE IF NOT EXISTS context_spills (
                agent_id TEXT NOT NULL,
                key TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                byte_count INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY(agent_id, key)
            );
            CREATE INDEX IF NOT EXISTS idx_context_spills_tenant
                ON context_spills(tenant_id, expires_at);
            CREATE TABLE IF NOT EXISTS context_pressure (
                agent_id TEXT PRIMARY KEY,
                active_tokens INTEGER NOT NULL,
                budget_tokens INTEGER NOT NULL,
                spill_count INTEGER NOT NULL DEFAULT 0,
                evicted_messages INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS context_snapshots (
                agent_id TEXT NOT NULL,
                label TEXT NOT NULL,
                context_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(agent_id, label)
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_agent ON context_snapshots(agent_id);
            CREATE TABLE IF NOT EXISTS generation_checkpoints (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                model_id TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_generation_checkpoints_agent
                ON generation_checkpoints(agent_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_generation_checkpoints_tenant
                ON generation_checkpoints(tenant_id, status, expires_at);
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                name TEXT NOT NULL,
                task TEXT NOT NULL,
                llm_provider TEXT NOT NULL,
                permission_profile TEXT NOT NULL,
                priority INTEGER NOT NULL,
                status TEXT NOT NULL,
                sandbox_config_json TEXT,
                created_at TEXT NOT NULL,
                last_activity_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS loaded_package_instances (
                agent_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                provider TEXT NOT NULL,
                profile TEXT NOT NULL,
                loaded_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_loaded_packages_tenant
                ON loaded_package_instances(tenant_id, loaded_at DESC);
            CREATE TABLE IF NOT EXISTS package_trust_keys (
                tenant_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                publisher TEXT NOT NULL,
                public_key BLOB NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('trusted', 'revoked')),
                valid_from TEXT NOT NULL,
                valid_until TEXT,
                superseded_by TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, key_id)
            );
            CREATE INDEX IF NOT EXISTS idx_package_trust_publisher
                ON package_trust_keys(tenant_id, publisher, status);
            CREATE TABLE IF NOT EXISTS package_artifacts (
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                publisher TEXT NOT NULL,
                digest TEXT NOT NULL,
                archive BLOB NOT NULL,
                manifest_json TEXT NOT NULL,
                yanked INTEGER NOT NULL DEFAULT 0 CHECK (yanked IN (0, 1)),
                published_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, name, version),
                UNIQUE (tenant_id, digest)
            );
            CREATE INDEX IF NOT EXISTS idx_package_artifact_search
                ON package_artifacts(tenant_id, name, yanked, version);
            CREATE TABLE IF NOT EXISTS package_installations (
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                digest TEXT NOT NULL,
                lock_json TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                installed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, name)
            );
            CREATE TABLE IF NOT EXISTS package_install_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_package_install_history
                ON package_install_history(tenant_id, name, id DESC);
            CREATE TABLE IF NOT EXISTS package_rate_limits (
                tenant_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                window_started_at INTEGER NOT NULL,
                requests INTEGER NOT NULL CHECK (requests >= 0),
                PRIMARY KEY (tenant_id, actor)
            );
            CREATE TABLE IF NOT EXISTS package_transparency (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                action TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                digest TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_package_transparency_tenant
                ON package_transparency(tenant_id, sequence);
            CREATE TABLE IF NOT EXISTS package_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                name TEXT,
                version TEXT,
                outcome TEXT NOT NULL,
                digest TEXT,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_package_audit_tenant
                ON package_audit(tenant_id, id DESC);
            CREATE TABLE IF NOT EXISTS operator_tunables (
                name TEXT PRIMARY KEY,
                value INTEGER NOT NULL CHECK (value >= 0),
                revision INTEGER NOT NULL CHECK (revision > 0),
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS operator_tunable_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                revision INTEGER,
                previous_value INTEGER,
                requested_value INTEGER,
                effective_value INTEGER,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_operator_tunable_audit_name
                ON operator_tunable_audit(name, id DESC);
            CREATE TABLE IF NOT EXISTS service_runtime (
                name TEXT PRIMARY KEY,
                definition_revision TEXT NOT NULL,
                status TEXT NOT NULL,
                agent_id TEXT,
                restart_count INTEGER NOT NULL CHECK (restart_count >= 0),
                restart_attempts_total INTEGER NOT NULL CHECK (restart_attempts_total >= 0),
                last_exit_code INTEGER,
                desired_running INTEGER NOT NULL CHECK (desired_running IN (0, 1)),
                ready INTEGER NOT NULL CHECK (ready IN (0, 1)),
                healthy INTEGER NOT NULL CHECK (healthy IN (0, 1)),
                restart_exhausted INTEGER NOT NULL CHECK (restart_exhausted IN (0, 1)),
                last_failure TEXT,
                next_restart_at TEXT,
                restart_window_started_at TEXT,
                last_transition_at TEXT NOT NULL,
                dependency_blocks INTEGER NOT NULL CHECK (dependency_blocks >= 0)
            );
            CREATE TABLE IF NOT EXISTS service_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                event TEXT NOT NULL,
                status TEXT NOT NULL,
                agent_id TEXT,
                reason TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_service_history_name
                ON service_history(name, id DESC);
            -- Tenancy: tenants are the top-level isolation unit; users/sessions/
            -- api-keys are scoped to a tenant. Secrets are stored hashed (the
            -- *_hash columns), never in plaintext (see auth.rs).
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
            CREATE TABLE IF NOT EXISTS api_keys (
                key_hash TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                user_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            -- Privacy-safe proof of a committed erasure. Subject identifiers,
            -- actors, reasons, and deleted values are intentionally absent.
            CREATE TABLE IF NOT EXISTS deletion_receipts (
                id TEXT PRIMARY KEY CHECK (length(id) = 36),
                subject_kind TEXT NOT NULL
                    CHECK (subject_kind IN ('agent', 'user', 'tenant')),
                deleted_at TEXT NOT NULL,
                deleted_rows_json TEXT NOT NULL,
                retained_records_json TEXT NOT NULL
            );
            -- Generic durable quota ledger. Unsigned counters and epochs are
            -- fixed-width big-endian blobs because SQLite INTEGER is signed
            -- and cannot represent the full u64 range. Equal-width big-endian
            -- blobs retain numeric ordering for pruning.
            CREATE TABLE IF NOT EXISTS quota_epoch_floor (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8)
            );
            CREATE TABLE IF NOT EXISTS quota_epochs (
                scope_kind TEXT NOT NULL
                    CHECK (length(scope_kind) BETWEEN 1 AND 64),
                scope_id TEXT NOT NULL
                    CHECK (length(scope_id) BETWEEN 1 AND 1024),
                epoch BLOB NOT NULL
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8),
                requests BLOB NOT NULL
                    CHECK (typeof(requests) = 'blob' AND length(requests) = 8),
                tokens BLOB NOT NULL
                    CHECK (typeof(tokens) = 'blob' AND length(tokens) = 8),
                PRIMARY KEY (scope_kind, scope_id, epoch)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_quota_epochs_prune
                ON quota_epochs(epoch);
            CREATE TABLE IF NOT EXISTS quota_receipts (
                id TEXT PRIMARY KEY CHECK (length(id) = 36),
                receipt_kind TEXT NOT NULL
                    CHECK (length(receipt_kind) BETWEEN 1 AND 64),
                epoch BLOB NOT NULL
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8),
                state TEXT NOT NULL
                    CHECK (state IN ('reserved', 'in_flight', 'estimated', 'reconciled')),
                reserved_requests BLOB NOT NULL
                    CHECK (typeof(reserved_requests) = 'blob'
                           AND length(reserved_requests) = 8),
                reserved_tokens BLOB NOT NULL
                    CHECK (typeof(reserved_tokens) = 'blob'
                           AND length(reserved_tokens) = 8),
                actual_requests BLOB
                    CHECK (actual_requests IS NULL
                           OR (typeof(actual_requests) = 'blob'
                               AND length(actual_requests) = 8)),
                actual_tokens BLOB
                    CHECK (actual_tokens IS NULL
                           OR (typeof(actual_tokens) = 'blob'
                               AND length(actual_tokens) = 8))
            );
            CREATE INDEX IF NOT EXISTS idx_quota_receipts_epoch_state
                ON quota_receipts(epoch, state);
            CREATE TABLE IF NOT EXISTS quota_receipt_scopes (
                receipt_id TEXT NOT NULL
                    REFERENCES quota_receipts(id) ON DELETE CASCADE,
                scope_order INTEGER NOT NULL DEFAULT 0
                    CHECK (scope_order >= 0),
                scope_kind TEXT NOT NULL
                    CHECK (length(scope_kind) BETWEEN 1 AND 64),
                scope_id TEXT NOT NULL
                    CHECK (length(scope_id) BETWEEN 1 AND 1024),
                reserved_requests BLOB NOT NULL
                    CHECK (typeof(reserved_requests) = 'blob'
                           AND length(reserved_requests) = 8),
                reserved_tokens BLOB NOT NULL
                    CHECK (typeof(reserved_tokens) = 'blob'
                           AND length(reserved_tokens) = 8),
                actual_requests BLOB
                    CHECK (actual_requests IS NULL
                           OR (typeof(actual_requests) = 'blob'
                               AND length(actual_requests) = 8)),
                actual_tokens BLOB
                    CHECK (actual_tokens IS NULL
                           OR (typeof(actual_tokens) = 'blob'
                               AND length(actual_tokens) = 8)),
                PRIMARY KEY (receipt_id, scope_kind, scope_id)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_quota_receipt_scopes_scope
                ON quota_receipt_scopes(scope_kind, scope_id, receipt_id);
            -- Refunded receipts are tombstoned so retries are idempotent and a
            -- UUID can never be reused for a different external request.
            CREATE TABLE IF NOT EXISTS quota_refunded_receipts (
                id TEXT PRIMARY KEY CHECK (length(id) = 36),
                epoch BLOB NOT NULL
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8)
            );
            CREATE INDEX IF NOT EXISTS idx_quota_refunded_receipts_epoch
                ON quota_refunded_receipts(epoch);
            CREATE TABLE IF NOT EXISTS quota_migration_fence (
                epoch BLOB PRIMARY KEY
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS cluster_node_identity (
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
            );
            CREATE TABLE IF NOT EXISTS cluster_agent_ownership (
                agent_id TEXT PRIMARY KEY CHECK (length(agent_id) = 36),
                owner_node_id TEXT NOT NULL CHECK (length(owner_node_id) = 36),
                fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
                generation INTEGER NOT NULL CHECK (generation >= 1),
                state TEXT NOT NULL CHECK (state IN ('active', 'released')),
                lease_expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                reason TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cluster_agent_ownership_owner
                ON cluster_agent_ownership(owner_node_id, state, lease_expires_at);
            CREATE TABLE IF NOT EXISTS cluster_agent_ownership_audit (
                agent_id TEXT NOT NULL CHECK (length(agent_id) = 36),
                generation INTEGER NOT NULL CHECK (generation >= 1),
                previous_owner_node_id TEXT,
                owner_node_id TEXT NOT NULL CHECK (length(owner_node_id) = 36),
                fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
                operation TEXT NOT NULL CHECK (
                    operation IN ('claim', 'transfer', 'renew', 'release')
                ),
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                PRIMARY KEY (agent_id, generation)
            ) WITHOUT ROWID;",
        ).map_err(|e| ContextError::StorageError(e.to_string()))?;
        // Legacy fact rows are deliberately marked stale and rebuilt on their
        // next query or an explicit reindex.
        for (column, definition) in [
            ("embedding_model", "TEXT NOT NULL DEFAULT 'legacy'"),
            ("embedding_version", "INTEGER NOT NULL DEFAULT 0"),
            ("embedding_dim", "INTEGER NOT NULL DEFAULT 0"),
            ("content_hash", "TEXT NOT NULL DEFAULT ''"),
        ] {
            crate::schema::add_column_if_missing(conn, "facts", column, definition)?;
        }
        if hierarchy_schema_upgrade_needed && hierarchy_database_has_rows {
            // The fence and the schema change share one transaction. A process
            // exit or later error therefore publishes both or neither.
            Self::install_current_quota_migration_fence(conn)?;
        }
        // Tenant scoping for the agent registry. Added via ALTER so an older DB
        // (created before tenancy) upgrades in place: legacy agents land in the
        // implicit "default" tenant. A duplicate-column error on a DB that
        // already has the column is expected and ignored.
        {
            // Quota receipt scopes gained a stable root-to-leaf order when
            // hierarchical cgroup accounting was introduced. Existing
            // provider-only rows become order zero.
            if hierarchy_schema_upgrade_needed {
                conn.execute(
                    "ALTER TABLE quota_receipt_scopes
                     ADD COLUMN scope_order INTEGER NOT NULL DEFAULT 0
                         CHECK (scope_order >= 0)",
                    [],
                )
                .map_err(|error| {
                    quota_error(format!(
                        "failed to add quota receipt scope-order column: {error}"
                    ))
                })?;
            }
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_quota_receipt_scope_order
                 ON quota_receipt_scopes(receipt_id, scope_order)",
                [],
            )
            .map_err(|error| {
                quota_error(format!(
                    "failed to create quota receipt scope-order index: {error}"
                ))
            })?;
            crate::schema::add_column_if_missing(
                conn,
                "agents",
                "tenant_id",
                "TEXT NOT NULL DEFAULT 'default'",
            )?;
            crate::schema::add_column_if_missing(conn, "usage_log", "provider", "TEXT")?;
            crate::schema::add_column_if_missing(
                conn,
                "usage_log",
                "tool_calls",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            for (column, definition) in [
                ("input_tokens", "INTEGER NOT NULL DEFAULT 0"),
                ("output_tokens", "INTEGER NOT NULL DEFAULT 0"),
                ("cached_tokens", "INTEGER NOT NULL DEFAULT 0"),
                ("llm_requests", "INTEGER NOT NULL DEFAULT 0"),
                ("retries", "INTEGER NOT NULL DEFAULT 0"),
                ("provider_latency_ms", "INTEGER NOT NULL DEFAULT 0"),
                ("provider_reported_requests", "INTEGER NOT NULL DEFAULT 0"),
                ("estimated_requests", "INTEGER NOT NULL DEFAULT 0"),
                ("cost_micros", "INTEGER NOT NULL DEFAULT 0"),
            ] {
                crate::schema::add_column_if_missing(conn, "usage_log", column, definition)?;
            }
            // Older rows only stored a floating-point USD estimate. Backfill
            // once into the exact integer unit used by enforcement. New rows
            // write this field directly and therefore need no conversion.
            conn.execute(
                "UPDATE usage_log
                 SET cost_micros = CASE
                     WHEN estimated_cost_usd IS NULL OR estimated_cost_usd <= 0.0 THEN 0
                     WHEN estimated_cost_usd >= 9223372036854.775807
                         THEN 9223372036854775807
                     ELSE CAST(ROUND(estimated_cost_usd * 1000000.0) AS INTEGER)
                 END
                 WHERE cost_micros = 0
                   AND COALESCE(estimated_cost_usd, 0.0) > 0.0",
                [],
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
            // A process can die after atomically claiming a checkpoint. Re-arm
            // that claim on boot: external side effects therefore have the
            // documented at-least-once crash semantics unless the tool uses its
            // stable call id as an idempotency key.
            conn.execute(
                "UPDATE generation_checkpoints SET status = 'active'
                 WHERE status = 'resuming' AND expires_at > ?1",
                params![Utc::now().to_rfc3339()],
            )
            .map_err(|error| {
                ContextError::StorageError(format!(
                    "failed to re-arm generation checkpoints: {error}"
                ))
            })?;
            conn.execute(
                "DELETE FROM generation_checkpoints WHERE expires_at <= ?1",
                params![Utc::now().to_rfc3339()],
            )
            .map_err(|error| {
                ContextError::StorageError(format!(
                    "failed to prune expired generation checkpoints: {error}"
                ))
            })?;
        }
        // PR129 stored context spills in agent_kv before digest/retention
        // metadata existed. Upgrade them in place so restart-safe references
        // remain usable without creating an unretained privacy bypass.
        let legacy_spills = {
            let mut statement = conn
                .prepare(
                    "SELECT kv.agent_id, kv.key, kv.value, kv.updated_at,
                            COALESCE(a.tenant_id, 'default')
                     FROM agent_kv kv
                     LEFT JOIN agents a ON a.id = kv.agent_id
                     LEFT JOIN context_spills spill
                       ON spill.agent_id = kv.agent_id AND spill.key = kv.key
                     WHERE kv.key LIKE 'context_spill:%' AND spill.key IS NULL",
                )
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            let mut spills = Vec::new();
            for row in rows {
                spills.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
            }
            spills
        };
        for (agent_id, key, value, updated_at, tenant_id) in legacy_spills {
            let digest = ring::digest::digest(&ring::digest::SHA256, value.as_bytes())
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let created_at = DateTime::parse_from_rfc3339(&updated_at)
                .map(|value| value.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now() - chrono::Duration::days(30));
            let expires_at = created_at + chrono::Duration::days(30);
            conn.execute(
                "INSERT INTO context_spills
                 (agent_id, key, tenant_id, sha256, byte_count, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    agent_id,
                    key,
                    tenant_id,
                    digest,
                    value.len() as u64,
                    created_at.to_rfc3339(),
                    expires_at.to_rfc3339()
                ],
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        }
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "DELETE FROM agent_kv
             WHERE EXISTS (
                SELECT 1 FROM context_spills
                WHERE context_spills.agent_id = agent_kv.agent_id
                  AND context_spills.key = agent_kv.key
                  AND context_spills.expires_at <= ?1
             )",
            params![now],
        )
        .map_err(|error| ContextError::StorageError(error.to_string()))?;
        conn.execute(
            "DELETE FROM context_spills WHERE expires_at <= ?1",
            params![now],
        )
        .map_err(|error| ContextError::StorageError(error.to_string()))?;
        if !legacy_database_has_rows {
            // A fresh store still needs an explicit floor marker. Without it,
            // a later reopen after the first ordinary usage row is
            // indistinguishable from an interrupted legacy quota migration
            // and would conservatively fence a current release by mistake.
            let zero = u64_blob(0);
            conn.execute(
                "INSERT OR IGNORE INTO quota_epoch_floor(singleton, epoch)
                 VALUES (1, ?1)",
                params![zero.as_slice()],
            )
            .map_err(|error| {
                quota_error(format!("failed to initialize fresh quota floor: {error}"))
            })?;
        }
        if legacy_database_has_rows {
            // The old release kept RPM/TPM only in process memory. There is no
            // honest backfill after upgrade, so fence just the current fixed
            // epoch instead of reopening unknown capacity. Fresh/empty
            // databases do not receive this fence.
            Self::install_current_quota_migration_fence(conn)?;
        }
        crate::accounting_integrity::install(conn)?;
        crate::schema::complete_migration(conn, schema_version)?;
        transaction.commit().map_err(|error| {
            quota_error(format!(
                "failed to commit atomic schema migration transaction: {error}"
            ))
        })?;
        crate::accounting_integrity::register_functions(&connection)?;
        crate::schema::verify(&connection)?;
        Ok(())
    }

    fn install_current_quota_migration_fence(conn: &Connection) -> Result<(), ContextError> {
        let now_seconds = Utc::now().timestamp();
        let current_epoch = u64::try_from(now_seconds)
            .map_err(|_| quota_error("system clock is before the Unix epoch"))?
            / PROVIDER_RATE_EPOCH_SECONDS;
        let stored_floor = conn
            .query_row(
                "SELECT epoch FROM quota_epoch_floor WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| {
                quota_error(format!(
                    "failed to read quota floor during migration: {error}"
                ))
            })?
            .map(|blob| parse_u64_blob(blob, "quota migration epoch floor"))
            .transpose()?;
        // A prior run can have advanced the monotonic floor beyond wall time.
        // Fence the epoch admissions will actually use, otherwise a backwards
        // clock step would make the lower wall-clock fence irrelevant.
        let effective_epoch = stored_floor.unwrap_or(0).max(current_epoch);
        let effective_epoch_blob = u64_blob(effective_epoch);
        conn.execute(
            "INSERT OR IGNORE INTO quota_migration_fence(epoch) VALUES (?1)",
            params![effective_epoch_blob.as_slice()],
        )
        .map_err(|error| quota_error(format!("failed to install legacy quota fence: {error}")))?;
        conn.execute(
            "INSERT INTO quota_epoch_floor(singleton, epoch) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET epoch = CASE
                 WHEN quota_epoch_floor.epoch < excluded.epoch
                 THEN excluded.epoch ELSE quota_epoch_floor.epoch END",
            params![effective_epoch_blob.as_slice()],
        )
        .map_err(|error| quota_error(format!("failed to initialize quota epoch floor: {error}")))?;
        Ok(())
    }

    fn begin_quota_transaction(conn: &mut Connection) -> Result<Transaction<'_>, ContextError> {
        conn.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                quota_error(format!(
                    "failed to start immediate quota transaction: {error}"
                ))
            })
    }

    fn effective_quota_epoch(
        tx: &Transaction<'_>,
        requested_epoch: u64,
    ) -> Result<u64, ContextError> {
        let stored = tx
            .query_row(
                "SELECT epoch FROM quota_epoch_floor WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| quota_error(format!("failed to read quota epoch floor: {error}")))?
            .map(|blob| parse_u64_blob(blob, "quota epoch floor"))
            .transpose()?;
        let effective = stored.unwrap_or(0).max(requested_epoch);
        let blob = u64_blob(effective);
        tx.execute(
            "INSERT INTO quota_epoch_floor(singleton, epoch) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET epoch = excluded.epoch",
            params![blob.as_slice()],
        )
        .map_err(|error| quota_error(format!("failed to persist quota epoch floor: {error}")))?;
        crash_quota_mutation_after_step_for_test("quota_epoch_floor upsert");
        Ok(effective)
    }

    fn load_quota_receipt(
        tx: &Transaction<'_>,
        id: uuid::Uuid,
    ) -> Result<Option<StoredQuotaReceipt>, ContextError> {
        let raw = tx
            .query_row(
                "SELECT id, receipt_kind, epoch, state, reserved_requests, reserved_tokens,
                        actual_requests, actual_tokens
                 FROM quota_receipts WHERE id = ?1",
                [id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                        row.get::<_, Option<Vec<u8>>>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| quota_error(format!("failed to read quota receipt {id}: {error}")))?;
        let Some((
            stored_id,
            receipt_kind,
            epoch,
            state,
            reserved_requests,
            reserved_tokens,
            actual_requests,
            actual_tokens,
        )) = raw
        else {
            return Ok(None);
        };
        let stored_id = uuid::Uuid::parse_str(&stored_id)
            .map_err(|error| quota_error(format!("malformed quota receipt id: {error}")))?;
        if stored_id != id {
            return Err(quota_error("quota receipt primary key mismatch"));
        }
        if receipt_kind != "provider_request" {
            return Err(quota_error(format!(
                "provider API received incompatible quota receipt kind {receipt_kind:?}"
            )));
        }
        let state = ProviderRateReceiptState::parse(&state)?;
        let actual_requests = actual_requests
            .map(|value| parse_u64_blob(value, "quota receipt actual_requests"))
            .transpose()?;
        let actual_tokens = actual_tokens
            .map(|value| parse_u64_blob(value, "quota receipt actual_tokens"))
            .transpose()?;
        match state {
            ProviderRateReceiptState::Reconciled
                if actual_requests.is_none() || actual_tokens.is_none() =>
            {
                return Err(quota_error(
                    "reconciled quota receipt is missing actual usage",
                ));
            }
            ProviderRateReceiptState::Reserved
            | ProviderRateReceiptState::InFlight
            | ProviderRateReceiptState::Estimated
                if actual_requests.is_some() || actual_tokens.is_some() =>
            {
                return Err(quota_error(
                    "unreconciled quota receipt unexpectedly has actual usage",
                ));
            }
            _ => {}
        }
        Ok(Some(StoredQuotaReceipt {
            id: stored_id,
            epoch: parse_u64_blob(epoch, "quota receipt epoch")?,
            state,
            reserved_requests: parse_u64_blob(
                reserved_requests,
                "quota receipt reserved_requests",
            )?,
            reserved_tokens: parse_u64_blob(reserved_tokens, "quota receipt reserved_tokens")?,
            actual_requests,
            actual_tokens,
        }))
    }

    fn load_receipt_scopes(
        tx: &Transaction<'_>,
        receipt: &StoredQuotaReceipt,
    ) -> Result<Vec<StoredQuotaScope>, ContextError> {
        let mut statement = tx
            .prepare(
                "SELECT scope_order, scope_kind, scope_id,
                        reserved_requests, reserved_tokens,
                        actual_requests, actual_tokens
                 FROM quota_receipt_scopes
                 WHERE receipt_id = ?1
                 ORDER BY scope_order",
            )
            .map_err(|error| {
                quota_error(format!(
                    "failed to prepare receipt scope scan for {}: {error}",
                    receipt.id
                ))
            })?;
        let rows = statement
            .query_map([receipt.id.to_string()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            })
            .map_err(|error| {
                quota_error(format!(
                    "failed to scan receipt scopes for {}: {error}",
                    receipt.id
                ))
            })?;
        let mut scopes = Vec::new();
        for row in rows {
            let (
                order,
                kind,
                id,
                reserved_requests,
                reserved_tokens,
                actual_requests,
                actual_tokens,
            ) = row.map_err(|error| {
                quota_error(format!(
                    "failed to read receipt scope for {}: {error}",
                    receipt.id
                ))
            })?;
            let order = u32::try_from(order)
                .map_err(|_| quota_error("quota receipt scope order is negative or oversized"))?;
            let key = QuotaScopeKey {
                kind: QuotaScopeKind::parse(&kind)?,
                id,
            };
            validate_quota_scope_key(&key)?;
            let scope = StoredQuotaScope {
                key,
                order,
                reserved_requests: parse_u64_blob(
                    reserved_requests,
                    "quota scope reserved_requests",
                )?,
                reserved_tokens: parse_u64_blob(reserved_tokens, "quota scope reserved_tokens")?,
                actual_requests: actual_requests
                    .map(|value| parse_u64_blob(value, "quota scope actual_requests"))
                    .transpose()?,
                actual_tokens: actual_tokens
                    .map(|value| parse_u64_blob(value, "quota scope actual_tokens"))
                    .transpose()?,
            };
            let expected_requests = if scope.key.kind == QuotaScopeKind::Provider {
                receipt.reserved_requests
            } else {
                0
            };
            let expected_actual_requests = receipt.actual_requests.map(|actual| {
                if scope.key.kind == QuotaScopeKind::Provider {
                    actual
                } else {
                    0
                }
            });
            if scope.reserved_requests != expected_requests
                || scope.reserved_tokens != receipt.reserved_tokens
                || scope.actual_requests != expected_actual_requests
                || scope.actual_tokens != receipt.actual_tokens
            {
                return Err(quota_error(format!(
                    "receipt {} disagrees with associated scope {:?}",
                    receipt.id, scope.key
                )));
            }
            scopes.push(scope);
        }
        drop(statement);
        if scopes.is_empty() {
            return Err(quota_error(format!(
                "provider receipt {} has no quota scopes",
                receipt.id
            )));
        }
        for (expected_order, scope) in scopes.iter().enumerate() {
            let expected_order = u32::try_from(expected_order)
                .map_err(|_| quota_error("too many quota scopes on one receipt"))?;
            if scope.order != expected_order {
                return Err(quota_error(format!(
                    "receipt {} has non-contiguous scope ordering",
                    receipt.id
                )));
            }
            if expected_order == 0 {
                if scope.key != QuotaScopeKey::provider_global() {
                    return Err(quota_error(format!(
                        "receipt {} scope zero is not provider/global",
                        receipt.id
                    )));
                }
            } else if scope.key.kind != QuotaScopeKind::Cgroup {
                return Err(quota_error(format!(
                    "receipt {} has a non-cgroup scope after provider/global",
                    receipt.id
                )));
            }
        }
        Ok(scopes)
    }

    fn scope_contribution(receipt: &StoredQuotaReceipt, scope: &StoredQuotaScope) -> (u64, u64) {
        if receipt.state == ProviderRateReceiptState::Reconciled {
            (
                scope
                    .actual_requests
                    .expect("validated reconciled actual requests"),
                scope
                    .actual_tokens
                    .expect("validated reconciled actual tokens"),
            )
        } else {
            (scope.reserved_requests, scope.reserved_tokens)
        }
    }

    fn compute_scope_epoch_usage(
        tx: &Transaction<'_>,
        scope: &QuotaScopeKey,
        epoch: u64,
    ) -> Result<QuotaScopeUsage, ContextError> {
        #[cfg(test)]
        QUOTA_FULL_RECEIPT_SCANS.with(|count| count.set(count.get().saturating_add(1)));
        validate_quota_scope_key(scope)?;
        let epoch_blob = u64_blob(epoch);
        let mut statement = tx
            .prepare(
                "SELECT r.id
                 FROM quota_receipts r
                 JOIN quota_receipt_scopes s ON s.receipt_id = r.id
                 WHERE r.receipt_kind = 'provider_request'
                   AND r.epoch = ?1
                   AND s.scope_kind = ?2 AND s.scope_id = ?3
                 ORDER BY r.id",
            )
            .map_err(|error| {
                quota_error(format!("failed to prepare quota scope usage scan: {error}"))
            })?;
        let rows = statement
            .query_map(
                params![epoch_blob.as_slice(), scope.kind.as_str(), scope.id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| quota_error(format!("failed to scan quota scope usage: {error}")))?;
        let mut ids = Vec::new();
        for row in rows {
            let id =
                row.map_err(|error| quota_error(format!("failed to read receipt id: {error}")))?;
            ids.push(uuid::Uuid::parse_str(&id).map_err(|error| {
                quota_error(format!("malformed provider receipt id {id:?}: {error}"))
            })?);
        }
        drop(statement);

        let mut usage = QuotaScopeUsage {
            epoch,
            scope: scope.clone(),
            requests: 0,
            tokens: 0,
            reserved_receipts: 0,
            in_flight_receipts: 0,
            estimated_receipts: 0,
            reconciled_receipts: 0,
        };
        for id in ids {
            let receipt = Self::load_quota_receipt(tx, id)?
                .ok_or_else(|| quota_error(format!("quota receipt {id} disappeared")))?;
            if receipt.epoch != epoch {
                return Err(quota_error(format!(
                    "quota receipt {id} epoch disagrees with usage scan"
                )));
            }
            let scopes = Self::load_receipt_scopes(tx, &receipt)?;
            let stored_scope = scopes
                .iter()
                .find(|candidate| &candidate.key == scope)
                .ok_or_else(|| {
                    quota_error(format!(
                        "quota receipt {id} disappeared from scope {:?}",
                        scope
                    ))
                })?;
            let (requests, tokens) = Self::scope_contribution(&receipt, stored_scope);
            usage.requests = usage.requests.saturating_add(requests);
            usage.tokens = usage.tokens.saturating_add(tokens);
            match receipt.state {
                ProviderRateReceiptState::Reserved => {
                    usage.reserved_receipts = usage.reserved_receipts.saturating_add(1);
                }
                ProviderRateReceiptState::InFlight => {
                    usage.in_flight_receipts = usage.in_flight_receipts.saturating_add(1);
                }
                ProviderRateReceiptState::Estimated => {
                    usage.estimated_receipts = usage.estimated_receipts.saturating_add(1);
                }
                ProviderRateReceiptState::Reconciled => {
                    usage.reconciled_receipts = usage.reconciled_receipts.saturating_add(1);
                }
            }
        }
        Ok(usage)
    }

    fn load_scope_epoch_aggregate(
        tx: &Transaction<'_>,
        scope: &QuotaScopeKey,
        epoch: u64,
    ) -> Result<Option<(u64, u64)>, ContextError> {
        let epoch_blob = u64_blob(epoch);
        tx.query_row(
            "SELECT requests, tokens FROM quota_epochs
             WHERE scope_kind = ?1 AND scope_id = ?2 AND epoch = ?3",
            params![scope.kind.as_str(), scope.id, epoch_blob.as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(|error| quota_error(format!("failed to read quota scope aggregate: {error}")))?
        .map(|(requests, tokens)| {
            Ok((
                parse_u64_blob(requests, "quota scope epoch requests")?,
                parse_u64_blob(tokens, "quota scope epoch tokens")?,
            ))
        })
        .transpose()
    }

    /// Load the aggregate trusted by the steady-state admission path.
    ///
    /// Recovery validates every aggregate against its receipts before the rate
    /// limiter admits work. From then on, `BEGIN IMMEDIATE` serializes writers
    /// and each receipt mutation updates this row in the same transaction.
    /// A missing row therefore means zero only for a new scope/epoch.
    fn trusted_scope_epoch_aggregate(
        tx: &Transaction<'_>,
        scope: &QuotaScopeKey,
        epoch: u64,
    ) -> Result<(u64, u64), ContextError> {
        validate_quota_scope_key(scope)?;
        Ok(Self::load_scope_epoch_aggregate(tx, scope, epoch)?.unwrap_or((0, 0)))
    }

    /// Existing receipts must always have an aggregate, including receipts
    /// whose contribution is zero. This cheap primary-key lookup preserves
    /// fail-closed behavior without rescanning historical receipts.
    fn required_scope_epoch_aggregate(
        tx: &Transaction<'_>,
        scope: &QuotaScopeKey,
        epoch: u64,
    ) -> Result<(u64, u64), ContextError> {
        validate_quota_scope_key(scope)?;
        Self::load_scope_epoch_aggregate(tx, scope, epoch)?.ok_or_else(|| {
            quota_error(format!(
                "quota scope {:?} epoch {epoch} is missing its aggregate",
                scope
            ))
        })
    }

    fn write_scope_epoch_aggregate(
        tx: &Transaction<'_>,
        scope: &QuotaScopeKey,
        epoch: u64,
        requests: u64,
        tokens: u64,
    ) -> Result<(), ContextError> {
        validate_quota_scope_key(scope)?;
        let epoch_blob = u64_blob(epoch);
        let requests = u64_blob(requests);
        let tokens = u64_blob(tokens);
        tx.execute(
            "INSERT INTO quota_epochs
                (scope_kind, scope_id, epoch, requests, tokens)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(scope_kind, scope_id, epoch) DO UPDATE SET
                requests = excluded.requests,
                tokens = excluded.tokens",
            params![
                scope.kind.as_str(),
                scope.id,
                epoch_blob.as_slice(),
                requests.as_slice(),
                tokens.as_slice()
            ],
        )
        .map_err(|error| {
            quota_error(format!(
                "failed to update trusted quota scope aggregate: {error}"
            ))
        })?;
        crash_quota_mutation_after_step_for_test("quota_epochs aggregate upsert");
        Ok(())
    }

    /// Replace one receipt's contribution in the trusted aggregate.
    ///
    /// Saturating sums are not invertible once they reach `u64::MAX`. A
    /// decrement from a saturated dimension therefore takes the rare,
    /// correctness-first full-recompute path; ordinary operations remain O(1)
    /// per associated scope.
    fn replace_scope_epoch_contribution(
        tx: &Transaction<'_>,
        scope: &QuotaScopeKey,
        epoch: u64,
        old: (u64, u64),
        new: (u64, u64),
    ) -> Result<(), ContextError> {
        let current = Self::required_scope_epoch_aggregate(tx, scope, epoch)?;
        let saturated_decrement =
            (new.0 < old.0 && current.0 == u64::MAX) || (new.1 < old.1 && current.1 == u64::MAX);
        if saturated_decrement {
            Self::write_scope_epoch_from_receipts(tx, scope, epoch)?;
            return Ok(());
        }
        let replace = |value: u64, previous: u64, replacement: u64, dimension: &str| {
            if replacement >= previous {
                Ok(value.saturating_add(replacement - previous))
            } else {
                value.checked_sub(previous - replacement).ok_or_else(|| {
                    quota_error(format!(
                        "quota scope {:?} epoch {epoch} {dimension} aggregate underflow",
                        scope
                    ))
                })
            }
        };
        let requests = replace(current.0, old.0, new.0, "request")?;
        let tokens = replace(current.1, old.1, new.1, "token")?;
        Self::write_scope_epoch_aggregate(tx, scope, epoch, requests, tokens)
    }

    #[cfg(test)]
    fn reset_quota_full_receipt_scan_count() {
        QUOTA_FULL_RECEIPT_SCANS.with(|count| count.set(0));
    }

    #[cfg(test)]
    fn quota_full_receipt_scan_count() -> u64 {
        QUOTA_FULL_RECEIPT_SCANS.with(std::cell::Cell::get)
    }

    fn validate_scope_epoch(
        tx: &Transaction<'_>,
        scope: &QuotaScopeKey,
        epoch: u64,
    ) -> Result<QuotaScopeUsage, ContextError> {
        let usage = Self::compute_scope_epoch_usage(tx, scope, epoch)?;
        let stored = Self::load_scope_epoch_aggregate(tx, scope, epoch)?;
        let expected = (usage.requests, usage.tokens);
        match stored {
            Some(value) if value == expected => Ok(usage),
            None if expected == (0, 0)
                && usage.reserved_receipts == 0
                && usage.in_flight_receipts == 0
                && usage.estimated_receipts == 0
                && usage.reconciled_receipts == 0 =>
            {
                Ok(usage)
            }
            Some(value) => Err(quota_error(format!(
                "quota scope {:?} epoch {epoch} aggregate {value:?} disagrees with receipts {expected:?}",
                scope
            ))),
            None => Err(quota_error(format!(
                "quota scope {:?} epoch {epoch} is missing its aggregate",
                scope
            ))),
        }
    }

    fn write_scope_epoch_from_receipts(
        tx: &Transaction<'_>,
        scope: &QuotaScopeKey,
        epoch: u64,
    ) -> Result<QuotaScopeUsage, ContextError> {
        let usage = Self::compute_scope_epoch_usage(tx, scope, epoch)?;
        let epoch_blob = u64_blob(epoch);
        if usage.requests == 0
            && usage.tokens == 0
            && usage.reserved_receipts == 0
            && usage.in_flight_receipts == 0
            && usage.estimated_receipts == 0
            && usage.reconciled_receipts == 0
        {
            tx.execute(
                "DELETE FROM quota_epochs
                 WHERE scope_kind = ?1 AND scope_id = ?2 AND epoch = ?3",
                params![scope.kind.as_str(), scope.id, epoch_blob.as_slice()],
            )
            .map_err(|error| {
                quota_error(format!("failed to delete empty quota scope epoch: {error}"))
            })?;
            crash_quota_mutation_after_step_for_test("quota_epochs empty aggregate delete");
        } else {
            let requests = u64_blob(usage.requests);
            let tokens = u64_blob(usage.tokens);
            tx.execute(
                "INSERT INTO quota_epochs
                    (scope_kind, scope_id, epoch, requests, tokens)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(scope_kind, scope_id, epoch) DO UPDATE SET
                    requests = excluded.requests,
                    tokens = excluded.tokens",
                params![
                    scope.kind.as_str(),
                    scope.id,
                    epoch_blob.as_slice(),
                    requests.as_slice(),
                    tokens.as_slice()
                ],
            )
            .map_err(|error| {
                quota_error(format!("failed to write quota scope aggregate: {error}"))
            })?;
            crash_quota_mutation_after_step_for_test("quota_epochs recomputed aggregate upsert");
        }
        Ok(usage)
    }

    fn receipt_scope_keys(
        tx: &Transaction<'_>,
        receipt: &StoredQuotaReceipt,
    ) -> Result<Vec<QuotaScopeKey>, ContextError> {
        Ok(Self::load_receipt_scopes(tx, receipt)?
            .into_iter()
            .map(|scope| scope.key)
            .collect())
    }

    fn validate_provider_epoch(
        tx: &Transaction<'_>,
        epoch: u64,
    ) -> Result<ProviderRateUsage, ContextError> {
        let usage = Self::validate_scope_epoch(tx, &QuotaScopeKey::provider_global(), epoch)?;
        Ok(ProviderRateUsage {
            epoch: usage.epoch,
            requests: usage.requests,
            tokens: usage.tokens,
            reserved_receipts: usage.reserved_receipts,
            in_flight_receipts: usage.in_flight_receipts,
            estimated_receipts: usage.estimated_receipts,
            reconciled_receipts: usage.reconciled_receipts,
        })
    }

    fn validate_all_provider_epochs(tx: &Transaction<'_>) -> Result<(), ContextError> {
        let dangling_scope = tx
            .query_row(
                "SELECT 1
                 FROM quota_receipt_scopes s
                 LEFT JOIN quota_receipts r ON r.id = s.receipt_id
                 WHERE r.id IS NULL LIMIT 1",
                [],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| {
                quota_error(format!("failed to validate quota scope ownership: {error}"))
            })?
            .is_some();
        if dangling_scope {
            return Err(quota_error("quota scope association has no receipt"));
        }

        let mut receipt_statement = tx
            .prepare("SELECT id FROM quota_receipts ORDER BY id")
            .map_err(|error| {
                quota_error(format!(
                    "failed to prepare quota receipt validation: {error}"
                ))
            })?;
        let receipt_rows = receipt_statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| quota_error(format!("failed to enumerate quota receipts: {error}")))?;
        let mut receipt_ids = Vec::new();
        for row in receipt_rows {
            let id = row.map_err(|error| {
                quota_error(format!("failed to read quota receipt id: {error}"))
            })?;
            receipt_ids.push(uuid::Uuid::parse_str(&id).map_err(|error| {
                quota_error(format!("malformed quota receipt id {id:?}: {error}"))
            })?);
        }
        drop(receipt_statement);
        for id in receipt_ids {
            let receipt = Self::load_quota_receipt(tx, id)?
                .ok_or_else(|| quota_error(format!("quota receipt {id} disappeared")))?;
            let _ = Self::load_receipt_scopes(tx, &receipt)?;
        }

        let mut scopes = BTreeSet::new();
        let mut epoch_statement = tx
            .prepare("SELECT scope_kind, scope_id, epoch FROM quota_epochs")
            .map_err(|error| {
                quota_error(format!("failed to prepare quota epoch validation: {error}"))
            })?;
        let epoch_rows = epoch_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|error| quota_error(format!("failed to enumerate quota epochs: {error}")))?;
        for row in epoch_rows {
            let (kind, id, epoch) =
                row.map_err(|error| quota_error(format!("failed to read quota epoch: {error}")))?;
            let scope = QuotaScopeKey {
                kind: QuotaScopeKind::parse(&kind)?,
                id,
            };
            validate_quota_scope_key(&scope)?;
            scopes.insert((scope, parse_u64_blob(epoch, "quota epoch")?));
        }
        drop(epoch_statement);

        let mut association_statement = tx
            .prepare(
                "SELECT s.scope_kind, s.scope_id, r.epoch
                 FROM quota_receipt_scopes s
                 JOIN quota_receipts r ON r.id = s.receipt_id",
            )
            .map_err(|error| {
                quota_error(format!(
                    "failed to prepare quota association validation: {error}"
                ))
            })?;
        let association_rows = association_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|error| {
                quota_error(format!("failed to enumerate quota associations: {error}"))
            })?;
        for row in association_rows {
            let (kind, id, epoch) = row.map_err(|error| {
                quota_error(format!("failed to read quota association: {error}"))
            })?;
            let scope = QuotaScopeKey {
                kind: QuotaScopeKind::parse(&kind)?,
                id,
            };
            validate_quota_scope_key(&scope)?;
            scopes.insert((scope, parse_u64_blob(epoch, "quota association epoch")?));
        }
        drop(association_statement);

        for (scope, epoch) in scopes {
            Self::validate_scope_epoch(tx, &scope, epoch)?;
        }
        Ok(())
    }

    fn quota_receipt_was_refunded(
        tx: &Transaction<'_>,
        id: uuid::Uuid,
    ) -> Result<bool, ContextError> {
        tx.query_row(
            "SELECT 1 FROM quota_refunded_receipts WHERE id = ?1",
            [id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|error| {
            quota_error(format!(
                "failed to inspect refunded quota receipt {id}: {error}"
            ))
        })
    }

    fn commit_quota_transaction(tx: Transaction<'_>) -> Result<(), ContextError> {
        tx.commit()
            .map_err(|error| quota_error(format!("failed to commit quota transaction: {error}")))
    }

    /// Atomically reserve one provider request and its token estimate.
    ///
    /// Zero RPM/TPM values are unlimited. Reusing the same UUID is idempotent
    /// when it describes the same estimate, even after the clock advances; a
    /// conflicting reuse fails closed.
    #[cfg(test)]
    pub(crate) fn reserve_provider_rate(
        &self,
        receipt_id: uuid::Uuid,
        requested_epoch: u64,
        rpm: u32,
        tpm: u64,
        estimated_tokens: u64,
    ) -> Result<ProviderRateReserveOutcome, ContextError> {
        self.reserve_provider_rate_with_cgroups(
            receipt_id,
            requested_epoch,
            rpm,
            tpm,
            estimated_tokens,
            &[],
        )
    }

    /// Atomically reserve provider/global and an ordered root-to-leaf set of
    /// stable cgroup scopes. Provider/global records one request plus the token
    /// estimate; cgroup scopes record only the same token estimate and enforce
    /// only their token limit.
    #[cfg(test)]
    pub(crate) fn reserve_provider_rate_with_cgroups(
        &self,
        receipt_id: uuid::Uuid,
        requested_epoch: u64,
        rpm: u32,
        tpm: u64,
        estimated_tokens: u64,
        cgroups: &[CgroupQuotaConstraint],
    ) -> Result<ProviderRateReserveOutcome, ContextError> {
        self.reserve_provider_rate_attempts_with_cgroups(
            ProviderRateRequest {
                receipt_id,
                requested_epoch,
                rpm,
                tpm,
                estimated_requests: 1,
                estimated_tokens,
            },
            cgroups,
        )
    }

    /// Reserve a bounded batch of possible resilient provider attempts under
    /// one affine receipt. The caller reconciles the exact attempt count after
    /// a successful request.
    pub(crate) fn reserve_provider_rate_attempts_with_cgroups(
        &self,
        request: ProviderRateRequest,
        cgroups: &[CgroupQuotaConstraint],
    ) -> Result<ProviderRateReserveOutcome, ContextError> {
        let ProviderRateRequest {
            receipt_id,
            requested_epoch,
            rpm,
            tpm,
            estimated_requests,
            estimated_tokens,
        } = request;
        if estimated_requests == 0 {
            return Err(quota_error(
                "provider attempt reservation must include at least one request",
            ));
        }
        let mut seen = BTreeSet::new();
        for constraint in cgroups {
            let key = QuotaScopeKey::cgroup(&constraint.scope_id);
            validate_quota_scope_key(&key)?;
            if !seen.insert(constraint.scope_id.as_str()) {
                return Err(quota_error(format!(
                    "duplicate cgroup quota scope {:?}",
                    constraint.scope_id
                )));
            }
        }
        if cgroups.len() >= u32::MAX as usize {
            return Err(quota_error("too many cgroup quota scopes"));
        }

        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        let effective_epoch = Self::effective_quota_epoch(&tx, requested_epoch)?;

        if let Some(receipt) = Self::load_quota_receipt(&tx, receipt_id)? {
            let scopes = Self::load_receipt_scopes(&tx, &receipt)?;
            for scope in &scopes {
                Self::required_scope_epoch_aggregate(&tx, &scope.key, receipt.epoch)?;
            }
            let stored_cgroups: Vec<&str> = scopes
                .iter()
                .skip(1)
                .map(|scope| scope.key.id.as_str())
                .collect();
            let requested_cgroups: Vec<&str> = cgroups
                .iter()
                .map(|constraint| constraint.scope_id.as_str())
                .collect();
            if receipt.reserved_requests != estimated_requests
                || receipt.reserved_tokens != estimated_tokens
            {
                return Err(quota_error(format!(
                    "quota receipt {receipt_id} was reused with conflicting reservation data"
                )));
            }
            if stored_cgroups != requested_cgroups {
                return Err(quota_error(format!(
                    "quota receipt {receipt_id} was reused with different cgroup scopes"
                )));
            }
            let reservation = ProviderRateReservation {
                id: receipt.id,
                epoch: receipt.epoch,
                reserved_requests: receipt.reserved_requests,
                reserved_tokens: receipt.reserved_tokens,
                state: receipt.state,
                cgroup_scopes: stored_cgroups.into_iter().map(str::to_string).collect(),
            };
            Self::commit_quota_transaction(tx)?;
            return Ok(ProviderRateReserveOutcome::Reserved(reservation));
        }
        if Self::quota_receipt_was_refunded(&tx, receipt_id)? {
            return Err(quota_error(format!(
                "refunded quota receipt {receipt_id} cannot be reused"
            )));
        }

        let epoch_blob = u64_blob(effective_epoch);
        let fenced = tx
            .query_row(
                "SELECT 1 FROM quota_migration_fence WHERE epoch = ?1",
                params![epoch_blob.as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| {
                quota_error(format!("failed to inspect quota migration fence: {error}"))
            })?
            .is_some();
        if fenced {
            let outcome = ProviderRateReserveOutcome::Denied {
                epoch: effective_epoch,
                scope: QuotaScopeKey::provider_global(),
                dimension: ProviderRateLimitDimension::MigrationFence,
                used: 0,
                requested: 0,
                limit: 0,
            };
            Self::commit_quota_transaction(tx)?;
            return Ok(outcome);
        }

        let provider_scope = QuotaScopeKey::provider_global();
        let usage = Self::trusted_scope_epoch_aggregate(&tx, &provider_scope, effective_epoch)?;
        let mut cgroup_usages = Vec::with_capacity(cgroups.len());
        for constraint in cgroups {
            let scope = QuotaScopeKey::cgroup(&constraint.scope_id);
            let usage = Self::trusted_scope_epoch_aggregate(&tx, &scope, effective_epoch)?;
            cgroup_usages.push((constraint, scope, usage));
        }
        let rpm = u64::from(rpm);
        if rpm != 0 && (usage.0 > rpm || estimated_requests > rpm.saturating_sub(usage.0)) {
            let outcome = ProviderRateReserveOutcome::Denied {
                epoch: effective_epoch,
                scope: provider_scope.clone(),
                dimension: ProviderRateLimitDimension::Requests,
                used: usage.0,
                requested: estimated_requests,
                limit: rpm,
            };
            Self::commit_quota_transaction(tx)?;
            return Ok(outcome);
        }
        if tpm != 0 && (usage.1 > tpm || estimated_tokens > tpm.saturating_sub(usage.1)) {
            let outcome = ProviderRateReserveOutcome::Denied {
                epoch: effective_epoch,
                scope: provider_scope.clone(),
                dimension: ProviderRateLimitDimension::Tokens,
                used: usage.1,
                requested: estimated_tokens,
                limit: tpm,
            };
            Self::commit_quota_transaction(tx)?;
            return Ok(outcome);
        }
        for (constraint, scope, usage) in &cgroup_usages {
            if constraint.token_limit != 0
                && (usage.1 > constraint.token_limit
                    || estimated_tokens > constraint.token_limit.saturating_sub(usage.1))
            {
                let outcome = ProviderRateReserveOutcome::Denied {
                    epoch: effective_epoch,
                    scope: scope.clone(),
                    dimension: ProviderRateLimitDimension::Tokens,
                    used: usage.1,
                    requested: estimated_tokens,
                    limit: constraint.token_limit,
                };
                Self::commit_quota_transaction(tx)?;
                return Ok(outcome);
            }
        }

        let requests = u64_blob(estimated_requests);
        let zero = u64_blob(0);
        let estimate = u64_blob(estimated_tokens);
        tx.execute(
            "INSERT INTO quota_receipts
                (id, receipt_kind, epoch, state, reserved_requests, reserved_tokens,
                 actual_requests, actual_tokens)
             VALUES (?1, 'provider_request', ?2, 'reserved', ?3, ?4, NULL, NULL)",
            params![
                receipt_id.to_string(),
                epoch_blob.as_slice(),
                requests.as_slice(),
                estimate.as_slice()
            ],
        )
        .map_err(|error| {
            quota_error(format!("failed to insert provider quota receipt: {error}"))
        })?;
        crash_quota_mutation_after_step_for_test("quota_receipts reservation insert");
        tx.execute(
            "INSERT INTO quota_receipt_scopes
                (receipt_id, scope_order, scope_kind, scope_id,
                 reserved_requests, reserved_tokens,
                 actual_requests, actual_tokens)
             VALUES (?1, 0, ?2, ?3, ?4, ?5, NULL, NULL)",
            params![
                receipt_id.to_string(),
                PROVIDER_QUOTA_SCOPE_KIND,
                PROVIDER_QUOTA_SCOPE_ID,
                requests.as_slice(),
                estimate.as_slice()
            ],
        )
        .map_err(|error| {
            quota_error(format!(
                "failed to associate provider quota receipt: {error}"
            ))
        })?;
        crash_quota_mutation_after_step_for_test("quota_receipt_scopes provider insert");
        for (index, constraint) in cgroups.iter().enumerate() {
            let scope_order = i64::try_from(index + 1)
                .map_err(|_| quota_error("too many cgroup quota scopes"))?;
            tx.execute(
                "INSERT INTO quota_receipt_scopes
                    (receipt_id, scope_order, scope_kind, scope_id,
                     reserved_requests, reserved_tokens,
                     actual_requests, actual_tokens)
                 VALUES (?1, ?2, 'cgroup', ?3, ?4, ?5, NULL, NULL)",
                params![
                    receipt_id.to_string(),
                    scope_order,
                    constraint.scope_id,
                    zero.as_slice(),
                    estimate.as_slice()
                ],
            )
            .map_err(|error| {
                quota_error(format!(
                    "failed to associate cgroup quota receipt scope {:?}: {error}",
                    constraint.scope_id
                ))
            })?;
            crash_quota_mutation_after_step_for_test("quota_receipt_scopes cgroup insert");
        }
        Self::write_scope_epoch_aggregate(
            &tx,
            &provider_scope,
            effective_epoch,
            usage.0.saturating_add(estimated_requests),
            usage.1.saturating_add(estimated_tokens),
        )?;
        for (_, scope, aggregate) in cgroup_usages {
            Self::write_scope_epoch_aggregate(
                &tx,
                &scope,
                effective_epoch,
                aggregate.0,
                aggregate.1.saturating_add(estimated_tokens),
            )?;
        }
        Self::commit_quota_transaction(tx)?;
        Ok(ProviderRateReserveOutcome::Reserved(
            ProviderRateReservation {
                id: receipt_id,
                epoch: effective_epoch,
                reserved_requests: estimated_requests,
                reserved_tokens: estimated_tokens,
                state: ProviderRateReceiptState::Reserved,
                cgroup_scopes: cgroups
                    .iter()
                    .map(|constraint| constraint.scope_id.clone())
                    .collect(),
            },
        ))
    }

    /// Mark that provider I/O may have started. This transition is idempotent;
    /// after it commits, cancellation/crash must retain at least the estimate.
    pub(crate) fn mark_provider_rate_invoked(
        &self,
        receipt_id: uuid::Uuid,
    ) -> Result<(), ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        let receipt = Self::load_quota_receipt(&tx, receipt_id)?
            .ok_or_else(|| quota_error(format!("unknown quota receipt {receipt_id}")))?;
        let scopes = Self::receipt_scope_keys(&tx, &receipt)?;
        for scope in &scopes {
            Self::required_scope_epoch_aggregate(&tx, scope, receipt.epoch)?;
        }
        if receipt.state == ProviderRateReceiptState::Reserved {
            tx.execute(
                "UPDATE quota_receipts SET state = 'in_flight' WHERE id = ?1",
                [receipt_id.to_string()],
            )
            .map_err(|error| {
                quota_error(format!(
                    "failed to mark provider quota receipt in flight: {error}"
                ))
            })?;
        }
        Self::commit_quota_transaction(tx)
    }

    /// Refund a reservation only while provider I/O is known not to have
    /// started. A tombstone makes repeated refunds idempotent.
    pub(crate) fn refund_provider_rate_before_invocation(
        &self,
        receipt_id: uuid::Uuid,
    ) -> Result<(), ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        let Some(receipt) = Self::load_quota_receipt(&tx, receipt_id)? else {
            if Self::quota_receipt_was_refunded(&tx, receipt_id)? {
                Self::commit_quota_transaction(tx)?;
                return Ok(());
            }
            return Err(quota_error(format!("unknown quota receipt {receipt_id}")));
        };
        let scopes = Self::load_receipt_scopes(&tx, &receipt)?;
        for scope in &scopes {
            Self::required_scope_epoch_aggregate(&tx, &scope.key, receipt.epoch)?;
        }
        if receipt.state != ProviderRateReceiptState::Reserved {
            return Err(quota_error(format!(
                "quota receipt {receipt_id} cannot be refunded after provider invocation"
            )));
        }
        let epoch_blob = u64_blob(receipt.epoch);
        tx.execute(
            "INSERT INTO quota_refunded_receipts(id, epoch) VALUES (?1, ?2)",
            params![receipt_id.to_string(), epoch_blob.as_slice()],
        )
        .map_err(|error| quota_error(format!("failed to tombstone refunded receipt: {error}")))?;
        crash_quota_mutation_after_step_for_test("quota_refunded_receipts refund insert");
        tx.execute(
            "DELETE FROM quota_receipts WHERE id = ?1",
            [receipt_id.to_string()],
        )
        .map_err(|error| quota_error(format!("failed to refund quota receipt: {error}")))?;
        crash_quota_mutation_after_step_for_test("quota_receipts refund delete");
        for scope in &scopes {
            Self::replace_scope_epoch_contribution(
                &tx,
                &scope.key,
                receipt.epoch,
                Self::scope_contribution(&receipt, scope),
                (0, 0),
            )?;
        }
        Self::commit_quota_transaction(tx)
    }

    /// Conservatively retain an in-flight estimate when actual usage is
    /// unavailable (provider error, cancellation, crash recovery).
    pub(crate) fn retain_provider_rate_estimate(
        &self,
        receipt_id: uuid::Uuid,
    ) -> Result<(), ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        let receipt = Self::load_quota_receipt(&tx, receipt_id)?
            .ok_or_else(|| quota_error(format!("unknown quota receipt {receipt_id}")))?;
        let scopes = Self::receipt_scope_keys(&tx, &receipt)?;
        for scope in &scopes {
            Self::required_scope_epoch_aggregate(&tx, scope, receipt.epoch)?;
        }
        match receipt.state {
            ProviderRateReceiptState::InFlight => {
                tx.execute(
                    "UPDATE quota_receipts SET state = 'estimated' WHERE id = ?1",
                    [receipt_id.to_string()],
                )
                .map_err(|error| {
                    quota_error(format!("failed to retain provider quota estimate: {error}"))
                })?;
            }
            ProviderRateReceiptState::Estimated | ProviderRateReceiptState::Reconciled => {}
            ProviderRateReceiptState::Reserved => {
                return Err(quota_error(format!(
                    "quota receipt {receipt_id} was not marked invoked"
                )));
            }
        }
        Self::commit_quota_transaction(tx)
    }

    /// Replace the estimate with actual usage in the original admission epoch.
    ///
    /// The original epoch is intentional: a long request cannot consume fresh
    /// capacity merely because its response arrived after a minute boundary.
    pub(crate) fn reconcile_provider_rate(
        &self,
        receipt_id: uuid::Uuid,
        actual_tokens: u64,
    ) -> Result<(), ContextError> {
        self.reconcile_provider_rate_inner(receipt_id, None, actual_tokens)
    }

    pub(crate) fn reconcile_provider_rate_attempts(
        &self,
        receipt_id: uuid::Uuid,
        actual_requests: u64,
        actual_tokens: u64,
    ) -> Result<(), ContextError> {
        self.reconcile_provider_rate_inner(receipt_id, Some(actual_requests), actual_tokens)
    }

    fn reconcile_provider_rate_inner(
        &self,
        receipt_id: uuid::Uuid,
        actual_requests: Option<u64>,
        actual_tokens: u64,
    ) -> Result<(), ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        let receipt = Self::load_quota_receipt(&tx, receipt_id)?
            .ok_or_else(|| quota_error(format!("unknown quota receipt {receipt_id}")))?;
        let scopes = Self::load_receipt_scopes(&tx, &receipt)?;
        let actual_requests = actual_requests.unwrap_or(receipt.reserved_requests);
        if actual_requests == 0 || actual_requests > receipt.reserved_requests {
            return Err(quota_error(format!(
                "quota receipt {receipt_id} actual request count {actual_requests} is outside reserved range 1..={}",
                receipt.reserved_requests
            )));
        }
        for scope in &scopes {
            Self::required_scope_epoch_aggregate(&tx, &scope.key, receipt.epoch)?;
        }
        match receipt.state {
            ProviderRateReceiptState::Reconciled => {
                if receipt.actual_requests != Some(actual_requests)
                    || receipt.actual_tokens != Some(actual_tokens)
                {
                    return Err(quota_error(format!(
                        "quota receipt {receipt_id} was reconciled with different usage"
                    )));
                }
            }
            ProviderRateReceiptState::InFlight | ProviderRateReceiptState::Estimated => {
                let actual_requests_blob = u64_blob(actual_requests);
                let actual_tokens_blob = u64_blob(actual_tokens);
                let zero = u64_blob(0);
                tx.execute(
                    "UPDATE quota_receipts
                     SET state = 'reconciled',
                         actual_requests = ?1, actual_tokens = ?2
                     WHERE id = ?3",
                    params![
                        actual_requests_blob.as_slice(),
                        actual_tokens_blob.as_slice(),
                        receipt_id.to_string()
                    ],
                )
                .map_err(|error| {
                    quota_error(format!("failed to reconcile quota receipt: {error}"))
                })?;
                crash_quota_mutation_after_step_for_test("quota_receipts reconcile update");
                tx.execute(
                    "UPDATE quota_receipt_scopes
                     SET actual_requests = CASE
                             WHEN scope_kind = 'provider' THEN ?1
                             ELSE ?2
                         END,
                         actual_tokens = ?3
                     WHERE receipt_id = ?4",
                    params![
                        actual_requests_blob.as_slice(),
                        zero.as_slice(),
                        actual_tokens_blob.as_slice(),
                        receipt_id.to_string()
                    ],
                )
                .map_err(|error| {
                    quota_error(format!("failed to reconcile provider quota scope: {error}"))
                })?;
                crash_quota_mutation_after_step_for_test("quota_receipt_scopes reconcile update");
                for scope in &scopes {
                    Self::replace_scope_epoch_contribution(
                        &tx,
                        &scope.key,
                        receipt.epoch,
                        Self::scope_contribution(&receipt, scope),
                        (
                            if scope.key.kind == QuotaScopeKind::Provider {
                                actual_requests
                            } else {
                                0
                            },
                            actual_tokens,
                        ),
                    )?;
                }
            }
            ProviderRateReceiptState::Reserved => {
                return Err(quota_error(format!(
                    "quota receipt {receipt_id} was not marked invoked"
                )));
            }
        }
        Self::commit_quota_transaction(tx)
    }

    /// Charge observed provider tokens without consuming an RPM slot.
    ///
    /// The caller supplies a stable UUID so retries cannot double-charge.
    pub(crate) fn charge_provider_rate_tokens(
        &self,
        receipt_id: uuid::Uuid,
        requested_epoch: u64,
        tokens: u64,
    ) -> Result<(), ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        let effective_epoch = Self::effective_quota_epoch(&tx, requested_epoch)?;
        if let Some(receipt) = Self::load_quota_receipt(&tx, receipt_id)? {
            let scopes = Self::load_receipt_scopes(&tx, &receipt)?;
            for scope in &scopes {
                Self::required_scope_epoch_aggregate(&tx, &scope.key, receipt.epoch)?;
            }
            if receipt.reserved_requests == 0
                && receipt.reserved_tokens == 0
                && receipt.state == ProviderRateReceiptState::Reconciled
                && receipt.actual_requests == Some(0)
                && receipt.actual_tokens == Some(tokens)
                && scopes.len() == 1
                && scopes[0].key == QuotaScopeKey::provider_global()
            {
                Self::commit_quota_transaction(tx)?;
                return Ok(());
            }
            return Err(quota_error(format!(
                "quota receipt {receipt_id} was reused with conflicting token charge"
            )));
        }
        if Self::quota_receipt_was_refunded(&tx, receipt_id)? {
            return Err(quota_error(format!(
                "refunded quota receipt {receipt_id} cannot be reused"
            )));
        }
        let provider_scope = QuotaScopeKey::provider_global();
        let aggregate = Self::trusted_scope_epoch_aggregate(&tx, &provider_scope, effective_epoch)?;
        let epoch_blob = u64_blob(effective_epoch);
        let zero = u64_blob(0);
        let token_blob = u64_blob(tokens);
        tx.execute(
            "INSERT INTO quota_receipts
                (id, receipt_kind, epoch, state, reserved_requests, reserved_tokens,
                 actual_requests, actual_tokens)
             VALUES (?1, 'provider_request', ?2, 'reconciled', ?3, ?3, ?3, ?4)",
            params![
                receipt_id.to_string(),
                epoch_blob.as_slice(),
                zero.as_slice(),
                token_blob.as_slice()
            ],
        )
        .map_err(|error| quota_error(format!("failed to insert direct token charge: {error}")))?;
        crash_quota_mutation_after_step_for_test("quota_receipts direct charge insert");
        tx.execute(
            "INSERT INTO quota_receipt_scopes
                (receipt_id, scope_order, scope_kind, scope_id,
                 reserved_requests, reserved_tokens,
                 actual_requests, actual_tokens)
             VALUES (?1, 0, ?2, ?3, ?4, ?4, ?4, ?5)",
            params![
                receipt_id.to_string(),
                PROVIDER_QUOTA_SCOPE_KIND,
                PROVIDER_QUOTA_SCOPE_ID,
                zero.as_slice(),
                token_blob.as_slice()
            ],
        )
        .map_err(|error| {
            quota_error(format!("failed to associate direct token charge: {error}"))
        })?;
        crash_quota_mutation_after_step_for_test("quota_receipt_scopes direct charge insert");
        Self::write_scope_epoch_aggregate(
            &tx,
            &provider_scope,
            effective_epoch,
            aggregate.0,
            aggregate.1.saturating_add(tokens),
        )?;
        Self::commit_quota_transaction(tx)
    }

    /// Return durable provider usage for the monotonic effective epoch.
    pub(crate) fn provider_rate_usage(
        &self,
        requested_epoch: u64,
    ) -> Result<ProviderRateUsage, ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        let effective_epoch = Self::effective_quota_epoch(&tx, requested_epoch)?;
        let usage = Self::validate_provider_epoch(&tx, effective_epoch)?;
        Self::commit_quota_transaction(tx)?;
        Ok(usage)
    }

    /// Return durable usage for one stable provider or cgroup scope in the
    /// monotonic effective epoch.
    #[cfg(test)]
    pub(crate) fn quota_scope_usage(
        &self,
        requested_epoch: u64,
        scope: &QuotaScopeKey,
    ) -> Result<QuotaScopeUsage, ContextError> {
        validate_quota_scope_key(scope)?;
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        let effective_epoch = Self::effective_quota_epoch(&tx, requested_epoch)?;
        let usage = Self::validate_scope_epoch(&tx, scope, effective_epoch)?;
        Self::commit_quota_transaction(tx)?;
        Ok(usage)
    }

    /// Recover all durable provider receipts before admitting new work.
    ///
    /// A merely-reserved request is known not to have reached provider I/O and
    /// is refunded. In-flight work may have happened, so its estimate becomes
    /// terminal/conservative. The whole recovery is one IMMEDIATE transaction.
    pub(crate) fn recover_provider_rate_state(
        &self,
        requested_epoch: u64,
    ) -> Result<ProviderRateRecovery, ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        let effective_epoch = Self::effective_quota_epoch(&tx, requested_epoch)?;
        Self::validate_all_provider_epochs(&tx)?;

        let mut statement = tx
            .prepare(
                "SELECT r.id
                 FROM quota_receipts r
                 WHERE r.receipt_kind = 'provider_request'
                   AND r.state IN ('reserved', 'in_flight')
                 ORDER BY r.id",
            )
            .map_err(|error| {
                quota_error(format!("failed to prepare quota recovery scan: {error}"))
            })?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| quota_error(format!("failed to scan quota recovery: {error}")))?;
        let mut ids = Vec::new();
        for row in rows {
            let id = row.map_err(|error| {
                quota_error(format!("failed to read recovery receipt: {error}"))
            })?;
            ids.push(uuid::Uuid::parse_str(&id).map_err(|error| {
                quota_error(format!("malformed recovery receipt id {id:?}: {error}"))
            })?);
        }
        drop(statement);

        let mut recovery = ProviderRateRecovery {
            effective_epoch,
            ..ProviderRateRecovery::default()
        };
        let mut affected_scopes = BTreeSet::new();
        for id in ids {
            let receipt = Self::load_quota_receipt(&tx, id)?
                .ok_or_else(|| quota_error(format!("recovery receipt {id} disappeared")))?;
            for scope in Self::receipt_scope_keys(&tx, &receipt)? {
                affected_scopes.insert((scope, receipt.epoch));
            }
            match receipt.state {
                ProviderRateReceiptState::Reserved => {
                    let epoch_blob = u64_blob(receipt.epoch);
                    tx.execute(
                        "INSERT INTO quota_refunded_receipts(id, epoch)
                         VALUES (?1, ?2)",
                        params![id.to_string(), epoch_blob.as_slice()],
                    )
                    .map_err(|error| {
                        quota_error(format!(
                            "failed to tombstone recovered reservation: {error}"
                        ))
                    })?;
                    crash_quota_mutation_after_step_for_test(
                        "quota_refunded_receipts recovery insert",
                    );
                    tx.execute("DELETE FROM quota_receipts WHERE id = ?1", [id.to_string()])
                        .map_err(|error| {
                            quota_error(format!("failed to refund recovered reservation: {error}"))
                        })?;
                    crash_quota_mutation_after_step_for_test(
                        "quota_receipts recovery refund delete",
                    );
                    recovery.refunded_reserved = recovery.refunded_reserved.saturating_add(1);
                }
                ProviderRateReceiptState::InFlight => {
                    tx.execute(
                        "UPDATE quota_receipts SET state = 'estimated' WHERE id = ?1",
                        [id.to_string()],
                    )
                    .map_err(|error| {
                        quota_error(format!(
                            "failed to retain recovered in-flight estimate: {error}"
                        ))
                    })?;
                    crash_quota_mutation_after_step_for_test(
                        "quota_receipts recovery estimate update",
                    );
                    recovery.retained_in_flight_estimates =
                        recovery.retained_in_flight_estimates.saturating_add(1);
                }
                ProviderRateReceiptState::Estimated | ProviderRateReceiptState::Reconciled => {}
            }
        }
        for (scope, epoch) in affected_scopes {
            Self::write_scope_epoch_from_receipts(&tx, &scope, epoch)?;
        }
        Self::commit_quota_transaction(tx)?;
        Ok(recovery)
    }

    /// Prune completed epochs strictly before `before_epoch`.
    ///
    /// Any epoch with a reserved or in-flight receipt is retained intact. This
    /// predicate is global across scopes so a future cgroup mapping cannot be
    /// orphaned by provider-led pruning.
    pub(crate) fn prune_provider_rate_epochs(
        &self,
        before_epoch: u64,
    ) -> Result<usize, ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| quota_error("SQLite connection mutex is poisoned"))?;
        let tx = Self::begin_quota_transaction(&mut conn)?;
        Self::validate_all_provider_epochs(&tx)?;
        let before_blob = u64_blob(before_epoch);
        let mut statement = tx
            .prepare(
                "SELECT epoch FROM quota_epochs
                 WHERE epoch < ?1
                 UNION
                 SELECT epoch FROM quota_receipts
                 WHERE receipt_kind = 'provider_request' AND epoch < ?1
                 UNION
                 SELECT epoch FROM quota_refunded_receipts WHERE epoch < ?1
                 UNION
                 SELECT epoch FROM quota_migration_fence WHERE epoch < ?1
                 ORDER BY epoch",
            )
            .map_err(|error| quota_error(format!("failed to prepare quota prune: {error}")))?;
        let rows = statement
            .query_map(params![before_blob.as_slice()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|error| quota_error(format!("failed to scan quota prune: {error}")))?;
        let mut candidates = Vec::new();
        for row in rows {
            candidates.push(parse_u64_blob(
                row.map_err(|error| quota_error(format!("failed to read prune epoch: {error}")))?,
                "quota prune epoch",
            )?);
        }
        drop(statement);

        let mut pruned = 0usize;
        for epoch in candidates {
            let epoch_blob = u64_blob(epoch);
            let active = tx
                .query_row(
                    "SELECT 1 FROM quota_receipts
                     WHERE epoch = ?1 AND state IN ('reserved', 'in_flight')
                     LIMIT 1",
                    params![epoch_blob.as_slice()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|error| {
                    quota_error(format!("failed to inspect live prune receipts: {error}"))
                })?
                .is_some();
            if active {
                continue;
            }
            tx.execute(
                "DELETE FROM quota_receipts
                 WHERE epoch = ?1 AND state IN ('estimated', 'reconciled')",
                params![epoch_blob.as_slice()],
            )
            .map_err(|error| quota_error(format!("failed to prune completed receipts: {error}")))?;
            crash_quota_mutation_after_step_for_test("quota_receipts prune delete");
            tx.execute(
                "DELETE FROM quota_epochs WHERE epoch = ?1",
                params![epoch_blob.as_slice()],
            )
            .map_err(|error| quota_error(format!("failed to prune quota epoch: {error}")))?;
            crash_quota_mutation_after_step_for_test("quota_epochs prune delete");
            tx.execute(
                "DELETE FROM quota_refunded_receipts WHERE epoch = ?1",
                params![epoch_blob.as_slice()],
            )
            .map_err(|error| quota_error(format!("failed to prune refund tombstones: {error}")))?;
            crash_quota_mutation_after_step_for_test("quota_refunded_receipts prune delete");
            tx.execute(
                "DELETE FROM quota_migration_fence WHERE epoch = ?1",
                params![epoch_blob.as_slice()],
            )
            .map_err(|error| quota_error(format!("failed to prune migration fence: {error}")))?;
            crash_quota_mutation_after_step_for_test("quota_migration_fence prune delete");
            pruned = pruned.saturating_add(1);
        }
        Self::commit_quota_transaction(tx)?;
        Ok(pruned)
    }

    fn persist_with_retry(
        &self,
        agent_id: AgentId,
        context: &AgentContext,
    ) -> Result<(), ContextError> {
        let json = serde_json::to_string(context)
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        let now = Utc::now().to_rfc3339();
        let id_str = agent_id.to_string();

        for attempt in 0..MAX_RETRIES {
            let mut conn = self.conn.lock().unwrap();
            let transaction = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
            let tenant_id = transaction
                .query_row(
                    "SELECT tenant_id FROM agents WHERE id = ?1",
                    params![id_str],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| ContextError::StorageError(error.to_string()))?
                .unwrap_or_else(|| DEFAULT_TENANT.to_string());
            let replaced_bytes = transaction
                .query_row(
                    "SELECT LENGTH(context_json) FROM contexts WHERE agent_id = ?1",
                    params![id_str],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(|error| ContextError::StorageError(error.to_string()))?
                .unwrap_or(0)
                .max(0) as u64;
            self.enforce_context_storage_locked(
                &transaction,
                agent_id,
                &tenant_id,
                json.len() as u64,
                replaced_bytes,
            )?;
            let result = (|| {
                transaction.execute(
                    "INSERT OR REPLACE INTO contexts (agent_id, context_json, updated_at) VALUES (?1, ?2, ?3)",
                    params![id_str, json, now],
                )?;
                transaction.commit()
            })();
            match result {
                Ok(()) => return Ok(()),
                Err(e) if attempt < MAX_RETRIES - 1 => {
                    tracing::warn!("Persist attempt {} failed: {}", attempt + 1, e);
                    continue;
                }
                Err(e) => {
                    return Err(ContextError::PersistenceFailed(format!(
                        "Failed after {} attempts: {}",
                        MAX_RETRIES, e
                    )))
                }
            }
        }
        unreachable!()
    }
}

#[async_trait::async_trait]
impl ContextManager for SqliteContextManager {
    async fn create_context(&self, agent_id: AgentId) -> Result<(), ContextError> {
        let context = AgentContext::default();
        self.persist_with_retry(agent_id, &context)
    }

    async fn get_context(&self, agent_id: AgentId) -> Result<AgentContext, ContextError> {
        let conn = self.conn.lock().unwrap();
        let id_str = agent_id.to_string();
        let result = conn.query_row(
            "SELECT context_json FROM contexts WHERE agent_id = ?1",
            params![id_str],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(json) => {
                serde_json::from_str(&json).map_err(|e| ContextError::RestoreFailed(e.to_string()))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(ContextError::RestoreFailed(format!(
                "No context for agent {}",
                agent_id
            ))),
            Err(e) => Err(ContextError::StorageError(e.to_string())),
        }
    }

    async fn persist_context(
        &self,
        agent_id: AgentId,
        context: &AgentContext,
    ) -> Result<(), ContextError> {
        self.persist_with_retry(agent_id, context)
    }

    async fn restore_context(&self, agent_id: AgentId) -> Result<AgentContext, ContextError> {
        self.get_context(agent_id).await
    }

    async fn summarize_overflow(
        &self,
        context: &AgentContext,
        token_limit: u32,
    ) -> Result<AgentContext, ContextError> {
        if context.token_count <= token_limit {
            return Ok(context.clone());
        }

        // Summarize by keeping the most recent messages that fit within 80% of limit
        let target_tokens = (token_limit as f64 * 0.8) as u32;
        let mut new_context = context.clone();

        // Estimate ~4 chars per token, keep recent messages
        let mut kept_messages = Vec::new();
        let mut running_tokens: u32 = 0;

        for msg in context.conversation_history.iter().rev() {
            let msg_tokens = (msg.content.len() as u32) / 4 + 1;
            if running_tokens + msg_tokens > target_tokens {
                break;
            }
            running_tokens += msg_tokens;
            kept_messages.push(msg.clone());
        }
        kept_messages.reverse();

        // Add a summary message at the beginning if we dropped messages
        if kept_messages.len() < context.conversation_history.len() {
            let dropped = context.conversation_history.len() - kept_messages.len();
            let summary = Message {
                role: "system".to_string(),
                content: format!("[Summary: {} earlier messages condensed]", dropped),
                timestamp: Utc::now(),
            };
            kept_messages.insert(0, summary);
        }

        new_context.conversation_history = kept_messages;
        new_context.token_count = running_tokens;
        Ok(new_context)
    }

    async fn store_fact(&self, agent_id: AgentId, fact: Fact) -> Result<(), ContextError> {
        let mut conn = self.conn.lock().unwrap();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        // Persistence owns the embedding: caller-supplied vectors are not
        // trusted because they may have the wrong model, dimension, or tenant.
        let embedding = self.embedder.embed(&fact.content);
        let embedding_json = Some(serde_json::to_string(&embedding).unwrap_or_default());
        let embedding_model = self.embedder.model_id();
        let embedding_version = self.embedder.version();
        let embedding_dim = self.embedder.dim();
        let content_hash = memory_content_hash(&fact.content);
        let category_str = serde_json::to_string(&fact.category)
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let tenant_id = transaction
            .query_row(
                "SELECT tenant_id FROM agents WHERE id = ?1",
                params![agent_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?
            .unwrap_or_else(|| DEFAULT_TENANT.to_string());
        let existing = transaction
            .query_row(
                "SELECT agent_id,
                        LENGTH(content) + COALESCE(LENGTH(embedding_json), 0)
                        + LENGTH(embedding_model) + LENGTH(content_hash)
                 FROM facts WHERE id = ?1",
                params![fact.id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        if existing
            .as_ref()
            .is_some_and(|(owner, _)| owner != &agent_id.to_string())
        {
            return Err(ContextError::StorageError(
                "fact id is already owned by another agent".into(),
            ));
        }
        let replaced_bytes = existing.map_or(0, |(_, bytes)| bytes.max(0) as u64);
        let incoming_bytes = fact
            .content
            .len()
            .saturating_add(embedding_json.as_deref().map_or(0, str::len))
            .saturating_add(embedding_model.len())
            .saturating_add(content_hash.len()) as u64;
        self.enforce_context_storage_locked(
            &transaction,
            agent_id,
            &tenant_id,
            incoming_bytes,
            replaced_bytes,
        )?;

        transaction
            .execute(
                "INSERT OR REPLACE INTO facts
                (id, agent_id, content, category, created_at, last_accessed_at,
                 embedding_json, embedding_model, embedding_version,
                 embedding_dim, content_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    fact.id.to_string(),
                    agent_id.to_string(),
                    fact.content,
                    category_str,
                    fact.created_at.to_rfc3339(),
                    fact.last_accessed_at.to_rfc3339(),
                    embedding_json,
                    embedding_model,
                    i64::from(embedding_version),
                    i64::try_from(embedding_dim).unwrap_or(i64::MAX),
                    content_hash,
                ],
            )
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        transaction
            .commit()
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        Ok(())
    }

    async fn query_memory(
        &self,
        agent_id: AgentId,
        query: &str,
    ) -> Result<Vec<Fact>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let id_str = agent_id.to_string();

        // Fetch the agent's candidate facts. We pull all of the agent's facts
        // (rather than a substring `LIKE` prefilter) so that semantic ranking
        // can surface relevant facts that don't share literal tokens with the
        // query — that's the whole point of vector retrieval.
        let mut stmt = conn
            .prepare(
                "SELECT id, content, category, created_at, last_accessed_at,
                        embedding_json, embedding_model, embedding_version,
                        embedding_dim, content_hash
             FROM facts WHERE agent_id = ?1
             ORDER BY last_accessed_at DESC",
            )
            .map_err(|e| ContextError::StorageError(e.to_string()))?;

        let facts = stmt
            .query_map(params![id_str], |row| {
                let id_str: String = row.get(0)?;
                let content: String = row.get(1)?;
                let category_str: String = row.get(2)?;
                let created_str: String = row.get(3)?;
                let accessed_str: String = row.get(4)?;
                let embedding_str: Option<String> = row.get(5)?;
                let embedding_model: String = row.get(6)?;
                let embedding_version: i64 = row.get(7)?;
                let embedding_dim: i64 = row.get(8)?;
                let content_hash: String = row.get(9)?;
                Ok((
                    id_str,
                    content,
                    category_str,
                    created_str,
                    accessed_str,
                    embedding_str,
                    embedding_model,
                    embedding_version,
                    embedding_dim,
                    content_hash,
                ))
            })
            .map_err(|e| ContextError::StorageError(e.to_string()))?;

        let mut result = Vec::new();
        let mut repairs = Vec::new();
        for row in facts {
            let (
                id_str,
                content,
                category_str,
                created_str,
                accessed_str,
                embedding_str,
                embedding_model,
                embedding_version,
                embedding_dim,
                content_hash,
            ) = row.map_err(|e| ContextError::StorageError(e.to_string()))?;

            let id = uuid::Uuid::parse_str(&id_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let category: FactCategory = serde_json::from_str(&category_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let created_at = DateTime::parse_from_rfc3339(&created_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?
                .with_timezone(&Utc);
            let last_accessed_at = DateTime::parse_from_rfc3339(&accessed_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?
                .with_timezone(&Utc);
            let stored_embedding: Option<Vec<f32>> = embedding_str
                .as_deref()
                .and_then(|value| serde_json::from_str(value).ok());
            let expected_hash = memory_content_hash(&content);
            let valid_embedding = embedding_model == self.embedder.model_id()
                && embedding_version == i64::from(self.embedder.version())
                && embedding_dim == i64::try_from(self.embedder.dim()).unwrap_or(i64::MAX)
                && content_hash == expected_hash
                && stored_embedding.as_ref().is_some_and(|embedding| {
                    embedding.len() == self.embedder.dim()
                        && embedding.iter().all(|value| value.is_finite())
                });
            let embedding = if valid_embedding {
                stored_embedding.expect("validated embedding is present")
            } else {
                let rebuilt = self.embedder.embed(&content);
                let rebuilt_json = serde_json::to_string(&rebuilt)
                    .map_err(|error| ContextError::StorageError(error.to_string()))?;
                repairs.push((id_str.clone(), rebuilt_json, expected_hash));
                rebuilt
            };

            result.push(Fact {
                id,
                content,
                category,
                created_at,
                last_accessed_at,
                embedding: Some(embedding),
            });
        }
        drop(stmt);

        for (fact_id, embedding_json, content_hash) in repairs {
            conn.execute(
                "UPDATE facts
                 SET embedding_json = ?1, embedding_model = ?2,
                     embedding_version = ?3, embedding_dim = ?4,
                     content_hash = ?5
                 WHERE id = ?6 AND agent_id = ?7",
                params![
                    embedding_json,
                    self.embedder.model_id(),
                    i64::from(self.embedder.version()),
                    i64::try_from(self.embedder.dim()).unwrap_or(i64::MAX),
                    content_hash,
                    fact_id,
                    id_str,
                ],
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        }

        // Semantic ranking: embed the query and return the top-K facts by cosine
        // similarity (best-first). Invalid or stale rows were rebuilt and
        // persisted above before they are admitted to the index.
        //
        // Ranking goes through the `VectorIndex` seam (`rank_topk`): an exact scan
        // at small candidate counts, and the approximate `LshIndex` above
        // `ANN_EXACT_THRESHOLD` so an agent with a large fact store bounds the work
        // instead of scoring every vector. The top-K cap also keeps the caller
        // (which injects these facts into the LLM context) from dumping the whole
        // store into the prompt.
        const MEMORY_QUERY_TOP_K: usize = 16;
        const ANN_EXACT_THRESHOLD: usize = 64;
        let query_vec = self.embedder.embed(query);
        let scored: Vec<(Fact, Vec<f32>)> = result
            .into_iter()
            .map(|fact| {
                let emb = match &fact.embedding {
                    Some(e) if !e.is_empty() => e.clone(),
                    _ => self.embedder.embed(&fact.content),
                };
                (fact, emb)
            })
            .collect();
        let result: Vec<Fact> = crate::memory_manager::rank_topk(
            &query_vec,
            scored,
            MEMORY_QUERY_TOP_K,
            ANN_EXACT_THRESHOLD,
        )
        .into_iter()
        .map(|(fact, _score)| fact)
        .collect();

        // Update last_accessed_at for returned facts
        let now = Utc::now().to_rfc3339();
        for fact in &result {
            let _ = conn.execute(
                "UPDATE facts SET last_accessed_at = ?1 WHERE id = ?2",
                params![now, fact.id.to_string()],
            );
        }

        Ok(result)
    }
}

/// Conversation persistence methods.
impl SqliteContextManager {
    /// Save a conversation (messages as JSON).
    pub fn save_conversation(
        &self,
        id: &str,
        agent_id: AgentId,
        messages: &[crate::connector::StandardMessage],
    ) -> Result<(), ContextError> {
        let json = serde_json::to_string(messages)
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let tenant_id = transaction
            .query_row(
                "SELECT tenant_id FROM agents WHERE id = ?1",
                params![agent_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?
            .unwrap_or_else(|| DEFAULT_TENANT.to_string());
        let existing = transaction
            .query_row(
                "SELECT agent_id, LENGTH(messages_json) FROM conversations WHERE id = ?1",
                params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        if existing
            .as_ref()
            .is_some_and(|(owner, _)| owner != &agent_id.to_string())
        {
            return Err(ContextError::PersistenceFailed(
                "conversation id is already owned by another agent".into(),
            ));
        }
        let replaced_bytes = existing.map_or(0, |(_, bytes)| bytes.max(0) as u64);
        self.enforce_context_storage_locked(
            &transaction,
            agent_id,
            &tenant_id,
            json.len() as u64,
            replaced_bytes,
        )?;
        transaction.execute(
            "INSERT OR REPLACE INTO conversations (id, agent_id, messages_json, created_at, updated_at) VALUES (?1, ?2, ?3, COALESCE((SELECT created_at FROM conversations WHERE id=?1), ?4), ?4)",
            rusqlite::params![id, agent_id.to_string(), json, now],
        ).map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("conversation.conversations");
        let text_content: String = messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        transaction.execute(
            "INSERT OR REPLACE INTO conversations_fts (conversation_id, content) VALUES (?1, ?2)",
            rusqlite::params![id, text_content],
        )
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("conversation.conversations_fts");
        transaction
            .commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(())
    }

    /// Load a conversation's messages.
    pub fn load_conversation(
        &self,
        id: &str,
    ) -> Result<Vec<crate::connector::StandardMessage>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let json: String = conn
            .query_row(
                "SELECT messages_json FROM conversations WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .map_err(|e| ContextError::RestoreFailed(e.to_string()))?;
        serde_json::from_str(&json).map_err(|e| ContextError::RestoreFailed(e.to_string()))
    }

    /// List all conversations, sorted by most recently updated.
    pub fn list_conversations(&self) -> Vec<(String, String, String)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, agent_id, updated_at FROM conversations ORDER BY updated_at DESC")
            .unwrap_or_else(|_| conn.prepare("SELECT 1, 2, 3 WHERE 0").unwrap());
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Delete a conversation.
    pub fn delete_conversation(&self, id: &str) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM conversations WHERE id = ?1",
            rusqlite::params![id],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Export a conversation as JSON.
    pub fn export_conversation(&self, id: &str) -> Result<String, ContextError> {
        let messages = self.load_conversation(id)?;
        let export = serde_json::json!({
            "version": 1,
            "conversation_id": id,
            "messages": messages,
            "exported_at": chrono::Utc::now().to_rfc3339(),
        });
        serde_json::to_string_pretty(&export)
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))
    }

    /// Import a conversation from JSON.
    pub fn import_conversation(&self, json: &str) -> Result<String, ContextError> {
        let data: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| ContextError::RestoreFailed(format!("Invalid JSON: {}", e)))?;
        let messages: Vec<crate::connector::StandardMessage> =
            serde_json::from_value(data["messages"].clone())
                .map_err(|e| ContextError::RestoreFailed(format!("Invalid messages: {}", e)))?;
        let id = uuid::Uuid::new_v4().to_string();
        let agent_id = uuid::Uuid::nil();
        self.save_conversation(&id, agent_id, &messages)?;
        Ok(id)
    }

    pub fn log_usage(&self, agent_id: AgentId, record: &UsageRecord) -> Result<(), ContextError> {
        let cost_micros = i64::try_from(record.cost_micros).map_err(|_| {
            ContextError::PersistenceFailed(format!(
                "cost_micros {} exceeds SQLite INTEGER range",
                record.cost_micros
            ))
        })?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO usage_log (id, agent_id, timestamp, tokens_used, input_tokens, output_tokens, cached_tokens, llm_requests, retries, provider_latency_ms, provider_reported_requests, estimated_requests, provider, model, tool_calls, estimated_cost_usd, cost_micros) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            rusqlite::params![uuid::Uuid::new_v4().to_string(), agent_id.to_string(), chrono::Utc::now().to_rfc3339(), record.tokens_used, record.input_tokens, record.output_tokens, record.cached_tokens, record.llm_requests, record.retries, record.provider_latency_ms, record.provider_reported_requests, record.estimated_requests, record.provider, record.model, record.tool_calls as i64, record.estimated_cost_usd.max(0.0), cost_micros],
        )
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(())
    }

    /// Reconstruct exact cumulative budget state from durable usage rows.
    ///
    /// SQLite's `SUM(INTEGER)` can overflow before Rust sees the result, so
    /// every row is accumulated in Rust with `u64::saturating_add`.
    pub fn load_budget_usage_snapshot(&self) -> Result<BudgetUsageSnapshot, ContextError> {
        let conn = self.conn.lock().unwrap();
        let mut snapshot = BudgetUsageSnapshot::default();

        {
            let mut stmt = conn
                .prepare("SELECT id, tenant_id FROM agents")
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            for row in rows {
                let (agent, tenant) =
                    row.map_err(|error| ContextError::StorageError(error.to_string()))?;
                let agent = uuid::Uuid::parse_str(&agent)
                    .map_err(|error| ContextError::StorageError(error.to_string()))?;
                snapshot.agent_tenants.insert(agent, tenant);
            }
        }

        let mut stmt = conn
            .prepare("SELECT agent_id, cost_micros FROM usage_log ORDER BY rowid ASC")
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        for row in rows {
            let (agent, cost_micros) =
                row.map_err(|error| ContextError::StorageError(error.to_string()))?;
            let agent = uuid::Uuid::parse_str(&agent)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            let cost_micros = u64::try_from(cost_micros)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            let tenant = snapshot
                .agent_tenants
                .entry(agent)
                .or_insert_with(|| DEFAULT_TENANT.to_string())
                .clone();

            snapshot.global_micros = snapshot.global_micros.saturating_add(cost_micros);
            let agent_total = snapshot.per_agent_micros.entry(agent).or_insert(0);
            *agent_total = agent_total.saturating_add(cost_micros);
            let tenant_total = snapshot.per_tenant_micros.entry(tenant).or_insert(0);
            *tenant_total = tenant_total.saturating_add(cost_micros);
        }
        Ok(snapshot)
    }

    pub fn get_total_usage(&self) -> (u64, f64) {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(SUM(tokens_used), 0), COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage_log",
            [], |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, f64>(1)?)),
        ).unwrap_or((0, 0.0))
    }

    pub fn latest_usage(&self, agent_id: AgentId) -> Option<UsageRecord> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT tokens_used, input_tokens, output_tokens, cached_tokens, llm_requests, retries, provider_latency_ms, provider_reported_requests, estimated_requests, COALESCE(provider, ''), COALESCE(model, ''), tool_calls, COALESCE(estimated_cost_usd, 0.0), cost_micros FROM usage_log WHERE agent_id = ?1 ORDER BY rowid DESC LIMIT 1",
            [agent_id.to_string()],
            |row| {
                Ok(UsageRecord {
                    tokens_used: row.get(0)?,
                    input_tokens: row.get(1)?,
                    output_tokens: row.get(2)?,
                    cached_tokens: row.get(3)?,
                    llm_requests: row.get(4)?,
                    retries: row.get(5)?,
                    provider_latency_ms: row.get(6)?,
                    provider_reported_requests: row.get(7)?,
                    estimated_requests: row.get(8)?,
                    provider: row.get(9)?,
                    model: row.get(10)?,
                    tool_calls: row.get::<_, i64>(11)? as usize,
                    estimated_cost_usd: row.get(12)?,
                    cost_micros: row.get::<_, i64>(13)? as u64,
                })
            },
        )
        .ok()
    }

    /// Persist a lifecycle transition without rewriting the agent's immutable
    /// identity/config or creation timestamp.
    pub fn update_agent_status(
        &self,
        agent_id: AgentId,
        status: &crate::AgentState,
    ) -> Result<(), ContextError> {
        #[cfg(test)]
        {
            let prior = self
                .fail_agent_status_update_after
                .fetch_update(
                    AtomicOrdering::AcqRel,
                    AtomicOrdering::Acquire,
                    |countdown| {
                        if countdown > 0 {
                            Some(countdown - 1)
                        } else {
                            None
                        }
                    },
                )
                .ok();
            if prior == Some(1) {
                return Err(ContextError::PersistenceFailed(
                    "injected agent-status update failure".into(),
                ));
            }
        }
        let status = serde_json::to_string(status)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE agents SET status = ?1, last_activity_at = ?2 WHERE id = ?3",
                rusqlite::params![
                    status,
                    chrono::Utc::now().to_rfc3339(),
                    agent_id.to_string()
                ],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        if changed == 0 {
            return Err(ContextError::PersistenceFailed(
                "agent registry row not found".into(),
            ));
        }
        Ok(())
    }

    pub fn search_conversations(&self, query: &str) -> Vec<(String, String)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT conversation_id, snippet(conversations_fts, 1, '**', '**', '...', 32) FROM conversations_fts WHERE content MATCH ?1 LIMIT 20"
        ).unwrap_or_else(|_| conn.prepare("SELECT 1, 2 WHERE 0").unwrap());
        stmt.query_map(rusqlite::params![query], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }
}

/// Per-agent durable key/value store ("storage manager").
///
/// A simple persistent KV namespace scoped per agent — distinct from the
/// long-term-memory facts table (which is semantic / queryable). Values are
/// opaque strings (callers may JSON-encode structured data). Backed by the same
/// single SQLite handle as the rest of the context manager (no separate db).
impl SqliteContextManager {
    pub fn set_context_storage_limits(
        &self,
        limits: ContextStorageLimits,
    ) -> Result<(), ContextError> {
        if limits.spill_retention_seconds == 0 {
            return Err(ContextError::PersistenceFailed(
                "context spill retention must be greater than zero".into(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let spills = {
            let mut statement = conn
                .prepare("SELECT agent_id, key, created_at, expires_at FROM context_spills")
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            let mut values = Vec::new();
            for row in rows {
                values.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
            }
            values
        };
        for (agent_id, key, created_at, current_expiry) in spills {
            let created_at = DateTime::parse_from_rfc3339(&created_at)
                .map_err(|error| ContextError::StorageError(error.to_string()))?
                .with_timezone(&Utc);
            let current_expiry = DateTime::parse_from_rfc3339(&current_expiry)
                .map_err(|error| ContextError::StorageError(error.to_string()))?
                .with_timezone(&Utc);
            let configured_expiry = created_at
                + chrono::Duration::seconds(
                    limits.spill_retention_seconds.min(i64::MAX as u64) as i64
                );
            if configured_expiry < current_expiry {
                conn.execute(
                    "UPDATE context_spills SET expires_at = ?1
                     WHERE agent_id = ?2 AND key = ?3",
                    params![configured_expiry.to_rfc3339(), agent_id, key],
                )
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            }
        }
        Self::purge_expired_spills_locked(&mut conn)?;
        drop(conn);
        if let Ok(mut configured) = self.storage_limits.write() {
            *configured = limits;
            Ok(())
        } else {
            Err(ContextError::StorageError(
                "context storage limit lock is poisoned".into(),
            ))
        }
    }

    fn context_storage_usage_locked(
        conn: &Connection,
        agent_id: AgentId,
        tenant_id: &str,
    ) -> Result<ContextStorageUsage, ContextError> {
        let (agent, tenant, global) = conn
            .query_row(
                "WITH context_bytes(agent_id, byte_count) AS (
                    SELECT agent_id, LENGTH(context_json) FROM contexts
                    UNION ALL
                    SELECT agent_id, LENGTH(content) + COALESCE(LENGTH(embedding_json), 0) FROM facts
                    UNION ALL
                    SELECT agent_id, LENGTH(messages_json) FROM conversations
                    UNION ALL
                    SELECT agent_id, LENGTH(value) FROM agent_kv
                        WHERE key LIKE 'context_spill:%'
                    UNION ALL
                    SELECT agent_id, LENGTH(context_json) FROM context_snapshots
                    UNION ALL
                    SELECT agent_id, LENGTH(checkpoint_json) FROM generation_checkpoints
                        WHERE status IN ('active', 'resuming')
                )
                SELECT
                    COALESCE(SUM(CASE WHEN agent_id = ?1 THEN byte_count ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN COALESCE(
                        (SELECT tenant_id FROM agents WHERE id = context_bytes.agent_id),
                        'default'
                    ) = ?2 THEN byte_count ELSE 0 END), 0),
                    COALESCE(SUM(byte_count), 0)
                FROM context_bytes",
                params![agent_id.to_string(), tenant_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        Ok(ContextStorageUsage {
            agent_bytes: agent.max(0) as u64,
            tenant_bytes: tenant.max(0) as u64,
            global_bytes: global.max(0) as u64,
        })
    }

    fn enforce_context_storage_locked(
        &self,
        conn: &Connection,
        agent_id: AgentId,
        tenant_id: &str,
        incoming_bytes: u64,
        replaced_bytes: u64,
    ) -> Result<(), ContextError> {
        let limits = self
            .storage_limits
            .read()
            .map(|limits| *limits)
            .unwrap_or_default();
        let usage = Self::context_storage_usage_locked(conn, agent_id, tenant_id)?;
        let delta = incoming_bytes.saturating_sub(replaced_bytes);
        for (scope, used, limit) in [
            ("agent", usage.agent_bytes, limits.per_agent_bytes),
            ("tenant", usage.tenant_bytes, limits.per_tenant_bytes),
            ("global", usage.global_bytes, limits.global_bytes),
        ] {
            if limit > 0 && used.saturating_add(delta) > limit {
                return Err(ContextError::PersistenceFailed(format!(
                    "context storage pressure: {scope} would use {} bytes above limit {limit}; delete retained context or retry after retention cleanup",
                    used.saturating_add(delta)
                )));
            }
        }
        Ok(())
    }

    fn purge_expired_spills_locked(conn: &mut Connection) -> Result<u64, ContextError> {
        let transaction = conn
            .transaction()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let now = Utc::now().to_rfc3339();
        let removed = transaction
            .execute(
                "DELETE FROM agent_kv
                 WHERE EXISTS (
                    SELECT 1 FROM context_spills
                    WHERE context_spills.agent_id = agent_kv.agent_id
                      AND context_spills.key = agent_kv.key
                      AND context_spills.expires_at <= ?1
                 )",
                params![now],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("spill_purge.agent_kv");
        transaction
            .execute(
                "DELETE FROM context_spills WHERE expires_at <= ?1",
                params![now],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("spill_purge.context_spills");
        transaction
            .commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(removed as u64)
    }

    /// Persist a spill with a verifiable digest, bounded retention, and atomic
    /// per-agent/tenant/global durable-byte admission.
    pub fn store_context_spill(
        &self,
        agent_id: AgentId,
        key: &str,
        value: &str,
        sha256: &str,
    ) -> Result<(), ContextError> {
        if !key.starts_with("context_spill:") {
            return Err(ContextError::PersistenceFailed(
                "context spill key must start with context_spill:".into(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        Self::purge_expired_spills_locked(&mut conn)?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let tenant_id = transaction
            .query_row(
                "SELECT tenant_id FROM agents WHERE id = ?1",
                params![agent_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?
            .unwrap_or_else(|| DEFAULT_TENANT.to_string());
        let replaced_bytes = transaction
            .query_row(
                "SELECT LENGTH(value) FROM agent_kv WHERE agent_id = ?1 AND key = ?2",
                params![agent_id.to_string(), key],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?
            .unwrap_or(0)
            .max(0) as u64;
        self.enforce_context_storage_locked(
            &transaction,
            agent_id,
            &tenant_id,
            value.len() as u64,
            replaced_bytes,
        )?;
        let retention_seconds = self
            .storage_limits
            .read()
            .map(|limits| limits.spill_retention_seconds)
            .unwrap_or(0);
        if retention_seconds == 0 {
            return Err(ContextError::PersistenceFailed(
                "context spill retention must be greater than zero".into(),
            ));
        }
        let now = Utc::now();
        let expires_at =
            now + chrono::Duration::seconds(retention_seconds.min(i64::MAX as u64) as i64);
        transaction
            .execute(
                "INSERT OR REPLACE INTO agent_kv
                 (agent_id, key, value, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params![agent_id.to_string(), key, value, now.to_rfc3339()],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("spill_store.agent_kv");
        transaction
            .execute(
                "INSERT OR REPLACE INTO context_spills
                 (agent_id, key, tenant_id, sha256, byte_count, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    agent_id.to_string(),
                    key,
                    tenant_id,
                    sha256,
                    value.len() as u64,
                    now.to_rfc3339(),
                    expires_at.to_rfc3339()
                ],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("spill_store.context_spills");
        transaction
            .commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(())
    }

    /// Put (insert-or-overwrite) a value for `key` under `agent_id`.
    pub fn kv_put(&self, agent_id: AgentId, key: &str, value: &str) -> Result<(), ContextError> {
        if key.starts_with("context_spill:") {
            return Err(ContextError::PersistenceFailed(
                "context spills require verified store_context_spill admission".into(),
            ));
        }
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO agent_kv (agent_id, key, value, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![agent_id.to_string(), key, value, now],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Get the value for `key` under `agent_id`, or `None` if absent.
    pub fn kv_get(&self, agent_id: AgentId, key: &str) -> Result<Option<String>, ContextError> {
        let mut conn = self.conn.lock().unwrap();
        Self::purge_expired_spills_locked(&mut conn)?;
        let result = conn.query_row(
            "SELECT value FROM agent_kv WHERE agent_id = ?1 AND key = ?2",
            params![agent_id.to_string(), key],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(value) if key.starts_with("context_spill:") => {
                let expected = conn
                    .query_row(
                        "SELECT sha256 FROM context_spills
                         WHERE agent_id = ?1 AND key = ?2",
                        params![agent_id.to_string(), key],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(|error| ContextError::StorageError(error.to_string()))?
                    .ok_or_else(|| {
                        ContextError::RestoreFailed(
                            "context spill metadata is missing; page-in fails closed".into(),
                        )
                    })?;
                let actual = ring::digest::digest(&ring::digest::SHA256, value.as_bytes())
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                if actual != expected {
                    return Err(ContextError::RestoreFailed(
                        "context spill digest mismatch; page-in fails closed".into(),
                    ));
                }
                Ok(Some(value))
            }
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ContextError::StorageError(e.to_string())),
        }
    }

    /// List the keys stored under `agent_id` (sorted ascending).
    pub fn kv_list(&self, agent_id: AgentId) -> Result<Vec<String>, ContextError> {
        let mut conn = self.conn.lock().unwrap();
        Self::purge_expired_spills_locked(&mut conn)?;
        let mut stmt = conn
            .prepare("SELECT key FROM agent_kv WHERE agent_id = ?1 ORDER BY key ASC")
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let rows = stmt
            .query_map(params![agent_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| ContextError::StorageError(e.to_string()))?);
        }
        Ok(keys)
    }

    /// Delete the value for `key` under `agent_id`. Returns `true` if a row was
    /// removed, `false` if no such key existed.
    pub fn kv_delete(&self, agent_id: AgentId, key: &str) -> Result<bool, ContextError> {
        let mut conn = self.conn.lock().unwrap();
        let transaction = conn
            .transaction()
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        transaction
            .execute(
                "DELETE FROM context_spills WHERE agent_id = ?1 AND key = ?2",
                params![agent_id.to_string(), key],
            )
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("kv_delete.context_spills");
        let affected = transaction
            .execute(
                "DELETE FROM agent_kv WHERE agent_id = ?1 AND key = ?2",
                params![agent_id.to_string(), key],
            )
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("kv_delete.agent_kv");
        transaction
            .commit()
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(affected > 0)
    }

    /// Record a successful durable spill or a fail-closed pressure decision.
    /// Counters are cumulative; the active/budget values and last error describe
    /// the most recent decision.
    pub fn record_context_pressure(
        &self,
        agent_id: AgentId,
        active_tokens: u32,
        budget_tokens: u32,
        evicted_messages: usize,
        error: Option<&str>,
    ) -> Result<(), ContextError> {
        let spill_increment = u64::from(error.is_none() && evicted_messages > 0);
        let error_increment = u64::from(error.is_some());
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO context_pressure
                (agent_id, active_tokens, budget_tokens, spill_count,
                 evicted_messages, error_count, last_error, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(agent_id) DO UPDATE SET
                active_tokens = excluded.active_tokens,
                budget_tokens = excluded.budget_tokens,
                spill_count = context_pressure.spill_count + excluded.spill_count,
                evicted_messages = context_pressure.evicted_messages + excluded.evicted_messages,
                error_count = context_pressure.error_count + excluded.error_count,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at",
            params![
                agent_id.to_string(),
                active_tokens,
                budget_tokens,
                spill_increment,
                evicted_messages as u64,
                error_increment,
                error,
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Inspect context pressure without exposing spilled prompt content. Current
    /// storage totals are derived from live spill rows, so deleting a spill is
    /// reflected immediately rather than leaving approximate counters behind.
    pub fn context_pressure_stats(
        &self,
        agent_id: AgentId,
    ) -> Result<ContextPressureStats, ContextError> {
        let mut conn = self.conn.lock().unwrap();
        Self::purge_expired_spills_locked(&mut conn)?;
        let tenant_id = conn
            .query_row(
                "SELECT tenant_id FROM agents WHERE id = ?1",
                params![agent_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?
            .unwrap_or_else(|| DEFAULT_TENANT.to_string());
        let recorded = conn.query_row(
            "SELECT active_tokens, budget_tokens, spill_count, evicted_messages,
                    error_count, last_error, updated_at
             FROM context_pressure WHERE agent_id = ?1",
            params![agent_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        );
        let (
            active_tokens,
            budget_tokens,
            spill_count,
            evicted_messages,
            error_count,
            last_error,
            updated_at,
        ) = match recorded {
            Ok(values) => values,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                (0, 0, 0, 0, 0, None, Utc::now().to_rfc3339())
            }
            Err(error) => return Err(ContextError::StorageError(error.to_string())),
        };
        let (stored_spills, stored_spill_bytes) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(value)), 0)
                 FROM agent_kv
                 WHERE agent_id = ?1 AND key LIKE 'context_spill:%'",
                params![agent_id.to_string()],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let updated_at = DateTime::parse_from_rfc3339(&updated_at)
            .map_err(|error| ContextError::StorageError(error.to_string()))?
            .with_timezone(&Utc);
        let storage = Self::context_storage_usage_locked(&conn, agent_id, &tenant_id)?;
        let limits = self
            .storage_limits
            .read()
            .map(|limits| *limits)
            .unwrap_or_default();
        Ok(ContextPressureStats {
            agent_id,
            tenant_id,
            active_tokens,
            budget_tokens,
            agent_active_tokens: 0,
            agent_active_limit: 0,
            tenant_active_tokens: 0,
            tenant_active_limit: 0,
            global_active_tokens: 0,
            global_active_limit: 0,
            active_rejection_count: 0,
            spill_count,
            evicted_messages,
            stored_spills,
            stored_spill_bytes,
            agent_stored_bytes: storage.agent_bytes,
            agent_storage_limit: limits.per_agent_bytes,
            tenant_stored_bytes: storage.tenant_bytes,
            tenant_storage_limit: limits.per_tenant_bytes,
            global_stored_bytes: storage.global_bytes,
            global_storage_limit: limits.global_bytes,
            spill_retention_seconds: limits.spill_retention_seconds,
            error_count,
            last_error,
            updated_at,
        })
    }
}

/// Named context snapshots — point-in-time copies of an agent's working context.
///
/// A snapshot captures the agent's current [`AgentContext`] under a `label` so a
/// turn can pause/resume or you can branch/rewind. Snapshots live in the
/// `context_snapshots` table on the same single SQLite handle as everything else
/// (no separate db). Restoring a snapshot writes it back as the agent's current
/// context via the same persist path `get_context`/`persist_context` use.
impl SqliteContextManager {
    /// Capture the agent's current context under `label` (insert-or-overwrite).
    ///
    /// Fetches the live context the same way [`get_context`](ContextManager::get_context)
    /// does, then serializes it into the snapshots table keyed by
    /// `(agent_id, label)`. Errors with [`ContextError::RestoreFailed`] if the
    /// agent has no current context to snapshot.
    pub fn snapshot_context(&self, agent_id: AgentId, label: &str) -> Result<(), ContextError> {
        let mut conn = self.conn.lock().unwrap();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let id_str = agent_id.to_string();
        // Read the agent's current context (mirrors get_context's query path).
        let json = match transaction.query_row(
            "SELECT context_json FROM contexts WHERE agent_id = ?1",
            params![id_str],
            |row| row.get::<_, String>(0),
        ) {
            Ok(json) => json,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(ContextError::RestoreFailed(format!(
                    "No context for agent {} to snapshot",
                    agent_id
                )))
            }
            Err(e) => return Err(ContextError::StorageError(e.to_string())),
        };
        let now = Utc::now().to_rfc3339();
        let tenant_id = transaction
            .query_row(
                "SELECT tenant_id FROM agents WHERE id = ?1",
                params![id_str],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?
            .unwrap_or_else(|| DEFAULT_TENANT.to_string());
        let replaced_bytes = transaction
            .query_row(
                "SELECT LENGTH(context_json) FROM context_snapshots
                 WHERE agent_id = ?1 AND label = ?2",
                params![id_str, label],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?
            .unwrap_or(0)
            .max(0) as u64;
        self.enforce_context_storage_locked(
            &transaction,
            agent_id,
            &tenant_id,
            json.len() as u64,
            replaced_bytes,
        )?;
        transaction.execute(
            "INSERT OR REPLACE INTO context_snapshots (agent_id, label, context_json, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id_str, label, json, now],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        transaction
            .commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(())
    }

    /// Restore a snapshot, making it the agent's current context.
    ///
    /// Loads the snapshot stored under `(agent_id, label)`, writes it back as the
    /// agent's current context (via the same persist path), and returns the
    /// restored [`AgentContext`]. Errors with [`ContextError::RestoreFailed`] if
    /// no such snapshot exists.
    pub fn restore_snapshot(
        &self,
        agent_id: AgentId,
        label: &str,
    ) -> Result<AgentContext, ContextError> {
        let json = {
            let conn = self.conn.lock().unwrap();
            match conn.query_row(
                "SELECT context_json FROM context_snapshots WHERE agent_id = ?1 AND label = ?2",
                params![agent_id.to_string(), label],
                |row| row.get::<_, String>(0),
            ) {
                Ok(json) => json,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Err(ContextError::RestoreFailed(format!(
                        "No snapshot '{}' for agent {}",
                        label, agent_id
                    )))
                }
                Err(e) => return Err(ContextError::StorageError(e.to_string())),
            }
        };
        let context: AgentContext =
            serde_json::from_str(&json).map_err(|e| ContextError::RestoreFailed(e.to_string()))?;
        // Make the snapshot the agent's current context via the persist path.
        self.persist_with_retry(agent_id, &context)?;
        Ok(context)
    }

    /// List the snapshot labels stored for `agent_id`, newest first.
    pub fn list_snapshots(&self, agent_id: AgentId) -> Result<Vec<String>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT label FROM context_snapshots WHERE agent_id = ?1 ORDER BY created_at DESC, label DESC",
            )
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let rows = stmt
            .query_map(params![agent_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let mut labels = Vec::new();
        for row in rows {
            labels.push(row.map_err(|e| ContextError::StorageError(e.to_string()))?);
        }
        Ok(labels)
    }

    /// Delete the snapshot stored under `(agent_id, label)`. Returns `true` if a
    /// row was removed, `false` if no such snapshot existed.
    pub fn delete_snapshot(&self, agent_id: AgentId, label: &str) -> Result<bool, ContextError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "DELETE FROM context_snapshots WHERE agent_id = ?1 AND label = ?2",
                params![agent_id.to_string(), label],
            )
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(affected > 0)
    }
}

/// Agent registry persistence — the durable identity of every created agent.
///
/// This is the piece that makes a restart "bring the agents back": when an
/// agent is created through the live path it is written here, and on boot from a
/// persistent DB the kernel reads these rows and rehydrates them into the
/// in-memory `AgentManager`. Backed by the same single SQLite handle (no second
/// db). Writes commit immediately, so a crash (drop without graceful shutdown)
/// still leaves committed agents recoverable.
impl SqliteContextManager {
    #[cfg(test)]
    pub(crate) fn fail_next_agent_save_for_test(&self) {
        self.fail_next_agent_save
            .store(true, AtomicOrdering::Release);
    }

    /// Fail the Nth subsequent lifecycle-status update. A value of one fails
    /// the next update; two lets the durable `Stopping` write commit and fails
    /// the following terminal `Stopped` write.
    #[cfg(test)]
    pub(crate) fn fail_agent_status_update_on_nth_call_for_test(&self, nth: usize) {
        assert!(nth > 0, "status-update failure index must be positive");
        self.fail_agent_status_update_after
            .store(nth, AtomicOrdering::Release);
    }

    /// Insert-or-update an agent's durable identity + config.
    pub fn save_agent(&self, agent: &PersistedAgent) -> Result<(), ContextError> {
        #[cfg(test)]
        if self
            .fail_next_agent_save
            .swap(false, AtomicOrdering::AcqRel)
        {
            return Err(ContextError::PersistenceFailed(
                "injected agent-registry save failure".into(),
            ));
        }
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO agents
                (id, session_id, tenant_id, name, task, llm_provider, permission_profile, priority, status, sandbox_config_json, created_at, last_activity_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                agent.id.to_string(),
                agent.session_id.to_string(),
                agent.tenant_id,
                agent.name,
                agent.task,
                agent.llm_provider,
                agent.permission_profile,
                agent.priority as i64,
                agent.status,
                agent.sandbox_config_json,
                agent.created_at.to_rfc3339(),
                agent.last_activity_at.to_rfc3339(),
            ],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Load every persisted agent (registry rehydration on boot).
    pub fn load_all_agents(&self) -> Result<Vec<PersistedAgent>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, session_id, tenant_id, name, task, llm_provider, permission_profile, priority, status, sandbox_config_json, created_at, last_activity_at
                 FROM agents ORDER BY created_at ASC",
            )
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            })
            .map_err(|e| ContextError::StorageError(e.to_string()))?;

        let mut agents = Vec::new();
        for row in rows {
            let (
                id_str,
                session_str,
                tenant_id,
                name,
                task,
                llm_provider,
                permission_profile,
                priority,
                status,
                sandbox_config_json,
                created_str,
                accessed_str,
            ) = row.map_err(|e| ContextError::StorageError(e.to_string()))?;
            let id = uuid::Uuid::parse_str(&id_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let session_id = uuid::Uuid::parse_str(&session_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let created_at = DateTime::parse_from_rfc3339(&created_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?
                .with_timezone(&Utc);
            let last_activity_at = DateTime::parse_from_rfc3339(&accessed_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?
                .with_timezone(&Utc);
            agents.push(PersistedAgent {
                id,
                session_id,
                tenant_id,
                name,
                task,
                llm_provider,
                permission_profile,
                priority: priority.clamp(0, u8::MAX as i64) as u8,
                status,
                sandbox_config_json,
                created_at,
                last_activity_at,
            });
        }
        Ok(agents)
    }

    /// The tenant that owns `agent_id`, if the agent is in the registry. Used to
    /// enforce that a caller may only read data for agents in its own tenant.
    pub fn agent_tenant(&self, agent_id: AgentId) -> Result<Option<String>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT tenant_id FROM agents WHERE id = ?1",
            params![agent_id.to_string()],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(t) => Ok(Some(t)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ContextError::StorageError(e.to_string())),
        }
    }

    /// Persist a versioned resumable turn. Sensitive content is kept in the
    /// owner-only SQLite database; callers receive only the opaque id.
    pub fn save_generation_checkpoint(
        &self,
        tenant_id: &str,
        provider_id: &str,
        model_id: &str,
        checkpoint: &crate::execution::GenerationCheckpoint,
        ttl: std::time::Duration,
    ) -> Result<uuid::Uuid, ContextError> {
        if checkpoint.agent_id.is_nil() {
            return Err(ContextError::PersistenceFailed(
                "checkpoint has an invalid agent id".into(),
            ));
        }
        let id = uuid::Uuid::new_v4();
        let now = Utc::now();
        let ttl = chrono::Duration::from_std(ttl)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let expires_at = now + ttl;
        let json = serde_json::to_string(checkpoint)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let mut conn = self.conn.lock().unwrap();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        transaction
            .execute(
                "DELETE FROM generation_checkpoints WHERE expires_at <= ?1",
                params![now.to_rfc3339()],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let replaced_bytes = transaction
            .query_row(
                "SELECT LENGTH(checkpoint_json) FROM generation_checkpoints
                 WHERE agent_id = ?1 AND status = 'active'
                 ORDER BY created_at DESC LIMIT 1 OFFSET ?2",
                params![
                    checkpoint.agent_id.to_string(),
                    (MAX_GENERATION_CHECKPOINTS_PER_AGENT - 1) as i64
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| ContextError::StorageError(error.to_string()))?
            .unwrap_or(0)
            .max(0) as u64;
        self.enforce_context_storage_locked(
            &transaction,
            checkpoint.agent_id,
            tenant_id,
            json.len() as u64,
            replaced_bytes,
        )?;
        transaction
            .execute(
                "INSERT INTO generation_checkpoints (id, agent_id, tenant_id, version, provider_id, model_id, checkpoint_json, status, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9)",
                params![
                    id.to_string(),
                    checkpoint.agent_id.to_string(),
                    tenant_id,
                    i64::from(GENERATION_CHECKPOINT_VERSION),
                    provider_id,
                    model_id,
                    json,
                    now.to_rfc3339(),
                    expires_at.to_rfc3339()
                ],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        transaction
            .execute(
                "DELETE FROM generation_checkpoints WHERE id IN (
                    SELECT id FROM generation_checkpoints
                    WHERE agent_id = ?1 AND status = 'active'
                    ORDER BY created_at DESC LIMIT -1 OFFSET ?2
                )",
                params![
                    checkpoint.agent_id.to_string(),
                    MAX_GENERATION_CHECKPOINTS_PER_AGENT as i64
                ],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(id)
    }

    /// List only metadata for active, unexpired checkpoints in one tenant.
    pub fn list_generation_checkpoints(
        &self,
        tenant_id: &str,
        agent_id: Option<AgentId>,
    ) -> Result<Vec<GenerationCheckpointMetadata>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        let sql = if agent_id.is_some() {
            "SELECT id, agent_id, version, provider_id, model_id, created_at, expires_at
             FROM generation_checkpoints
             WHERE tenant_id = ?1 AND agent_id = ?2 AND status = 'active' AND expires_at > ?3
             ORDER BY created_at DESC"
        } else {
            "SELECT id, agent_id, version, provider_id, model_id, created_at, expires_at
             FROM generation_checkpoints
             WHERE tenant_id = ?1 AND status = 'active' AND expires_at > ?3
             ORDER BY created_at DESC"
        };
        let mut statement = conn
            .prepare(sql)
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let parse = |row: &rusqlite::Row<'_>| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        };
        let mut rows = match agent_id {
            Some(agent_id) => statement
                .query_map(params![tenant_id, agent_id.to_string(), now], parse)
                .map_err(|error| ContextError::StorageError(error.to_string()))?,
            None => statement
                .query_map(params![tenant_id, "", now], parse)
                .map_err(|error| ContextError::StorageError(error.to_string()))?,
        };
        let mut checkpoints = Vec::new();
        rows.try_for_each(|row| {
            let (id, agent_id, version, provider_id, model_id, created_at, expires_at) =
                row.map_err(|error| ContextError::StorageError(error.to_string()))?;
            checkpoints.push(GenerationCheckpointMetadata {
                id: uuid::Uuid::parse_str(&id)
                    .map_err(|error| ContextError::StorageError(error.to_string()))?,
                agent_id: uuid::Uuid::parse_str(&agent_id)
                    .map_err(|error| ContextError::StorageError(error.to_string()))?,
                version: u32::try_from(version).map_err(|error| {
                    ContextError::StorageError(format!("invalid checkpoint version: {error}"))
                })?,
                provider_id,
                model_id,
                created_at: DateTime::parse_from_rfc3339(&created_at)
                    .map_err(|error| ContextError::StorageError(error.to_string()))?
                    .with_timezone(&Utc),
                expires_at: DateTime::parse_from_rfc3339(&expires_at)
                    .map_err(|error| ContextError::StorageError(error.to_string()))?
                    .with_timezone(&Utc),
            });
            Ok::<(), ContextError>(())
        })?;
        Ok(checkpoints)
    }

    /// Atomically claim a checkpoint. A second concurrent resume fails instead
    /// of replaying a tool side effect twice.
    pub fn claim_generation_checkpoint(
        &self,
        checkpoint_id: uuid::Uuid,
        agent_id: AgentId,
        tenant_id: &str,
    ) -> Result<StoredGenerationCheckpoint, ContextError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE generation_checkpoints SET status = 'resuming'
                 WHERE id = ?1 AND agent_id = ?2 AND tenant_id = ?3
                   AND status = 'active' AND expires_at > ?4",
                params![
                    checkpoint_id.to_string(),
                    agent_id.to_string(),
                    tenant_id,
                    Utc::now().to_rfc3339()
                ],
            )
            .map_err(|error| ContextError::RestoreFailed(error.to_string()))?;
        if changed != 1 {
            return Err(ContextError::RestoreFailed(
                "checkpoint is absent, expired, foreign, or already being resumed".into(),
            ));
        }
        let row = conn
            .query_row(
                "SELECT version, provider_id, model_id, checkpoint_json, created_at, expires_at
                 FROM generation_checkpoints WHERE id = ?1",
                params![checkpoint_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .map_err(|error| ContextError::RestoreFailed(error.to_string()))?;
        let version =
            u32::try_from(row.0).map_err(|error| ContextError::RestoreFailed(error.to_string()))?;
        if version != GENERATION_CHECKPOINT_VERSION {
            let _ = conn.execute(
                "UPDATE generation_checkpoints SET status = 'incompatible' WHERE id = ?1",
                params![checkpoint_id.to_string()],
            );
            return Err(ContextError::RestoreFailed(format!(
                "checkpoint version {version} is incompatible with runtime version {GENERATION_CHECKPOINT_VERSION}"
            )));
        }
        let checkpoint = match serde_json::from_str(&row.3) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                let _ = conn.execute(
                    "UPDATE generation_checkpoints SET status = 'corrupt' WHERE id = ?1",
                    params![checkpoint_id.to_string()],
                );
                return Err(ContextError::RestoreFailed(format!(
                    "checkpoint payload is corrupt: {error}"
                )));
            }
        };
        Ok(StoredGenerationCheckpoint {
            metadata: GenerationCheckpointMetadata {
                id: checkpoint_id,
                agent_id,
                version,
                provider_id: row.1,
                model_id: row.2,
                created_at: DateTime::parse_from_rfc3339(&row.4)
                    .map_err(|error| ContextError::RestoreFailed(error.to_string()))?
                    .with_timezone(&Utc),
                expires_at: DateTime::parse_from_rfc3339(&row.5)
                    .map_err(|error| ContextError::RestoreFailed(error.to_string()))?
                    .with_timezone(&Utc),
            },
            checkpoint,
        })
    }

    pub fn release_generation_checkpoint(
        &self,
        checkpoint_id: uuid::Uuid,
    ) -> Result<(), ContextError> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE generation_checkpoints SET status = 'active' WHERE id = ?1 AND status = 'resuming'",
                params![checkpoint_id.to_string()],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(())
    }

    pub fn consume_generation_checkpoint(
        &self,
        checkpoint_id: uuid::Uuid,
    ) -> Result<(), ContextError> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE generation_checkpoints SET status = 'consumed', checkpoint_json = '{}' WHERE id = ?1 AND status = 'resuming'",
                params![checkpoint_id.to_string()],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(())
    }

    pub fn delete_generation_checkpoint(
        &self,
        checkpoint_id: uuid::Uuid,
        tenant_id: &str,
    ) -> Result<bool, ContextError> {
        let changed = self
            .conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM generation_checkpoints WHERE id = ?1 AND tenant_id = ?2 AND status != 'resuming'",
                params![checkpoint_id.to_string(), tenant_id],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(changed == 1)
    }

    /// List the ids of agents that belong to `tenant_id` (tenant-scoped registry
    /// view — a tenant-A caller never sees tenant-B agents).
    pub fn list_agents_for_tenant(&self, tenant_id: &str) -> Result<Vec<AgentId>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id FROM agents WHERE tenant_id = ?1 ORDER BY created_at ASC")
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let rows = stmt
            .query_map(params![tenant_id], |row| row.get::<_, String>(0))
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let mut ids = Vec::new();
        for row in rows {
            let s = row.map_err(|e| ContextError::StorageError(e.to_string()))?;
            if let Ok(id) = uuid::Uuid::parse_str(&s) {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Irreversibly erase an agent's durable identity and every directly owned
    /// artifact. Shared provider/tenant quota aggregates remain so deletion
    /// cannot refund already consumed system capacity.
    pub fn delete_agent(&self, agent_id: AgentId) -> Result<bool, ContextError> {
        self.erase_agent_data(agent_id)
            .map(|receipt| receipt.is_some())
    }

    /// Perform a schema-wide agent erasure in one `BEGIN IMMEDIATE`
    /// transaction and return a non-identifying durable receipt.
    pub fn erase_agent_data(
        &self,
        agent_id: AgentId,
    ) -> Result<Option<DeletionReceipt>, ContextError> {
        self.erase_agent_data_with_receipt(agent_id, true, 0)
    }

    pub(crate) fn erase_agent_data_after_backup_purge(
        &self,
        agent_id: AgentId,
        managed_backups_deleted: usize,
    ) -> Result<Option<DeletionReceipt>, ContextError> {
        self.erase_agent_data_with_receipt(agent_id, true, managed_backups_deleted)
    }

    /// Transactionally remove every durable row owned by an agent whose
    /// creation must be rolled back (for example, a package load that fails
    /// while seeding memory). Normal stop/kill intentionally does not call this
    /// because terminal history is retained.
    pub fn purge_agent_data(&self, agent_id: AgentId) -> Result<(), ContextError> {
        self.erase_agent_data_with_receipt(agent_id, false, 0)
            .map(|_| ())
    }

    fn erase_agent_data_with_receipt(
        &self,
        agent_id: AgentId,
        record_receipt: bool,
        managed_backups_deleted: usize,
    ) -> Result<Option<DeletionReceipt>, ContextError> {
        if agent_id.is_nil() {
            return Err(ContextError::PersistenceFailed(
                "the reserved nil agent id cannot be erased".into(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let id = agent_id.to_string();
        let mut deleted_rows = BTreeMap::new();

        let deleted = tx
            .execute(
                "DELETE FROM conversations_fts WHERE conversation_id IN
             (SELECT id FROM conversations WHERE agent_id = ?1)",
                params![&id],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "conversations_fts", deleted);
        crash_erasure_after_step_for_test("agent.conversations_fts");

        for table in [
            "contexts",
            "facts",
            "conversations",
            "usage_log",
            "agent_kv",
            "context_spills",
            "context_snapshots",
            "generation_checkpoints",
            "context_pressure",
            "loaded_package_instances",
        ] {
            let deleted = tx
                .execute(
                    &format!("DELETE FROM {table} WHERE agent_id = ?1"),
                    params![&id],
                )
                .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
            record_deleted_rows(&mut deleted_rows, table, deleted);
            crash_erasure_after_step_for_test(match table {
                "contexts" => "agent.contexts",
                "facts" => "agent.facts",
                "conversations" => "agent.conversations",
                "usage_log" => "agent.usage_log",
                "agent_kv" => "agent.agent_kv",
                "context_spills" => "agent.context_spills",
                "context_snapshots" => "agent.context_snapshots",
                "generation_checkpoints" => "agent.generation_checkpoints",
                "context_pressure" => "agent.context_pressure",
                "loaded_package_instances" => "agent.loaded_package_instances",
                _ => unreachable!("agent erasure table list is closed"),
            });
        }

        let cleared = tx
            .execute(
                "UPDATE service_runtime SET agent_id = NULL WHERE agent_id = ?1",
                params![&id],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        record_deleted_rows(
            &mut deleted_rows,
            "service_runtime.agent_reference",
            cleared,
        );
        crash_erasure_after_step_for_test("agent.service_runtime");
        let cleared = tx
            .execute(
                "UPDATE service_history SET agent_id = NULL WHERE agent_id = ?1",
                params![&id],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        record_deleted_rows(
            &mut deleted_rows,
            "service_history.agent_reference",
            cleared,
        );
        crash_erasure_after_step_for_test("agent.service_history");

        let agent_scope_suffix = format!("/agent/{agent_id}");
        let deleted = tx
            .execute(
                "DELETE FROM quota_receipt_scopes
                 WHERE scope_kind = 'cgroup'
                   AND substr(scope_id, -length(?1)) = ?1",
                params![&agent_scope_suffix],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "quota_receipt_scopes", deleted);
        crash_erasure_after_step_for_test("agent.quota_receipt_scopes");
        let deleted = tx
            .execute(
                "DELETE FROM quota_epochs
                 WHERE scope_kind = 'cgroup'
                   AND substr(scope_id, -length(?1)) = ?1",
                params![&agent_scope_suffix],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "quota_epochs", deleted);
        crash_erasure_after_step_for_test("agent.quota_epochs");

        let deleted = tx
            .execute("DELETE FROM agents WHERE id = ?1", params![&id])
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "agents", deleted);
        crash_erasure_after_step_for_test("agent.agents");

        if deleted_rows.is_empty() {
            return Ok(None);
        }
        record_deleted_rows(
            &mut deleted_rows,
            "managed_backup_copies",
            managed_backups_deleted,
        );
        let receipt = if record_receipt {
            Some(persist_deletion_receipt(
                &tx,
                DeletionSubjectKind::Agent,
                deleted_rows,
                vec![
                    "shared provider and tenant quota aggregates".to_string(),
                    "non-identifying quota receipt and refund tombstones".to_string(),
                    "backup copies outside the configured managed root".to_string(),
                ],
            )?)
        } else {
            None
        };
        crash_erasure_after_step_for_test("agent.deletion_receipt");
        tx.commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(receipt)
    }

    /// Flush the WAL into the main database file (truncating checkpoint) so a
    /// subsequent open recovers a fully-consolidated, consistent DB. Called on
    /// graceful shutdown; best-effort (a busy DB simply checkpoints later).
    pub fn checkpoint(&self) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        let (busy, _log_pages, _checkpointed_pages): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| {
                ContextError::StorageError(format!("SQLite WAL checkpoint failed: {error}"))
            })?;
        if busy != 0 {
            return Err(ContextError::StorageError(
                "SQLite WAL checkpoint could not complete because the database is busy".into(),
            ));
        }
        Ok(())
    }
}

/// Durable operator-control state and non-sensitive package-instance metadata.
impl SqliteContextManager {
    pub fn ensure_operator_tunable(
        &self,
        name: &str,
        value: u64,
        actor: &str,
    ) -> Result<(), ContextError> {
        let value = i64::try_from(value).map_err(|_| {
            ContextError::PersistenceFailed(format!(
                "operator tunable {name:?} exceeds SQLite integer range"
            ))
        })?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let now = Utc::now().to_rfc3339();
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO operator_tunables
                 (name, value, revision, updated_at, updated_by)
                 VALUES (?1, ?2, 1, ?3, ?4)",
                params![name, value, &now, actor],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        if inserted > 0 {
            crash_multi_table_mutation_after_step_for_test("tunable_ensure.operator_tunables");
            tx.execute(
                "INSERT INTO operator_tunable_audit
                 (name, revision, previous_value, requested_value, effective_value,
                  action, outcome, actor, reason, created_at)
                 VALUES (?1, 1, NULL, ?2, ?2, 'bootstrap', 'applied', ?3, NULL, ?4)",
                params![name, value, actor, now],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
            crash_multi_table_mutation_after_step_for_test("tunable_ensure.operator_tunable_audit");
        }
        tx.commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))
    }

    pub fn list_operator_tunables(
        &self,
    ) -> Result<Vec<crate::operator_control::StoredOperatorTunable>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT name, value, revision, updated_at, updated_by
                 FROM operator_tunables ORDER BY name",
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let rows = statement
            .query_map([], |row| {
                Ok(crate::operator_control::StoredOperatorTunable {
                    name: row.get(0)?,
                    value: row.get::<_, i64>(1)?.max(0) as u64,
                    revision: row.get::<_, i64>(2)?.max(0) as u64,
                    updated_at: row.get(3)?,
                    updated_by: row.get(4)?,
                })
            })
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let mut tunables = Vec::new();
        for row in rows {
            tunables.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
        }
        Ok(tunables)
    }

    pub fn set_operator_tunable(
        &self,
        name: &str,
        value: u64,
        expected_revision: u64,
        actor: &str,
    ) -> Result<crate::operator_control::StoredOperatorTunable, ContextError> {
        let value = i64::try_from(value).map_err(|_| {
            ContextError::PersistenceFailed(format!(
                "operator tunable {name:?} exceeds SQLite integer range"
            ))
        })?;
        let expected_revision = i64::try_from(expected_revision).map_err(|_| {
            ContextError::PersistenceFailed("operator tunable revision is too large".into())
        })?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let current = tx
            .query_row(
                "SELECT value, revision FROM operator_tunables WHERE name = ?1",
                params![name],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?
            .ok_or_else(|| {
                ContextError::PersistenceFailed(format!(
                    "operator tunable {name:?} is not registered"
                ))
            })?;
        if current.1 != expected_revision {
            return Err(ContextError::PersistenceFailed(format!(
                "operator tunable conflict for {name:?}: expected revision {expected_revision}, current revision {}",
                current.1
            )));
        }
        let revision = current
            .1
            .checked_add(1)
            .ok_or_else(|| ContextError::PersistenceFailed("revision overflow".into()))?;
        let now = Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE operator_tunables
             SET value = ?1, revision = ?2, updated_at = ?3, updated_by = ?4
             WHERE name = ?5",
            params![value, revision, &now, actor, name],
        )
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("tunable_set.operator_tunables");
        tx.execute(
            "INSERT INTO operator_tunable_audit
             (name, revision, previous_value, requested_value, effective_value,
              action, outcome, actor, reason, created_at)
             VALUES (?1, ?2, ?3, ?4, ?4, 'set', 'applied', ?5, NULL, ?6)",
            params![name, revision, current.0, value, actor, &now],
        )
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("tunable_set.operator_tunable_audit");
        tx.commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(crate::operator_control::StoredOperatorTunable {
            name: name.to_string(),
            value: value as u64,
            revision: revision as u64,
            updated_at: now,
            updated_by: actor.to_string(),
        })
    }

    pub fn rollback_operator_tunable(
        &self,
        name: &str,
        target_revision: u64,
        expected_revision: u64,
        actor: &str,
    ) -> Result<crate::operator_control::StoredOperatorTunable, ContextError> {
        let target_revision = i64::try_from(target_revision).map_err(|_| {
            ContextError::PersistenceFailed("target tunable revision is too large".into())
        })?;
        let expected_revision = i64::try_from(expected_revision).map_err(|_| {
            ContextError::PersistenceFailed("operator tunable revision is too large".into())
        })?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let current = tx
            .query_row(
                "SELECT value, revision FROM operator_tunables WHERE name = ?1",
                params![name],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?
            .ok_or_else(|| {
                ContextError::PersistenceFailed(format!(
                    "operator tunable {name:?} is not registered"
                ))
            })?;
        if current.1 != expected_revision {
            return Err(ContextError::PersistenceFailed(format!(
                "operator tunable conflict for {name:?}: expected revision {expected_revision}, current revision {}",
                current.1
            )));
        }
        let target_value = tx
            .query_row(
                "SELECT effective_value FROM operator_tunable_audit
                 WHERE name = ?1 AND revision = ?2
                   AND outcome = 'applied' AND effective_value IS NOT NULL
                 ORDER BY id DESC LIMIT 1",
                params![name, target_revision],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?
            .ok_or_else(|| {
                ContextError::PersistenceFailed(format!(
                    "operator tunable {name:?} has no applied revision {target_revision}"
                ))
            })?;
        let revision = current
            .1
            .checked_add(1)
            .ok_or_else(|| ContextError::PersistenceFailed("revision overflow".into()))?;
        let now = Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE operator_tunables
             SET value = ?1, revision = ?2, updated_at = ?3, updated_by = ?4
             WHERE name = ?5",
            params![target_value, revision, &now, actor, name],
        )
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("tunable_rollback.operator_tunables");
        tx.execute(
            "INSERT INTO operator_tunable_audit
             (name, revision, previous_value, requested_value, effective_value,
              action, outcome, actor, reason, created_at)
             VALUES (?1, ?2, ?3, ?4, ?4, 'rollback', 'applied', ?5, ?6, ?7)",
            params![
                name,
                revision,
                current.0,
                target_value,
                actor,
                format!("restored revision {target_revision}"),
                &now
            ],
        )
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("tunable_rollback.operator_tunable_audit");
        tx.commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(crate::operator_control::StoredOperatorTunable {
            name: name.to_string(),
            value: target_value.max(0) as u64,
            revision: revision as u64,
            updated_at: now,
            updated_by: actor.to_string(),
        })
    }

    pub fn record_operator_tunable_denial(
        &self,
        name: &str,
        requested_value: Option<u64>,
        actor: &str,
        reason: &str,
    ) -> Result<(), ContextError> {
        let requested_value = requested_value
            .map(i64::try_from)
            .transpose()
            .map_err(|_| ContextError::PersistenceFailed("requested value is too large".into()))?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO operator_tunable_audit
             (name, revision, previous_value, requested_value, effective_value,
              action, outcome, actor, reason, created_at)
             VALUES (?1, NULL, NULL, ?2, NULL, 'set', 'denied', ?3, ?4, ?5)",
            params![
                name,
                requested_value,
                actor,
                reason,
                Utc::now().to_rfc3339()
            ],
        )
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(())
    }

    pub fn list_operator_tunable_audit(
        &self,
        name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::operator_control::OperatorTunableAudit>, ContextError> {
        let limit = i64::try_from(limit.clamp(1, 1_000)).unwrap_or(1_000);
        let conn = self.conn.lock().unwrap();
        let sql = if name.is_some() {
            "SELECT id, name, revision, previous_value, requested_value,
                    effective_value, action, outcome, actor, reason, created_at
             FROM operator_tunable_audit WHERE name = ?1
             ORDER BY id DESC LIMIT ?2"
        } else {
            "SELECT id, name, revision, previous_value, requested_value,
                    effective_value, action, outcome, actor, reason, created_at
             FROM operator_tunable_audit
             ORDER BY id DESC LIMIT ?1"
        };
        let mut statement = conn
            .prepare(sql)
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let map_row = |row: &rusqlite::Row<'_>| {
            Ok(crate::operator_control::OperatorTunableAudit {
                id: row.get::<_, i64>(0)?.max(0) as u64,
                name: row.get(1)?,
                revision: row
                    .get::<_, Option<i64>>(2)?
                    .map(|value| value.max(0) as u64),
                previous_value: row
                    .get::<_, Option<i64>>(3)?
                    .map(|value| value.max(0) as u64),
                requested_value: row
                    .get::<_, Option<i64>>(4)?
                    .map(|value| value.max(0) as u64),
                effective_value: row
                    .get::<_, Option<i64>>(5)?
                    .map(|value| value.max(0) as u64),
                action: row.get(6)?,
                outcome: row.get(7)?,
                actor: row.get(8)?,
                reason: row.get(9)?,
                created_at: row.get(10)?,
            })
        };
        let mut audit = Vec::new();
        if let Some(name) = name {
            let rows = statement
                .query_map(params![name, limit], map_row)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            for row in rows {
                audit.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
            }
        } else {
            let rows = statement
                .query_map(params![limit], map_row)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            for row in rows {
                audit.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
            }
        }
        Ok(audit)
    }

    pub fn save_loaded_package_instance(
        &self,
        instance: &crate::operator_control::LoadedPackageInstance,
    ) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO loaded_package_instances
             (agent_id, tenant_id, name, provider, profile, loaded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                instance.agent_id,
                instance.tenant_id,
                instance.name,
                instance.provider,
                instance.profile,
                instance.loaded_at
            ],
        )
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(())
    }

    pub fn list_loaded_package_instances(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<crate::operator_control::LoadedPackageInstance>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let sql = if tenant_id.is_some() {
            "SELECT agent_id, tenant_id, name, provider, profile, loaded_at
             FROM loaded_package_instances WHERE tenant_id = ?1
             ORDER BY loaded_at DESC, agent_id"
        } else {
            "SELECT agent_id, tenant_id, name, provider, profile, loaded_at
             FROM loaded_package_instances ORDER BY loaded_at DESC, agent_id"
        };
        let mut statement = conn
            .prepare(sql)
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let map_row = |row: &rusqlite::Row<'_>| {
            Ok(crate::operator_control::LoadedPackageInstance {
                agent_id: row.get(0)?,
                tenant_id: row.get(1)?,
                name: row.get(2)?,
                provider: row.get(3)?,
                profile: row.get(4)?,
                loaded_at: row.get(5)?,
            })
        };
        let mut packages = Vec::new();
        if let Some(tenant_id) = tenant_id {
            let rows = statement
                .query_map(params![tenant_id], map_row)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            for row in rows {
                packages.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
            }
        } else {
            let rows = statement
                .query_map([], map_row)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            for row in rows {
                packages.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
            }
        }
        Ok(packages)
    }
}

/// Durable init-supervisor ownership and bounded transition history.
impl SqliteContextManager {
    pub fn save_service_runtime(
        &self,
        runtime: &crate::init_system::ServiceRuntimeInfo,
        event: &str,
        reason: Option<&str>,
    ) -> Result<(), ContextError> {
        let status = serde_json::to_string(&runtime.status)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let restart_count = i64::from(runtime.restart_count);
        let restart_attempts_total =
            i64::try_from(runtime.restart_attempts_total).map_err(|_| {
                ContextError::PersistenceFailed("service restart counter overflow".into())
            })?;
        let dependency_blocks = i64::try_from(runtime.dependency_blocks).map_err(|_| {
            ContextError::PersistenceFailed("service dependency block counter overflow".into())
        })?;
        let mut conn = self.conn.lock().unwrap();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO service_runtime
                 (name, definition_revision, status, agent_id, restart_count,
                  restart_attempts_total, last_exit_code, desired_running, ready, healthy,
                  restart_exhausted, last_failure, next_restart_at,
                  restart_window_started_at, last_transition_at, dependency_blocks)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                 ON CONFLICT(name) DO UPDATE SET
                   definition_revision = excluded.definition_revision,
                   status = excluded.status,
                   agent_id = excluded.agent_id,
                   restart_count = excluded.restart_count,
                   restart_attempts_total = excluded.restart_attempts_total,
                   last_exit_code = excluded.last_exit_code,
                   desired_running = excluded.desired_running,
                   ready = excluded.ready,
                   healthy = excluded.healthy,
                   restart_exhausted = excluded.restart_exhausted,
                   last_failure = excluded.last_failure,
                   next_restart_at = excluded.next_restart_at,
                   restart_window_started_at = excluded.restart_window_started_at,
                   last_transition_at = excluded.last_transition_at,
                   dependency_blocks = excluded.dependency_blocks",
                params![
                    runtime.name,
                    runtime.definition_revision,
                    status,
                    runtime.agent_id.map(|id| id.to_string()),
                    restart_count,
                    restart_attempts_total,
                    runtime.last_exit_code,
                    i64::from(runtime.desired_running),
                    i64::from(runtime.ready),
                    i64::from(runtime.healthy),
                    i64::from(runtime.restart_exhausted),
                    runtime.last_failure,
                    runtime.next_restart_at,
                    runtime.restart_window_started_at,
                    runtime.last_transition_at,
                    dependency_blocks
                ],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("service_save.service_runtime");
        transaction
            .execute(
                "INSERT INTO service_history
                 (name, event, status, agent_id, reason, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    runtime.name,
                    event,
                    status,
                    runtime.agent_id.map(|id| id.to_string()),
                    reason,
                    Utc::now().to_rfc3339()
                ],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("service_save.service_history");
        transaction
            .execute(
                "DELETE FROM service_history
                 WHERE name = ?1
                   AND id NOT IN (
                     SELECT id FROM service_history
                     WHERE name = ?1 ORDER BY id DESC LIMIT 1000
                   )",
                params![runtime.name],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("service_save.history_retention");
        transaction
            .commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))
    }

    pub fn load_service_runtime(
        &self,
    ) -> Result<Vec<crate::init_system::ServiceRuntimeInfo>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT name, definition_revision, status, agent_id,
                        restart_count, restart_attempts_total, last_exit_code, desired_running, ready,
                        healthy, restart_exhausted, last_failure,
                        next_restart_at, restart_window_started_at,
                        last_transition_at, dependency_blocks
                 FROM service_runtime ORDER BY name",
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let rows = statement
            .query_map([], |row| {
                let status: String = row.get(2)?;
                let status = serde_json::from_str::<crate::init_system::ServiceStatus>(&status)
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                let agent_id = row
                    .get::<_, Option<String>>(3)?
                    .map(|id| {
                        uuid::Uuid::parse_str(&id).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                3,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })
                    })
                    .transpose()?;
                Ok(crate::init_system::ServiceRuntimeInfo {
                    name: row.get(0)?,
                    definition_revision: row.get(1)?,
                    status,
                    agent_id,
                    restart_count: u32::try_from(row.get::<_, i64>(4)?.max(0)).unwrap_or(u32::MAX),
                    restart_attempts_total: row.get::<_, i64>(5)?.max(0) as u64,
                    last_exit_code: row.get(6)?,
                    desired_running: row.get::<_, i64>(7)? != 0,
                    ready: row.get::<_, i64>(8)? != 0,
                    healthy: row.get::<_, i64>(9)? != 0,
                    restart_exhausted: row.get::<_, i64>(10)? != 0,
                    last_failure: row.get(11)?,
                    next_restart_at: row.get(12)?,
                    restart_window_started_at: row.get(13)?,
                    last_transition_at: row.get(14)?,
                    dependency_blocks: row.get::<_, i64>(15)?.max(0) as u64,
                })
            })
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let mut runtime = Vec::new();
        for row in rows {
            runtime.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
        }
        Ok(runtime)
    }

    pub fn remove_service_runtime(&self, name: &str, reason: &str) -> Result<(), ContextError> {
        let mut conn = self.conn.lock().unwrap();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        transaction
            .execute("DELETE FROM service_runtime WHERE name = ?1", params![name])
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("service_remove.service_runtime");
        transaction
            .execute(
                "INSERT INTO service_history
                 (name, event, status, agent_id, reason, created_at)
                 VALUES (?1, 'definition_removed', ?2, NULL, ?3, ?4)",
                params![
                    name,
                    serde_json::to_string(&crate::init_system::ServiceStatus::Inactive)
                        .unwrap_or_else(|_| "\"Inactive\"".into()),
                    reason,
                    Utc::now().to_rfc3339()
                ],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("service_remove.service_history");
        transaction
            .commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))
    }

    pub fn list_service_history(
        &self,
        name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::init_system::ServiceHistoryEntry>, ContextError> {
        let limit = i64::try_from(limit.clamp(1, 1_000)).unwrap_or(1_000);
        let conn = self.conn.lock().unwrap();
        let sql = if name.is_some() {
            "SELECT id, name, event, status, agent_id, reason, created_at
             FROM service_history WHERE name = ?1 ORDER BY id DESC LIMIT ?2"
        } else {
            "SELECT id, name, event, status, agent_id, reason, created_at
             FROM service_history ORDER BY id DESC LIMIT ?1"
        };
        let mut statement = conn
            .prepare(sql)
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let map_row = |row: &rusqlite::Row<'_>| {
            let status: String = row.get(3)?;
            let status = serde_json::from_str::<crate::init_system::ServiceStatus>(&status)
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            let agent_id = row
                .get::<_, Option<String>>(4)?
                .map(|id| {
                    uuid::Uuid::parse_str(&id).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                })
                .transpose()?;
            Ok(crate::init_system::ServiceHistoryEntry {
                id: row.get::<_, i64>(0)?.max(0) as u64,
                name: row.get(1)?,
                event: row.get(2)?,
                status,
                agent_id,
                reason: row.get(5)?,
                created_at: row.get(6)?,
            })
        };
        let mut entries = Vec::new();
        if let Some(name) = name {
            let rows = statement
                .query_map(params![name, limit], map_row)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            for row in rows {
                entries.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
            }
        } else {
            let rows = statement
                .query_map(params![limit], map_row)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            for row in rows {
                entries.push(row.map_err(|error| ContextError::StorageError(error.to_string()))?);
            }
        }
        Ok(entries)
    }
}

/// Tenancy persistence — tenants, users, sessions and api-keys, plus the
/// tenant-scoped data reads that make cross-tenant access impossible.
///
/// All on the single SQLite handle (no second db). Secrets are persisted
/// **hashed** (the `auth.rs` `*_hash` columns) — the plaintext is never written.
/// On boot the kernel calls [`load_tenancy`](Self::load_tenancy) to rehydrate the
/// in-memory `AuthSystem`, so tenants/users/keys survive a restart.
impl SqliteContextManager {
    /// Persist a tenant (insert-or-replace).
    pub fn save_tenant(&self, t: &crate::auth::Tenant) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO tenants (id, name, created_at) VALUES (?1, ?2, ?3)",
            params![t.id, t.name, t.created_at.to_rfc3339()],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Persist a user (insert-or-replace).
    pub fn save_user(&self, u: &crate::auth::User) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO users (id, tenant_id, username, email, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                u.id,
                u.tenant_id,
                u.username,
                u.email,
                u.role.as_str(),
                u.created_at.to_rfc3339()
            ],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Persist an api-key record (hash only — never the plaintext).
    pub fn save_api_key(&self, k: &crate::auth::ApiKey) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO api_keys (key_hash, name, user_id, tenant_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                k.key_hash,
                k.name,
                k.user_id,
                k.tenant_id,
                k.created_at.to_rfc3339()
            ],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Persist a session record (hash only — never the plaintext token).
    pub fn save_session(&self, s: &crate::auth::Session) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token_hash, user_id, tenant_id, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                s.token_hash,
                s.user_id,
                s.tenant_id,
                s.expires_at.to_rfc3339()
            ],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Permanently revoke a session by its stored hash.
    pub fn revoke_session_hash(&self, token_hash: &str) -> Result<bool, ContextError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "DELETE FROM sessions WHERE token_hash = ?1",
                params![token_hash],
            )
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(changed > 0)
    }

    /// Permanently revoke an API key by its stored hash.
    pub fn revoke_api_key_hash(&self, key_hash: &str) -> Result<bool, ContextError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "DELETE FROM api_keys WHERE key_hash = ?1",
                params![key_hash],
            )
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(changed > 0)
    }

    /// Revoke a user and all credentials issued to that user in one durable
    /// transaction. Agent/data ownership is tenant-scoped and is intentionally
    /// not deleted by identity revocation.
    pub fn revoke_user_identity(&self, user_id: &str) -> Result<bool, ContextError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        let mut changed = tx
            .execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("user_revoke.sessions");
        changed += tx
            .execute("DELETE FROM api_keys WHERE user_id = ?1", params![user_id])
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("user_revoke.api_keys");
        changed += tx
            .execute("DELETE FROM users WHERE id = ?1", params![user_id])
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("user_revoke.users");
        tx.commit()
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(changed > 0)
    }

    /// Irreversibly erase one user's identity and credentials. Runtime agents
    /// are tenant-owned rather than user-owned. Package transparency/audit
    /// entries retain only the now-pseudonymous actor id so their security
    /// chain remains verifiable.
    pub fn erase_user_data(&self, user_id: &str) -> Result<Option<DeletionReceipt>, ContextError> {
        self.erase_user_data_after_backup_purge(user_id, 0)
    }

    pub(crate) fn erase_user_data_after_backup_purge(
        &self,
        user_id: &str,
        managed_backups_deleted: usize,
    ) -> Result<Option<DeletionReceipt>, ContextError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        let mut deleted_rows = BTreeMap::new();
        for table in ["sessions", "api_keys"] {
            let deleted = tx
                .execute(
                    &format!("DELETE FROM {table} WHERE user_id = ?1"),
                    params![user_id],
                )
                .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
            record_deleted_rows(&mut deleted_rows, table, deleted);
            crash_erasure_after_step_for_test(match table {
                "sessions" => "user.sessions",
                "api_keys" => "user.api_keys",
                _ => unreachable!("user erasure table list is closed"),
            });
        }
        let deleted = tx
            .execute(
                "DELETE FROM package_rate_limits WHERE actor = ?1",
                params![user_id],
            )
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "package_rate_limits", deleted);
        crash_erasure_after_step_for_test("user.package_rate_limits");
        let deleted = tx
            .execute("DELETE FROM users WHERE id = ?1", params![user_id])
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "users", deleted);
        crash_erasure_after_step_for_test("user.users");

        if deleted_rows.is_empty() {
            return Ok(None);
        }
        record_deleted_rows(
            &mut deleted_rows,
            "managed_backup_copies",
            managed_backups_deleted,
        );
        let receipt = persist_deletion_receipt(
            &tx,
            DeletionSubjectKind::User,
            deleted_rows,
            vec![
                "tenant-owned agents and runtime data".to_string(),
                "pseudonymous package transparency and security audit actor references".to_string(),
                "backup copies outside the configured managed root".to_string(),
            ],
        )?;
        crash_erasure_after_step_for_test("user.deletion_receipt");
        tx.commit()
            .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
        Ok(Some(receipt))
    }

    /// Revoke a tenant, its users, and every issued credential atomically.
    /// Durable agent data remains present for explicit administrative recovery,
    /// but no tenant principal can authenticate after this commits.
    pub fn revoke_tenant_identity(&self, tenant_id: &str) -> Result<bool, ContextError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        let mut changed = tx
            .execute(
                "DELETE FROM sessions WHERE tenant_id = ?1",
                params![tenant_id],
            )
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("tenant_revoke.sessions");
        changed += tx
            .execute(
                "DELETE FROM api_keys WHERE tenant_id = ?1",
                params![tenant_id],
            )
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("tenant_revoke.api_keys");
        changed += tx
            .execute("DELETE FROM users WHERE tenant_id = ?1", params![tenant_id])
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("tenant_revoke.users");
        changed += tx
            .execute("DELETE FROM tenants WHERE id = ?1", params![tenant_id])
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        crash_multi_table_mutation_after_step_for_test("tenant_revoke.tenants");
        tx.commit()
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(changed > 0)
    }

    /// Load all persisted tenancy state. Returns `(tenants, users, api_keys,
    /// sessions)` for the kernel to reinsert into a fresh `AuthSystem` on boot.
    /// A malformed row is skipped, never fatal (best-effort rehydration).
    #[allow(clippy::type_complexity)]
    pub fn load_tenancy(
        &self,
    ) -> Result<
        (
            Vec<crate::auth::Tenant>,
            Vec<crate::auth::User>,
            Vec<crate::auth::ApiKey>,
            Vec<crate::auth::Session>,
        ),
        ContextError,
    > {
        let conn = self.conn.lock().unwrap();
        let parse_ts = |s: &str| {
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now())
        };

        let mut tenants = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT id, name, created_at FROM tenants")
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            for r in rows.flatten() {
                tenants.push(crate::auth::Tenant {
                    id: r.0,
                    name: r.1,
                    created_at: parse_ts(&r.2),
                });
            }
        }

        let mut users = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT id, tenant_id, username, email, role, created_at FROM users")
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            for r in rows.flatten() {
                let Some(role) = crate::auth::Role::parse(&r.4) else {
                    tracing::warn!(
                        user_id = %r.0,
                        role = %r.4,
                        "skipping user with unknown persisted role"
                    );
                    continue;
                };
                users.push(crate::auth::User {
                    id: r.0,
                    tenant_id: r.1,
                    username: r.2,
                    email: r.3,
                    role,
                    created_at: parse_ts(&r.5),
                });
            }
        }

        let mut api_keys = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT key_hash, name, user_id, tenant_id, created_at FROM api_keys")
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            for r in rows.flatten() {
                api_keys.push(crate::auth::ApiKey {
                    key_hash: r.0,
                    name: r.1,
                    user_id: r.2,
                    tenant_id: r.3,
                    created_at: parse_ts(&r.4),
                });
            }
        }

        let mut sessions = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT token_hash, user_id, tenant_id, expires_at FROM sessions")
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            for r in rows.flatten() {
                sessions.push(crate::auth::Session {
                    token_hash: r.0,
                    user_id: r.1,
                    tenant_id: r.2,
                    expires_at: parse_ts(&r.3),
                });
            }
        }

        Ok((tenants, users, api_keys, sessions))
    }
}

/// Tenant-scoped data reads. These prove cross-tenant isolation at the storage
/// layer: each takes the caller's `tenant_id` and returns the agent's data
/// **only** if that agent belongs to the caller's tenant — otherwise an empty /
/// `None` result, exactly as if the data did not exist. The kernel routes
/// tenant-bound connections through these instead of the raw per-agent reads.
impl SqliteContextManager {
    /// Rebuild every embedding owned by one agent with the currently configured
    /// model/version. Returns the number of rows migrated.
    pub fn reindex_memory(&self, agent_id: AgentId) -> Result<usize, ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| ContextError::StorageError("SQLite mutex poisoned".into()))?;
        let facts = {
            let mut statement = conn
                .prepare("SELECT id, content FROM facts WHERE agent_id = ?1 ORDER BY id")
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            let rows = statement
                .query_map([agent_id.to_string()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| ContextError::StorageError(error.to_string()))?
        };
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        for (id, content) in &facts {
            let embedding = self.embedder.embed(content);
            let embedding_json = serde_json::to_string(&embedding)
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            transaction
                .execute(
                    "UPDATE facts
                     SET embedding_json = ?1, embedding_model = ?2,
                         embedding_version = ?3, embedding_dim = ?4,
                         content_hash = ?5
                     WHERE id = ?6 AND agent_id = ?7",
                    params![
                        embedding_json,
                        self.embedder.model_id(),
                        i64::from(self.embedder.version()),
                        i64::try_from(self.embedder.dim()).unwrap_or(i64::MAX),
                        memory_content_hash(content),
                        id,
                        agent_id.to_string(),
                    ],
                )
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
        }
        transaction
            .commit()
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        Ok(facts.len())
    }

    /// Update one fact only when it belongs to the supplied agent.
    pub fn update_fact(
        &self,
        agent_id: AgentId,
        fact_id: uuid::Uuid,
        content: &str,
    ) -> Result<bool, ContextError> {
        let embedding = self.embedder.embed(content);
        let embedding_json = serde_json::to_string(&embedding)
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| ContextError::StorageError("SQLite mutex poisoned".into()))?;
        let updated = conn
            .execute(
                "UPDATE facts
                 SET content = ?1, last_accessed_at = ?2, embedding_json = ?3,
                     embedding_model = ?4, embedding_version = ?5,
                     embedding_dim = ?6, content_hash = ?7
                 WHERE id = ?8 AND agent_id = ?9",
                params![
                    content,
                    Utc::now().to_rfc3339(),
                    embedding_json,
                    self.embedder.model_id(),
                    i64::from(self.embedder.version()),
                    i64::try_from(self.embedder.dim()).unwrap_or(i64::MAX),
                    memory_content_hash(content),
                    fact_id.to_string(),
                    agent_id.to_string(),
                ],
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        Ok(updated == 1)
    }

    /// Delete one fact only when it belongs to the supplied agent.
    pub fn delete_fact(
        &self,
        agent_id: AgentId,
        fact_id: uuid::Uuid,
    ) -> Result<bool, ContextError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| ContextError::StorageError("SQLite mutex poisoned".into()))?;
        let deleted = conn
            .execute(
                "DELETE FROM facts WHERE id = ?1 AND agent_id = ?2",
                params![fact_id.to_string(), agent_id.to_string()],
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        Ok(deleted == 1)
    }

    /// Irreversibly erase all tenant-owned identities, credentials, agents,
    /// memory, package state, indexes, checkpoints, and subject quota scopes.
    pub fn purge_tenant_data(&self, tenant_id: &str) -> Result<usize, ContextError> {
        let receipt = self.erase_tenant_data(tenant_id)?;
        Ok(receipt
            .map(|receipt| {
                receipt
                    .deleted_rows
                    .values()
                    .fold(0u64, |total, count| total.saturating_add(*count))
                    .min(usize::MAX as u64) as usize
            })
            .unwrap_or(0))
    }

    /// Schema-wide tenant erasure with a privacy-safe durable receipt.
    pub fn erase_tenant_data(
        &self,
        tenant_id: &str,
    ) -> Result<Option<DeletionReceipt>, ContextError> {
        self.erase_tenant_data_after_backup_purge(tenant_id, 0)
    }

    pub(crate) fn erase_tenant_data_after_backup_purge(
        &self,
        tenant_id: &str,
        managed_backups_deleted: usize,
    ) -> Result<Option<DeletionReceipt>, ContextError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| ContextError::StorageError("SQLite mutex poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        let agent_selector = "SELECT id FROM agents WHERE tenant_id = ?1";
        let mut deleted_rows = BTreeMap::new();
        let deleted = transaction
            .execute(
                &format!(
                    "DELETE FROM conversations_fts WHERE conversation_id IN
                     (SELECT id FROM conversations WHERE agent_id IN ({agent_selector}))"
                ),
                [tenant_id],
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "conversations_fts", deleted);
        crash_erasure_after_step_for_test("tenant.conversations_fts");

        for table in ["service_runtime", "service_history"] {
            let cleared = transaction
                .execute(
                    &format!(
                        "UPDATE {table} SET agent_id = NULL
                         WHERE agent_id IN ({agent_selector})"
                    ),
                    [tenant_id],
                )
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            record_deleted_rows(
                &mut deleted_rows,
                format!("{table}.agent_reference"),
                cleared,
            );
            crash_erasure_after_step_for_test(match table {
                "service_runtime" => "tenant.service_runtime",
                "service_history" => "tenant.service_history",
                _ => unreachable!("tenant service table list is closed"),
            });
        }

        for table in [
            "contexts",
            "facts",
            "conversations",
            "usage_log",
            "agent_kv",
            "context_pressure",
            "context_snapshots",
        ] {
            let deleted = transaction
                .execute(
                    &format!("DELETE FROM {table} WHERE agent_id IN ({agent_selector})"),
                    [tenant_id],
                )
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            record_deleted_rows(&mut deleted_rows, table, deleted);
            crash_erasure_after_step_for_test(match table {
                "contexts" => "tenant.contexts",
                "facts" => "tenant.facts",
                "conversations" => "tenant.conversations",
                "usage_log" => "tenant.usage_log",
                "agent_kv" => "tenant.agent_kv",
                "context_pressure" => "tenant.context_pressure",
                "context_snapshots" => "tenant.context_snapshots",
                _ => unreachable!("tenant agent table list is closed"),
            });
        }
        for table in ["context_spills", "generation_checkpoints"] {
            let deleted = transaction
                .execute(
                    &format!(
                        "DELETE FROM {table}
                         WHERE tenant_id = ?1 OR agent_id IN ({agent_selector})"
                    ),
                    [tenant_id],
                )
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            record_deleted_rows(&mut deleted_rows, table, deleted);
            crash_erasure_after_step_for_test(match table {
                "context_spills" => "tenant.context_spills",
                "generation_checkpoints" => "tenant.generation_checkpoints",
                _ => unreachable!("tenant dual-scope table list is closed"),
            });
        }

        for table in [
            "loaded_package_instances",
            "package_trust_keys",
            "package_artifacts",
            "package_installations",
            "package_install_history",
            "package_rate_limits",
            "package_transparency",
            "package_audit",
            "sessions",
            "api_keys",
            "users",
        ] {
            let deleted = transaction
                .execute(
                    &format!("DELETE FROM {table} WHERE tenant_id = ?1"),
                    [tenant_id],
                )
                .map_err(|error| ContextError::StorageError(error.to_string()))?;
            record_deleted_rows(&mut deleted_rows, table, deleted);
            crash_erasure_after_step_for_test(match table {
                "loaded_package_instances" => "tenant.loaded_package_instances",
                "package_trust_keys" => "tenant.package_trust_keys",
                "package_artifacts" => "tenant.package_artifacts",
                "package_installations" => "tenant.package_installations",
                "package_install_history" => "tenant.package_install_history",
                "package_rate_limits" => "tenant.package_rate_limits",
                "package_transparency" => "tenant.package_transparency",
                "package_audit" => "tenant.package_audit",
                "sessions" => "tenant.sessions",
                "api_keys" => "tenant.api_keys",
                "users" => "tenant.users",
                _ => unreachable!("tenant-owned table list is closed"),
            });
        }

        let tenant_scope = format!("/tenant/{}", quota_scope_segment(tenant_id));
        let descendant_prefix = format!("{tenant_scope}/");
        let deleted = transaction
            .execute(
                "DELETE FROM quota_receipt_scopes
                 WHERE scope_kind = 'cgroup'
                   AND (scope_id = ?1
                        OR substr(scope_id, 1, length(?2)) = ?2)",
                params![&tenant_scope, &descendant_prefix],
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "quota_receipt_scopes", deleted);
        crash_erasure_after_step_for_test("tenant.quota_receipt_scopes");
        let deleted = transaction
            .execute(
                "DELETE FROM quota_epochs
                 WHERE scope_kind = 'cgroup'
                   AND (scope_id = ?1
                        OR substr(scope_id, 1, length(?2)) = ?2)",
                params![&tenant_scope, &descendant_prefix],
            )
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "quota_epochs", deleted);
        crash_erasure_after_step_for_test("tenant.quota_epochs");

        let deleted = transaction
            .execute("DELETE FROM agents WHERE tenant_id = ?1", [tenant_id])
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "agents", deleted);
        crash_erasure_after_step_for_test("tenant.agents");
        let deleted = transaction
            .execute("DELETE FROM tenants WHERE id = ?1", [tenant_id])
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        record_deleted_rows(&mut deleted_rows, "tenants", deleted);
        crash_erasure_after_step_for_test("tenant.tenants");

        if deleted_rows.is_empty() {
            return Ok(None);
        }
        record_deleted_rows(
            &mut deleted_rows,
            "managed_backup_copies",
            managed_backups_deleted,
        );
        let receipt = persist_deletion_receipt(
            &transaction,
            DeletionSubjectKind::Tenant,
            deleted_rows,
            vec![
                "system-wide provider quota aggregates".to_string(),
                "non-identifying quota receipt and refund tombstones".to_string(),
                "operator, cluster, and schema state".to_string(),
                "backup copies outside the configured managed root".to_string(),
            ],
        )?;
        crash_erasure_after_step_for_test("tenant.deletion_receipt");
        transaction
            .commit()
            .map_err(|error| ContextError::StorageError(error.to_string()))?;
        Ok(Some(receipt))
    }

    /// `true` if `agent_id` is owned by `tenant_id` (or the agent is unknown,
    /// which callers treat as "no data"). The single isolation predicate the
    /// scoped reads below share.
    fn agent_in_tenant(&self, agent_id: AgentId, tenant_id: &str) -> bool {
        match self.agent_tenant(agent_id) {
            Ok(Some(t)) => t == tenant_id,
            _ => false,
        }
    }

    /// Query an agent's long-term memory, scoped to `tenant_id`. Returns an empty
    /// vec if the agent belongs to a different tenant.
    pub async fn query_memory_for_tenant(
        &self,
        tenant_id: &str,
        agent_id: AgentId,
        query: &str,
    ) -> Result<Vec<Fact>, ContextError> {
        if !self.agent_in_tenant(agent_id, tenant_id) {
            return Ok(Vec::new());
        }
        self.query_memory(agent_id, query).await
    }

    /// Get a KV value for an agent, scoped to `tenant_id`. Returns `None` if the
    /// agent belongs to a different tenant.
    pub fn kv_get_for_tenant(
        &self,
        tenant_id: &str,
        agent_id: AgentId,
        key: &str,
    ) -> Result<Option<String>, ContextError> {
        if !self.agent_in_tenant(agent_id, tenant_id) {
            return Ok(None);
        }
        self.kv_get(agent_id, key)
    }

    /// List an agent's KV keys, scoped to `tenant_id`. Empty for a foreign tenant.
    pub fn kv_list_for_tenant(
        &self,
        tenant_id: &str,
        agent_id: AgentId,
    ) -> Result<Vec<String>, ContextError> {
        if !self.agent_in_tenant(agent_id, tenant_id) {
            return Ok(Vec::new());
        }
        self.kv_list(agent_id)
    }

    /// List an agent's snapshot labels, scoped to `tenant_id`. Empty for a
    /// foreign tenant.
    pub fn list_snapshots_for_tenant(
        &self,
        tenant_id: &str,
        agent_id: AgentId,
    ) -> Result<Vec<String>, ContextError> {
        if !self.agent_in_tenant(agent_id, tenant_id) {
            return Ok(Vec::new());
        }
        self.list_snapshots(agent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_logical_durable_table_has_an_ownership_and_deletion_classification() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let connection = manager.conn.lock().unwrap();
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .unwrap();
        let actual: BTreeSet<String> = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .filter(|name| !name.starts_with("conversations_fts_"))
            .collect();
        let classified: BTreeSet<String> = DURABLE_DATA_CATALOG
            .iter()
            .map(|entry| {
                assert!(
                    !entry.owner.trim().is_empty(),
                    "{} has no owner",
                    entry.table
                );
                assert!(
                    !entry.deletion.trim().is_empty(),
                    "{} has no deletion policy",
                    entry.table
                );
                entry.table.to_string()
            })
            .collect();
        assert_eq!(
            classified.len(),
            DURABLE_DATA_CATALOG.len(),
            "durable data catalog contains duplicate table entries"
        );
        assert_eq!(
            actual, classified,
            "every new logical durable table must be explicitly classified"
        );

        let inventory: BTreeSet<String> = crate::data_inventory::SQLITE_DATA_INVENTORY
            .iter()
            .map(|entry| {
                assert_eq!(entry.persistence, "durable-sqlite");
                for (field, value) in [
                    ("owner", entry.owner),
                    ("tenant_key", entry.tenant_key),
                    ("sensitivity", entry.sensitivity),
                    ("retention", entry.retention),
                    ("encryption", entry.encryption),
                    ("backup", entry.backup),
                    ("deletion", entry.deletion),
                ] {
                    assert!(
                        !value.trim().is_empty(),
                        "{} has no {field} policy",
                        entry.id
                    );
                }
                entry
                    .id
                    .strip_prefix("sqlite/")
                    .expect("SQLite inventory ids use the sqlite/ prefix")
                    .to_string()
            })
            .collect();
        assert_eq!(
            inventory.len(),
            crate::data_inventory::SQLITE_DATA_INVENTORY.len(),
            "full data inventory contains duplicate SQLite entries"
        );
        assert_eq!(
            actual, inventory,
            "every logical SQLite object needs owner, tenant, sensitivity, retention, encryption, backup, and deletion policy"
        );
    }

    fn sample_generation_checkpoint(agent_id: AgentId) -> crate::execution::GenerationCheckpoint {
        crate::execution::GenerationCheckpoint {
            agent_id,
            conversation_id: "checkpoint-conversation".into(),
            user_message: "sensitive prompt".into(),
            messages: vec![crate::connector::StandardMessage::user("sensitive prompt")],
            partial_content: String::new(),
            tool_calls_made: 0,
            tokens_used: 0,
            usage: crate::execution::UsageTelemetry::default(),
        }
    }

    #[test]
    fn generation_checkpoint_retention_version_and_corruption_fail_closed() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let retention_agent = uuid::Uuid::new_v4();
        let retention_checkpoint = sample_generation_checkpoint(retention_agent);
        for _ in 0..(MAX_GENERATION_CHECKPOINTS_PER_AGENT + 3) {
            manager
                .save_generation_checkpoint(
                    DEFAULT_TENANT,
                    "provider",
                    "model",
                    &retention_checkpoint,
                    std::time::Duration::from_secs(60),
                )
                .unwrap();
        }
        assert_eq!(
            manager
                .list_generation_checkpoints(DEFAULT_TENANT, Some(retention_agent))
                .unwrap()
                .len(),
            MAX_GENERATION_CHECKPOINTS_PER_AGENT
        );

        let incompatible_agent = uuid::Uuid::new_v4();
        let incompatible = manager
            .save_generation_checkpoint(
                DEFAULT_TENANT,
                "provider",
                "model",
                &sample_generation_checkpoint(incompatible_agent),
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        manager
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE generation_checkpoints SET version = ?1 WHERE id = ?2",
                params![
                    i64::from(GENERATION_CHECKPOINT_VERSION) + 1,
                    incompatible.to_string()
                ],
            )
            .unwrap();
        let incompatible_error = manager
            .claim_generation_checkpoint(incompatible, incompatible_agent, DEFAULT_TENANT)
            .unwrap_err();
        assert!(incompatible_error.to_string().contains("incompatible"));

        let corrupt_agent = uuid::Uuid::new_v4();
        let corrupt = manager
            .save_generation_checkpoint(
                DEFAULT_TENANT,
                "provider",
                "model",
                &sample_generation_checkpoint(corrupt_agent),
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        manager
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE generation_checkpoints SET checkpoint_json = '{' WHERE id = ?1",
                params![corrupt.to_string()],
            )
            .unwrap();
        let corrupt_error = manager
            .claim_generation_checkpoint(corrupt, corrupt_agent, DEFAULT_TENANT)
            .unwrap_err();
        assert!(corrupt_error.to_string().contains("corrupt"));

        let statuses = manager.conn.lock().unwrap();
        for (id, expected) in [(incompatible, "incompatible"), (corrupt, "corrupt")] {
            let status = statuses
                .query_row(
                    "SELECT status FROM generation_checkpoints WHERE id = ?1",
                    params![id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap();
            assert_eq!(status, expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn persistent_checkpoint_store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "aiagentos-checkpoint-permissions-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("kernel.sqlite");
        let manager = SqliteContextManager::new(&db).unwrap();
        let agent_id = uuid::Uuid::new_v4();
        manager
            .save_generation_checkpoint(
                DEFAULT_TENANT,
                "provider",
                "model",
                &sample_generation_checkpoint(agent_id),
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600
        );

        drop(manager);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn create_and_get_context() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        mgr.create_context(id).await.unwrap();
        let ctx = mgr.get_context(id).await.unwrap();
        assert_eq!(ctx, AgentContext::default());
    }

    #[tokio::test]
    async fn persist_and_restore_context() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        mgr.create_context(id).await.unwrap();

        let mut ctx = AgentContext::default();
        ctx.conversation_history.push(Message {
            role: "user".to_string(),
            content: "hello".to_string(),
            timestamp: Utc::now(),
        });
        ctx.token_count = 10;

        mgr.persist_context(id, &ctx).await.unwrap();
        let restored = mgr.restore_context(id).await.unwrap();
        assert_eq!(restored.conversation_history.len(), 1);
        assert_eq!(restored.conversation_history[0].content, "hello");
        assert_eq!(restored.token_count, 10);
    }

    #[tokio::test]
    async fn summarize_overflow_reduces_tokens() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let mut ctx = AgentContext::default();
        // Add many messages to exceed token limit
        for i in 0..100 {
            ctx.conversation_history.push(Message {
                role: "user".to_string(),
                content: format!("message number {} with some content", i),
                timestamp: Utc::now(),
            });
        }
        ctx.token_count = 5000;

        let summarized = mgr.summarize_overflow(&ctx, 1000).await.unwrap();
        assert!(summarized.token_count <= 1000);
        assert!(summarized.conversation_history.len() < ctx.conversation_history.len());
    }

    #[tokio::test]
    async fn summarize_within_limit_unchanged() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let ctx = AgentContext {
            token_count: 500,
            ..Default::default()
        };
        let result = mgr.summarize_overflow(&ctx, 1000).await.unwrap();
        assert_eq!(result.token_count, 500);
    }

    #[tokio::test]
    async fn store_and_query_fact() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let fact = Fact {
            id: uuid::Uuid::new_v4(),
            content: "The user prefers dark mode".to_string(),
            category: FactCategory::Preference,
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
            embedding: None,
        };
        mgr.store_fact(id, fact.clone()).await.unwrap();

        let results = mgr.query_memory(id, "dark mode").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, fact.content);
    }

    #[tokio::test]
    async fn query_memory_empty_when_no_facts() {
        // With semantic ranking, query_memory ranks an agent's facts rather than
        // substring-filtering them, so it only returns empty when there are no
        // facts stored for the agent.
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let results = mgr.query_memory(id, "tea").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_fact_persists_computed_embedding() {
        // store_fact should compute an embedding when none is supplied, so the
        // round-tripped fact comes back with a populated embedding vector.
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let fact = Fact {
            id: uuid::Uuid::new_v4(),
            content: "likes coffee in the morning".to_string(),
            category: FactCategory::Preference,
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
            embedding: None,
        };
        mgr.store_fact(id, fact).await.unwrap();
        let results = mgr.query_memory(id, "coffee").await.unwrap();
        assert_eq!(results.len(), 1);
        let emb = results[0].embedding.as_ref().expect("embedding persisted");
        assert_eq!(emb.len(), crate::memory_manager::EMBED_DIM);
    }

    #[tokio::test]
    async fn query_memory_ranks_semantically_closest_first() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();

        let facts = [
            "the user prefers dark mode in the editor",
            "the spacecraft reached orbital velocity at dawn",
            "the user enjoys drinking coffee every morning",
        ];
        for content in facts {
            mgr.store_fact(
                id,
                Fact {
                    id: uuid::Uuid::new_v4(),
                    content: content.to_string(),
                    category: FactCategory::Fact,
                    created_at: Utc::now(),
                    last_accessed_at: Utc::now(),
                    embedding: None,
                },
            )
            .await
            .unwrap();
        }

        let results = mgr
            .query_memory(id, "what theme does the user like in their editor")
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
        // The dark-mode/editor fact is semantically closest to the query.
        assert_eq!(
            results[0].content,
            "the user prefers dark mode in the editor"
        );
    }

    #[tokio::test]
    async fn query_memory_large_store_caps_topk_and_finds_target() {
        // An agent with many facts (above the ANN threshold) still surfaces the
        // semantically closest fact, and the result set is capped (not the whole
        // store dumped into the caller's prompt).
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();

        for i in 0..150 {
            mgr.store_fact(
                id,
                Fact {
                    id: uuid::Uuid::new_v4(),
                    content: format!("noise fact {i} about gardening and the weather"),
                    category: FactCategory::Fact,
                    created_at: Utc::now(),
                    last_accessed_at: Utc::now(),
                    embedding: None,
                },
            )
            .await
            .unwrap();
        }
        mgr.store_fact(
            id,
            Fact {
                id: uuid::Uuid::new_v4(),
                content: "the syscall gate enforces capability and MAC checks".to_string(),
                category: FactCategory::Fact,
                created_at: Utc::now(),
                last_accessed_at: Utc::now(),
                embedding: None,
            },
        )
        .await
        .unwrap();

        let results = mgr
            .query_memory(id, "how does the syscall gate enforce capabilities")
            .await
            .unwrap();

        // Capped to the top-K, not all 151 facts.
        assert!(
            results.len() <= 16,
            "results should be capped, got {}",
            results.len()
        );
        // The planted, semantically-closest fact is surfaced.
        assert!(
            results
                .iter()
                .any(|f| f.content.contains("syscall gate enforces capability")),
            "the closest fact should be in the capped results"
        );
    }

    #[tokio::test]
    async fn corrupt_or_stale_memory_is_rebuilt_and_owner_mutations_are_isolated() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        let foreign = uuid::Uuid::new_v4();
        let fact_id = uuid::Uuid::new_v4();
        manager
            .store_fact(
                owner,
                Fact {
                    id: fact_id,
                    content: "durable memory content".into(),
                    category: FactCategory::Fact,
                    created_at: Utc::now(),
                    last_accessed_at: Utc::now(),
                    embedding: None,
                },
            )
            .await
            .unwrap();
        manager
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE facts
                 SET embedding_json = 'not-json', embedding_model = 'old',
                     embedding_version = 0, embedding_dim = 1,
                     content_hash = 'wrong'
                 WHERE id = ?1",
                [fact_id.to_string()],
            )
            .unwrap();

        let results = manager.query_memory(owner, "durable").await.unwrap();
        assert_eq!(
            results[0].embedding.as_ref().unwrap().len(),
            crate::memory_manager::EMBED_DIM
        );
        let metadata = manager
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT embedding_model, embedding_version, embedding_dim,
                        content_hash
                 FROM facts WHERE id = ?1",
                [fact_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(metadata.0, manager.embedder.model_id());
        assert_eq!(metadata.1, i64::from(manager.embedder.version()));
        assert_eq!(metadata.2, manager.embedder.dim() as i64);
        assert_eq!(metadata.3, memory_content_hash("durable memory content"));

        assert!(!manager
            .update_fact(foreign, fact_id, "foreign update")
            .unwrap());
        assert!(!manager.delete_fact(foreign, fact_id).unwrap());
        assert!(manager.update_fact(owner, fact_id, "owner update").unwrap());
        assert_eq!(manager.reindex_memory(owner).unwrap(), 1);
        assert!(manager.delete_fact(owner, fact_id).unwrap());
    }

    #[test]
    fn concurrent_memory_writes_preserve_all_rows() {
        let manager = std::sync::Arc::new(SqliteContextManager::in_memory().unwrap());
        let agent = uuid::Uuid::new_v4();
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let manager = std::sync::Arc::clone(&manager);
                scope.spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    for item in 0..20 {
                        runtime
                            .block_on(manager.store_fact(
                                agent,
                                Fact {
                                    id: uuid::Uuid::new_v4(),
                                    content: format!("worker {worker} memory {item}"),
                                    category: FactCategory::Fact,
                                    created_at: Utc::now(),
                                    last_accessed_at: Utc::now(),
                                    embedding: None,
                                },
                            ))
                            .unwrap();
                    }
                });
            }
        });
        let count: i64 = manager
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM facts WHERE agent_id = ?1",
                [agent.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 160);
    }

    #[tokio::test]
    async fn tenant_purge_removes_artifacts_and_identity_without_touching_other_tenants() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let tenant_a_agent = uuid::Uuid::new_v4();
        let tenant_b_agent = uuid::Uuid::new_v4();
        {
            let conn = manager.conn.lock().unwrap();
            for (agent, tenant) in [(tenant_a_agent, "tenant-a"), (tenant_b_agent, "tenant-b")] {
                conn.execute(
                    "INSERT INTO agents
                     (id, session_id, name, task, llm_provider, permission_profile,
                      priority, status, created_at, last_activity_at, tenant_id)
                     VALUES (?1, ?2, 'agent', 'task', 'provider', 'standard',
                             3, '\"Running\"', ?3, ?3, ?4)",
                    params![
                        agent.to_string(),
                        uuid::Uuid::new_v4().to_string(),
                        Utc::now().to_rfc3339(),
                        tenant
                    ],
                )
                .unwrap();
            }
        }
        for agent in [tenant_a_agent, tenant_b_agent] {
            manager
                .store_fact(
                    agent,
                    Fact {
                        id: uuid::Uuid::new_v4(),
                        content: format!("memory for {agent}"),
                        category: FactCategory::Fact,
                        created_at: Utc::now(),
                        last_accessed_at: Utc::now(),
                        embedding: None,
                    },
                )
                .await
                .unwrap();
            manager.kv_put(agent, "secret", "value").unwrap();
            manager
                .save_conversation(
                    &format!("conversation-{agent}"),
                    agent,
                    &[crate::connector::StandardMessage::user("private")],
                )
                .unwrap();
            let spill = format!("spill-{agent}");
            manager
                .store_context_spill(
                    agent,
                    &format!("context_spill:purge:{agent}"),
                    &spill,
                    &sha256(&spill),
                )
                .unwrap();
        }

        assert!(manager.purge_tenant_data("tenant-a").unwrap() > 0);
        let conn = manager.conn.lock().unwrap();
        for table in ["facts", "conversations", "agent_kv", "context_spills"] {
            let tenant_a_rows: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE agent_id = ?1"),
                    [tenant_a_agent.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            let tenant_b_rows: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE agent_id = ?1"),
                    [tenant_b_agent.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(tenant_a_rows, 0, "{table} retained tenant A artifacts");
            let expected_tenant_b_rows = if table == "agent_kv" { 2 } else { 1 };
            assert_eq!(
                tenant_b_rows, expected_tenant_b_rows,
                "{table} damaged tenant B artifacts"
            );
        }
        let identities: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM agents WHERE id IN (?1, ?2)",
                params![tenant_a_agent.to_string(), tenant_b_agent.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(identities, 1, "only the other tenant identity may remain");
        let receipt: (String, String) = conn
            .query_row(
                "SELECT subject_kind, deleted_rows_json FROM deletion_receipts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(receipt.0, "tenant");
        assert!(!receipt.1.contains("tenant-a"));
        assert!(!receipt.1.contains(&tenant_a_agent.to_string()));
    }

    #[test]
    fn user_erasure_revokes_identity_while_retaining_pseudonymous_security_chain() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let tenant_id = "tenant-a";
        let user_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        {
            let connection = manager.conn.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO tenants (id, name, created_at)
                     VALUES (?1, 'Tenant A', ?2)",
                    params![tenant_id, &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO users (id, tenant_id, username, email, role, created_at)
                     VALUES (?1, ?2, 'alice', 'alice@example.test', 'admin', ?3)",
                    params![&user_id, tenant_id, &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO api_keys (key_hash, name, user_id, tenant_id, created_at)
                     VALUES ('key-hash', 'key', ?1, ?2, ?3)",
                    params![&user_id, tenant_id, &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO sessions (token_hash, user_id, tenant_id, expires_at)
                     VALUES ('session-hash', ?1, ?2, ?3)",
                    params![&user_id, tenant_id, &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO package_rate_limits
                     (tenant_id, actor, window_started_at, requests)
                     VALUES (?1, ?2, 1, 1)",
                    params![tenant_id, &user_id],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO package_transparency
                     (tenant_id, action, name, version, digest, previous_hash,
                      entry_hash, actor, created_at)
                     VALUES (?1, 'publish', 'pkg', '1.0.0', 'digest', 'previous',
                             'entry', ?2, ?3)",
                    params![tenant_id, &user_id, &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO package_audit
                     (tenant_id, actor, action, outcome, created_at)
                     VALUES (?1, ?2, 'publish', 'allowed', ?3)",
                    params![tenant_id, &user_id, &now],
                )
                .unwrap();
        }

        let receipt = manager
            .erase_user_data(&user_id)
            .unwrap()
            .expect("user exists");
        assert_eq!(receipt.subject_kind, DeletionSubjectKind::User);
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        assert!(!receipt_json.contains(&user_id));
        assert!(!receipt_json.contains(tenant_id));

        let connection = manager.conn.lock().unwrap();
        for (table, column) in [
            ("users", "id"),
            ("api_keys", "user_id"),
            ("sessions", "user_id"),
            ("package_rate_limits", "actor"),
        ] {
            let count: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
                    [&user_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} retained active user identity data");
        }
        for table in ["package_transparency", "package_audit"] {
            let count: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE actor = ?1"),
                    [&user_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{table} security evidence was not retained");
        }
    }

    #[test]
    fn tenant_erasure_and_private_receipt_survive_restart() {
        let database = QuotaTestDatabase::new("tenant-erasure-restart");
        let tenant_id = "tenant-restart";
        let agent_id = uuid::Uuid::new_v4();
        let now = Utc::now();
        let receipt_id;
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            manager
                .save_agent(&PersistedAgent {
                    id: agent_id,
                    session_id: uuid::Uuid::new_v4(),
                    tenant_id: tenant_id.into(),
                    name: "private agent".into(),
                    task: "private task".into(),
                    llm_provider: "stub".into(),
                    permission_profile: "standard".into(),
                    priority: 3,
                    status: "\"Stopped\"".into(),
                    sandbox_config_json: None,
                    created_at: now,
                    last_activity_at: now,
                })
                .unwrap();
            manager
                .conn
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO tenants (id, name, created_at)
                     VALUES (?1, 'private tenant', ?2)",
                    params![tenant_id, now.to_rfc3339()],
                )
                .unwrap();
            let receipt = manager
                .erase_tenant_data(tenant_id)
                .unwrap()
                .expect("tenant exists");
            receipt_id = receipt.id;
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        let connection = manager.conn.lock().unwrap();
        let subject_rows: i64 = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM tenants WHERE id = ?1) +
                    (SELECT COUNT(*) FROM agents WHERE tenant_id = ?1)",
                [tenant_id],
                |row| row.get(0),
            )
            .unwrap();
        let receipt: (String, String, String) = connection
            .query_row(
                "SELECT subject_kind, deleted_rows_json, retained_records_json
                 FROM deletion_receipts WHERE id = ?1",
                [receipt_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(subject_rows, 0);
        assert_eq!(receipt.0, "tenant");
        assert!(!receipt.1.contains(tenant_id));
        assert!(!receipt.2.contains(tenant_id));
        assert!(!receipt.1.contains(&agent_id.to_string()));
    }

    #[test]
    fn kv_put_get_list_delete_roundtrip() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();

        // Missing key → None.
        assert_eq!(mgr.kv_get(id, "color").unwrap(), None);

        // Put then get.
        mgr.kv_put(id, "color", "blue").unwrap();
        mgr.kv_put(id, "size", "large").unwrap();
        assert_eq!(mgr.kv_get(id, "color").unwrap().as_deref(), Some("blue"));

        // List returns both keys, sorted.
        assert_eq!(
            mgr.kv_list(id).unwrap(),
            vec!["color".to_string(), "size".to_string()]
        );

        // Overwrite an existing key.
        mgr.kv_put(id, "color", "green").unwrap();
        assert_eq!(mgr.kv_get(id, "color").unwrap().as_deref(), Some("green"));
        assert_eq!(
            mgr.kv_list(id).unwrap().len(),
            2,
            "overwrite must not add a row"
        );

        // Delete an existing key returns true; deleting again returns false.
        assert!(mgr.kv_delete(id, "color").unwrap());
        assert!(!mgr.kv_delete(id, "color").unwrap());
        assert_eq!(mgr.kv_get(id, "color").unwrap(), None);
        assert_eq!(mgr.kv_list(id).unwrap(), vec!["size".to_string()]);
    }

    #[test]
    fn kv_is_isolated_between_agents() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();

        mgr.kv_put(a, "shared", "a-value").unwrap();
        mgr.kv_put(b, "shared", "b-value").unwrap();

        assert_eq!(mgr.kv_get(a, "shared").unwrap().as_deref(), Some("a-value"));
        assert_eq!(mgr.kv_get(b, "shared").unwrap().as_deref(), Some("b-value"));

        // Agent A's keys don't leak into agent B's listing.
        assert_eq!(mgr.kv_list(a).unwrap(), vec!["shared".to_string()]);
        assert_eq!(mgr.kv_list(b).unwrap(), vec!["shared".to_string()]);

        // Deleting from A leaves B untouched.
        assert!(mgr.kv_delete(a, "shared").unwrap());
        assert_eq!(mgr.kv_get(a, "shared").unwrap(), None);
        assert_eq!(mgr.kv_get(b, "shared").unwrap().as_deref(), Some("b-value"));
    }

    #[tokio::test]
    async fn snapshot_restore_list_delete_roundtrip() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        mgr.create_context(id).await.unwrap();

        // Establish an initial context and snapshot it.
        let mut ctx = AgentContext::default();
        ctx.conversation_history.push(Message {
            role: "user".to_string(),
            content: "first".to_string(),
            timestamp: Utc::now(),
        });
        ctx.token_count = 7;
        mgr.persist_context(id, &ctx).await.unwrap();
        mgr.snapshot_context(id, "checkpoint-a").unwrap();

        // Mutate the live context away from the snapshot.
        let mut mutated = ctx.clone();
        mutated.conversation_history.push(Message {
            role: "assistant".to_string(),
            content: "second".to_string(),
            timestamp: Utc::now(),
        });
        mutated.token_count = 42;
        mgr.persist_context(id, &mutated).await.unwrap();
        assert_eq!(mgr.get_context(id).await.unwrap().token_count, 42);

        // A second snapshot (created later) should sort newest-first.
        mgr.snapshot_context(id, "checkpoint-b").unwrap();
        assert_eq!(
            mgr.list_snapshots(id).unwrap(),
            vec!["checkpoint-b".to_string(), "checkpoint-a".to_string()]
        );

        // Restoring the first snapshot returns the original and makes it current.
        let restored = mgr.restore_snapshot(id, "checkpoint-a").unwrap();
        assert_eq!(restored, ctx);
        let current = mgr.get_context(id).await.unwrap();
        assert_eq!(current, ctx);
        assert_eq!(current.token_count, 7);
        assert_eq!(current.conversation_history.len(), 1);

        // Delete is idempotent: true once, false after.
        assert!(mgr.delete_snapshot(id, "checkpoint-a").unwrap());
        assert!(!mgr.delete_snapshot(id, "checkpoint-a").unwrap());
        assert_eq!(
            mgr.list_snapshots(id).unwrap(),
            vec!["checkpoint-b".to_string()]
        );

        // Restoring or snapshotting unknown things errors rather than panics.
        assert!(mgr.restore_snapshot(id, "missing").is_err());
        let no_ctx = uuid::Uuid::new_v4();
        assert!(mgr.snapshot_context(no_ctx, "x").is_err());
    }

    #[test]
    fn snapshots_are_isolated_between_agents() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        mgr.persist_with_retry(a, &AgentContext::default()).unwrap();
        mgr.persist_with_retry(b, &AgentContext::default()).unwrap();

        mgr.snapshot_context(a, "shared").unwrap();
        mgr.snapshot_context(b, "shared").unwrap();

        // Agent A's snapshot listing doesn't include agent B's, and deleting
        // from A leaves B's untouched.
        assert_eq!(mgr.list_snapshots(a).unwrap(), vec!["shared".to_string()]);
        assert!(mgr.delete_snapshot(a, "shared").unwrap());
        assert!(mgr.list_snapshots(a).unwrap().is_empty());
        assert_eq!(mgr.list_snapshots(b).unwrap(), vec!["shared".to_string()]);
    }

    #[tokio::test]
    async fn get_nonexistent_context_fails() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let result = mgr.get_context(id).await;
        assert!(result.is_err());
    }

    #[test]
    fn agent_registry_save_load_roundtrip() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let now = Utc::now();
        let a = PersistedAgent {
            id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            tenant_id: DEFAULT_TENANT.to_string(),
            name: "alpha".into(),
            task: "do the thing".into(),
            llm_provider: "stub".into(),
            permission_profile: "read-only".into(),
            priority: 2,
            status: "\"Running\"".into(),
            sandbox_config_json: None,
            created_at: now,
            last_activity_at: now,
        };
        mgr.save_agent(&a).unwrap();
        let loaded = mgr.load_all_agents().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], a);

        // Upsert (INSERT OR REPLACE) on the same id does not duplicate.
        let mut a2 = a.clone();
        a2.name = "alpha-renamed".into();
        mgr.save_agent(&a2).unwrap();
        let loaded = mgr.load_all_agents().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "alpha-renamed");

        // Delete removes it.
        assert!(mgr.delete_agent(a.id).unwrap());
        assert!(mgr.load_all_agents().unwrap().is_empty());
    }

    #[tokio::test]
    async fn agent_erasure_cascades_indexes_services_quota_and_returns_private_receipt() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let agent = uuid::Uuid::new_v4();
        let tenant = "tenant/%_special";
        let profile = "standard";
        let now = Utc::now();
        manager
            .save_agent(&PersistedAgent {
                id: agent,
                session_id: uuid::Uuid::new_v4(),
                tenant_id: tenant.to_string(),
                name: "private name".into(),
                task: "private task".into(),
                llm_provider: "stub".into(),
                permission_profile: profile.into(),
                priority: 3,
                status: "\"Stopped\"".into(),
                sandbox_config_json: None,
                created_at: now,
                last_activity_at: now,
            })
            .unwrap();
        manager.create_context(agent).await.unwrap();
        manager
            .store_fact(
                agent,
                Fact {
                    id: uuid::Uuid::new_v4(),
                    content: "private memory".into(),
                    category: FactCategory::Fact,
                    created_at: now,
                    last_accessed_at: now,
                    embedding: None,
                },
            )
            .await
            .unwrap();
        let conversation_id = format!("private-conversation-{agent}");
        manager
            .save_conversation(
                &conversation_id,
                agent,
                &[crate::connector::StandardMessage::user("private prompt")],
            )
            .unwrap();
        manager
            .kv_put(agent, "private-key", "private-value")
            .unwrap();
        manager
            .store_context_spill(
                agent,
                &format!("context_spill:test:{agent}"),
                "private spill",
                &sha256("private spill"),
            )
            .unwrap();
        manager.snapshot_context(agent, "private-snapshot").unwrap();
        manager
            .save_generation_checkpoint(
                tenant,
                "provider",
                "model",
                &sample_generation_checkpoint(agent),
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        manager
            .log_usage(
                agent,
                &UsageRecord {
                    tokens_used: 10,
                    input_tokens: 8,
                    output_tokens: 2,
                    cached_tokens: 0,
                    llm_requests: 1,
                    retries: 0,
                    provider_latency_ms: 1,
                    provider_reported_requests: 1,
                    estimated_requests: 0,
                    provider: "stub".into(),
                    model: "stub".into(),
                    tool_calls: 0,
                    estimated_cost_usd: 0.01,
                    cost_micros: 10_000,
                },
            )
            .unwrap();

        let agent_scope = format!(
            "/tenant/{}/profile/{}/agent/{agent}",
            quota_scope_segment(tenant),
            quota_scope_segment(profile)
        );
        let quota_receipt = uuid::Uuid::new_v4();
        {
            let connection = manager.conn.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO context_pressure
                     (agent_id, active_tokens, budget_tokens, updated_at)
                     VALUES (?1, 1, 10, ?2)",
                    params![agent.to_string(), now.to_rfc3339()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO loaded_package_instances
                     (agent_id, tenant_id, name, provider, profile, loaded_at)
                     VALUES (?1, ?2, 'pkg', 'stub', ?3, ?4)",
                    params![agent.to_string(), tenant, profile, now.to_rfc3339()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO service_runtime
                     (name, definition_revision, status, agent_id, restart_count,
                      restart_attempts_total, desired_running, ready, healthy,
                      restart_exhausted, last_transition_at, dependency_blocks)
                     VALUES ('svc', 'rev', '\"Running\"', ?1, 0, 0, 0, 0, 0, 0, ?2, 0)",
                    params![agent.to_string(), now.to_rfc3339()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO service_history
                     (name, event, status, agent_id, created_at)
                     VALUES ('svc', 'started', '\"Running\"', ?1, ?2)",
                    params![agent.to_string(), now.to_rfc3339()],
                )
                .unwrap();
            let epoch = u64_blob(7);
            let one = u64_blob(1);
            for scope in ["provider-global".to_string(), agent_scope.clone()] {
                let (kind, id) = if scope == "provider-global" {
                    ("provider", "global")
                } else {
                    ("cgroup", scope.as_str())
                };
                connection
                    .execute(
                        "INSERT INTO quota_epochs
                         (scope_kind, scope_id, epoch, requests, tokens)
                         VALUES (?1, ?2, ?3, ?4, ?4)",
                        params![kind, id, epoch.as_slice(), one.as_slice()],
                    )
                    .unwrap();
            }
            connection
                .execute(
                    "INSERT INTO quota_receipts
                     (id, receipt_kind, epoch, state, reserved_requests, reserved_tokens)
                     VALUES (?1, 'provider_rate', ?2, 'reserved', ?3, ?3)",
                    params![quota_receipt.to_string(), epoch.as_slice(), one.as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO quota_receipt_scopes
                     (receipt_id, scope_order, scope_kind, scope_id,
                      reserved_requests, reserved_tokens)
                     VALUES (?1, 0, 'cgroup', ?2, ?3, ?3)",
                    params![quota_receipt.to_string(), &agent_scope, one.as_slice()],
                )
                .unwrap();
        }

        let receipt = manager
            .erase_agent_data(agent)
            .unwrap()
            .expect("agent exists");
        assert_eq!(receipt.subject_kind, DeletionSubjectKind::Agent);
        assert!(receipt.deleted_rows.contains_key("context_spills"));
        assert!(receipt.deleted_rows.contains_key("quota_epochs"));
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        assert!(!receipt_json.contains(&agent.to_string()));
        assert!(!receipt_json.contains(tenant));
        assert!(!receipt_json.contains("private"));

        let connection = manager.conn.lock().unwrap();
        for table in [
            "contexts",
            "facts",
            "conversations",
            "usage_log",
            "agent_kv",
            "context_spills",
            "context_pressure",
            "context_snapshots",
            "generation_checkpoints",
            "loaded_package_instances",
        ] {
            let count: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE agent_id = ?1"),
                    [agent.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} retained erased agent data");
        }
        let fts_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM conversations_fts WHERE conversation_id = ?1",
                [&conversation_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fts_count, 0);
        for table in ["service_runtime", "service_history"] {
            let count: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE agent_id = ?1"),
                    [agent.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} retained an agent reference");
        }
        let erased_scope_rows: i64 = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM quota_epochs WHERE scope_id = ?1) +
                    (SELECT COUNT(*) FROM quota_receipt_scopes WHERE scope_id = ?1)",
                [&agent_scope],
                |row| row.get(0),
            )
            .unwrap();
        let shared_provider_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM quota_epochs
                 WHERE scope_kind = 'provider' AND scope_id = 'global'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let accounting_receipt_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM quota_receipts WHERE id = ?1",
                [quota_receipt.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(erased_scope_rows, 0);
        assert_eq!(shared_provider_rows, 1);
        assert_eq!(accounting_receipt_rows, 1);
    }

    fn update_fingerprint_value(
        digest: &mut ring::digest::Context,
        value: rusqlite::types::ValueRef<'_>,
    ) {
        use rusqlite::types::ValueRef;

        match value {
            ValueRef::Null => digest.update(&[0]),
            ValueRef::Integer(value) => {
                digest.update(&[1]);
                digest.update(&value.to_le_bytes());
            }
            ValueRef::Real(value) => {
                digest.update(&[2]);
                digest.update(&value.to_bits().to_le_bytes());
            }
            ValueRef::Text(value) => {
                digest.update(&[3]);
                digest.update(&(value.len() as u64).to_le_bytes());
                digest.update(value);
            }
            ValueRef::Blob(value) => {
                digest.update(&[4]);
                digest.update(&(value.len() as u64).to_le_bytes());
                digest.update(value);
            }
        }
    }

    fn logical_database_fingerprints(path: &std::path::Path) -> BTreeMap<String, String> {
        let connection = Connection::open(path).unwrap();
        crate::schema::verify(&connection).unwrap();
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(quick_check, "ok");

        let tables = {
            let mut statement = connection
                .prepare(
                    "SELECT name FROM sqlite_schema
                     WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                     ORDER BY name",
                )
                .unwrap();
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        let mut fingerprints = BTreeMap::new();
        for table in tables {
            let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
            digest.update(&(table.len() as u64).to_le_bytes());
            digest.update(table.as_bytes());
            let quoted_table = format!("\"{}\"", table.replace('"', "\"\""));
            // Opening an already-current store refreshes only this operational
            // timestamp. Fingerprint the durable identity/version fields while
            // excluding that expected pre-transaction startup write.
            let (selection, column_count) = if table == "storage_meta" {
                (
                    "singleton, application_id, schema_version, \
                     min_reader_schema_version, installation_id, created_at"
                        .to_string(),
                    6,
                )
            } else {
                (
                    "*".to_string(),
                    connection
                        .prepare(&format!("PRAGMA table_info({quoted_table})"))
                        .unwrap()
                        .query_map([], |_| Ok(()))
                        .unwrap()
                        .count(),
                )
            };
            assert!(column_count > 0, "{table} has no visible columns");
            let order = (1..=column_count)
                .map(|column| column.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let mut statement = connection
                .prepare(&format!(
                    "SELECT {selection} FROM {quoted_table} ORDER BY {order}"
                ))
                .unwrap();
            let mut rows = statement.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                digest.update(&[0xff]);
                for column in 0..column_count {
                    update_fingerprint_value(&mut digest, row.get_ref(column).unwrap());
                }
            }
            let fingerprint = digest
                .finish()
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            fingerprints.insert(table, fingerprint);
        }
        fingerprints
    }

    async fn seed_agent_erasure_crash_fixture(
        path: &std::path::Path,
        agent: AgentId,
        tenant: &str,
    ) {
        let manager = SqliteContextManager::new(path).unwrap();
        let now = Utc::now();
        manager
            .save_agent(&PersistedAgent {
                id: agent,
                session_id: uuid::Uuid::new_v4(),
                tenant_id: tenant.to_string(),
                name: "crash qualification agent".into(),
                task: "prove transaction rollback".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: 3,
                status: "\"Stopped\"".into(),
                sandbox_config_json: None,
                created_at: now,
                last_activity_at: now,
            })
            .unwrap();
        manager.create_context(agent).await.unwrap();
        manager
            .store_fact(
                agent,
                Fact {
                    id: uuid::Uuid::new_v4(),
                    content: "crash qualification memory".into(),
                    category: FactCategory::Fact,
                    created_at: now,
                    last_accessed_at: now,
                    embedding: None,
                },
            )
            .await
            .unwrap();
        manager
            .save_conversation(
                "crash-qualification-conversation",
                agent,
                &[crate::connector::StandardMessage::user(
                    "crash qualification prompt",
                )],
            )
            .unwrap();
        manager
            .log_usage(
                agent,
                &UsageRecord {
                    tokens_used: 1,
                    input_tokens: 1,
                    output_tokens: 0,
                    cached_tokens: 0,
                    llm_requests: 1,
                    retries: 0,
                    provider_latency_ms: 1,
                    provider_reported_requests: 1,
                    estimated_requests: 0,
                    provider: "stub".into(),
                    model: "stub".into(),
                    tool_calls: 0,
                    estimated_cost_usd: 0.000_001,
                    cost_micros: 1,
                },
            )
            .unwrap();
        manager.kv_put(agent, "crash-proof", "retained").unwrap();
        manager
            .store_context_spill(
                agent,
                &format!("context_spill:crash:{agent}"),
                "crash qualification spill",
                &sha256("crash qualification spill"),
            )
            .unwrap();
        manager
            .snapshot_context(agent, "crash-qualification-snapshot")
            .unwrap();
        manager
            .save_generation_checkpoint(
                tenant,
                "stub",
                "stub",
                &sample_generation_checkpoint(agent),
                std::time::Duration::from_secs(60),
            )
            .unwrap();

        let agent_scope = format!("/tenant/{tenant}/profile/standard/agent/{agent}");
        let quota_receipt = uuid::Uuid::new_v4();
        let connection = manager.conn.lock().unwrap();
        connection
            .execute(
                "INSERT INTO context_pressure
                 (agent_id, active_tokens, budget_tokens, updated_at)
                 VALUES (?1, 1, 10, ?2)",
                params![agent.to_string(), now.to_rfc3339()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO loaded_package_instances
                 (agent_id, tenant_id, name, provider, profile, loaded_at)
                 VALUES (?1, ?2, 'pkg', 'stub', 'standard', ?3)",
                params![agent.to_string(), tenant, now.to_rfc3339()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO service_runtime
                 (name, definition_revision, status, agent_id, restart_count,
                  restart_attempts_total, desired_running, ready, healthy,
                  restart_exhausted, last_transition_at, dependency_blocks)
                 VALUES ('crash-svc', 'rev', '\"Running\"', ?1, 0, 0,
                         0, 0, 0, 0, ?2, 0)",
                params![agent.to_string(), now.to_rfc3339()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO service_history
                 (name, event, status, agent_id, created_at)
                 VALUES ('crash-svc', 'started', '\"Running\"', ?1, ?2)",
                params![agent.to_string(), now.to_rfc3339()],
            )
            .unwrap();
        let epoch = u64_blob(1);
        let one = u64_blob(1);
        connection
            .execute(
                "INSERT INTO quota_epochs
                 (scope_kind, scope_id, epoch, requests, tokens)
                 VALUES ('cgroup', ?1, ?2, ?3, ?3)",
                params![&agent_scope, epoch.as_slice(), one.as_slice()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO quota_receipts
                 (id, receipt_kind, epoch, state, reserved_requests, reserved_tokens)
                 VALUES (?1, 'provider_rate', ?2, 'reserved', ?3, ?3)",
                params![quota_receipt.to_string(), epoch.as_slice(), one.as_slice()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO quota_receipt_scopes
                 (receipt_id, scope_order, scope_kind, scope_id,
                  reserved_requests, reserved_tokens)
                 VALUES (?1, 0, 'cgroup', ?2, ?3, ?3)",
                params![quota_receipt.to_string(), &agent_scope, one.as_slice()],
            )
            .unwrap();
    }

    fn seed_user_erasure_crash_fixture(path: &std::path::Path, tenant: &str, user: &str) {
        let manager = SqliteContextManager::new(path).unwrap();
        let now = Utc::now().to_rfc3339();
        let connection = manager.conn.lock().unwrap();
        connection
            .execute(
                "INSERT INTO tenants (id, name, created_at)
                 VALUES (?1, 'Crash qualification tenant', ?2)",
                params![tenant, &now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO users
                 (id, tenant_id, username, email, role, created_at)
                 VALUES (?1, ?2, 'crash-user', 'crash@example.test', 'admin', ?3)",
                params![user, tenant, &now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO api_keys
                 (key_hash, name, user_id, tenant_id, created_at)
                 VALUES ('crash-key', 'crash key', ?1, ?2, ?3)",
                params![user, tenant, &now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions (token_hash, user_id, tenant_id, expires_at)
                 VALUES ('crash-session', ?1, ?2, ?3)",
                params![user, tenant, &now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO package_rate_limits
                 (tenant_id, actor, window_started_at, requests)
                 VALUES (?1, ?2, 1, 1)",
                params![tenant, user],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO package_transparency
                 (tenant_id, action, name, version, digest, previous_hash,
                  entry_hash, actor, created_at)
                 VALUES (?1, 'publish', 'crash-pkg', '1.0.0', 'crash-digest',
                         'crash-previous', 'crash-entry', ?2, ?3)",
                params![tenant, user, &now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO package_audit
                 (tenant_id, actor, action, outcome, created_at)
                 VALUES (?1, ?2, 'publish', 'allowed', ?3)",
                params![tenant, user, &now],
            )
            .unwrap();
    }

    async fn seed_tenant_erasure_crash_fixture(
        path: &std::path::Path,
        tenant: &str,
        user: &str,
        agent: AgentId,
    ) {
        seed_user_erasure_crash_fixture(path, tenant, user);
        {
            let manager = SqliteContextManager::new(path).unwrap();
            let now = Utc::now().to_rfc3339();
            let connection = manager.conn.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO package_trust_keys
                     (tenant_id, key_id, publisher, public_key, status,
                      valid_from, created_at)
                     VALUES (?1, 'crash-key-id', 'crash-publisher', ?2,
                             'trusted', ?3, ?3)",
                    params![tenant, vec![7_u8; 32], &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO package_artifacts
                     (tenant_id, name, version, publisher, digest, archive,
                      manifest_json, published_at)
                     VALUES (?1, 'crash-pkg', '1.0.0', 'crash-publisher',
                             'crash-artifact-digest', ?2, '{}', ?3)",
                    params![tenant, vec![1_u8, 2, 3], &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO package_installations
                     (tenant_id, name, version, digest, lock_json,
                      manifest_json, installed_at)
                     VALUES (?1, 'crash-pkg', '1.0.0',
                             'crash-artifact-digest', '{}', '{}', ?2)",
                    params![tenant, &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO package_install_history
                     (tenant_id, name, snapshot_json, action, created_at)
                     VALUES (?1, 'crash-pkg', '{}', 'install', ?2)",
                    params![tenant, &now],
                )
                .unwrap();
        }
        seed_agent_erasure_crash_fixture(path, agent, tenant).await;
    }

    const USER_ERASURE_CRASH_STEPS: &[&str] = &[
        "user.sessions",
        "user.api_keys",
        "user.package_rate_limits",
        "user.users",
        "user.deletion_receipt",
    ];

    #[test]
    fn process_exit_at_every_user_erasure_mutation_rolls_back_all_tables() {
        let database = QuotaTestDatabase::new("user-erasure-process-exit");
        let tenant = "user-crash-qualification-tenant";
        let user = uuid::Uuid::new_v4().to_string();
        seed_user_erasure_crash_fixture(&database.path, tenant, &user);
        let baseline = logical_database_fingerprints(&database.path);

        for step in USER_ERASURE_CRASH_STEPS {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--ignored")
                .arg("user_erasure_crash_child_only")
                .env("AIAGENTOS_TEST_ERASURE_DB", &database.path)
                .env("AIAGENTOS_TEST_ERASURE_USER", &user)
                .env("AIAGENTOS_TEST_EXIT_ERASURE_AFTER_STEP", step)
                .status()
                .unwrap();
            assert_eq!(
                child.code(),
                Some(87),
                "child did not terminate at crash point {step}"
            );
            assert_eq!(
                logical_database_fingerprints(&database.path),
                baseline,
                "process exit after {step} left a partial durable mutation"
            );
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        assert!(manager.erase_user_data(&user).unwrap().is_some());
        let connection = manager.conn.lock().unwrap();
        crate::schema::verify(&connection).unwrap();
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(quick_check, "ok");
        for (table, column) in [
            ("sessions", "user_id"),
            ("api_keys", "user_id"),
            ("package_rate_limits", "actor"),
            ("users", "id"),
        ] {
            let remaining: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
                    [&user],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(remaining, 0, "{table} retained the erased user");
        }
        for table in ["package_transparency", "package_audit"] {
            let retained: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE actor = ?1"),
                    [&user],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(retained, 1, "{table} lost retained security evidence");
        }
        let receipt_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM deletion_receipts
                 WHERE subject_kind = 'user'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(receipt_count, 1);
    }

    #[test]
    #[ignore = "child-process helper for user-erasure crash regression"]
    fn user_erasure_crash_child_only() {
        let Some(database) = std::env::var_os("AIAGENTOS_TEST_ERASURE_DB") else {
            return;
        };
        let user = std::env::var("AIAGENTOS_TEST_ERASURE_USER")
            .expect("user erasure crash helper requires a user id");
        let manager = SqliteContextManager::new(std::path::Path::new(&database)).unwrap();
        let _ = manager.erase_user_data(&user).unwrap();
        panic!("user erasure crash helper did not terminate at the requested mutation");
    }

    const TENANT_ERASURE_CRASH_STEPS: &[&str] = &[
        "tenant.conversations_fts",
        "tenant.service_runtime",
        "tenant.service_history",
        "tenant.contexts",
        "tenant.facts",
        "tenant.conversations",
        "tenant.usage_log",
        "tenant.agent_kv",
        "tenant.context_pressure",
        "tenant.context_snapshots",
        "tenant.context_spills",
        "tenant.generation_checkpoints",
        "tenant.loaded_package_instances",
        "tenant.package_trust_keys",
        "tenant.package_artifacts",
        "tenant.package_installations",
        "tenant.package_install_history",
        "tenant.package_rate_limits",
        "tenant.package_transparency",
        "tenant.package_audit",
        "tenant.sessions",
        "tenant.api_keys",
        "tenant.users",
        "tenant.quota_receipt_scopes",
        "tenant.quota_epochs",
        "tenant.agents",
        "tenant.tenants",
        "tenant.deletion_receipt",
    ];

    #[tokio::test]
    async fn process_exit_at_every_tenant_erasure_mutation_rolls_back_all_tables() {
        let database = QuotaTestDatabase::new("tenant-erasure-process-exit");
        let tenant = "tenant-crash-qualification";
        let user = uuid::Uuid::new_v4().to_string();
        let agent = uuid::Uuid::new_v4();
        seed_tenant_erasure_crash_fixture(&database.path, tenant, &user, agent).await;
        let baseline = logical_database_fingerprints(&database.path);

        for step in TENANT_ERASURE_CRASH_STEPS {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--ignored")
                .arg("tenant_erasure_crash_child_only")
                .env("AIAGENTOS_TEST_ERASURE_DB", &database.path)
                .env("AIAGENTOS_TEST_ERASURE_TENANT", tenant)
                .env("AIAGENTOS_TEST_EXIT_ERASURE_AFTER_STEP", step)
                .status()
                .unwrap();
            assert_eq!(
                child.code(),
                Some(87),
                "child did not terminate at crash point {step}"
            );
            assert_eq!(
                logical_database_fingerprints(&database.path),
                baseline,
                "process exit after {step} left a partial durable mutation"
            );
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        assert!(manager.erase_tenant_data(tenant).unwrap().is_some());
        let connection = manager.conn.lock().unwrap();
        crate::schema::verify(&connection).unwrap();
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(quick_check, "ok");
        for table in [
            "context_spills",
            "generation_checkpoints",
            "loaded_package_instances",
            "package_trust_keys",
            "package_artifacts",
            "package_installations",
            "package_install_history",
            "package_rate_limits",
            "package_transparency",
            "package_audit",
            "sessions",
            "api_keys",
            "users",
            "agents",
        ] {
            let remaining: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE tenant_id = ?1"),
                    [tenant],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(remaining, 0, "{table} retained the erased tenant");
        }
        for table in [
            "contexts",
            "facts",
            "conversations",
            "usage_log",
            "agent_kv",
            "context_pressure",
            "context_snapshots",
        ] {
            let remaining: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE agent_id = ?1"),
                    [agent.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(remaining, 0, "{table} retained the tenant agent");
        }
        for table in ["service_runtime", "service_history"] {
            let remaining: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE agent_id = ?1"),
                    [agent.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(remaining, 0, "{table} retained the tenant agent reference");
        }
        let tenant_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM tenants WHERE id = ?1",
                [tenant],
                |row| row.get(0),
            )
            .unwrap();
        let fts_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM conversations_fts
                 WHERE conversation_id = 'crash-qualification-conversation'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let receipt_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM deletion_receipts
                 WHERE subject_kind = 'tenant'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tenant_rows, 0);
        assert_eq!(fts_rows, 0);
        assert_eq!(receipt_count, 1);
    }

    #[test]
    #[ignore = "child-process helper for tenant-erasure crash regression"]
    fn tenant_erasure_crash_child_only() {
        let Some(database) = std::env::var_os("AIAGENTOS_TEST_ERASURE_DB") else {
            return;
        };
        let tenant = std::env::var("AIAGENTOS_TEST_ERASURE_TENANT")
            .expect("tenant erasure crash helper requires a tenant id");
        let manager = SqliteContextManager::new(std::path::Path::new(&database)).unwrap();
        let _ = manager.erase_tenant_data(&tenant).unwrap();
        panic!("tenant erasure crash helper did not terminate at the requested mutation");
    }

    const AGENT_ERASURE_CRASH_STEPS: &[&str] = &[
        "agent.conversations_fts",
        "agent.contexts",
        "agent.facts",
        "agent.conversations",
        "agent.usage_log",
        "agent.agent_kv",
        "agent.context_spills",
        "agent.context_snapshots",
        "agent.generation_checkpoints",
        "agent.context_pressure",
        "agent.loaded_package_instances",
        "agent.service_runtime",
        "agent.service_history",
        "agent.quota_receipt_scopes",
        "agent.quota_epochs",
        "agent.agents",
        "agent.deletion_receipt",
    ];

    #[tokio::test]
    async fn process_exit_at_every_agent_erasure_mutation_rolls_back_all_tables() {
        let database = QuotaTestDatabase::new("agent-erasure-process-exit");
        let agent = uuid::Uuid::new_v4();
        let tenant = "crash-qualification-tenant";
        seed_agent_erasure_crash_fixture(&database.path, agent, tenant).await;
        let baseline = logical_database_fingerprints(&database.path);

        for step in AGENT_ERASURE_CRASH_STEPS {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--ignored")
                .arg("agent_erasure_crash_child_only")
                .env("AIAGENTOS_TEST_ERASURE_DB", &database.path)
                .env("AIAGENTOS_TEST_ERASURE_AGENT", agent.to_string())
                .env("AIAGENTOS_TEST_EXIT_ERASURE_AFTER_STEP", step)
                .status()
                .unwrap();
            assert_eq!(
                child.code(),
                Some(87),
                "child did not terminate at crash point {step}"
            );
            assert_eq!(
                logical_database_fingerprints(&database.path),
                baseline,
                "process exit after {step} left a partial durable mutation"
            );
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        assert!(manager.erase_agent_data(agent).unwrap().is_some());
        let connection = manager.conn.lock().unwrap();
        crate::schema::verify(&connection).unwrap();
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(quick_check, "ok");
        let remaining: i64 = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM agents WHERE id = ?1) +
                   (SELECT COUNT(*) FROM contexts WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM facts WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM conversations WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM usage_log WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM agent_kv WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM context_spills WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM context_snapshots WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM generation_checkpoints WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM context_pressure WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM loaded_package_instances WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM service_runtime WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM service_history WHERE agent_id = ?1)",
                [agent.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        let receipt_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM deletion_receipts
                 WHERE subject_kind = 'agent'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
        assert_eq!(receipt_count, 1);
    }

    #[test]
    #[ignore = "child-process helper for agent-erasure crash regression"]
    fn agent_erasure_crash_child_only() {
        let Some(database) = std::env::var_os("AIAGENTOS_TEST_ERASURE_DB") else {
            return;
        };
        let agent = std::env::var("AIAGENTOS_TEST_ERASURE_AGENT")
            .ok()
            .and_then(|value| uuid::Uuid::parse_str(&value).ok())
            .expect("agent erasure crash helper requires a valid agent id");
        let manager = SqliteContextManager::new(std::path::Path::new(&database)).unwrap();
        let _ = manager.erase_agent_data(agent).unwrap();
        panic!("agent erasure crash helper did not terminate at the requested mutation");
    }

    #[test]
    fn injected_agent_erasure_failure_rolls_back_rows_and_receipt() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let agent = uuid::Uuid::new_v4();
        let now = Utc::now();
        manager
            .save_agent(&PersistedAgent {
                id: agent,
                session_id: uuid::Uuid::new_v4(),
                tenant_id: "tenant-a".into(),
                name: "agent".into(),
                task: "task".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: 3,
                status: "\"Stopped\"".into(),
                sandbox_config_json: None,
                created_at: now,
                last_activity_at: now,
            })
            .unwrap();
        {
            let connection = manager.conn.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO facts
                     (id, agent_id, content, category, created_at, last_accessed_at)
                     VALUES (?1, ?2, 'private', '\"Fact\"', ?3, ?3)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        agent.to_string(),
                        now.to_rfc3339()
                    ],
                )
                .unwrap();
            connection
                .execute_batch(
                    "CREATE TRIGGER fail_agent_erasure
                     BEFORE DELETE ON agents BEGIN
                       SELECT RAISE(ABORT, 'injected erasure failure');
                     END;",
                )
                .unwrap();
        }

        assert!(manager.erase_agent_data(agent).is_err());
        {
            let connection = manager.conn.lock().unwrap();
            let counts: (i64, i64, i64) = connection
                .query_row(
                    "SELECT
                       (SELECT COUNT(*) FROM agents WHERE id = ?1),
                       (SELECT COUNT(*) FROM facts WHERE agent_id = ?1),
                       (SELECT COUNT(*) FROM deletion_receipts)",
                    [agent.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(counts, (1, 1, 0));
            connection
                .execute("DROP TRIGGER fail_agent_erasure", [])
                .unwrap();
        }
        assert!(manager.erase_agent_data(agent).unwrap().is_some());
    }

    #[test]
    fn erasure_reconciles_orphaned_agent_user_and_tenant_rows() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let agent = uuid::Uuid::new_v4();
        let user = uuid::Uuid::new_v4().to_string();
        let tenant = "orphan-tenant";
        let now = Utc::now().to_rfc3339();
        {
            let connection = manager.conn.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO facts
                     (id, agent_id, content, category, created_at, last_accessed_at)
                     VALUES (?1, ?2, 'orphan memory', '\"Fact\"', ?3, ?3)",
                    params![uuid::Uuid::new_v4().to_string(), agent.to_string(), &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO api_keys
                     (key_hash, name, user_id, tenant_id, created_at)
                     VALUES ('orphan-key', 'key', ?1, ?2, ?3)",
                    params![&user, tenant, &now],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO package_audit
                     (tenant_id, actor, action, outcome, created_at)
                     VALUES (?1, 'system', 'orphan', 'allowed', ?2)",
                    params![tenant, &now],
                )
                .unwrap();
        }

        assert!(manager.erase_agent_data(agent).unwrap().is_some());
        assert!(manager.erase_user_data(&user).unwrap().is_some());
        assert!(manager.erase_tenant_data(tenant).unwrap().is_some());
        let connection = manager.conn.lock().unwrap();
        let remaining: i64 = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM facts WHERE agent_id = ?1) +
                   (SELECT COUNT(*) FROM api_keys WHERE user_id = ?2) +
                   (SELECT COUNT(*) FROM package_audit WHERE tenant_id = ?3)",
                params![agent.to_string(), &user, tenant],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn usage_log_preserves_provider_model_tokens_retries_latency_and_price() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let agent = uuid::Uuid::new_v4();
        let expected = UsageRecord {
            tokens_used: 150,
            input_tokens: 120,
            output_tokens: 30,
            cached_tokens: 20,
            llm_requests: 2,
            retries: 1,
            provider_latency_ms: 345,
            provider_reported_requests: 1,
            estimated_requests: 0,
            provider: "openai".into(),
            model: "gpt-test".into(),
            tool_calls: 3,
            estimated_cost_usd: 0.004501,
            cost_micros: 4_501,
        };
        mgr.log_usage(agent, &expected).unwrap();

        let record = mgr.latest_usage(agent).expect("usage row");
        assert_eq!(record, expected);
    }

    #[test]
    fn legacy_usage_cost_is_backfilled_to_exact_micros() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE usage_log (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                tokens_used INTEGER NOT NULL,
                model TEXT,
                estimated_cost_usd REAL
            );
            INSERT INTO usage_log
                (id, agent_id, timestamp, tokens_used, model, estimated_cost_usd)
            VALUES
                ('legacy', '00000000-0000-0000-0000-000000000001',
                 '2026-01-01T00:00:00Z', 1, 'legacy-model', 0.0045006);",
        )
        .unwrap();
        let mgr = SqliteContextManager {
            conn: Mutex::new(conn),
            _storage_lease: None,
            encryption_key: None,
            retired_encryption_keys: Vec::new(),
            storage_limits: RwLock::new(ContextStorageLimits::default()),
            embedder: crate::memory_manager::default_embedder(),
            fail_next_agent_save: AtomicBool::new(false),
            fail_agent_status_update_after: AtomicUsize::new(0),
        };
        mgr.init_schema(0).unwrap();

        let record = mgr
            .latest_usage(uuid::Uuid::from_u128(1))
            .expect("migrated usage row");
        assert_eq!(record.cost_micros, 4_501);
        assert!((record.estimated_cost_usd - 0.0045006).abs() < f64::EPSILON);
    }

    #[test]
    fn budget_snapshot_saturates_and_preserves_tenant_mapping() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let agent = uuid::Uuid::new_v4();
        let now = Utc::now();
        mgr.save_agent(&PersistedAgent {
            id: agent,
            session_id: uuid::Uuid::new_v4(),
            tenant_id: "tenant-a".to_string(),
            name: "budget-agent".to_string(),
            task: "test saturation".to_string(),
            llm_provider: "stub".to_string(),
            permission_profile: "default".to_string(),
            priority: 3,
            status: "\"Stopped\"".to_string(),
            sandbox_config_json: None,
            created_at: now,
            last_activity_at: now,
        })
        .unwrap();

        let usage = |cost_micros| UsageRecord {
            tokens_used: 0,
            input_tokens: 0,
            output_tokens: 0,
            cached_tokens: 0,
            llm_requests: 0,
            retries: 0,
            provider_latency_ms: 0,
            provider_reported_requests: 0,
            estimated_requests: 0,
            provider: "stub".to_string(),
            model: "stub".to_string(),
            tool_calls: 0,
            estimated_cost_usd: 0.0,
            cost_micros,
        };
        mgr.log_usage(agent, &usage(i64::MAX as u64)).unwrap();
        mgr.log_usage(agent, &usage(i64::MAX as u64)).unwrap();
        mgr.log_usage(agent, &usage(1)).unwrap();

        let snapshot = mgr.load_budget_usage_snapshot().unwrap();
        assert_eq!(snapshot.global_micros, u64::MAX);
        assert_eq!(snapshot.per_agent_micros.get(&agent), Some(&u64::MAX));
        assert_eq!(snapshot.per_tenant_micros.get("tenant-a"), Some(&u64::MAX));
        assert_eq!(
            snapshot.agent_tenants.get(&agent).map(String::as_str),
            Some("tenant-a")
        );
    }

    struct QuotaTestDatabase {
        path: std::path::PathBuf,
    }

    impl QuotaTestDatabase {
        fn new(label: &str) -> Self {
            Self {
                path: std::env::temp_dir().join(format!(
                    "aiagentos-quota-{label}-{}.db",
                    uuid::Uuid::new_v4()
                )),
            }
        }
    }

    impl Drop for QuotaTestDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let mut wal = self.path.as_os_str().to_os_string();
            wal.push("-wal");
            let _ = std::fs::remove_file(std::path::PathBuf::from(wal));
            let mut shm = self.path.as_os_str().to_os_string();
            shm.push("-shm");
            let _ = std::fs::remove_file(std::path::PathBuf::from(shm));
        }
    }

    const MULTI_TABLE_AGENT: AgentId = uuid::Uuid::from_u128(0x41);
    const MULTI_TABLE_TENANT: &str = "multi-table-crash-tenant";
    const MULTI_TABLE_USER: &str = "00000000-0000-0000-0000-000000000042";
    const MULTI_TABLE_TUNABLE: &str = "crash_matrix_tunable";
    const MULTI_TABLE_SERVICE: &str = "crash-matrix-service";
    const MULTI_TABLE_SPILL_KEY: &str = "context_spill:crash-matrix";

    const CONTEXT_MULTI_TABLE_CRASH_CASES: &[(&str, &[&str])] = &[
        (
            "conversation",
            &[
                "conversation.conversations",
                "conversation.conversations_fts",
            ],
        ),
        (
            "spill_purge",
            &["spill_purge.agent_kv", "spill_purge.context_spills"],
        ),
        (
            "spill_store",
            &["spill_store.agent_kv", "spill_store.context_spills"],
        ),
        (
            "kv_delete",
            &["kv_delete.context_spills", "kv_delete.agent_kv"],
        ),
        (
            "tunable_ensure",
            &[
                "tunable_ensure.operator_tunables",
                "tunable_ensure.operator_tunable_audit",
            ],
        ),
        (
            "tunable_set",
            &[
                "tunable_set.operator_tunables",
                "tunable_set.operator_tunable_audit",
            ],
        ),
        (
            "tunable_rollback",
            &[
                "tunable_rollback.operator_tunables",
                "tunable_rollback.operator_tunable_audit",
            ],
        ),
        (
            "service_save",
            &[
                "service_save.service_runtime",
                "service_save.service_history",
                "service_save.history_retention",
            ],
        ),
        (
            "service_remove",
            &[
                "service_remove.service_runtime",
                "service_remove.service_history",
            ],
        ),
        (
            "user_revoke",
            &[
                "user_revoke.sessions",
                "user_revoke.api_keys",
                "user_revoke.users",
            ],
        ),
        (
            "tenant_revoke",
            &[
                "tenant_revoke.sessions",
                "tenant_revoke.api_keys",
                "tenant_revoke.users",
                "tenant_revoke.tenants",
            ],
        ),
    ];

    fn seed_multi_table_agent(manager: &SqliteContextManager) {
        let now = Utc::now();
        manager
            .save_agent(&PersistedAgent {
                id: MULTI_TABLE_AGENT,
                session_id: uuid::Uuid::from_u128(0x43),
                tenant_id: MULTI_TABLE_TENANT.to_string(),
                name: "multi-table crash agent".into(),
                task: "prove atomic mutation recovery".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: 3,
                status: "\"Stopped\"".into(),
                sandbox_config_json: None,
                created_at: now,
                last_activity_at: now,
            })
            .unwrap();
    }

    fn multi_table_service_runtime() -> crate::init_system::ServiceRuntimeInfo {
        crate::init_system::ServiceRuntimeInfo {
            name: MULTI_TABLE_SERVICE.to_string(),
            status: crate::init_system::ServiceStatus::Running,
            desired_running: true,
            ready: true,
            healthy: true,
            last_transition_at: Utc::now().to_rfc3339(),
            definition_revision: "crash-matrix-revision".into(),
            ..crate::init_system::ServiceRuntimeInfo::default()
        }
    }

    fn seed_multi_table_identity(manager: &SqliteContextManager) {
        let now = Utc::now().to_rfc3339();
        let connection = manager.conn.lock().unwrap();
        connection
            .execute(
                "INSERT INTO tenants (id, name, created_at) VALUES (?1, ?2, ?3)",
                params![MULTI_TABLE_TENANT, "Crash matrix tenant", &now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO users
                 (id, tenant_id, username, email, role, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'admin', ?5)",
                params![
                    MULTI_TABLE_USER,
                    MULTI_TABLE_TENANT,
                    "crash-matrix-user",
                    "crash-matrix@example.test",
                    &now
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO api_keys
                 (key_hash, name, user_id, tenant_id, created_at)
                 VALUES ('crash-matrix-key', 'crash matrix', ?1, ?2, ?3)",
                params![MULTI_TABLE_USER, MULTI_TABLE_TENANT, &now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions (token_hash, user_id, tenant_id, expires_at)
                 VALUES ('crash-matrix-session', ?1, ?2, '2999-01-01T00:00:00Z')",
                params![MULTI_TABLE_USER, MULTI_TABLE_TENANT],
            )
            .unwrap();
    }

    fn seed_context_multi_table_operation(path: &std::path::Path, operation: &str) {
        let manager = SqliteContextManager::new(path).unwrap();
        match operation {
            "conversation" | "spill_store" => seed_multi_table_agent(&manager),
            "spill_purge" | "kv_delete" => {
                seed_multi_table_agent(&manager);
                let expires_at = if operation == "spill_purge" {
                    "2000-01-01T00:00:00Z"
                } else {
                    "2999-01-01T00:00:00Z"
                };
                let connection = manager.conn.lock().unwrap();
                connection
                    .execute(
                        "INSERT INTO agent_kv (agent_id, key, value, updated_at)
                         VALUES (?1, ?2, 'crash matrix spill', ?3)",
                        params![
                            MULTI_TABLE_AGENT.to_string(),
                            MULTI_TABLE_SPILL_KEY,
                            Utc::now().to_rfc3339()
                        ],
                    )
                    .unwrap();
                connection
                    .execute(
                        "INSERT INTO context_spills
                         (agent_id, key, tenant_id, sha256, byte_count, created_at, expires_at)
                         VALUES (?1, ?2, ?3, ?4, 18, ?5, ?6)",
                        params![
                            MULTI_TABLE_AGENT.to_string(),
                            MULTI_TABLE_SPILL_KEY,
                            MULTI_TABLE_TENANT,
                            sha256("crash matrix spill"),
                            Utc::now().to_rfc3339(),
                            expires_at
                        ],
                    )
                    .unwrap();
            }
            "tunable_ensure" => {}
            "tunable_set" => manager
                .ensure_operator_tunable(MULTI_TABLE_TUNABLE, 10, "seed")
                .unwrap(),
            "tunable_rollback" => {
                manager
                    .ensure_operator_tunable(MULTI_TABLE_TUNABLE, 10, "seed")
                    .unwrap();
                manager
                    .set_operator_tunable(MULTI_TABLE_TUNABLE, 20, 1, "seed")
                    .unwrap();
            }
            "service_save" => {}
            "service_remove" => manager
                .save_service_runtime(
                    &multi_table_service_runtime(),
                    "seeded",
                    Some("seed for crash matrix"),
                )
                .unwrap(),
            "user_revoke" | "tenant_revoke" => seed_multi_table_identity(&manager),
            unknown => panic!("unknown multi-table crash operation {unknown}"),
        }
    }

    fn run_context_multi_table_operation(path: &std::path::Path, operation: &str) {
        if operation == "spill_purge" {
            let mut connection = rusqlite::Connection::open(path).unwrap();
            SqliteContextManager::purge_expired_spills_locked(&mut connection).unwrap();
            return;
        }
        let manager = SqliteContextManager::new(path).unwrap();
        match operation {
            "conversation" => manager
                .save_conversation(
                    "crash-matrix-conversation",
                    MULTI_TABLE_AGENT,
                    &[crate::connector::StandardMessage::user(
                        "atomic conversation persistence",
                    )],
                )
                .unwrap(),
            "spill_store" => manager
                .store_context_spill(
                    MULTI_TABLE_AGENT,
                    MULTI_TABLE_SPILL_KEY,
                    "crash matrix spill",
                    &sha256("crash matrix spill"),
                )
                .unwrap(),
            "kv_delete" => {
                assert!(manager
                    .kv_delete(MULTI_TABLE_AGENT, MULTI_TABLE_SPILL_KEY)
                    .unwrap());
            }
            "tunable_ensure" => manager
                .ensure_operator_tunable(MULTI_TABLE_TUNABLE, 10, "crash-matrix")
                .unwrap(),
            "tunable_set" => {
                manager
                    .set_operator_tunable(MULTI_TABLE_TUNABLE, 20, 1, "crash-matrix")
                    .unwrap();
            }
            "tunable_rollback" => {
                manager
                    .rollback_operator_tunable(MULTI_TABLE_TUNABLE, 1, 2, "crash-matrix")
                    .unwrap();
            }
            "service_save" => manager
                .save_service_runtime(
                    &multi_table_service_runtime(),
                    "started",
                    Some("crash matrix"),
                )
                .unwrap(),
            "service_remove" => manager
                .remove_service_runtime(MULTI_TABLE_SERVICE, "crash matrix")
                .unwrap(),
            "user_revoke" => {
                assert!(manager.revoke_user_identity(MULTI_TABLE_USER).unwrap());
            }
            "tenant_revoke" => {
                assert!(manager.revoke_tenant_identity(MULTI_TABLE_TENANT).unwrap());
            }
            unknown => panic!("unknown multi-table crash operation {unknown}"),
        }
    }

    fn assert_context_multi_table_operation_committed(path: &std::path::Path, operation: &str) {
        let manager = SqliteContextManager::new(path).unwrap();
        let connection = manager.conn.lock().unwrap();
        let count = |sql: &str| {
            connection
                .query_row(sql, [], |row| row.get::<_, i64>(0))
                .unwrap()
        };
        match operation {
            "conversation" => {
                assert_eq!(
                    count(
                        "SELECT COUNT(*) FROM conversations
                         WHERE id = 'crash-matrix-conversation'"
                    ),
                    1
                );
                assert_eq!(
                    count(
                        "SELECT COUNT(*) FROM conversations_fts
                         WHERE conversation_id = 'crash-matrix-conversation'"
                    ),
                    1
                );
            }
            "spill_store" => {
                assert_eq!(count("SELECT COUNT(*) FROM agent_kv"), 1);
                assert_eq!(count("SELECT COUNT(*) FROM context_spills"), 1);
            }
            "spill_purge" | "kv_delete" => {
                assert_eq!(count("SELECT COUNT(*) FROM agent_kv"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM context_spills"), 0);
            }
            "tunable_ensure" => {
                assert_eq!(
                    count(
                        "SELECT COUNT(*) FROM operator_tunables
                         WHERE name = 'crash_matrix_tunable' AND revision = 1"
                    ),
                    1
                );
                assert_eq!(count("SELECT COUNT(*) FROM operator_tunable_audit"), 1);
            }
            "tunable_set" => {
                assert_eq!(
                    count(
                        "SELECT COUNT(*) FROM operator_tunables
                         WHERE name = 'crash_matrix_tunable' AND value = 20 AND revision = 2"
                    ),
                    1
                );
                assert_eq!(count("SELECT COUNT(*) FROM operator_tunable_audit"), 2);
            }
            "tunable_rollback" => {
                assert_eq!(
                    count(
                        "SELECT COUNT(*) FROM operator_tunables
                         WHERE name = 'crash_matrix_tunable' AND value = 10 AND revision = 3"
                    ),
                    1
                );
                assert_eq!(count("SELECT COUNT(*) FROM operator_tunable_audit"), 3);
            }
            "service_save" => {
                assert_eq!(count("SELECT COUNT(*) FROM service_runtime"), 1);
                assert_eq!(count("SELECT COUNT(*) FROM service_history"), 1);
            }
            "service_remove" => {
                assert_eq!(count("SELECT COUNT(*) FROM service_runtime"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM service_history"), 2);
            }
            "user_revoke" => {
                assert_eq!(count("SELECT COUNT(*) FROM sessions"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM api_keys"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM users"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM tenants"), 1);
            }
            "tenant_revoke" => {
                for table in ["sessions", "api_keys", "users", "tenants"] {
                    assert_eq!(
                        count(&format!("SELECT COUNT(*) FROM {table}")),
                        0,
                        "{table} retained a revoked tenant identity"
                    );
                }
            }
            unknown => panic!("unknown multi-table crash operation {unknown}"),
        }
        crate::schema::verify(&connection).unwrap();
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(quick_check, "ok");
    }

    #[test]
    fn process_exit_at_every_context_multi_table_statement_preserves_atomicity() {
        for (operation, steps) in CONTEXT_MULTI_TABLE_CRASH_CASES {
            let database = QuotaTestDatabase::new(operation);
            seed_context_multi_table_operation(&database.path, operation);
            let baseline = logical_database_fingerprints(&database.path);

            for step in *steps {
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--ignored")
                    .arg("context_multi_table_mutation_crash_child_only")
                    .env("AIAGENTOS_TEST_MULTI_TABLE_DB", &database.path)
                    .env("AIAGENTOS_TEST_MULTI_TABLE_OPERATION", operation)
                    .env("AIAGENTOS_TEST_EXIT_MULTI_TABLE_AFTER_STEP", step)
                    .status()
                    .unwrap();
                assert_eq!(
                    child.code(),
                    Some(86),
                    "{operation} child did not terminate at {step}"
                );
                assert_eq!(
                    logical_database_fingerprints(&database.path),
                    baseline,
                    "process exit after {operation}:{step} left a partial mutation"
                );
            }

            run_context_multi_table_operation(&database.path, operation);
            assert_ne!(
                logical_database_fingerprints(&database.path),
                baseline,
                "{operation} did not publish its complete transaction"
            );
            assert_context_multi_table_operation_committed(&database.path, operation);
        }
    }

    #[test]
    #[ignore = "child-process helper for context multi-table crash regression"]
    fn context_multi_table_mutation_crash_child_only() {
        let Some(database) = std::env::var_os("AIAGENTOS_TEST_MULTI_TABLE_DB") else {
            return;
        };
        let operation = std::env::var("AIAGENTOS_TEST_MULTI_TABLE_OPERATION")
            .expect("multi-table crash helper requires an operation");
        run_context_multi_table_operation(std::path::Path::new(&database), &operation);
        panic!("multi-table crash helper did not terminate at the requested statement");
    }

    const QUOTA_CRASH_EPOCH: u64 = 500;
    const QUOTA_CRASH_PRUNE_FIRST_EPOCH: u64 = 480;
    const QUOTA_CRASH_PRUNE_SECOND_EPOCH: u64 = 481;
    const QUOTA_CRASH_RECEIPT: uuid::Uuid = uuid::Uuid::from_u128(0x510);
    const QUOTA_CRASH_SECOND_RECEIPT: uuid::Uuid = uuid::Uuid::from_u128(0x511);
    const QUOTA_CRASH_FIRST_TOMBSTONE: uuid::Uuid = uuid::Uuid::from_u128(0x512);
    const QUOTA_CRASH_SECOND_TOMBSTONE: uuid::Uuid = uuid::Uuid::from_u128(0x513);

    const QUOTA_MULTI_TABLE_CRASH_CASES: &[(&str, usize)] = &[
        ("reserve", 8),
        ("refund", 5),
        ("reconcile", 5),
        ("direct_charge", 4),
        ("recovery", 7),
        ("prune", 8),
    ];

    fn quota_crash_scopes() -> [CgroupQuotaConstraint; 2] {
        [
            cgroup_constraint("/", 10_000),
            cgroup_constraint("/tenant/crash-matrix", 10_000),
        ]
    }

    fn reset_quota_mutation_steps_for_test() {
        QUOTA_MUTATION_STEP_FOR_TEST.with(|counter| counter.set(0));
    }

    fn quota_mutation_steps_for_test() -> usize {
        QUOTA_MUTATION_STEP_FOR_TEST.with(std::cell::Cell::get)
    }

    fn seed_quota_multi_table_operation(path: &std::path::Path, operation: &str) {
        let manager = SqliteContextManager::new(path).unwrap();
        let scopes = quota_crash_scopes();
        match operation {
            "reserve" | "direct_charge" => {}
            "refund" => {
                expect_provider_reservation(
                    manager
                        .reserve_provider_rate_with_cgroups(
                            QUOTA_CRASH_RECEIPT,
                            QUOTA_CRASH_EPOCH,
                            100,
                            100_000,
                            300,
                            &scopes,
                        )
                        .unwrap(),
                );
            }
            "reconcile" => {
                expect_provider_reservation(
                    manager
                        .reserve_provider_rate_with_cgroups(
                            QUOTA_CRASH_RECEIPT,
                            QUOTA_CRASH_EPOCH,
                            100,
                            100_000,
                            300,
                            &scopes,
                        )
                        .unwrap(),
                );
                manager
                    .mark_provider_rate_invoked(QUOTA_CRASH_RECEIPT)
                    .unwrap();
            }
            "recovery" => {
                for receipt in [QUOTA_CRASH_RECEIPT, QUOTA_CRASH_SECOND_RECEIPT] {
                    expect_provider_reservation(
                        manager
                            .reserve_provider_rate_with_cgroups(
                                receipt,
                                QUOTA_CRASH_EPOCH,
                                100,
                                100_000,
                                300,
                                &scopes,
                            )
                            .unwrap(),
                    );
                }
                manager
                    .mark_provider_rate_invoked(QUOTA_CRASH_SECOND_RECEIPT)
                    .unwrap();
            }
            "prune" => {
                manager
                    .charge_provider_rate_tokens(
                        QUOTA_CRASH_RECEIPT,
                        QUOTA_CRASH_PRUNE_FIRST_EPOCH,
                        40,
                    )
                    .unwrap();
                expect_provider_reservation(
                    manager
                        .reserve_provider_rate(
                            QUOTA_CRASH_SECOND_RECEIPT,
                            QUOTA_CRASH_PRUNE_SECOND_EPOCH,
                            100,
                            100_000,
                            60,
                        )
                        .unwrap(),
                );
                manager
                    .mark_provider_rate_invoked(QUOTA_CRASH_SECOND_RECEIPT)
                    .unwrap();
                manager
                    .retain_provider_rate_estimate(QUOTA_CRASH_SECOND_RECEIPT)
                    .unwrap();
                let connection = manager.conn.lock().unwrap();
                for (receipt, epoch) in [
                    (QUOTA_CRASH_FIRST_TOMBSTONE, QUOTA_CRASH_PRUNE_FIRST_EPOCH),
                    (QUOTA_CRASH_SECOND_TOMBSTONE, QUOTA_CRASH_PRUNE_SECOND_EPOCH),
                ] {
                    let epoch = u64_blob(epoch);
                    connection
                        .execute(
                            "INSERT INTO quota_refunded_receipts(id, epoch) VALUES (?1, ?2)",
                            params![receipt.to_string(), epoch.as_slice()],
                        )
                        .unwrap();
                    connection
                        .execute(
                            "INSERT INTO quota_migration_fence(epoch) VALUES (?1)",
                            params![epoch.as_slice()],
                        )
                        .unwrap();
                }
            }
            unknown => panic!("unknown quota crash operation {unknown}"),
        }
    }

    fn run_quota_multi_table_operation(path: &std::path::Path, operation: &str) {
        let manager = SqliteContextManager::new(path).unwrap();
        let scopes = quota_crash_scopes();
        match operation {
            "reserve" => {
                expect_provider_reservation(
                    manager
                        .reserve_provider_rate_with_cgroups(
                            QUOTA_CRASH_RECEIPT,
                            QUOTA_CRASH_EPOCH,
                            100,
                            100_000,
                            300,
                            &scopes,
                        )
                        .unwrap(),
                );
            }
            "refund" => manager
                .refund_provider_rate_before_invocation(QUOTA_CRASH_RECEIPT)
                .unwrap(),
            "reconcile" => manager
                .reconcile_provider_rate_attempts(QUOTA_CRASH_RECEIPT, 1, 125)
                .unwrap(),
            "direct_charge" => manager
                .charge_provider_rate_tokens(QUOTA_CRASH_RECEIPT, QUOTA_CRASH_EPOCH, 125)
                .unwrap(),
            "recovery" => {
                let recovery = manager
                    .recover_provider_rate_state(QUOTA_CRASH_EPOCH)
                    .unwrap();
                assert_eq!(recovery.refunded_reserved, 1);
                assert_eq!(recovery.retained_in_flight_estimates, 1);
            }
            "prune" => assert_eq!(
                manager
                    .prune_provider_rate_epochs(QUOTA_CRASH_PRUNE_SECOND_EPOCH + 1)
                    .unwrap(),
                2
            ),
            unknown => panic!("unknown quota crash operation {unknown}"),
        }
    }

    fn assert_quota_multi_table_operation_committed(path: &std::path::Path, operation: &str) {
        let manager = SqliteContextManager::new(path).unwrap();
        {
            let mut connection = manager.conn.lock().unwrap();
            let transaction = connection.transaction().unwrap();
            SqliteContextManager::validate_all_provider_epochs(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        let connection = manager.conn.lock().unwrap();
        let count = |sql: &str| {
            connection
                .query_row(sql, [], |row| row.get::<_, i64>(0))
                .unwrap()
        };
        match operation {
            "reserve" => {
                assert_eq!(count("SELECT COUNT(*) FROM quota_receipts"), 1);
                assert_eq!(count("SELECT COUNT(*) FROM quota_receipt_scopes"), 3);
                assert_eq!(count("SELECT COUNT(*) FROM quota_epochs"), 3);
                assert_eq!(count("SELECT COUNT(*) FROM quota_epoch_floor"), 1);
            }
            "refund" => {
                assert_eq!(count("SELECT COUNT(*) FROM quota_receipts"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM quota_receipt_scopes"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM quota_refunded_receipts"), 1);
                assert_eq!(count("SELECT COUNT(*) FROM quota_epochs"), 3);
            }
            "reconcile" => {
                assert_eq!(
                    count(
                        "SELECT COUNT(*) FROM quota_receipts
                         WHERE state = 'reconciled'
                           AND CAST(actual_tokens AS BLOB) = x'000000000000007D'"
                    ),
                    1
                );
                assert_eq!(
                    count(
                        "SELECT COUNT(*) FROM quota_receipt_scopes
                         WHERE actual_tokens IS NOT NULL"
                    ),
                    3
                );
                assert_eq!(count("SELECT COUNT(*) FROM quota_epochs"), 3);
            }
            "direct_charge" => {
                assert_eq!(
                    count(
                        "SELECT COUNT(*) FROM quota_receipts
                         WHERE state = 'reconciled'"
                    ),
                    1
                );
                assert_eq!(count("SELECT COUNT(*) FROM quota_receipt_scopes"), 1);
                assert_eq!(count("SELECT COUNT(*) FROM quota_epochs"), 1);
                assert_eq!(count("SELECT COUNT(*) FROM quota_epoch_floor"), 1);
            }
            "recovery" => {
                assert_eq!(
                    count(
                        "SELECT COUNT(*) FROM quota_receipts
                         WHERE state = 'estimated'"
                    ),
                    1
                );
                assert_eq!(count("SELECT COUNT(*) FROM quota_receipt_scopes"), 3);
                assert_eq!(count("SELECT COUNT(*) FROM quota_refunded_receipts"), 1);
                assert_eq!(count("SELECT COUNT(*) FROM quota_epochs"), 3);
            }
            "prune" => {
                assert_eq!(count("SELECT COUNT(*) FROM quota_receipts"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM quota_receipt_scopes"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM quota_epochs"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM quota_refunded_receipts"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM quota_migration_fence"), 0);
                assert_eq!(count("SELECT COUNT(*) FROM quota_epoch_floor"), 1);
            }
            unknown => panic!("unknown quota crash operation {unknown}"),
        }
        crate::schema::verify(&connection).unwrap();
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(quick_check, "ok");
    }

    #[test]
    fn process_exit_at_every_quota_multi_table_statement_preserves_atomicity() {
        for (operation, expected_steps) in QUOTA_MULTI_TABLE_CRASH_CASES {
            let database = QuotaTestDatabase::new(&format!("quota-crash-{operation}"));
            seed_quota_multi_table_operation(&database.path, operation);
            let baseline = logical_database_fingerprints(&database.path);

            for step in 1..=*expected_steps {
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--ignored")
                    .arg("quota_multi_table_mutation_crash_child_only")
                    .env("AIAGENTOS_TEST_QUOTA_CRASH_DB", &database.path)
                    .env("AIAGENTOS_TEST_QUOTA_CRASH_OPERATION", operation)
                    .env("AIAGENTOS_TEST_EXIT_QUOTA_AFTER_STEP", step.to_string())
                    .status()
                    .unwrap();
                assert_eq!(
                    child.code(),
                    Some(87),
                    "{operation} child did not terminate at mutation {step}"
                );
                assert_eq!(
                    logical_database_fingerprints(&database.path),
                    baseline,
                    "process exit after {operation} mutation {step} left partial quota state"
                );
            }

            reset_quota_mutation_steps_for_test();
            run_quota_multi_table_operation(&database.path, operation);
            assert_eq!(
                quota_mutation_steps_for_test(),
                *expected_steps,
                "{operation} mutation inventory changed without updating the crash matrix"
            );
            assert_ne!(
                logical_database_fingerprints(&database.path),
                baseline,
                "{operation} did not publish its complete quota transaction"
            );
            assert_quota_multi_table_operation_committed(&database.path, operation);
        }
    }

    #[test]
    #[ignore = "child-process helper for quota multi-table crash regression"]
    fn quota_multi_table_mutation_crash_child_only() {
        let Some(database) = std::env::var_os("AIAGENTOS_TEST_QUOTA_CRASH_DB") else {
            return;
        };
        let operation = std::env::var("AIAGENTOS_TEST_QUOTA_CRASH_OPERATION")
            .expect("quota crash helper requires an operation");
        run_quota_multi_table_operation(std::path::Path::new(&database), &operation);
        panic!("quota crash helper did not terminate at the requested mutation");
    }

    fn expect_provider_reservation(outcome: ProviderRateReserveOutcome) -> ProviderRateReservation {
        match outcome {
            ProviderRateReserveOutcome::Reserved(reservation) => reservation,
            ProviderRateReserveOutcome::Denied { dimension, .. } => {
                panic!("reservation was unexpectedly denied by {dimension:?}")
            }
        }
    }

    #[test]
    fn provider_rate_epochs_are_fixed_and_floor_never_moves_backwards() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let reservation = expect_provider_reservation(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), 10, 1, 100, 100)
                .unwrap(),
        );
        assert_eq!(reservation.epoch, 10);
        assert_eq!(mgr.provider_rate_usage(10).unwrap().tokens, 100);

        // The exact next epoch is fresh.
        let next = mgr.provider_rate_usage(11).unwrap();
        assert_eq!(next.epoch, 11);
        assert_eq!((next.requests, next.tokens), (0, 0));

        // A wall-clock rollback cannot reopen the exhausted earlier epoch.
        let rolled_back = mgr.provider_rate_usage(9).unwrap();
        assert_eq!(rolled_back.epoch, 11);
        assert_eq!((rolled_back.requests, rolled_back.tokens), (0, 0));
        let second = expect_provider_reservation(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), 9, 1, 100, 1)
                .unwrap(),
        );
        assert_eq!(second.epoch, 11);
    }

    #[test]
    fn provider_receipt_transitions_refund_retain_and_reconcile_exactly() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let refunded = uuid::Uuid::new_v4();
        expect_provider_reservation(
            mgr.reserve_provider_rate(refunded, 20, 10, 1_000, 300)
                .unwrap(),
        );
        mgr.refund_provider_rate_before_invocation(refunded)
            .unwrap();
        mgr.refund_provider_rate_before_invocation(refunded)
            .unwrap();
        assert_eq!(
            mgr.provider_rate_usage(20).unwrap(),
            ProviderRateUsage {
                epoch: 20,
                ..ProviderRateUsage::default()
            }
        );
        assert!(mgr
            .reserve_provider_rate(refunded, 20, 10, 1_000, 300)
            .is_err());

        let estimated = uuid::Uuid::new_v4();
        expect_provider_reservation(
            mgr.reserve_provider_rate(estimated, 20, 10, 1_000, 200)
                .unwrap(),
        );
        mgr.mark_provider_rate_invoked(estimated).unwrap();
        mgr.mark_provider_rate_invoked(estimated).unwrap();
        assert!(mgr
            .refund_provider_rate_before_invocation(estimated)
            .is_err());
        mgr.retain_provider_rate_estimate(estimated).unwrap();
        mgr.retain_provider_rate_estimate(estimated).unwrap();

        let reconciled = uuid::Uuid::new_v4();
        expect_provider_reservation(
            mgr.reserve_provider_rate(reconciled, 20, 10, 1_000, 400)
                .unwrap(),
        );
        mgr.mark_provider_rate_invoked(reconciled).unwrap();
        mgr.reconcile_provider_rate(reconciled, 125).unwrap();
        mgr.reconcile_provider_rate(reconciled, 125).unwrap();
        assert!(mgr.reconcile_provider_rate(reconciled, 126).is_err());

        let usage = mgr.provider_rate_usage(20).unwrap();
        assert_eq!((usage.requests, usage.tokens), (2, 325));
        assert_eq!(usage.estimated_receipts, 1);
        assert_eq!(usage.reconciled_receipts, 1);
    }

    #[test]
    fn provider_reservation_limits_deny_without_partial_writes() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        expect_provider_reservation(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), 25, 1, 100, 60)
                .unwrap(),
        );
        assert!(matches!(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), 25, 1, 100, 1)
                .unwrap(),
            ProviderRateReserveOutcome::Denied {
                dimension: ProviderRateLimitDimension::Requests,
                used: 1,
                requested: 1,
                limit: 1,
                ..
            }
        ));
        let usage = mgr.provider_rate_usage(25).unwrap();
        assert_eq!(
            (usage.requests, usage.tokens, usage.reserved_receipts),
            (1, 60, 1)
        );

        assert!(matches!(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), 26, 10, 50, 51)
                .unwrap(),
            ProviderRateReserveOutcome::Denied {
                dimension: ProviderRateLimitDimension::Tokens,
                used: 0,
                requested: 51,
                limit: 50,
                ..
            }
        ));
        assert_eq!(
            mgr.provider_rate_usage(26).unwrap(),
            ProviderRateUsage {
                epoch: 26,
                ..ProviderRateUsage::default()
            }
        );

        // Zero limits are explicitly unlimited and counters saturate rather
        // than wrapping when the full u64 domain is exercised.
        expect_provider_reservation(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), 27, 0, 0, u64::MAX)
                .unwrap(),
        );
        expect_provider_reservation(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), 27, 0, 0, 1)
                .unwrap(),
        );
        let unlimited = mgr.provider_rate_usage(27).unwrap();
        assert_eq!((unlimited.requests, unlimited.tokens), (2, u64::MAX));
    }

    #[test]
    fn reconciliation_updates_the_original_epoch_after_clock_advances() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        expect_provider_reservation(mgr.reserve_provider_rate(id, 30, 10, 1_000, 500).unwrap());
        mgr.mark_provider_rate_invoked(id).unwrap();
        assert_eq!(mgr.provider_rate_usage(31).unwrap().tokens, 0);
        let duplicate =
            expect_provider_reservation(mgr.reserve_provider_rate(id, 31, 10, 1_000, 500).unwrap());
        assert_eq!(duplicate.epoch, 30);
        assert_eq!(duplicate.state, ProviderRateReceiptState::InFlight);
        mgr.reconcile_provider_rate(id, 175).unwrap();
        assert_eq!(mgr.provider_rate_usage(31).unwrap().tokens, 0);

        let conn = mgr.conn.lock().unwrap();
        let epoch = u64_blob(30);
        let stored: Vec<u8> = conn
            .query_row(
                "SELECT tokens FROM quota_epochs
                 WHERE scope_kind = 'provider' AND scope_id = 'global'
                   AND epoch = ?1",
                params![epoch.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(parse_u64_blob(stored, "test tokens").unwrap(), 175);
    }

    #[test]
    fn restart_recovery_refunds_reserved_and_retains_in_flight_estimate() {
        let database = QuotaTestDatabase::new("restart");
        let reserved = uuid::Uuid::new_v4();
        let in_flight = uuid::Uuid::new_v4();
        {
            let mgr = SqliteContextManager::new(&database.path).unwrap();
            expect_provider_reservation(
                mgr.reserve_provider_rate(reserved, 40, 10, 1_000, 100)
                    .unwrap(),
            );
            expect_provider_reservation(
                mgr.reserve_provider_rate(in_flight, 40, 10, 1_000, 250)
                    .unwrap(),
            );
            mgr.mark_provider_rate_invoked(in_flight).unwrap();
        }

        let mgr = SqliteContextManager::new(&database.path).unwrap();
        let recovery = mgr.recover_provider_rate_state(40).unwrap();
        assert_eq!(recovery.effective_epoch, 40);
        assert_eq!(recovery.refunded_reserved, 1);
        assert_eq!(recovery.retained_in_flight_estimates, 1);
        let usage = mgr.provider_rate_usage(40).unwrap();
        assert_eq!((usage.requests, usage.tokens), (1, 250));
        assert_eq!(usage.estimated_receipts, 1);
        assert_eq!(usage.reserved_receipts, 0);
        assert_eq!(usage.in_flight_receipts, 0);

        // A restart after the fixed boundary selects fresh capacity while the
        // conservative old estimate remains durable until pruning.
        let next = mgr.recover_provider_rate_state(41).unwrap();
        assert_eq!(next.effective_epoch, 41);
        assert_eq!(mgr.provider_rate_usage(41).unwrap().tokens, 0);
    }

    #[test]
    fn provider_usage_preserves_full_u64_and_saturates_without_wrapping() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let max_charge = uuid::Uuid::new_v4();
        mgr.charge_provider_rate_tokens(max_charge, 50, u64::MAX)
            .unwrap();
        // Retry is idempotent.
        mgr.charge_provider_rate_tokens(max_charge, 50, u64::MAX)
            .unwrap();
        mgr.charge_provider_rate_tokens(uuid::Uuid::new_v4(), 50, 1)
            .unwrap();
        let usage = mgr.provider_rate_usage(50).unwrap();
        assert_eq!(usage.requests, 0);
        assert_eq!(usage.tokens, u64::MAX);
        assert_eq!(usage.reconciled_receipts, 2);
    }

    #[test]
    fn malformed_or_negative_quota_state_fails_closed() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        expect_provider_reservation(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), 60, 10, 1_000, 25)
                .unwrap(),
        );
        {
            let conn = mgr.conn.lock().unwrap();
            conn.pragma_update(None, "ignore_check_constraints", "ON")
                .unwrap();
            conn.execute(
                "UPDATE quota_epochs SET tokens = -1
                 WHERE scope_kind = 'provider' AND scope_id = 'global'",
                [],
            )
            .unwrap();
        }
        assert!(mgr.provider_rate_usage(60).is_err());
        assert!(mgr
            .reserve_provider_rate(uuid::Uuid::new_v4(), 60, 10, 1_000, 1)
            .is_err());
    }

    #[test]
    fn recovery_detects_valid_but_inconsistent_aggregate() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        expect_provider_reservation(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), 62, 10, 1_000, 25)
                .unwrap(),
        );
        {
            let conn = mgr.conn.lock().unwrap();
            let wrong = u64_blob(24);
            conn.execute(
                "UPDATE quota_epochs SET tokens = ?1
                 WHERE scope_kind = 'provider' AND scope_id = 'global'",
                params![wrong.as_slice()],
            )
            .unwrap();
        }
        assert!(mgr.recover_provider_rate_state(62).is_err());
    }

    #[test]
    fn missing_provider_scope_fails_closed() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        expect_provider_reservation(mgr.reserve_provider_rate(id, 65, 10, 1_000, 25).unwrap());
        {
            let conn = mgr.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM quota_receipt_scopes WHERE receipt_id = ?1",
                [id.to_string()],
            )
            .unwrap();
        }
        assert!(mgr.provider_rate_usage(65).is_err());
        assert!(mgr.recover_provider_rate_state(65).is_err());
    }

    #[test]
    fn pruning_never_removes_a_live_old_epoch_receipt() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        expect_provider_reservation(mgr.reserve_provider_rate(id, 70, 10, 1_000, 80).unwrap());
        mgr.mark_provider_rate_invoked(id).unwrap();
        assert_eq!(mgr.provider_rate_usage(71).unwrap().tokens, 0);
        assert_eq!(mgr.prune_provider_rate_epochs(71).unwrap(), 0);

        mgr.retain_provider_rate_estimate(id).unwrap();
        assert_eq!(mgr.prune_provider_rate_epochs(71).unwrap(), 1);
        let conn = mgr.conn.lock().unwrap();
        let old_epoch = u64_blob(70);
        let old_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM quota_epochs WHERE epoch = ?1",
                params![old_epoch.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_rows, 0);
    }

    #[test]
    fn two_sqlite_handles_reserve_atomically_against_one_limit() {
        let database = QuotaTestDatabase::new("concurrent");
        let first =
            Arc::new(SqliteContextManager::new_without_storage_lease(&database.path).unwrap());
        let second =
            Arc::new(SqliteContextManager::new_without_storage_lease(&database.path).unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(20));
        let mut threads = Vec::new();
        for index in 0..20 {
            let manager = if index % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                matches!(
                    manager
                        .reserve_provider_rate(uuid::Uuid::new_v4(), 80, 10, 10_000, 1)
                        .unwrap(),
                    ProviderRateReserveOutcome::Reserved(_)
                )
            }));
        }
        let admitted = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 10);
        assert_eq!(first.provider_rate_usage(80).unwrap().requests, 10);
        crate::accounting_integrity::verify(&first.conn.lock().unwrap()).unwrap();
    }

    #[test]
    fn production_sqlite_durability_pragmas_are_verified() {
        let database = QuotaTestDatabase::new("pragmas");
        let mgr = SqliteContextManager::new(&database.path).unwrap();
        let conn = mgr.conn.lock().unwrap();
        let journal: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        let synchronous: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        let foreign_keys: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        let busy_timeout: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(journal.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 2);
        assert_eq!(foreign_keys, 1);
        assert_eq!(busy_timeout, 5_000);
    }

    #[test]
    fn sqlite_full_aborts_the_transaction_and_preserves_committed_data() {
        let database = QuotaTestDatabase::new("sqlite-full");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            let mut connection = manager.conn.lock().unwrap();
            connection
                .execute(
                    "CREATE TABLE disk_full_regression (
                        id INTEGER PRIMARY KEY,
                        payload BLOB NOT NULL
                    )",
                    [],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO disk_full_regression (id, payload) VALUES (1, X'01')",
                    [],
                )
                .unwrap();
            connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
                .unwrap();
            let page_count: i64 = connection
                .pragma_query_value(None, "page_count", |row| row.get(0))
                .unwrap();
            connection
                .pragma_update(None, "max_page_count", page_count)
                .unwrap();

            let transaction = connection.transaction().unwrap();
            let error = transaction
                .execute(
                    "INSERT INTO disk_full_regression (id, payload)
                     VALUES (2, zeroblob(1048576))",
                    [],
                )
                .unwrap_err();
            match error {
                rusqlite::Error::SqliteFailure(sqlite, _) => {
                    assert_eq!(sqlite.code, rusqlite::ErrorCode::DiskFull);
                }
                other => panic!("expected SQLITE_FULL, got {other}"),
            }
            drop(transaction);
            connection
                .pragma_update(None, "max_page_count", 2_147_483_646_i64)
                .unwrap();
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM disk_full_regression", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
            crate::schema::verify(&connection).unwrap();
        }

        let reopened = SqliteContextManager::new(&database.path).unwrap();
        let connection = reopened.conn.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT hex(payload) FROM disk_full_regression WHERE id = 1",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "01"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM disk_full_regression WHERE id = 2",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        crate::schema::verify(&connection).unwrap();
    }

    #[test]
    fn fresh_database_is_owned_versioned_complete_and_idempotent() {
        let database = QuotaTestDatabase::new("schema-version");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            let connection = manager.conn.lock().unwrap();
            let application_id: i64 = connection
                .pragma_query_value(None, "application_id", |row| row.get(0))
                .unwrap();
            let schema_version: i64 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap();
            let migration_count: i64 = connection
                .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let cluster_table_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table' AND name LIKE 'cluster_%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(application_id, crate::schema::APPLICATION_ID);
            assert_eq!(schema_version, crate::schema::CURRENT_SCHEMA_VERSION);
            assert_eq!(
                migration_count,
                crate::schema::CURRENT_SCHEMA_VERSION,
                "fresh stores record every released schema transition"
            );
            assert_eq!(cluster_table_count, 9);
        }

        let reopened = SqliteContextManager::new(&database.path).unwrap();
        let connection = reopened.conn.lock().unwrap();
        let migration_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            migration_count,
            crate::schema::CURRENT_SCHEMA_VERSION,
            "idempotent reopen must not duplicate migration entries"
        );
        crate::schema::verify(&connection).unwrap();
    }

    #[test]
    fn schema_v1_version_marker_recovers_through_current_schema() {
        let database = QuotaTestDatabase::new("schema-v1-to-current");
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            let connection = manager.conn.lock().unwrap();
            connection
                .execute("DELETE FROM schema_migrations WHERE version = 2", [])
                .unwrap();
            connection
                .execute("DROP TABLE deletion_receipts", [])
                .unwrap();
            connection
                .execute("UPDATE storage_meta SET schema_version = 1", [])
                .unwrap();
            connection.pragma_update(None, "user_version", 1).unwrap();
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        let connection = manager.conn.lock().unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let migration_name: String = connection
            .query_row(
                "SELECT name FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let receipt_table: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'deletion_receipts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let integrity_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'table'
                   AND name IN ('accounting_integrity', 'accounting_events')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, crate::schema::CURRENT_SCHEMA_VERSION);
        assert_eq!(migration_name, "add-privacy-safe-deletion-receipts");
        assert_eq!(receipt_table, 1);
        assert_eq!(integrity_tables, 2);
        crate::accounting_integrity::verify(&connection).unwrap();
        crate::schema::verify(&connection).unwrap();
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReleasedStorageFixtureManifest {
        format_version: u32,
        release: Vec<ReleasedStorageFixture>,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReleasedStorageFixture {
        tag: String,
        source_commit: String,
        sql_file: String,
        sql_sha256: String,
        legacy_schema_version: i64,
        agent_id: String,
        context_marker: String,
        memory_marker: String,
        conversation_marker: String,
        usage_tokens: i64,
        usage_cost_micros: i64,
        tenant_id: Option<String>,
        kv_marker: Option<String>,
    }

    fn released_storage_fixture_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/storage")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[tokio::test]
    async fn every_published_release_fixture_upgrades_atomically_and_retains_state() {
        let root = released_storage_fixture_root();
        let manifest_text = std::fs::read_to_string(root.join("releases.toml")).unwrap();
        let manifest: ReleasedStorageFixtureManifest = toml::from_str(&manifest_text).unwrap();
        assert_eq!(manifest.format_version, 1);
        assert_eq!(
            manifest
                .release
                .iter()
                .map(|fixture| fixture.tag.as_str())
                .collect::<Vec<_>>(),
            ["v0.1.0", "v0.2.0", "v0.3.0"],
            "the fixture manifest must enumerate every immutable published tag"
        );
        assert_eq!(
            manifest.release.last().map(|fixture| fixture.tag.as_str()),
            Some(concat!("v", env!("CARGO_PKG_VERSION"))),
            "a release version bump must add its immutable storage fixture before tagging"
        );

        for fixture in manifest.release {
            assert_eq!(fixture.source_commit.len(), 40, "{}", fixture.tag);
            assert!(
                fixture
                    .source_commit
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
                "{} has an invalid source commit",
                fixture.tag
            );
            let fixture_file = std::path::Path::new(&fixture.sql_file);
            assert_eq!(
                fixture_file.components().count(),
                1,
                "{} fixture path must be one local filename",
                fixture.tag
            );
            assert_eq!(
                fixture_file.extension().and_then(std::ffi::OsStr::to_str),
                Some("sql"),
                "{} fixture must be reviewable SQL",
                fixture.tag
            );
            let sql = std::fs::read(root.join(fixture_file)).unwrap();
            assert_eq!(
                sha256_hex(&sql),
                fixture.sql_sha256,
                "{} fixture changed without updating its reviewed digest",
                fixture.tag
            );

            let database = QuotaTestDatabase::new(&format!("release-{}", fixture.tag));
            {
                let connection = Connection::open(&database.path).unwrap();
                connection
                    .execute_batch(std::str::from_utf8(&sql).unwrap())
                    .unwrap();
                assert_eq!(
                    crate::schema::preflight(&connection).unwrap(),
                    fixture.legacy_schema_version,
                    "{} fixture does not reproduce its released version",
                    fixture.tag
                );
            }

            {
                let manager = SqliteContextManager::new(&database.path)
                    .unwrap_or_else(|error| panic!("{} upgrade failed: {error}", fixture.tag));
                let agent_id = uuid::Uuid::parse_str(&fixture.agent_id).unwrap();
                let context = manager.get_context(agent_id).await.unwrap();
                assert_eq!(
                    context
                        .conversation_history
                        .first()
                        .map(|message| message.content.as_str()),
                    Some(fixture.context_marker.as_str()),
                    "{} context was not retained",
                    fixture.tag
                );

                let connection = manager.conn.lock().unwrap();
                crate::schema::verify(&connection).unwrap();
                let migration_count: i64 = connection
                    .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(
                    migration_count,
                    crate::schema::CURRENT_SCHEMA_VERSION,
                    "{} did not record every schema migration",
                    fixture.tag
                );
                let memory: String = connection
                    .query_row(
                        "SELECT content FROM facts WHERE agent_id = ?1",
                        [&fixture.agent_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(memory, fixture.memory_marker, "{}", fixture.tag);
                let conversation: String = connection
                    .query_row("SELECT content FROM conversations_fts LIMIT 1", [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(
                    conversation, fixture.conversation_marker,
                    "{} FTS state was not retained",
                    fixture.tag
                );
                let (tokens, cost_micros): (i64, i64) = connection
                    .query_row(
                        "SELECT tokens_used, cost_micros FROM usage_log WHERE agent_id = ?1",
                        [&fixture.agent_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                assert_eq!(tokens, fixture.usage_tokens, "{}", fixture.tag);
                assert_eq!(
                    cost_micros, fixture.usage_cost_micros,
                    "{} legacy cost was not backfilled exactly",
                    fixture.tag
                );
                if let Some(tenant_id) = &fixture.tenant_id {
                    let (agent_tenant, kv): (String, String) = connection
                        .query_row(
                            "SELECT agents.tenant_id, agent_kv.value
                             FROM agents
                             JOIN agent_kv ON agent_kv.agent_id = agents.id
                             WHERE agents.id = ?1 AND agent_kv.key = 'release-proof'",
                            [&fixture.agent_id],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .unwrap();
                    assert_eq!(&agent_tenant, tenant_id, "{}", fixture.tag);
                    assert_eq!(
                        Some(kv.as_str()),
                        fixture.kv_marker.as_deref(),
                        "{} tenant-scoped KV state was not retained",
                        fixture.tag
                    );
                }
            }

            let reopened = SqliteContextManager::new(&database.path).unwrap();
            let connection = reopened.conn.lock().unwrap();
            crate::schema::verify(&connection).unwrap();
            let migration_count: i64 = connection
                .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(
                migration_count,
                crate::schema::CURRENT_SCHEMA_VERSION,
                "{} idempotent reopen duplicated migration history",
                fixture.tag
            );
        }
    }

    #[test]
    fn newer_database_is_rejected_before_schema_mutation() {
        let database = QuotaTestDatabase::new("future-schema");
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute("CREATE TABLE future_only(value TEXT NOT NULL)", [])
                .unwrap();
            connection
                .execute("INSERT INTO future_only VALUES ('preserve-me')", [])
                .unwrap();
            connection
                .pragma_update(None, "application_id", crate::schema::APPLICATION_ID)
                .unwrap();
            connection
                .pragma_update(
                    None,
                    "user_version",
                    crate::schema::CURRENT_SCHEMA_VERSION + 1,
                )
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("a newer schema must fail closed");
        assert_eq!(
            error,
            ContextError::DatabaseTooNew {
                found: crate::schema::CURRENT_SCHEMA_VERSION + 1,
                supported: crate::schema::CURRENT_SCHEMA_VERSION,
            }
        );

        let connection = Connection::open(&database.path).unwrap();
        let value: String = connection
            .query_row("SELECT value FROM future_only", [], |row| row.get(0))
            .unwrap();
        let contexts_exist = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'contexts'",
                [],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some();
        assert_eq!(value, "preserve-me");
        assert!(!contexts_exist);
    }

    #[test]
    fn unrelated_owned_database_is_rejected() {
        let database = QuotaTestDatabase::new("foreign-application");
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute("CREATE TABLE foreign_data(value TEXT NOT NULL)", [])
                .unwrap();
            connection
                .pragma_update(None, "application_id", 0x1234_i64)
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("an unrelated application database must be rejected");
        assert!(error.to_string().contains("is not an AI Agent OS store"));
        let connection = Connection::open(&database.path).unwrap();
        let contexts_exist = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'contexts'",
                [],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some();
        assert!(!contexts_exist);
    }

    #[test]
    fn unowned_unrelated_database_is_not_adopted_as_legacy() {
        let database = QuotaTestDatabase::new("unowned-foreign-application");
        {
            let connection = Connection::open(&database.path).unwrap();
            connection
                .execute("CREATE TABLE customer_orders(value TEXT NOT NULL)", [])
                .unwrap();
        }

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("an unrelated unowned database must not be adopted");
        assert!(error
            .to_string()
            .contains("has no recognized AI Agent OS legacy tables"));
        let connection = Connection::open(&database.path).unwrap();
        let contexts_exist = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'contexts'",
                [],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some();
        assert!(!contexts_exist);
    }

    #[test]
    fn nonempty_legacy_database_is_fenced_for_exactly_its_upgrade_epoch() {
        let database = QuotaTestDatabase::new("migration");
        {
            let conn = Connection::open(&database.path).unwrap();
            conn.execute_batch(
                "CREATE TABLE usage_log (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    tokens_used INTEGER NOT NULL,
                    model TEXT,
                    estimated_cost_usd REAL
                );
                INSERT INTO usage_log
                    (id, agent_id, timestamp, tokens_used, model, estimated_cost_usd)
                VALUES
                    ('legacy', '00000000-0000-0000-0000-000000000001',
                     '2026-01-01T00:00:00Z', 1, 'legacy', 0.0);",
            )
            .unwrap();
        }
        let mgr = SqliteContextManager::new(&database.path).unwrap();
        let fence = {
            let conn = mgr.conn.lock().unwrap();
            let value: Vec<u8> = conn
                .query_row("SELECT epoch FROM quota_migration_fence", [], |row| {
                    row.get(0)
                })
                .unwrap();
            parse_u64_blob(value, "migration fence").unwrap()
        };
        assert!(matches!(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), fence, 10, 100, 1)
                .unwrap(),
            ProviderRateReserveOutcome::Denied {
                dimension: ProviderRateLimitDimension::MigrationFence,
                ..
            }
        ));
        assert!(matches!(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), fence + 1, 10, 100, 1)
                .unwrap(),
            ProviderRateReserveOutcome::Reserved(_)
        ));
    }

    #[test]
    fn interrupted_legacy_quota_migration_is_fenced_on_retry() {
        let database = QuotaTestDatabase::new("interrupted-migration");
        {
            let conn = Connection::open(&database.path).unwrap();
            conn.execute_batch(
                "CREATE TABLE usage_log (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    tokens_used INTEGER NOT NULL,
                    model TEXT,
                    estimated_cost_usd REAL
                );
                INSERT INTO usage_log
                    (id, agent_id, timestamp, tokens_used, model, estimated_cost_usd)
                VALUES
                    ('legacy', '00000000-0000-0000-0000-000000000001',
                     '2026-01-01T00:00:00Z', 1, 'legacy', 0.0);
                CREATE TABLE quota_epoch_floor (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    epoch BLOB NOT NULL
                        CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8)
                );
                CREATE TABLE quota_epochs (
                    scope_kind TEXT NOT NULL,
                    scope_id TEXT NOT NULL,
                    epoch BLOB NOT NULL,
                    requests BLOB NOT NULL,
                    tokens BLOB NOT NULL,
                    PRIMARY KEY (scope_kind, scope_id, epoch)
                ) WITHOUT ROWID;",
            )
            .unwrap();
        }

        // This shape models a crash after the quota tables committed but
        // before the legacy fence/floor transaction. Startup must not mistake
        // table existence for a completed migration and reopen quota.
        let mgr = SqliteContextManager::new(&database.path).unwrap();
        let fence = {
            let conn = mgr.conn.lock().unwrap();
            let value: Vec<u8> = conn
                .query_row("SELECT epoch FROM quota_migration_fence", [], |row| {
                    row.get(0)
                })
                .unwrap();
            parse_u64_blob(value, "interrupted migration fence").unwrap()
        };
        assert!(matches!(
            mgr.reserve_provider_rate(uuid::Uuid::new_v4(), fence, 10, 100, 1)
                .unwrap(),
            ProviderRateReserveOutcome::Denied {
                dimension: ProviderRateLimitDimension::MigrationFence,
                ..
            }
        ));
    }

    fn create_pr140_quota_schema(conn: &Connection, duplicate_receipt_scopes: bool) {
        conn.execute_batch(
            "CREATE TABLE quota_epoch_floor (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL
                    CHECK (typeof(epoch) = 'blob' AND length(epoch) = 8)
            );
            INSERT INTO quota_epoch_floor(singleton, epoch)
                VALUES (1, x'0000000000000001');
            CREATE TABLE quota_epochs (
                scope_kind TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                epoch BLOB NOT NULL,
                requests BLOB NOT NULL,
                tokens BLOB NOT NULL,
                PRIMARY KEY (scope_kind, scope_id, epoch)
            ) WITHOUT ROWID;
            INSERT INTO quota_epochs
                (scope_kind, scope_id, epoch, requests, tokens)
            VALUES
                ('provider', 'global', x'0000000000000001',
                 x'0000000000000001', x'0000000000000001');
            CREATE TABLE quota_receipts (
                id TEXT PRIMARY KEY,
                receipt_kind TEXT NOT NULL,
                epoch BLOB NOT NULL,
                state TEXT NOT NULL,
                reserved_requests BLOB NOT NULL,
                reserved_tokens BLOB NOT NULL,
                actual_requests BLOB,
                actual_tokens BLOB
            );
            CREATE TABLE quota_receipt_scopes (
                receipt_id TEXT NOT NULL
                    REFERENCES quota_receipts(id) ON DELETE CASCADE,
                scope_kind TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                reserved_requests BLOB NOT NULL,
                reserved_tokens BLOB NOT NULL,
                actual_requests BLOB,
                actual_tokens BLOB,
                PRIMARY KEY (receipt_id, scope_kind, scope_id)
            ) WITHOUT ROWID;
            INSERT INTO quota_receipts
                (id, receipt_kind, epoch, state, reserved_requests,
                 reserved_tokens, actual_requests, actual_tokens)
            VALUES
                ('00000000-0000-0000-0000-000000000001', 'provider_request',
                 x'0000000000000001', 'estimated',
                 x'0000000000000001', x'0000000000000001', NULL, NULL);
            INSERT INTO quota_receipt_scopes
                (receipt_id, scope_kind, scope_id, reserved_requests,
                 reserved_tokens, actual_requests, actual_tokens)
            VALUES
                ('00000000-0000-0000-0000-000000000001',
                 'provider', 'global',
                 x'0000000000000001', x'0000000000000001', NULL, NULL);",
        )
        .unwrap();
        if duplicate_receipt_scopes {
            // PR140 only wrote the provider scope. This extra structurally
            // valid row is a failure-injection fixture: after both rows receive
            // the default order zero, creating the new unique order index
            // fails, simulating an interruption after ALTER TABLE.
            conn.execute(
                "INSERT INTO quota_receipt_scopes
                    (receipt_id, scope_kind, scope_id, reserved_requests,
                     reserved_tokens, actual_requests, actual_tokens)
                 VALUES (?1, 'cgroup', '/injected',
                         ?2, ?2, NULL, NULL)",
                params![
                    "00000000-0000-0000-0000-000000000001",
                    u64_blob(1).as_slice()
                ],
            )
            .unwrap();
        }
    }

    fn logical_sqlite_schema(connection: &Connection) -> Vec<(String, String, String)> {
        let mut statement = connection
            .prepare(
                "SELECT type, name, COALESCE(sql, '')
                 FROM sqlite_schema
                 WHERE name NOT LIKE 'sqlite_%'
                 ORDER BY type, name",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn pr140_quota_schema_upgrade_fences_unknown_cgroup_usage() {
        let database = QuotaTestDatabase::new("pr140-hierarchy-migration");
        {
            let conn = Connection::open(&database.path).unwrap();
            create_pr140_quota_schema(&conn, false);
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        let conn = manager.conn.lock().unwrap();
        let has_scope_order = conn
            .prepare("PRAGMA table_info(quota_receipt_scopes)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .any(|column| column == "scope_order");
        assert!(has_scope_order);
        let fence: Vec<u8> = conn
            .query_row("SELECT epoch FROM quota_migration_fence", [], |row| {
                row.get(0)
            })
            .unwrap();
        let fence = parse_u64_blob(fence, "PR140 migration fence").unwrap();
        drop(conn);
        assert!(matches!(
            manager
                .reserve_provider_rate(uuid::Uuid::new_v4(), fence, 10, 100, 1)
                .unwrap(),
            ProviderRateReserveOutcome::Denied {
                dimension: ProviderRateLimitDimension::MigrationFence,
                ..
            }
        ));
        manager
            .recover_provider_rate_state(fence.saturating_add(1))
            .expect("the migrated PR140 provider receipt must remain readable");
    }

    #[test]
    fn pr140_hierarchy_migration_fences_ahead_of_rolled_back_wall_clock() {
        let database = QuotaTestDatabase::new("pr140-ahead-floor");
        let ahead_floor = u64::MAX - 1;
        {
            let conn = Connection::open(&database.path).unwrap();
            create_pr140_quota_schema(&conn, false);
            conn.execute(
                "UPDATE quota_epoch_floor SET epoch = ?1 WHERE singleton = 1",
                params![u64_blob(ahead_floor).as_slice()],
            )
            .unwrap();
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        let fence = {
            let conn = manager.conn.lock().unwrap();
            let value: Vec<u8> = conn
                .query_row(
                    "SELECT epoch FROM quota_migration_fence WHERE epoch = ?1",
                    params![u64_blob(ahead_floor).as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            parse_u64_blob(value, "ahead-floor migration fence").unwrap()
        };
        assert_eq!(fence, ahead_floor);
        assert!(matches!(
            manager
                .reserve_provider_rate(uuid::Uuid::new_v4(), 1, 10, 100, 1)
                .unwrap(),
            ProviderRateReserveOutcome::Denied {
                epoch,
                dimension: ProviderRateLimitDimension::MigrationFence,
                ..
            } if epoch == ahead_floor
        ));
    }

    #[test]
    fn pr140_hierarchy_migration_rolls_back_every_change_after_late_failure() {
        let database = QuotaTestDatabase::new("pr140-interrupted-hierarchy");
        let schema_before = {
            let conn = Connection::open(&database.path).unwrap();
            create_pr140_quota_schema(&conn, true);
            logical_sqlite_schema(&conn)
        };

        let error = SqliteContextManager::new(&database.path)
            .err()
            .expect("duplicate scope orders must fail the index migration");
        assert!(error.to_string().contains("scope-order index"));

        {
            let conn = Connection::open(&database.path).unwrap();
            assert_eq!(
                logical_sqlite_schema(&conn),
                schema_before,
                "a late migration failure must roll back the complete logical schema"
            );
            let application_id: i64 = conn
                .pragma_query_value(None, "application_id", |row| row.get(0))
                .unwrap();
            let schema_version: i64 = conn
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap();
            assert_eq!(application_id, 0);
            assert_eq!(schema_version, 0);
            let has_scope_order = conn
                .prepare("PRAGMA table_info(quota_receipt_scopes)")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .map(Result::unwrap)
                .any(|column| column == "scope_order");
            assert!(
                !has_scope_order,
                "the late failure must roll back the earlier ALTER TABLE"
            );
            let migration_fence_exists = conn
                .query_row(
                    "SELECT 1 FROM sqlite_schema
                     WHERE type = 'table' AND name = 'quota_migration_fence'",
                    [],
                    |_| Ok(()),
                )
                .optional()
                .unwrap();
            assert!(
                migration_fence_exists.is_none(),
                "the late failure must roll back newly created schema"
            );
            conn.execute(
                "DELETE FROM quota_receipt_scopes WHERE scope_kind = 'cgroup'",
                [],
            )
            .unwrap();
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        let durable_fence = {
            let conn = manager.conn.lock().unwrap();
            let value: Vec<u8> = conn
                .query_row("SELECT epoch FROM quota_migration_fence", [], |row| {
                    row.get(0)
                })
                .unwrap();
            parse_u64_blob(value, "retried PR140 migration fence").unwrap()
        };
        assert!(matches!(
            manager
                .reserve_provider_rate(uuid::Uuid::new_v4(), durable_fence, 10, 100, 1)
                .unwrap(),
            ProviderRateReserveOutcome::Denied {
                dimension: ProviderRateLimitDimension::MigrationFence,
                ..
            }
        ));
    }

    fn cgroup_constraint(scope_id: &str, token_limit: u64) -> CgroupQuotaConstraint {
        CgroupQuotaConstraint {
            scope_id: scope_id.to_string(),
            token_limit,
        }
    }

    fn cgroup_usage(manager: &SqliteContextManager, epoch: u64, scope_id: &str) -> QuotaScopeUsage {
        manager
            .quota_scope_usage(epoch, &QuotaScopeKey::cgroup(scope_id))
            .unwrap()
    }

    #[test]
    fn hierarchical_parent_denial_leaves_every_scope_unchanged() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let first = [
            cgroup_constraint("/", 100),
            cgroup_constraint("/agent/a", 100),
        ];
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(
                    uuid::Uuid::new_v4(),
                    100,
                    10,
                    1_000,
                    80,
                    &first,
                )
                .unwrap(),
        );

        let second = [
            cgroup_constraint("/", 100),
            cgroup_constraint("/agent/b", 100),
        ];
        let outcome = manager
            .reserve_provider_rate_with_cgroups(uuid::Uuid::new_v4(), 100, 10, 1_000, 30, &second)
            .unwrap();
        assert!(matches!(
            outcome,
            ProviderRateReserveOutcome::Denied {
                scope: QuotaScopeKey {
                    kind: QuotaScopeKind::Cgroup,
                    ref id
                },
                dimension: ProviderRateLimitDimension::Tokens,
                used: 80,
                requested: 30,
                limit: 100,
                ..
            } if id == "/"
        ));
        assert_eq!(
            (
                manager.provider_rate_usage(100).unwrap().requests,
                manager.provider_rate_usage(100).unwrap().tokens,
            ),
            (1, 80)
        );
        assert_eq!(
            (
                cgroup_usage(&manager, 100, "/").requests,
                cgroup_usage(&manager, 100, "/").tokens
            ),
            (0, 80)
        );
        assert_eq!(
            (
                cgroup_usage(&manager, 100, "/agent/a").requests,
                cgroup_usage(&manager, 100, "/agent/a").tokens,
            ),
            (0, 80)
        );
        assert_eq!(
            (
                cgroup_usage(&manager, 100, "/agent/b").requests,
                cgroup_usage(&manager, 100, "/agent/b").tokens,
            ),
            (0, 0)
        );
    }

    #[test]
    fn hierarchical_scope_order_and_stable_paths_survive_restart() {
        let database = QuotaTestDatabase::new("stable-cgroup-scopes");
        let paths = [
            "/",
            "/profile/read~0only",
            "/tenant/a~1b/%/雪",
            "/tenant/a~1b/%/雪/agent/stable",
        ];
        let receipt = uuid::Uuid::new_v4();
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            let constraints: Vec<_> = paths
                .iter()
                .map(|path| cgroup_constraint(path, 1_000))
                .collect();
            let reservation = expect_provider_reservation(
                manager
                    .reserve_provider_rate_with_cgroups(receipt, 110, 10, 10_000, 42, &constraints)
                    .unwrap(),
            );
            assert_eq!(
                reservation.cgroup_scopes,
                paths
                    .iter()
                    .map(|path| path.to_string())
                    .collect::<Vec<_>>()
            );
            manager.mark_provider_rate_invoked(receipt).unwrap();
            manager.retain_provider_rate_estimate(receipt).unwrap();
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        manager.recover_provider_rate_state(110).unwrap();
        for path in paths {
            let usage = cgroup_usage(&manager, 110, path);
            assert_eq!((usage.requests, usage.tokens), (0, 42));
            assert_eq!(usage.estimated_receipts, 1);
        }
        let conn = manager.conn.lock().unwrap();
        let stored: Vec<(i64, String)> = {
            let mut statement = conn
                .prepare(
                    "SELECT scope_order, scope_id FROM quota_receipt_scopes
                     WHERE receipt_id = ?1 ORDER BY scope_order",
                )
                .unwrap();
            statement
                .query_map([receipt.to_string()], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(stored[0], (0, "global".to_string()));
        assert_eq!(
            stored[1..],
            paths
                .iter()
                .enumerate()
                .map(|(index, path)| ((index + 1) as i64, path.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn hierarchical_restart_refunds_reserved_and_retains_all_in_flight_scopes() {
        let database = QuotaTestDatabase::new("cgroup-recovery");
        let scopes = [
            cgroup_constraint("/", 1_000),
            cgroup_constraint("/tenant/a", 1_000),
        ];
        let reserved = uuid::Uuid::new_v4();
        let invoked = uuid::Uuid::new_v4();
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            expect_provider_reservation(
                manager
                    .reserve_provider_rate_with_cgroups(reserved, 120, 10, 10_000, 30, &scopes)
                    .unwrap(),
            );
            expect_provider_reservation(
                manager
                    .reserve_provider_rate_with_cgroups(invoked, 120, 10, 10_000, 70, &scopes)
                    .unwrap(),
            );
            manager.mark_provider_rate_invoked(invoked).unwrap();
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        let recovery = manager.recover_provider_rate_state(120).unwrap();
        assert_eq!(recovery.refunded_reserved, 1);
        assert_eq!(recovery.retained_in_flight_estimates, 1);
        for scope in ["/", "/tenant/a"] {
            let usage = cgroup_usage(&manager, 120, scope);
            assert_eq!((usage.requests, usage.tokens), (0, 70));
            assert_eq!(usage.estimated_receipts, 1);
        }
        let provider = manager.provider_rate_usage(120).unwrap();
        assert_eq!((provider.requests, provider.tokens), (1, 70));
    }

    #[test]
    fn hierarchical_reconciliation_updates_all_original_epoch_scopes() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let receipt = uuid::Uuid::new_v4();
        let scopes = [
            cgroup_constraint("/", 1_000),
            cgroup_constraint("/profile/standard", 1_000),
        ];
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(receipt, 130, 10, 10_000, 500, &scopes)
                .unwrap(),
        );
        manager.mark_provider_rate_invoked(receipt).unwrap();
        assert_eq!(cgroup_usage(&manager, 131, "/").tokens, 0);
        manager.reconcile_provider_rate(receipt, 175).unwrap();
        assert_eq!(manager.provider_rate_usage(131).unwrap().tokens, 0);
        assert_eq!(cgroup_usage(&manager, 131, "/").tokens, 0);

        let conn = manager.conn.lock().unwrap();
        let old_epoch = u64_blob(130);
        for (kind, id) in [
            ("provider", "global"),
            ("cgroup", "/"),
            ("cgroup", "/profile/standard"),
        ] {
            let tokens: Vec<u8> = conn
                .query_row(
                    "SELECT tokens FROM quota_epochs
                     WHERE scope_kind = ?1 AND scope_id = ?2 AND epoch = ?3",
                    params![kind, id, old_epoch.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(parse_u64_blob(tokens, "old scope tokens").unwrap(), 175);
        }
    }

    #[test]
    fn hierarchical_zero_limits_and_full_u64_never_wrap() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let scopes = [cgroup_constraint("/", 0)];
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(
                    uuid::Uuid::new_v4(),
                    140,
                    0,
                    0,
                    u64::MAX,
                    &scopes,
                )
                .unwrap(),
        );
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(uuid::Uuid::new_v4(), 140, 0, 0, 1, &scopes)
                .unwrap(),
        );
        let provider = manager.provider_rate_usage(140).unwrap();
        let root = cgroup_usage(&manager, 140, "/");
        assert_eq!((provider.requests, provider.tokens), (2, u64::MAX));
        assert_eq!((root.requests, root.tokens), (0, u64::MAX));
    }

    #[test]
    fn saturated_aggregate_decrements_recompute_exact_usage() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let scopes = [cgroup_constraint("/", 0)];

        let refundable = uuid::Uuid::new_v4();
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(refundable, 145, 0, 0, u64::MAX, &scopes)
                .unwrap(),
        );
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(uuid::Uuid::new_v4(), 145, 0, 0, 1, &scopes)
                .unwrap(),
        );
        manager
            .refund_provider_rate_before_invocation(refundable)
            .unwrap();
        let provider = manager.provider_rate_usage(145).unwrap();
        assert_eq!((provider.requests, provider.tokens), (1, 1));
        assert_eq!(cgroup_usage(&manager, 145, "/").tokens, 1);

        let reconciled = uuid::Uuid::new_v4();
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(reconciled, 146, 0, 0, u64::MAX, &scopes)
                .unwrap(),
        );
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(uuid::Uuid::new_v4(), 146, 0, 0, 1, &scopes)
                .unwrap(),
        );
        manager.mark_provider_rate_invoked(reconciled).unwrap();
        manager.reconcile_provider_rate(reconciled, 2).unwrap();
        let provider = manager.provider_rate_usage(146).unwrap();
        assert_eq!((provider.requests, provider.tokens), (2, 3));
        assert_eq!(cgroup_usage(&manager, 146, "/").tokens, 3);
    }

    #[test]
    fn provider_only_and_hierarchical_receipts_coexist_without_cgroup_crosstalk() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let scopes = [cgroup_constraint("/", 1_000)];
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(
                    uuid::Uuid::new_v4(),
                    150,
                    10,
                    10_000,
                    100,
                    &scopes,
                )
                .unwrap(),
        );
        expect_provider_reservation(
            manager
                .reserve_provider_rate(uuid::Uuid::new_v4(), 150, 10, 10_000, 50)
                .unwrap(),
        );
        manager
            .charge_provider_rate_tokens(uuid::Uuid::new_v4(), 150, 25)
            .unwrap();

        let provider = manager.provider_rate_usage(150).unwrap();
        let root = cgroup_usage(&manager, 150, "/");
        assert_eq!((provider.requests, provider.tokens), (2, 175));
        assert_eq!((root.requests, root.tokens), (0, 100));
    }

    #[test]
    fn hierarchical_constraints_reject_invalid_or_duplicate_stable_scopes() {
        let manager = SqliteContextManager::in_memory().unwrap();
        for invalid in ["", "relative", "bad\0scope"] {
            assert!(manager
                .reserve_provider_rate_with_cgroups(
                    uuid::Uuid::new_v4(),
                    160,
                    10,
                    1_000,
                    1,
                    &[cgroup_constraint(invalid, 10)],
                )
                .is_err());
        }
        let oversized = format!("/{}", "x".repeat(1024));
        assert!(manager
            .reserve_provider_rate_with_cgroups(
                uuid::Uuid::new_v4(),
                160,
                10,
                1_000,
                1,
                &[cgroup_constraint(&oversized, 10)],
            )
            .is_err());
        assert!(manager
            .reserve_provider_rate_with_cgroups(
                uuid::Uuid::new_v4(),
                160,
                10,
                1_000,
                1,
                &[cgroup_constraint("/", 10), cgroup_constraint("/", 20),],
            )
            .is_err());
    }

    #[test]
    fn concurrent_siblings_cannot_race_past_shared_parent_limit() {
        let database = QuotaTestDatabase::new("cgroup-siblings");
        let first =
            Arc::new(SqliteContextManager::new_without_storage_lease(&database.path).unwrap());
        let second =
            Arc::new(SqliteContextManager::new_without_storage_lease(&database.path).unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(20));
        let mut threads = Vec::new();
        for index in 0..20 {
            let manager = if index % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let constraints = [
                    cgroup_constraint("/", 10),
                    cgroup_constraint(&format!("/sibling/{index}"), 10),
                ];
                barrier.wait();
                matches!(
                    manager
                        .reserve_provider_rate_with_cgroups(
                            uuid::Uuid::new_v4(),
                            170,
                            100,
                            1_000,
                            1,
                            &constraints,
                        )
                        .unwrap(),
                    ProviderRateReserveOutcome::Reserved(_)
                )
            }));
        }
        let admitted = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 10);
        let parent = cgroup_usage(&first, 170, "/");
        assert_eq!((parent.requests, parent.tokens), (0, 10));
        assert_eq!(first.provider_rate_usage(170).unwrap().requests, 10);
    }

    #[test]
    fn hierarchical_refund_updates_every_associated_scope() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let receipt = uuid::Uuid::new_v4();
        let scopes = [
            cgroup_constraint("/", 100),
            cgroup_constraint("/tenant/refund", 100),
        ];
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(receipt, 180, 10, 1_000, 75, &scopes)
                .unwrap(),
        );
        manager
            .refund_provider_rate_before_invocation(receipt)
            .unwrap();
        let provider = manager.provider_rate_usage(180).unwrap();
        assert_eq!((provider.requests, provider.tokens), (0, 0));
        for scope in ["/", "/tenant/refund"] {
            let usage = cgroup_usage(&manager, 180, scope);
            assert_eq!((usage.requests, usage.tokens), (0, 0));
            assert_eq!(usage.reserved_receipts, 0);
        }
    }

    #[test]
    fn quota_hot_path_does_not_rescan_prior_receipts() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let scopes = [
            cgroup_constraint("/", 0),
            cgroup_constraint("/tenant/hot-path", 0),
        ];
        for _ in 0..128 {
            expect_provider_reservation(
                manager
                    .reserve_provider_rate_with_cgroups(uuid::Uuid::new_v4(), 185, 0, 0, 1, &scopes)
                    .unwrap(),
            );
        }

        // This counter is deterministic: unlike a latency assertion it records
        // entry into the receipt-ledger scan used only by integrity/recovery
        // paths. Historical receipt count must not affect routine work.
        SqliteContextManager::reset_quota_full_receipt_scan_count();
        let reconciled = uuid::Uuid::new_v4();
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(reconciled, 185, 0, 0, 7, &scopes)
                .unwrap(),
        );
        manager.mark_provider_rate_invoked(reconciled).unwrap();
        manager.reconcile_provider_rate(reconciled, 3).unwrap();

        let refunded = uuid::Uuid::new_v4();
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(refunded, 185, 0, 0, 11, &scopes)
                .unwrap(),
        );
        manager
            .refund_provider_rate_before_invocation(refunded)
            .unwrap();
        assert_eq!(
            SqliteContextManager::quota_full_receipt_scan_count(),
            0,
            "reserve/reconcile/refund must use trusted aggregates, not receipt scans"
        );

        // The independent audit path still scans and proves the incrementally
        // maintained rows agree with every durable receipt.
        let provider = manager.provider_rate_usage(185).unwrap();
        assert_eq!((provider.requests, provider.tokens), (129, 131));
        for scope in ["/", "/tenant/hot-path"] {
            let usage = cgroup_usage(&manager, 185, scope);
            assert_eq!((usage.requests, usage.tokens), (0, 131));
        }
        assert!(
            SqliteContextManager::quota_full_receipt_scan_count() > 0,
            "integrity inspection must retain full receipt-ledger validation"
        );
    }

    #[test]
    fn corrupted_cgroup_aggregate_fails_closed_before_any_new_reservation() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let scopes = [cgroup_constraint("/", 100)];
        expect_provider_reservation(
            manager
                .reserve_provider_rate_with_cgroups(
                    uuid::Uuid::new_v4(),
                    190,
                    10,
                    1_000,
                    25,
                    &scopes,
                )
                .unwrap(),
        );
        {
            let conn = manager.conn.lock().unwrap();
            conn.pragma_update(None, "ignore_check_constraints", "ON")
                .unwrap();
            conn.execute(
                "UPDATE quota_epochs SET tokens = -1
                 WHERE scope_kind = 'cgroup' AND scope_id = '/'",
                [],
            )
            .unwrap();
        }
        assert!(manager
            .quota_scope_usage(190, &QuotaScopeKey::cgroup("/"))
            .is_err());
        assert!(manager
            .reserve_provider_rate_with_cgroups(uuid::Uuid::new_v4(), 190, 10, 1_000, 1, &scopes,)
            .is_err());
    }

    fn sha256(value: &str) -> String {
        ring::digest::digest(&ring::digest::SHA256, value.as_bytes())
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn context_spill_quota_restart_integrity_and_retention_fail_closed() {
        let database = QuotaTestDatabase::new("context-pressure");
        let agent = uuid::Uuid::new_v4();
        let legacy_agent = uuid::Uuid::new_v4();
        let first_value = "a".repeat(80);
        let first_key = "context_spill:conversation:first";
        {
            let manager = SqliteContextManager::new(&database.path).unwrap();
            manager
                .set_context_storage_limits(ContextStorageLimits {
                    per_agent_bytes: 120,
                    per_tenant_bytes: 200,
                    global_bytes: 240,
                    spill_retention_seconds: 60,
                })
                .unwrap();
            manager
                .store_context_spill(agent, first_key, &first_value, &sha256(&first_value))
                .unwrap();
            let error = manager
                .store_context_spill(
                    agent,
                    "context_spill:conversation:second",
                    &"b".repeat(80),
                    &sha256(&"b".repeat(80)),
                )
                .unwrap_err();
            assert!(error.to_string().contains("agent would use 160 bytes"));
            manager
                .conn
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO agent_kv (agent_id, key, value, updated_at)
                     VALUES (?1, 'context_spill:legacy:1', 'legacy-value', ?2)",
                    params![legacy_agent.to_string(), Utc::now().to_rfc3339()],
                )
                .unwrap();
        }

        let manager = SqliteContextManager::new(&database.path).unwrap();
        manager
            .set_context_storage_limits(ContextStorageLimits {
                per_agent_bytes: 120,
                per_tenant_bytes: 200,
                global_bytes: 240,
                spill_retention_seconds: 60,
            })
            .unwrap();
        assert_eq!(
            manager.kv_get(agent, first_key).unwrap().as_deref(),
            Some(first_value.as_str())
        );
        assert_eq!(
            manager
                .kv_get(legacy_agent, "context_spill:legacy:1")
                .unwrap()
                .as_deref(),
            Some("legacy-value"),
            "legacy spills must gain digest/retention metadata during restart migration"
        );
        manager
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE agent_kv SET value = 'corrupt'
                 WHERE agent_id = ?1 AND key = ?2",
                params![agent.to_string(), first_key],
            )
            .unwrap();
        assert!(manager
            .kv_get(agent, first_key)
            .unwrap_err()
            .to_string()
            .contains("digest mismatch"));
        manager
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE context_spills SET expires_at = ?1
                 WHERE agent_id = ?2 AND key = ?3",
                params![
                    (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339(),
                    agent.to_string(),
                    first_key
                ],
            )
            .unwrap();
        assert_eq!(manager.kv_get(agent, first_key).unwrap(), None);
        assert_eq!(
            manager.context_pressure_stats(agent).unwrap().stored_spills,
            0
        );
    }

    #[tokio::test]
    async fn durable_context_quota_covers_conversations_embeddings_and_checkpoints() {
        let manager = SqliteContextManager::in_memory().unwrap();
        manager
            .set_context_storage_limits(ContextStorageLimits {
                per_agent_bytes: 128,
                per_tenant_bytes: 0,
                global_bytes: 0,
                spill_retention_seconds: 60,
            })
            .unwrap();

        let conversation_agent = uuid::Uuid::new_v4();
        let conversation = vec![crate::connector::StandardMessage::user("x".repeat(256))];
        assert!(manager
            .save_conversation("oversized", conversation_agent, &conversation)
            .unwrap_err()
            .to_string()
            .contains("context storage pressure"));

        let fact_agent = uuid::Uuid::new_v4();
        let fact = Fact {
            id: uuid::Uuid::new_v4(),
            content: "memory".repeat(40),
            category: FactCategory::Fact,
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
            embedding: None,
        };
        assert!(manager
            .store_fact(fact_agent, fact)
            .await
            .unwrap_err()
            .to_string()
            .contains("context storage pressure"));

        let checkpoint_agent = uuid::Uuid::new_v4();
        assert!(manager
            .save_generation_checkpoint(
                DEFAULT_TENANT,
                "provider",
                "model",
                &sample_generation_checkpoint(checkpoint_agent),
                std::time::Duration::from_secs(60),
            )
            .unwrap_err()
            .to_string()
            .contains("context storage pressure"));
    }

    #[test]
    fn durable_storage_admission_is_tenant_and_global_isolated() {
        let manager = SqliteContextManager::in_memory().unwrap();
        manager
            .set_context_storage_limits(ContextStorageLimits {
                per_agent_bytes: 200,
                per_tenant_bytes: 150,
                global_bytes: 220,
                spill_retention_seconds: 60,
            })
            .unwrap();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        let c = uuid::Uuid::new_v4();
        {
            let conn = manager.conn.lock().unwrap();
            for (agent, tenant) in [(a, "tenant-a"), (b, "tenant-a"), (c, "tenant-b")] {
                conn.execute(
                    "INSERT INTO agents
                     (id, session_id, name, task, llm_provider, permission_profile,
                      priority, status, created_at, last_activity_at, tenant_id)
                     VALUES (?1, ?2, 'agent', 'task', 'provider', 'standard',
                             3, '\"Running\"', ?3, ?3, ?4)",
                    params![
                        agent.to_string(),
                        uuid::Uuid::new_v4().to_string(),
                        Utc::now().to_rfc3339(),
                        tenant
                    ],
                )
                .unwrap();
            }
        }
        let value = "x".repeat(80);
        manager
            .store_context_spill(a, "context_spill:a:1", &value, &sha256(&value))
            .unwrap();
        let tenant_error = manager
            .store_context_spill(b, "context_spill:b:1", &value, &sha256(&value))
            .unwrap_err();
        assert!(tenant_error
            .to_string()
            .contains("tenant would use 160 bytes"));

        manager
            .store_context_spill(c, "context_spill:c:1", &value, &sha256(&value))
            .unwrap();
        let global_error = manager
            .store_context_spill(
                c,
                "context_spill:c:2",
                &"y".repeat(70),
                &sha256(&"y".repeat(70)),
            )
            .unwrap_err();
        assert!(global_error
            .to_string()
            .contains("global would use 230 bytes"));
        assert_eq!(
            manager
                .context_pressure_stats(a)
                .unwrap()
                .tenant_stored_bytes,
            80
        );
        assert_eq!(
            manager
                .context_pressure_stats(c)
                .unwrap()
                .global_stored_bytes,
            160
        );
    }

    #[test]
    fn independent_sqlite_handles_cannot_race_past_context_storage_limit() {
        let database = QuotaTestDatabase::new("context-storage-race");
        let first =
            Arc::new(SqliteContextManager::new_without_storage_lease(&database.path).unwrap());
        let second =
            Arc::new(SqliteContextManager::new_without_storage_lease(&database.path).unwrap());
        let limits = ContextStorageLimits {
            per_agent_bytes: 0,
            per_tenant_bytes: 100,
            global_bytes: 100,
            spill_retention_seconds: 60,
        };
        first.set_context_storage_limits(limits).unwrap();
        second.set_context_storage_limits(limits).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let attempts = [
            (first, uuid::Uuid::new_v4()),
            (second, uuid::Uuid::new_v4()),
        ]
        .into_iter()
        .map(|(manager, agent)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let value = "r".repeat(80);
                barrier.wait();
                manager.store_context_spill(
                    agent,
                    &format!("context_spill:race:{agent}"),
                    &value,
                    &sha256(&value),
                )
            })
        })
        .collect::<Vec<_>>();
        let results = attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert!(results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .any(|error| error.to_string().contains("context storage pressure")));
    }

    #[tokio::test]
    async fn durable_context_ids_cannot_be_reassigned_across_agents() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        let foreign = uuid::Uuid::new_v4();
        manager
            .save_conversation(
                "owned-conversation",
                owner,
                &[crate::connector::StandardMessage::user("owner")],
            )
            .unwrap();
        assert!(manager
            .save_conversation(
                "owned-conversation",
                foreign,
                &[crate::connector::StandardMessage::user("foreign")],
            )
            .unwrap_err()
            .to_string()
            .contains("owned by another agent"));

        let fact_id = uuid::Uuid::new_v4();
        let fact = Fact {
            id: fact_id,
            content: "owner fact".into(),
            category: FactCategory::Fact,
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
            embedding: None,
        };
        manager.store_fact(owner, fact.clone()).await.unwrap();
        assert!(manager
            .store_fact(foreign, fact)
            .await
            .unwrap_err()
            .to_string()
            .contains("owned by another agent"));
    }
}
