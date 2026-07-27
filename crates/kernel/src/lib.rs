//! AI Agent OS Kernel
//!
//! Core types, error hierarchy, and module declarations for the Agent Kernel.

mod accounting_integrity;
pub mod agent;
pub mod agent_hub;
pub mod agent_package;
pub mod agent_struct;
pub mod agent_syscalls;
pub mod agentpkg;
pub mod agentps;
pub mod auth;
pub mod budget;
pub mod cfs;
pub mod cgroups;
pub mod cluster_control;
pub mod config;
pub mod connector;
pub mod context;
pub mod context_paging;
pub mod custom_tools;
pub mod data_inventory;
pub mod database;
pub mod delegation;
pub mod docker_sandbox;
pub mod editing;
pub mod event_loop;
pub mod execution;
pub mod function_calling;
pub mod github;
pub mod indexer;
pub mod init_system;
pub mod ipc;
pub mod learning;
pub mod linux_compat;
pub mod llm_sched;
pub mod mac;
pub mod marketplace;
pub mod mcp;
pub mod mcp_server;
pub mod memory_manager;
pub mod metrics;
pub mod models;
pub mod modules;
pub mod mount_table;
pub mod namespaces;
pub mod observability;
pub mod operator_control;
pub mod package;
pub mod permissions;
pub mod planning;
pub mod policy;
pub mod prerequisites;
pub mod procfs;
pub mod production;
pub mod quota_clock;
pub mod rate_limit;
pub mod resources;
pub mod runtime;
pub mod sandbox;
pub mod scheduler;
mod schema;
pub mod shell;
pub mod storage;
pub mod storage_encryption;
pub mod syscall_gate;
pub mod syscall_interface;
pub mod syscall_server;
pub mod sysctl;
pub mod telemetry;
pub mod tool_descriptors;
pub mod tool_registry_share;
pub mod tools;
pub mod vision;
pub mod voice;
pub mod wire_contract;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use wire_fuzz::exercise_fragmented_transport;
#[cfg(feature = "fuzzing")]
mod wire_fuzz;
mod wire_io;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

// ─── Type Aliases ────────────────────────────────────────────────────────────

/// Unique identifier for an agent instance.
pub type AgentId = uuid::Uuid;

/// Unique identifier for a session.
pub type SessionId = uuid::Uuid;

/// Identifier for an LLM provider.
pub type ProviderId = String;

/// Identifier for a permission profile.
pub type PermissionProfileId = String;

/// Identifier for a loadable module.
pub type ModuleId = String;

/// Identifier for a sandbox instance.
pub type SandboxId = uuid::Uuid;

// ─── Agent State ─────────────────────────────────────────────────────────────

/// Agent lifecycle states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentState {
    Initializing,
    Running,
    Paused,
    Stopping,
    Stopped,
    Error(String),
}

// ─── Priority ────────────────────────────────────────────────────────────────

/// Priority level constrained to 1..=5 (1 = highest, 5 = lowest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Priority(u8);

impl Priority {
    /// Create a new Priority. Returns `None` if value is outside 1..=5.
    pub fn new(value: u8) -> Option<Self> {
        if (1..=5).contains(&value) {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the inner priority value.
    pub fn value(&self) -> u8 {
        self.0
    }
}

impl Default for Priority {
    fn default() -> Self {
        Self(3)
    }
}

// ─── Sandbox Config ──────────────────────────────────────────────────────────

/// Sandbox configuration for agent isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub workspace_dir: std::path::PathBuf,
    pub allowed_network_hosts: Option<Vec<String>>,
    pub max_disk_usage_bytes: Option<u64>,
    pub max_memory_bytes: Option<u64>,
    pub isolation_level: IsolationLevel,
    /// Operator-selected OCI image for `Container` isolation. It must be an
    /// immutable digest reference (`name@sha256:<64 hex>`); packages and wire
    /// creation cannot populate this field.
    #[serde(default)]
    pub container_image: Option<String>,
}

/// Level of isolation for the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationLevel {
    /// Explicit operator-trusted host access. This is never selected by wire or
    /// package creation defaults and must not be used for untrusted agents.
    Trusted,
    /// Filesystem-only isolation (chroot-like path restrictions).
    Filesystem,
    /// Process-level isolation (separate process with restricted syscalls).
    Process,
    /// Container-level isolation (Linux namespaces / Windows containers).
    Container,
}

// ─── Agent Config ────────────────────────────────────────────────────────────

/// Configuration for creating a new agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub name: String,
    pub task: String,
    pub llm_provider: ProviderId,
    pub permission_profile: PermissionProfileId,
    pub priority: Priority,
    pub sandbox_config: Option<SandboxConfig>,
}

// ─── Agent Handle ────────────────────────────────────────────────────────────

/// Handle to a running agent, providing its ID, current state, and a command channel.
#[derive(Debug)]
pub struct AgentHandle {
    pub id: AgentId,
    pub state: AgentState,
    pub cmd_tx: mpsc::Sender<AgentCommand>,
}

// ─── Agent Command ───────────────────────────────────────────────────────────

/// Internal commands sent to an agent via its command channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentCommand {
    Pause,
    Resume,
    Stop,
    Execute(String),
}

/// Bounded lifecycle operation labels used by events and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleOperation {
    Pause,
    Resume,
    Stop,
    Kill,
    Wait,
}

/// Bounded lifecycle outcomes. `forced` is the successful terminal outcome of
/// `kill`; the other operations complete cooperatively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleOutcome {
    Requested,
    Completed,
    TimedOut,
    Forced,
    Failed,
}

// ─── Kernel Event ────────────────────────────────────────────────────────────

/// Events broadcast by the kernel to subsystems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelEvent {
    AgentCreated(AgentId),
    AgentStateChanged {
        agent_id: AgentId,
        old: AgentState,
        new: AgentState,
    },
    AgentLifecycle {
        agent_id: AgentId,
        operation: LifecycleOperation,
        outcome: LifecycleOutcome,
    },
    ResourceRequested {
        agent_id: AgentId,
        resource: String,
        operation: String,
    },
    ServiceStateChanged {
        name: String,
        status: crate::init_system::ServiceStatus,
        reason: Option<String>,
    },
    ShutdownInitiated,
}

// ─── Error Hierarchy ─────────────────────────────────────────────────────────

/// Top-level kernel error encompassing all subsystem errors.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("Agent error: {0}")]
    Agent(#[from] AgentError),

    #[error("Scheduler error: {0}")]
    Scheduler(#[from] SchedulerError),

    #[error("Context error: {0}")]
    Context(#[from] ContextError),

    #[error("Resource error: {0}")]
    Resource(#[from] ResourceError),

    #[error("Permission error: {0}")]
    Permission(#[from] PermissionError),

    #[error("Connector error: {0}")]
    Connector(#[from] ConnectorError),

    #[error("Module error: {0}")]
    Module(#[from] ModuleError),

    #[error("IPC error: {0}")]
    Ipc(#[from] IpcError),

    #[error("Sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("Rate-limit error: {0}")]
    RateLimit(#[from] crate::rate_limit::RateLimitError),

    #[error(
        "Credential revocation incomplete after {timeout_ms}ms; the identity remains durably revoked and closed to new requests"
    )]
    CredentialRevocationIncomplete { timeout_ms: u64 },

    #[error("Lifecycle operation timed out: {0}")]
    LifecycleTimeout(String),

    #[error("Lifecycle cleanup incomplete: {0}")]
    LifecycleCleanup(String),

    #[error("Policy error: {0}")]
    Policy(String),
}

/// Errors related to agent lifecycle management.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AgentError {
    #[error("Agent {0} not found")]
    NotFound(AgentId),

    #[error("Agent {0} is unresponsive")]
    Unresponsive(AgentId),

    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidTransition { from: AgentState, to: AgentState },

    #[error("Agent creation timeout")]
    CreationTimeout,
}

/// Errors related to the scheduler subsystem.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    #[error("Scheduler queue is full")]
    QueueFull,

    #[error("Agent {0} is not scheduled")]
    AgentNotScheduled(AgentId),

    #[error("Deadlock detected")]
    DeadlockDetected,

    #[error("Turn admission queue is full (capacity {capacity}); retry with backoff")]
    AdmissionQueueFull { capacity: usize },

    #[error("Turn admission cancelled for scheduler pid {0}")]
    AdmissionCancelled(u64),

    #[error("LLM admission queue is full (capacity {capacity}); retry with backoff")]
    LlmQueueFull { capacity: usize },

    #[error("LLM admission cancelled for scheduler pid {0}")]
    LlmAdmissionCancelled(u64),
}

/// Errors related to context and memory management.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ContextError {
    #[error("Context persistence failed: {0}")]
    PersistenceFailed(String),

    #[error("Context restore failed: {0}")]
    RestoreFailed(String),

    #[error("Context summarization failed: {0}")]
    SummarizationFailed(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error(
        "Database schema version {found} is newer than this binary supports ({supported}); \
         refusing to modify it"
    )]
    DatabaseTooNew { found: i64, supported: i64 },
}

/// Errors related to resource access.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ResourceError {
    #[error("Resource provider not found: {0}")]
    ProviderNotFound(String),

    #[error("Resource operation failed: {0}")]
    OperationFailed(String),

    #[error("Resource operation timed out")]
    Timeout,
}

/// Errors related to the permission system.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PermissionError {
    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Permission profile not found: {0}")]
    ProfileNotFound(String),

    #[error("Permission elevation failed: {0}")]
    ElevationFailed(String),
}

/// Redacted, correlation-friendly context for a provider failure.
///
/// Provider adapters must never place credentials or raw response bodies in
/// this structure. `request_id` is the provider-issued correlation identifier,
/// when one was supplied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderErrorContext {
    pub provider: ProviderId,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Structured provider throttling metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRateLimit {
    pub context: ProviderErrorContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Errors related to the LLM connector.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    #[error("Provider unavailable: {0}")]
    ProviderUnavailable(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Stream error: {0}")]
    StreamError(String),

    /// A provider stream failed after publishing output. Retrying or failing
    /// over would duplicate already-visible content, so this is terminal.
    #[error("Partial provider stream: {0}")]
    PartialStream(String),

    #[error("Provider authentication failed: {0:?}")]
    Authentication(ProviderErrorContext),

    #[error("Provider authorization failed: {0:?}")]
    Authorization(ProviderErrorContext),

    #[error("Provider rate limited request: {0:?}")]
    RateLimited(ProviderRateLimit),

    #[error("Provider service unavailable: {0:?}")]
    ServiceUnavailable(ProviderErrorContext),

    #[error("Provider rejected request: {0:?}")]
    InvalidRequest(ProviderErrorContext),

    #[error("Provider content filter blocked request: {0:?}")]
    ContentFiltered(ProviderErrorContext),

    #[error("Provider request timed out: {0:?}")]
    Timeout(ProviderErrorContext),

    #[error("Provider request cancelled: {0:?}")]
    Cancelled(ProviderErrorContext),
}

impl ConnectorError {
    fn provider_context(
        provider: ProviderId,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> ProviderErrorContext {
        ProviderErrorContext {
            provider,
            message: message.into(),
            request_id,
        }
    }

    pub fn authentication(
        provider: ProviderId,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self::Authentication(Self::provider_context(provider, message, request_id))
    }

    pub fn authorization(
        provider: ProviderId,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self::Authorization(Self::provider_context(provider, message, request_id))
    }

    pub fn rate_limited(
        provider: ProviderId,
        message: impl Into<String>,
        request_id: Option<String>,
        retry_after_ms: Option<u64>,
    ) -> Self {
        Self::RateLimited(ProviderRateLimit {
            context: Self::provider_context(provider, message, request_id),
            retry_after_ms,
        })
    }

    pub fn service_unavailable(
        provider: ProviderId,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self::ServiceUnavailable(Self::provider_context(provider, message, request_id))
    }

    pub fn invalid_request(
        provider: ProviderId,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self::InvalidRequest(Self::provider_context(provider, message, request_id))
    }

    pub fn content_filtered(
        provider: ProviderId,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self::ContentFiltered(Self::provider_context(provider, message, request_id))
    }

    pub fn timeout(
        provider: ProviderId,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self::Timeout(Self::provider_context(provider, message, request_id))
    }

    pub fn cancelled(provider: ProviderId, request_id: Option<String>) -> Self {
        Self::Cancelled(Self::provider_context(
            provider,
            "request cancelled",
            request_id,
        ))
    }

    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Authentication(context)
            | Self::Authorization(context)
            | Self::ServiceUnavailable(context)
            | Self::InvalidRequest(context)
            | Self::ContentFiltered(context)
            | Self::Timeout(context)
            | Self::Cancelled(context) => context.request_id.as_deref(),
            Self::RateLimited(limit) => limit.context.request_id.as_deref(),
            Self::ProviderUnavailable(_)
            | Self::ConnectionFailed(_)
            | Self::ProtocolError(_)
            | Self::StreamError(_)
            | Self::PartialStream(_) => None,
        }
    }
}

/// Errors related to the WASM module system.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ModuleError {
    #[error("Module install failed: {0}")]
    InstallFailed(String),

    #[error("Module load failed: {0}")]
    LoadFailed(String),

    #[error("Module validation failed: {0}")]
    ValidationFailed(String),

    #[error("Module crash detected: {0}")]
    CrashDetected(String),

    #[error("Module not found: {0}")]
    NotFound(String),
}

/// Errors related to inter-agent communication.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum IpcError {
    #[error("Message delivery failed: {0}")]
    DeliveryFailed(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(AgentId),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

/// Errors related to sandbox management.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SandboxError {
    #[error("Sandbox creation failed: {0}")]
    CreationFailed(String),

    #[error("Sandbox destruction failed: {0}")]
    DestructionFailed(String),

    #[error("Sandbox boundary violation: {0}")]
    BoundaryViolation(String),
}

// ─── Built-in Resource Providers ─────────────────────────────────────────────

use crate::resources::{ResourceProvider, ResourceType};

/// Configurable max chars for browse_url (set from config on startup).
static MAX_BROWSE_CHARS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(16000);

/// Set the max browse chars (call from config on startup).
pub fn set_max_browse_chars(chars: usize) {
    MAX_BROWSE_CHARS.store(chars, std::sync::atomic::Ordering::Relaxed);
}

/// Translate a permission profile id into a capability set used by the syscall gate.
///
/// Unknown / custom profiles fail closed with no capabilities. Custom profiles
/// must be explicitly defined before they can grant authority; a typo must
/// never silently become `full-access`.
fn caps_for_profile(profile: &str) -> CapabilitySet {
    let mut caps = CapabilitySet::none();
    match profile {
        "read-only" => {
            // Reads only; no writes/exec/delete. Network read is permitted.
            caps.grant(CapabilitySet::CAP_NET_ACCESS);
        }
        "standard" => {
            caps.grant(CapabilitySet::CAP_FILE_WRITE);
            caps.grant(CapabilitySet::CAP_NET_ACCESS);
            caps.grant(CapabilitySet::CAP_EXEC);
        }
        "elevated" => {
            caps.grant(CapabilitySet::CAP_FILE_WRITE);
            caps.grant(CapabilitySet::CAP_FILE_DELETE);
            caps.grant(CapabilitySet::CAP_NET_ACCESS);
            caps.grant(CapabilitySet::CAP_EXEC);
        }
        "full-access" => return CapabilitySet::all(),
        _ => {}
    }
    caps
}

/// Per-agent durable/provider and concurrent-tool limits derived from the
/// permission profile. Aggregate tenant and profile nodes are separate: this
/// leaf prevents one agent from consuming another agent's allowance.
fn agent_cgroup_limits(profile: &str, budgets: &crate::config::BudgetConfig) -> CgroupLimits {
    match profile {
        // Unlimited resources are an explicit privilege. An absent, misspelled,
        // or custom profile follows the bounded managed default.
        "full-access" => CgroupLimits {
            // Full access removes the per-agent provider-token and concurrent
            // tool ceilings, but the kernel's active-context bound is applied
            // uniformly by every executor and must remain truthful here.
            tokens_per_min: 0,
            max_concurrent_tool_calls: 0,
            max_context_tokens: budgets.max_context_tokens,
            max_agents: 0,
        },
        "elevated" => CgroupLimits {
            tokens_per_min: budgets.agent_tokens_per_min.saturating_mul(4),
            max_concurrent_tool_calls: budgets.max_concurrent_tool_calls,
            max_context_tokens: budgets.max_context_tokens,
            max_agents: 0,
        },
        _ => CgroupLimits {
            tokens_per_min: budgets.agent_tokens_per_min,
            max_concurrent_tool_calls: budgets.max_concurrent_tool_calls,
            max_context_tokens: budgets.max_context_tokens,
            max_agents: 0,
        },
    }
}

/// Encode one user-controlled path component without collisions. This is the
/// JSON Pointer escaping rule and is stable across processes and platforms.
fn quota_scope_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

struct BuiltinFilesystemProvider;

#[async_trait::async_trait]
impl ResourceProvider for BuiltinFilesystemProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Filesystem
    }
    fn supported_operations(&self) -> Vec<String> {
        vec![
            "read".into(),
            "write".into(),
            "create".into(),
            "create_dir".into(),
            "edit".into(),
            "delete".into(),
            "list".into(),
        ]
    }
    async fn execute(
        &self,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ResourceError::OperationFailed("Missing 'path'".into()))?;
        match operation {
            "read" => {
                let content = tokio::fs::read_to_string(path)
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"content": content}))
            }
            "write" | "create" => {
                let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("");
                tokio::fs::write(path, content)
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"written": true}))
            }
            "create_dir" => {
                tokio::fs::create_dir_all(path)
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"created": true}))
            }
            "edit" => {
                // Precise find→replace via the transactional editing engine
                // (atomic apply + rollback on failure). EditTransaction is
                // synchronous std::fs, so run it on the blocking pool to avoid
                // stalling an async runtime worker on large files / slow disks.
                let search = params
                    .get("search")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ResourceError::OperationFailed("Missing 'search'".into()))?
                    .to_string();
                let replace = params
                    .get("replace")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let path = path.to_string();
                let results = tokio::task::spawn_blocking(move || {
                    let mut tx = crate::editing::EditTransaction::new();
                    tx.add(crate::editing::FileEdit {
                        path: std::path::PathBuf::from(path),
                        operation: crate::editing::EditOperation::Replace { search, replace },
                    });
                    tx.apply()
                })
                .await
                .map_err(|e| ResourceError::OperationFailed(e.to_string()))?
                .map_err(ResourceError::OperationFailed)?;
                Ok(serde_json::json!({"edited": true, "detail": results}))
            }
            "delete" => {
                tokio::fs::remove_file(path)
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"deleted": true}))
            }
            "list" => {
                let mut entries = Vec::new();
                let mut dir = tokio::fs::read_dir(path)
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                while let Some(entry) = dir
                    .next_entry()
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?
                {
                    entries.push(entry.file_name().to_string_lossy().to_string());
                }
                Ok(serde_json::json!({"entries": entries}))
            }
            _ => Err(ResourceError::OperationFailed(format!(
                "Unknown op: {}",
                operation
            ))),
        }
    }
}

/// Routes the `Ipc` resource type to the kernel's `IpcManager`, so the
/// `send_agent_message` / `check_inbox` tools deliver real inter-agent messages.
/// Namespace isolation is enforced inside `IpcManager::send`.
struct IpcResourceProvider {
    ipc: Arc<IpcManager>,
    /// Live agent directory, for `discover` and name→UUID recipient resolution.
    agents: Arc<AgentManager>,
    /// Namespace-visibility checker, so `discover` only lists peers the caller
    /// shares a namespace with (matching what `send`/`delegate` can reach).
    gate: Arc<SyscallGate>,
}

#[async_trait::async_trait]
impl ResourceProvider for IpcResourceProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Ipc
    }
    fn supported_operations(&self) -> Vec<String> {
        vec![
            "send".into(),
            "receive".into(),
            "delegate".into(),
            "delegation_status".into(),
            "complete_delegation".into(),
            "discover".into(),
        ]
    }
    async fn execute(
        &self,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError> {
        use crate::ipc::{AgentIpc, NamespaceVisibility};
        let parse_uuid = |key: &str| -> Result<uuid::Uuid, ResourceError> {
            params
                .get(key)
                .and_then(|v| v.as_str())
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .ok_or_else(|| {
                    ResourceError::OperationFailed(format!(
                        "invalid or missing '{key}' (expected UUID)"
                    ))
                })
        };
        // Resolve a recipient given as either a UUID or a live agent NAME.
        // Name lookup is scoped to the caller's namespaces and rejects
        // ambiguity, so it cannot be used as a foreign directory oracle.
        let resolve_recipient =
            |caller: uuid::Uuid, key: &str| -> Result<uuid::Uuid, ResourceError> {
                let s = params.get(key).and_then(|v| v.as_str()).unwrap_or("");
                if let Ok(id) = uuid::Uuid::parse_str(s) {
                    return Ok(id);
                }
                let mut matches = self
                    .agents
                    .list_agents(None)
                    .into_iter()
                    .filter(|agent| agent.name == s && self.gate.allows(caller, agent.id));
                let Some(agent) = matches.next() else {
                    return Err(ResourceError::OperationFailed("agent not found".into()));
                };
                if matches.next().is_some() {
                    return Err(ResourceError::OperationFailed("agent not found".into()));
                }
                Ok(agent.id)
            };
        let hide_absent_recipient = |error: crate::IpcError| match error {
            crate::IpcError::AgentNotFound(_) => {
                ResourceError::OperationFailed("agent not found".into())
            }
            other => ResourceError::OperationFailed(other.to_string()),
        };
        match operation {
            "send" => {
                let from = parse_uuid("from")?;
                let to = resolve_recipient(from, "to")?;
                let payload = params
                    .get("payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                self.ipc
                    .send(from, to, payload)
                    .await
                    .map_err(hide_absent_recipient)?;
                Ok(serde_json::json!({"sent": true}))
            }
            "receive" => {
                let agent = parse_uuid("agent")?;
                match self.ipc.receive(agent).await {
                    Ok(msg) => Ok(serde_json::json!({
                        "from": msg.from.to_string(),
                        "payload": msg.payload,
                    })),
                    // An empty inbox is not an error.
                    Err(crate::IpcError::ChannelClosed) => Ok(serde_json::json!({"empty": true})),
                    Err(e) => Err(ResourceError::OperationFailed(e.to_string())),
                }
            }
            "delegate" => {
                let from = parse_uuid("from")?;
                let to = resolve_recipient(from, "to")?;
                let description = params
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let task_id = self
                    .ipc
                    .delegate(from, to, description)
                    .await
                    .map_err(hide_absent_recipient)?;
                Ok(serde_json::json!({"task_id": task_id.to_string()}))
            }
            "delegation_status" => {
                // `from` is the calling agent (injected at tool resolution).
                // Non-parties see "unknown" — the gate already returns None for
                // them, so there is no existence leak.
                let caller = parse_uuid("from")?;
                let task_id = parse_uuid("task_id")?;
                let status = match self.ipc.get_delegation_status(caller, task_id) {
                    Some(crate::ipc::DelegationStatus::Pending) => "pending",
                    Some(crate::ipc::DelegationStatus::InProgress) => "in_progress",
                    Some(crate::ipc::DelegationStatus::Completed) => "completed",
                    Some(crate::ipc::DelegationStatus::Failed(_)) => "failed",
                    None => "unknown",
                };
                Ok(serde_json::json!({"status": status}))
            }
            "complete_delegation" => {
                let caller = parse_uuid("from")?;
                let task_id = parse_uuid("task_id")?;
                self.ipc
                    .complete_delegation(caller, task_id)
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"completed": true}))
            }
            "discover" => {
                // Only list peers the caller shares a namespace with — matching
                // what send/delegate can actually reach (no cross-group leak).
                let viewer = parse_uuid("viewer")?;
                let agents: Vec<serde_json::Value> = self
                    .agents
                    .list_agents(None)
                    .into_iter()
                    .filter(|a| self.gate.allows(viewer, a.id))
                    .map(|a| {
                        serde_json::json!({
                            "name": a.name,
                            "id": a.id.to_string(),
                            "state": format!("{:?}", a.state),
                        })
                    })
                    .collect();
                Ok(serde_json::json!({"agents": agents}))
            }
            _ => Err(ResourceError::OperationFailed(format!(
                "Unknown IPC op: {operation}"
            ))),
        }
    }
}

struct BuiltinNetworkProvider;

#[async_trait::async_trait]
impl ResourceProvider for BuiltinNetworkProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Network
    }
    fn supported_operations(&self) -> Vec<String> {
        vec!["get".into(), "post".into(), "browse".into()]
    }
    async fn execute(
        &self,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError> {
        let url = params
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ResourceError::OperationFailed("Missing 'url'".into()))?;
        // Redirects are disabled deliberately. The sandbox validates the
        // caller-supplied URL before dispatch; automatically following a 3xx
        // would let an allowlisted host redirect the provider to a private or
        // otherwise unapproved destination. DNS rebinding remains separate
        // host-isolation qualification work.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
        match operation {
            "get" => {
                let resp = client
                    .get(url)
                    .send()
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                let status = resp.status().as_u16();
                let body = resp
                    .text()
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"status": status, "body": body}))
            }
            "post" => {
                let body = params
                    .get("body")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let resp = client
                    .post(url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                let status = resp.status().as_u16();
                let text = resp
                    .text()
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"status": status, "body": text}))
            }
            "browse" => {
                let resp = client
                    .get(url)
                    .header("User-Agent", "Mozilla/5.0 AIAgentOS/1.0")
                    .send()
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                let html = resp
                    .text()
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                let mut in_tag = false;
                let mut text = String::new();
                for c in html.chars() {
                    match c {
                        '<' => in_tag = true,
                        '>' => in_tag = false,
                        _ if !in_tag => text.push(c),
                        _ => {}
                    }
                }
                let clean: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
                let truncated: String = clean
                    .chars()
                    .take(MAX_BROWSE_CHARS.load(std::sync::atomic::Ordering::Relaxed))
                    .collect();
                Ok(serde_json::json!({"content": truncated}))
            }
            _ => Err(ResourceError::OperationFailed(format!(
                "Unknown op: {}",
                operation
            ))),
        }
    }
}

struct BuiltinAppProvider;

/// Cancelling an application tool must terminate the complete process tree,
/// not only the direct shell/launcher child.
struct ProcessTreeGuard {
    pid: u32,
    armed: bool,
}

impl ProcessTreeGuard {
    fn new(pid: u32) -> Self {
        Self { pid, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(unix)]
        {
            // The child is placed in a new process group whose id equals its
            // pid. A negative pid targets every descendant that inherited the
            // group, including background grandchildren.
            if let Ok(pid) = libc::pid_t::try_from(self.pid) {
                // SAFETY: `kill` does not dereference memory; the negative,
                // validated process-group id is scoped to the spawned child.
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            }
        }
        #[cfg(windows)]
        {
            // `taskkill /T` is the platform process-tree primitive. The child
            // also has Tokio's kill-on-drop enabled as a direct-child fallback.
            let pid = self.pid.to_string();
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", pid.as_str(), "/T", "/F"])
                .status();
        }
    }
}

#[async_trait::async_trait]
impl ResourceProvider for BuiltinAppProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Application
    }
    fn supported_operations(&self) -> Vec<String> {
        vec!["launch".into()]
    }
    async fn execute(
        &self,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError> {
        if operation != "launch" {
            return Err(ResourceError::OperationFailed(format!(
                "Unknown application op: {operation}"
            )));
        }
        let cmd = params
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ResourceError::OperationFailed("Missing 'command'".into()))?;
        let args: Vec<&str> = params
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let mut command = tokio::process::Command::new(cmd);
        command.args(&args).kill_on_drop(true);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }
        let child = command
            .spawn()
            .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
        let pid = child.id().ok_or_else(|| {
            ResourceError::OperationFailed("spawned application has no process id".into())
        })?;
        let mut process_tree = ProcessTreeGuard::new(pid);
        let output = child.wait_with_output().await;
        if output.is_ok() {
            process_tree.disarm();
        }
        let output = output.map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
        Ok(serde_json::json!({
            "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
            "stderr": String::from_utf8_lossy(&output.stderr).to_string(),
            "exit_code": output.status.code(),
        }))
    }
}

// ─── Kernel Orchestrator ─────────────────────────────────────────────────────

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::agent::{AgentKernel, AgentManager};
use crate::agent_struct::{CapabilitySet, SchedClass};
use crate::cfs::{CfsScheduler, TurnAdmission};
use crate::cgroups::{CgroupId, CgroupLimits, CgroupManager};
use crate::connector::{AgentConnector, AgentConnectorImpl, LlmProviderAdapter};
use crate::context::{ContextManager, SqliteContextManager, UsageRecord};
use crate::execution::{AgentExecutor, AgentOutput, TurnResult};
use crate::init_system::{InitSystem, ServiceRuntimeInfo, ServiceStatus};
use crate::ipc::IpcManager;
use crate::llm_sched::{LlmScheduler, DEFAULT_LLM_CORES};
use crate::namespaces::{NamespaceId, NamespaceRegistry, NamespaceType};
use crate::observability::{ObservabilityEngine, ObservabilityEngineImpl};
use crate::permissions::{PermissionManager, PermissionSystem};
use crate::procfs::ProcFs;
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::resources::{ResourceBroker, ResourceBrokerImpl};
use crate::sandbox::{SandboxManager, SandboxManagerImpl};
use crate::scheduler::PriorityScheduler;
use crate::syscall_gate::SyscallGate;
use crate::sysctl::Sysctl;
use crate::tools::ToolRegistry;

/// OS-style subsystems unified into the kernel orchestrator.
///
/// Phase 2: these used to live only on the standalone `OsKernel` struct.
/// Folding them into `AgentKernelImpl` makes the kernel a single source of
/// truth — both halves now share IDs through the syscall gate's PID table.
pub struct OsSubsystems {
    pub cfs: tokio::sync::Mutex<CfsScheduler>,
    pub namespaces: NamespaceRegistry,
    pub init: tokio::sync::Mutex<InitSystem>,
    pub procfs: tokio::sync::Mutex<ProcFs>,
    pub sysctl: tokio::sync::Mutex<Sysctl>,
}

impl Default for OsSubsystems {
    fn default() -> Self {
        Self::new()
    }
}

impl OsSubsystems {
    pub fn new() -> Self {
        Self {
            cfs: tokio::sync::Mutex::new(CfsScheduler::new(1000)),
            namespaces: NamespaceRegistry::new(),
            init: tokio::sync::Mutex::new(InitSystem::new()),
            procfs: tokio::sync::Mutex::new(ProcFs::new()),
            sysctl: tokio::sync::Mutex::new(Sysctl::new()),
        }
    }
}

/// The wired kernel orchestrator holding all subsystem instances.
pub struct AgentKernelImpl {
    pub agent_manager: Arc<AgentManager>,
    pub scheduler: Arc<PriorityScheduler>,
    pub context_manager: Arc<SqliteContextManager>,
    /// Automatic verified-backup policy, health, and bounded operator status.
    pub backup_maintenance: Arc<crate::storage::BackupMaintenance>,
    /// Root-kernel ownership lease. Unlike the shared context manager, this is
    /// released as soon as the file-backed kernel itself stops, even if a
    /// cancelled background task briefly retains a subsystem reference.
    _storage_lease: Option<crate::storage::StorageLease>,
    /// Durable cryptographic node identity plus generation-fenced
    /// active/draining/quarantined admission state.
    pub cluster_control: Arc<crate::cluster_control::ClusterControl>,
    pub permission_manager: Arc<PermissionManager>,
    pub sandbox_manager: Arc<SandboxManagerImpl>,
    pub ipc: Arc<IpcManager>,
    pub observability: Arc<ObservabilityEngineImpl>,
    pub connector: Arc<AgentConnectorImpl>,
    pub resource_broker: Arc<ResourceBrokerImpl>,
    pub tool_registry: Arc<ToolRegistry>,
    /// Signed, tenant-scoped package supply chain backed by the same durable
    /// SQLite boundary as agents, auth, quotas, and operator state.
    pub package_registry: Arc<crate::package::PackageRegistry>,
    /// Shared fixed-epoch clock. The cgroup hierarchy uses the same source when
    /// durable hierarchical quota accounting is enabled.
    pub quota_clock: Arc<dyn crate::quota_clock::QuotaClock>,
    pub rate_limiter: Arc<RateLimiter>,
    pub cgroups: Arc<CgroupManager>,
    pub syscall_gate: Arc<SyscallGate>,
    /// Durable, audited operator settings plus the consistency barrier used by
    /// the typed operations snapshot.
    pub operator_control: Arc<crate::operator_control::OperatorControl>,
    /// Hard cumulative USD spend ceiling on the LLM path (the cgroup quota only
    /// bounds per-minute tokens, not lifetime cost). Inert unless config sets a
    /// price + ceiling. Installed on each executor in `send_message`.
    pub budget_enforcer: Arc<crate::budget::BudgetEnforcer>,
    /// Active-context token budget applied to each executor (from
    /// `budgets.max_context_tokens`; 0 = unbounded). Drives context paging.
    context_budget_tokens: u32,
    /// Atomic per-agent/tenant/global admission for active provider prompts.
    context_admission: Arc<crate::context_paging::ActiveContextManager>,
    /// Cumulative tool-call ceiling for one logical turn, including calls made
    /// before a durable pause/resume boundary. `0` means unlimited.
    max_tool_calls_per_turn: u32,
    /// Provider-enforced completion allowance reserved with every prompt.
    max_output_tokens_per_request: u32,
    /// Finite timeout applied to every hosted or local provider attempt.
    provider_request_timeout: std::time::Duration,
    /// CFS-ordered turn admission: bounds concurrent turns to
    /// `budgets.max_concurrent` and, under contention, grants the next slot to
    /// the CFS-preferred (lowest-vruntime / highest-priority) waiting agent.
    turn_admission: Arc<TurnAdmission>,
    /// LLM-request scheduler: a bounded pool of "LLM cores". Where
    /// `turn_admission` gates whole agent turns, this gates the LLM-request step
    /// inside `send_message`, and under contention grants the next freed core to
    /// the highest-priority (lowest-nice) waiter — mirroring CFS ordering.
    llm_scheduler: Arc<LlmScheduler>,
    pub os: Arc<OsSubsystems>,
    /// Stable tenant/profile aggregate nodes in the uniform
    /// root→tenant→profile→agent hierarchy. The key is the canonical durable
    /// scope, not the process-local numeric cgroup id.
    tenant_cgroups: DashMap<String, CgroupId>,
    profile_cgroups: DashMap<String, CgroupId>,
    /// Per-agent leaf nodes, rebuilt with the same canonical scope after a
    /// restart even though numeric cgroup ids change.
    agent_cgroups: DashMap<AgentId, CgroupId>,
    /// Serializes structural get-or-create operations. Cgroup membership has a
    /// separate mutation lock in the syscall gate.
    cgroup_tree_lock: std::sync::Mutex<()>,
    /// Agent+Tool namespaces per agent group, created lazily. Agents created via
    /// `create_agent_in_namespace` with the same group share these (and can
    /// see/message each other); ungrouped agents use the registry defaults.
    group_namespaces: DashMap<String, (NamespaceId, NamespaceId)>,
    /// Publishes a namespace tag and its group-scoped tool binding as one
    /// kernel transaction. Readers may observe the tag before the binding
    /// exists (safe), but competing group registrations cannot overwrite and
    /// then roll back another group's winning tag.
    group_tool_publication_lock: std::sync::Mutex<()>,
    /// Multi-tenant auth/identity. Owned by the kernel (behind a `RwLock` — auth
    /// resolution is read-heavy), persisted + rehydrated through the single
    /// SQLite handle. Resolves an API key / session token to a `(user, tenant,
    /// role)`; the tenant then maps onto the namespace group + cgroup below.
    pub auth: Arc<tokio::sync::RwLock<crate::auth::AuthSystem>>,
    /// Serializes identity and credential mutations without blocking normal
    /// authentication reads. Erasure closes request admission, drains existing
    /// leases, and then commits while this fence prevents a new credential from
    /// appearing between the drain and the durable deletion transaction.
    auth_mutation_lock: tokio::sync::Mutex<()>,
    /// Public request barrier for destructive erasure. Normal wire dispatch
    /// holds a read guard; erasure first closes/drains affected credentials and
    /// then takes the write guard so no admitted request can recreate deleted
    /// state during the storage transaction.
    pub(crate) erasure_barrier: tokio::sync::RwLock<()>,
    /// Per-credential in-flight request admission. Revocation closes and drains
    /// only the affected identity instead of holding the global auth lock across
    /// syscall, tool, or provider I/O.
    credential_leases: Arc<crate::auth::CredentialLeaseManager>,
    /// Budget template used when lazily building tenant and per-agent nodes.
    cgroup_budgets: crate::config::BudgetConfig,
    executors: DashMap<AgentId, Arc<tokio::sync::Mutex<AgentExecutor>>>,
    lifecycle_locks: DashMap<AgentId, Arc<tokio::sync::Mutex<()>>>,
    active_cancellations: DashMap<AgentId, tokio_util::sync::CancellationToken>,
    /// Request-scoped cancellation handles for public streaming turns. The
    /// agent id is part of the key so tenant authorization happens before a
    /// request can signal another turn.
    active_requests: DashMap<(AgentId, String), tokio_util::sync::CancellationToken>,
    pub(crate) lifecycle_counters: crate::metrics::LifecycleCounters,
    /// Stable, bounded-cardinality request outcomes and latency. Correlation
    /// identifiers remain in trace spans and never become metric labels.
    pub(crate) request_telemetry: crate::telemetry::RequestTelemetry,
    /// Serializes public service lifecycle, rolling reload, and supervisor
    /// recovery so two control paths cannot create duplicate live instances.
    service_operation_lock: tokio::sync::Mutex<()>,
    /// Monotonic per-service liveness cadence. Durable service state stores
    /// outcomes; monotonic process time is intentionally rebuilt after boot.
    service_health_checks: DashMap<String, std::time::Instant>,
    /// Explicit operator-configured definition source used by remote reload.
    service_directory: std::sync::RwLock<Option<std::path::PathBuf>>,
    event_tx: broadcast::Sender<KernelEvent>,
}

/// Removes live turn/request registrations even when the owning future is
/// dropped because a client disconnects. This keeps cancellation and
/// observability state from leaking across requests.
struct ActiveTurnRegistration<'a> {
    kernel: &'a AgentKernelImpl,
    agent_id: AgentId,
    request_id: Option<String>,
}

impl Drop for ActiveTurnRegistration<'_> {
    fn drop(&mut self) {
        self.kernel.active_cancellations.remove(&self.agent_id);
        if let Some(request_id) = self.request_id.as_ref() {
            self.kernel
                .active_requests
                .remove(&(self.agent_id, request_id.clone()));
        }
        match self.kernel.agent_manager.get_agent_state(self.agent_id) {
            Some(AgentState::Running) => self.kernel.scheduler.set_queued(self.agent_id),
            Some(AgentState::Paused) => self.kernel.scheduler.set_paused(self.agent_id),
            _ => self.kernel.scheduler.deschedule(self.agent_id),
        }
    }
}

#[cfg(test)]
fn crash_live_erasure_after_step_for_test(step: &str) {
    if std::env::var("AIAGENTOS_TEST_EXIT_LIVE_ERASURE_AFTER_STEP").as_deref() == Ok(step) {
        std::process::exit(88);
    }
}

#[cfg(not(test))]
fn crash_live_erasure_after_step_for_test(_step: &str) {}

impl AgentKernelImpl {
    const WATCHDOG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    #[cfg(not(test))]
    const TOOL_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    #[cfg(test)]
    const TOOL_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
    #[cfg(not(test))]
    const CREDENTIAL_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    #[cfg(test)]
    const CREDENTIAL_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

    /// Create an in-memory kernel with the same enforcing security defaults as
    /// production. Tests that need permissive MAC must use the explicit
    /// `with_context_manager(..., false, ...)` escape hatch.
    pub fn new() -> Result<Self, KernelError> {
        let context_manager =
            Arc::new(SqliteContextManager::in_memory().map_err(KernelError::Context)?);
        let security = crate::config::Config::default();
        Self::with_context_manager(
            context_manager,
            &security.budgets,
            security.mac_enforcing,
            &security.mac_rules,
        )
    }

    /// Create a kernel with persistent SQLite storage at the given path.
    pub fn with_db_path(db_path: &std::path::Path) -> Result<Self, KernelError> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let storage_lease =
            crate::storage::acquire_storage_lease(db_path).map_err(KernelError::Context)?;
        let context_manager = Arc::new(
            SqliteContextManager::new_without_storage_lease(db_path)
                .map_err(KernelError::Context)?,
        );
        let security = crate::config::Config::default();
        let kernel = Self::with_context_manager_clock_and_lease(
            context_manager,
            &security.budgets,
            security.mac_enforcing,
            &security.mac_rules,
            Arc::new(crate::quota_clock::SystemQuotaClock::new()),
            Some(storage_lease),
        )?;
        // Bring back any agents persisted by a previous run on this DB so a
        // restart restores the full registry (and re-arms enforcement).
        kernel.rehydrate_agents_blocking();
        Ok(kernel)
    }

    /// Create a kernel from config (uses config.data_dir for persistence and
    /// config.budgets for cgroup/rate-limit quotas).
    pub fn from_config(config: &crate::config::Config) -> Result<Self, KernelError> {
        Self::validate_storage_boot_config(config)?;
        let db_path = config.data_dir.join("agent_os.db");
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let storage_lease =
            crate::storage::acquire_storage_lease(&db_path).map_err(KernelError::Context)?;
        Self::from_validated_config_with_storage_lease(config, storage_lease)
    }

    fn validate_storage_boot_config(config: &crate::config::Config) -> Result<(), KernelError> {
        config.budgets.validate().map_err(|error| {
            KernelError::Policy(format!("invalid budget configuration: {error}"))
        })?;
        config.backup.validate().map_err(|error| {
            KernelError::Policy(format!("invalid scheduled-backup configuration: {error}"))
        })?;
        config.storage_encryption.validate().map_err(|error| {
            KernelError::Policy(format!("invalid storage-encryption configuration: {error}"))
        })?;
        Ok(())
    }

    pub(crate) fn from_config_with_storage_lease(
        config: &crate::config::Config,
        storage_lease: crate::storage::StorageLease,
    ) -> Result<Self, KernelError> {
        Self::validate_storage_boot_config(config)?;
        Self::from_validated_config_with_storage_lease(config, storage_lease)
    }

    fn from_validated_config_with_storage_lease(
        config: &crate::config::Config,
        storage_lease: crate::storage::StorageLease,
    ) -> Result<Self, KernelError> {
        set_max_browse_chars(config.max_browse_chars);
        let db_path = config.data_dir.join("agent_os.db");
        let context_manager = Arc::new(match config.storage_encryption.key_path.as_deref() {
            Some(key_path) => {
                let key = crate::storage_encryption::load_storage_encryption_key(key_path)
                    .map_err(KernelError::Context)?;
                let mut key_ids = std::collections::BTreeSet::new();
                key_ids.insert(key.key_id().to_owned());
                let mut retired_keys =
                    Vec::with_capacity(config.storage_encryption.retired_key_paths.len());
                for retired_path in &config.storage_encryption.retired_key_paths {
                    let retired =
                        crate::storage_encryption::load_storage_encryption_key(retired_path)
                            .map_err(KernelError::Context)?;
                    if !key_ids.insert(retired.key_id().to_owned()) {
                        return Err(KernelError::Policy(format!(
                            "storage encryption key id {:?} is configured more than once",
                            retired.key_id()
                        )));
                    }
                    retired_keys.push(retired);
                }
                SqliteContextManager::new_without_storage_lease_encrypted(
                    &db_path,
                    key,
                    retired_keys,
                )
                .map_err(KernelError::Context)?
            }
            None => SqliteContextManager::new_without_storage_lease(&db_path)
                .map_err(KernelError::Context)?,
        });
        tracing::info!(
            target: "agentos::storage",
            storage_encryption_enabled = context_manager.storage_encryption_key_id().is_some(),
            storage_encryption_key_id = context_manager
                .storage_encryption_key_id()
                .unwrap_or("none"),
            retired_storage_encryption_keys =
                context_manager.retired_storage_encryption_key_count(),
            "kernel storage encryption configuration applied"
        );
        // Resolve the effective MAC config: a `policy_file`, when set,
        // supersedes the inline `mac_enforcing`/`mac_rules`. A malformed or
        // unreadable policy file fails startup with a clear message.
        let (mac_enforcing, mac_rules) = config.resolve_mac().map_err(KernelError::Policy)?;
        if !mac_enforcing {
            tracing::warn!(
                target: "agentos::security",
                "MAC enforcement is DISABLED by local configuration; tool policy is permissive"
            );
        }
        let kernel = Self::with_context_manager_clock_and_lease(
            context_manager,
            &config.budgets,
            mac_enforcing,
            &mac_rules,
            Arc::new(crate::quota_clock::SystemQuotaClock::new()),
            Some(storage_lease),
        )?;
        kernel.backup_maintenance.configure(config.backup.clone())?;
        if let Some(service_dir) = &config.service_dir {
            *kernel
                .service_directory
                .write()
                .map_err(|_| KernelError::Policy("service directory lock is poisoned".into()))? =
                Some(service_dir.clone());
            let mut init = kernel.os.init.try_lock().map_err(|_| {
                KernelError::Policy("service supervisor was unexpectedly busy during boot".into())
            })?;
            init.set_allowed_secret_refs(config.api_keys.keys().cloned())
                .map_err(KernelError::Policy)?;
            init.load_directory_checked(service_dir)
                .map_err(KernelError::Policy)?;
        }
        // Bring back any agents persisted by a previous run on this DB so a
        // restart restores the full registry (and re-arms enforcement).
        kernel.rehydrate_agents_blocking();
        kernel.restore_service_runtime_from_store()?;
        Ok(kernel)
    }

    /// Build a kernel around a provided context manager + budget/MAC config.
    /// This is the canonical wiring entry point (the CLI/Tauri/`from_config` all
    /// funnel through it); exposed so tests can construct a kernel with a custom
    /// `BudgetConfig` (e.g. a small per-minute token quota). Does *not* rehydrate
    /// or start background tasks — use `from_config`/`boot` for that.
    pub fn with_context_manager(
        context_manager: Arc<SqliteContextManager>,
        budgets: &crate::config::BudgetConfig,
        mac_enforcing: bool,
        mac_rules: &[crate::mac::PolicyRule],
    ) -> Result<Self, KernelError> {
        Self::with_context_manager_and_clock(
            context_manager,
            budgets,
            mac_enforcing,
            mac_rules,
            Arc::new(crate::quota_clock::SystemQuotaClock::new()),
        )
    }

    /// Build a kernel with an explicit fixed-epoch clock.
    ///
    /// Production entry points use [`SystemQuotaClock`](crate::quota_clock::SystemQuotaClock).
    /// This seam exists so boundary and restart behavior can be proven without
    /// real minute-long sleeps.
    pub fn with_context_manager_and_clock(
        context_manager: Arc<SqliteContextManager>,
        budgets: &crate::config::BudgetConfig,
        mac_enforcing: bool,
        mac_rules: &[crate::mac::PolicyRule],
        quota_clock: Arc<dyn crate::quota_clock::QuotaClock>,
    ) -> Result<Self, KernelError> {
        Self::with_context_manager_clock_and_lease(
            context_manager,
            budgets,
            mac_enforcing,
            mac_rules,
            quota_clock,
            None,
        )
    }

    fn with_context_manager_clock_and_lease(
        context_manager: Arc<SqliteContextManager>,
        budgets: &crate::config::BudgetConfig,
        mac_enforcing: bool,
        mac_rules: &[crate::mac::PolicyRule],
        quota_clock: Arc<dyn crate::quota_clock::QuotaClock>,
        storage_lease: Option<crate::storage::StorageLease>,
    ) -> Result<Self, KernelError> {
        budgets.validate().map_err(|error| {
            KernelError::Policy(format!("invalid budget configuration: {error}"))
        })?;
        context_manager.set_context_storage_limits(crate::context::ContextStorageLimits {
            per_agent_bytes: budgets.max_context_storage_bytes,
            per_tenant_bytes: budgets.tenant_max_context_storage_bytes,
            global_bytes: budgets.global_max_context_storage_bytes,
            spill_retention_seconds: budgets.context_spill_retention_seconds,
        })?;
        let rate_limiter = Arc::new(RateLimiter::with_store(
            RateLimitConfig {
                rpm: budgets.rpm,
                tpm: budgets.tpm,
                max_concurrent: budgets.max_concurrent,
            },
            context_manager.clone(),
            quota_clock.clone(),
        )?);
        let (event_tx, _) = broadcast::channel(256);
        let permission_manager = Arc::new(PermissionManager::new());
        let sandbox_manager = Arc::new(SandboxManagerImpl::new());
        let resource_broker = Arc::new(ResourceBrokerImpl::new(
            permission_manager.clone(),
            sandbox_manager.clone(),
        ));

        // Register built-in resource providers
        resource_broker.register_provider(Box::new(BuiltinFilesystemProvider));
        resource_broker.register_provider(Box::new(BuiltinNetworkProvider));
        resource_broker.register_provider(Box::new(BuiltinAppProvider));

        let cgroups = Arc::new(CgroupManager::new());
        let syscall_gate = Arc::new(SyscallGate::with_mac(
            cgroups.clone(),
            mac_enforcing,
            mac_rules.to_vec(),
        ));
        // Wire observability in as the gate's audit sink so MAC `audit`
        // decisions (and denials) are recorded in the agent activity log.
        let observability = Arc::new(ObservabilityEngineImpl::new());
        syscall_gate.set_audit_sink(observability.clone());
        // Cumulative USD spend ceiling (inert unless price + ceiling configured).
        // Rehydrate exact fixed-point charges before any agent can be admitted;
        // resetting a configured lifetime ceiling on restart would fail open.
        let budget_enforcer = Arc::new(
            crate::budget::BudgetEnforcer::try_from_config(budgets).map_err(|error| {
                KernelError::Policy(format!("invalid budget configuration: {error}"))
            })?,
        );
        let budget_snapshot = context_manager
            .load_budget_usage_snapshot()
            .map_err(KernelError::Context)?;
        budget_enforcer.rehydrate(&budget_snapshot);
        let operator_control = Arc::new(crate::operator_control::OperatorControl::new(
            context_manager.clone(),
        )?);
        let package_registry = Arc::new(crate::package::PackageRegistry::from_store(
            context_manager.clone(),
        ));
        let cluster_control = Arc::new(
            crate::cluster_control::ClusterControl::new(context_manager.clone())
                .map_err(KernelError::Context)?,
        );
        let os = Arc::new(OsSubsystems::new());

        let ipc = Arc::new(IpcManager::new());
        // Wire the gate as the IPC namespace visibility checker so that
        // cross-namespace sends fail like sends to a non-existent agent.
        ipc.set_namespace_visibility(syscall_gate.clone());
        let agent_manager = Arc::new(AgentManager::new(256));
        // Route the Ipc resource type to the kernel's IpcManager (messaging +
        // delegation) and give it the agent directory for discovery / name
        // resolution, all through the broker.
        resource_broker.register_provider(Box::new(IpcResourceProvider {
            ipc: ipc.clone(),
            gate: syscall_gate.clone(),
            agents: agent_manager.clone(),
        }));

        // Register the full default toolset on the shared registry: built-ins
        // (registered in `ToolRegistry::new`) plus the advanced (browse_url),
        // git (git_commit/git_diff), and file-editing (edit/create/delete_file)
        // sets. Interior mutability (#10) lets these land on the Arc directly.
        let tool_registry = Arc::new(ToolRegistry::new());
        tool_registry.register_advanced_tools();
        tool_registry.register_git_tools();
        tool_registry.register_ipc_tools();
        crate::editing::register_edit_tools(&tool_registry);

        Ok(Self {
            agent_manager,
            scheduler: Arc::new(PriorityScheduler::new()),
            context_manager,
            backup_maintenance: Arc::new(crate::storage::BackupMaintenance::default()),
            _storage_lease: storage_lease,
            cluster_control,
            permission_manager,
            sandbox_manager,
            ipc,
            observability,
            connector: Arc::new(AgentConnectorImpl::new()),
            resource_broker,
            tool_registry,
            package_registry,
            quota_clock,
            rate_limiter,
            cgroups,
            syscall_gate,
            operator_control,
            budget_enforcer,
            context_budget_tokens: budgets.max_context_tokens.min(u32::MAX as u64) as u32,
            context_admission: Arc::new(crate::context_paging::ActiveContextManager::new(
                crate::context_paging::ActiveContextLimits {
                    per_agent_tokens: budgets.max_context_tokens,
                    per_tenant_tokens: budgets.tenant_max_context_tokens,
                    global_tokens: budgets.global_max_context_tokens,
                },
            )),
            max_tool_calls_per_turn: budgets.max_tool_calls,
            max_output_tokens_per_request: budgets.max_output_tokens_per_request,
            provider_request_timeout: std::time::Duration::from_secs(120),
            turn_admission: Arc::new(if budgets.max_waiting_turns == 0 {
                TurnAdmission::new(budgets.max_concurrent as usize)
            } else {
                let capacity = if budgets.max_concurrent == 0 {
                    usize::MAX
                } else {
                    budgets.max_concurrent as usize
                };
                TurnAdmission::with_queue_limit(capacity, budgets.max_waiting_turns as usize)
            }),
            llm_scheduler: Arc::new(LlmScheduler::new(DEFAULT_LLM_CORES)),
            os,
            tenant_cgroups: DashMap::new(),
            profile_cgroups: DashMap::new(),
            agent_cgroups: DashMap::new(),
            cgroup_tree_lock: std::sync::Mutex::new(()),
            group_namespaces: DashMap::new(),
            group_tool_publication_lock: std::sync::Mutex::new(()),
            auth: Arc::new(tokio::sync::RwLock::new(crate::auth::AuthSystem::new())),
            auth_mutation_lock: tokio::sync::Mutex::new(()),
            erasure_barrier: tokio::sync::RwLock::new(()),
            credential_leases: Arc::new(crate::auth::CredentialLeaseManager::default()),
            cgroup_budgets: budgets.clone(),
            executors: DashMap::new(),
            lifecycle_locks: DashMap::new(),
            active_cancellations: DashMap::new(),
            active_requests: DashMap::new(),
            lifecycle_counters: crate::metrics::LifecycleCounters::default(),
            request_telemetry: crate::telemetry::RequestTelemetry::default(),
            service_operation_lock: tokio::sync::Mutex::new(()),
            service_health_checks: DashMap::new(),
            service_directory: std::sync::RwLock::new(None),
            event_tx,
        })
    }

    /// Register an LLM provider adapter.
    pub fn register_provider(
        &self,
        adapter: Arc<dyn LlmProviderAdapter>,
    ) -> Result<(), KernelError> {
        self.connector
            .register_provider(adapter)
            .map_err(KernelError::Connector)
    }

    /// Create agent with full subsystem coordination.
    pub async fn create_agent_full(&self, config: AgentConfig) -> Result<AgentHandle, KernelError> {
        self.create_agent_grouped(config, None, crate::context::DEFAULT_TENANT)
            .await
    }

    /// Create an agent that belongs to `tenant_id`. The agent is placed into the
    /// tenant's **namespace group** (so it cannot see or message agents/tools of
    /// any other tenant — enforced at the syscall gate) and the tenant's
    /// **cgroup** (so its token use counts against the tenant's budget, not
    /// another tenant's). The tenant is persisted on the agent record and
    /// restored on rehydrate, so tenancy survives a restart.
    ///
    /// `tenant_id` should be a tenant created via the `AuthSystem`; an unknown id
    /// still isolates correctly (it just gets its own fresh namespace + cgroup).
    pub async fn create_agent_for_tenant(
        &self,
        tenant_id: &str,
        config: AgentConfig,
    ) -> Result<AgentHandle, KernelError> {
        // The namespace group of a tenanted agent IS its tenant id, so two
        // tenants land in distinct namespaces and the gate denies cross-tenant
        // tool/IPC access. (DEFAULT_TENANT keeps the shared default namespaces so
        // legacy / un-tenanted agents still collaborate.)
        let group = if tenant_id == crate::context::DEFAULT_TENANT {
            None
        } else {
            Some(tenant_id)
        };
        self.create_agent_grouped(config, group, tenant_id).await
    }

    /// Get or build the stable root→tenant→profile→agent hierarchy used for
    /// both durable provider-token accounting and concurrent tool-call limits.
    fn cgroup_for_agent(
        &self,
        tenant_id: &str,
        profile: &str,
        agent_id: AgentId,
    ) -> Result<CgroupId, KernelError> {
        let _tree = self
            .cgroup_tree_lock
            .lock()
            .map_err(|_| KernelError::Policy("cgroup hierarchy lock is poisoned".into()))?;
        let tenant_scope = format!("/tenant/{}", quota_scope_segment(tenant_id));
        let tenant_cgroup = if let Some(id) = self.tenant_cgroups.get(&tenant_scope) {
            *id
        } else {
            let id = self
                .cgroups
                .create_scoped(
                    format!("tenant:{tenant_id}"),
                    self.cgroups.root(),
                    tenant_scope.clone(),
                    CgroupLimits {
                        tokens_per_min: self.cgroup_budgets.tenant_tokens_per_min,
                        ..CgroupLimits::default()
                    },
                )
                .map_err(|error| {
                    KernelError::Policy(format!("cannot create tenant cgroup: {error}"))
                })?;
            self.tenant_cgroups.insert(tenant_scope.clone(), id);
            id
        };

        let profile_scope = format!("{tenant_scope}/profile/{}", quota_scope_segment(profile));
        let profile_cgroup = if let Some(id) = self.profile_cgroups.get(&profile_scope) {
            *id
        } else {
            let id = self
                .cgroups
                .create_scoped(
                    format!("profile:{profile}"),
                    tenant_cgroup,
                    profile_scope.clone(),
                    CgroupLimits::default(),
                )
                .map_err(|error| {
                    KernelError::Policy(format!("cannot create profile cgroup: {error}"))
                })?;
            self.profile_cgroups.insert(profile_scope.clone(), id);
            id
        };

        let agent_scope = format!("{profile_scope}/agent/{agent_id}");
        if let Some(id) = self.agent_cgroups.get(&agent_id) {
            let group = self.cgroups.get(*id).ok_or_else(|| {
                KernelError::Policy(format!(
                    "agent {agent_id} references missing cgroup {}",
                    *id
                ))
            })?;
            if group.quota_scope != agent_scope {
                return Err(KernelError::Policy(format!(
                    "agent {agent_id} cgroup identity changed from {:?} to {agent_scope:?}",
                    group.quota_scope
                )));
            }
            return Ok(*id);
        }
        let id = self
            .cgroups
            .create_scoped(
                format!("agent:{agent_id}"),
                profile_cgroup,
                agent_scope,
                agent_cgroup_limits(profile, &self.cgroup_budgets),
            )
            .map_err(|error| {
                KernelError::Policy(format!("cannot create per-agent cgroup: {error}"))
            })?;
        self.agent_cgroups.insert(agent_id, id);
        Ok(id)
    }

    /// Create an agent placed in a named namespace `group`. Agents in the same
    /// group share Agent + Tool namespaces (and can discover/message each
    /// other); agents in different groups are isolated by the syscall gate —
    /// cross-group IPC/delegation is denied like a non-existent agent. The
    /// ungrouped `create_agent_full` uses the shared default namespaces (prior
    /// behavior), so ungrouped agents still collaborate.
    pub async fn create_agent_in_namespace(
        &self,
        config: AgentConfig,
        group: &str,
    ) -> Result<AgentHandle, KernelError> {
        self.create_agent_grouped(config, Some(group), crate::context::DEFAULT_TENANT)
            .await
    }

    /// Register a tool that is visible **only** to agents in `group`'s
    /// namespace. The binding is added to the shared tool registry (so it
    /// resolves and executes like any other tool) *and* tagged in the syscall
    /// gate with the group's Tool namespace, so the gate's namespace-visibility
    /// check (step 0 of `check_tool_call`) denies any caller outside the group
    /// with `NotInNamespace` — including ungrouped agents.
    ///
    /// Grouped agents already join their group's Tool namespace at creation
    /// (`create_agent_grouped`), so a same-group agent passes; agents in another
    /// group or in the default namespace do not. This is what makes the gate's
    /// tool-namespace isolation load-bearing (previously no tool was ever
    /// tagged, so every tool was global).
    pub fn register_group_tool(
        &self,
        group: &str,
        mut binding: crate::tools::ToolBinding,
    ) -> Result<(), crate::tools::ToolRegistrationError> {
        let _publication = self
            .group_tool_publication_lock
            .lock()
            .expect("group tool publication lock poisoned");
        let name = binding.name.clone();
        if self.tool_registry.has_tool(&name) {
            return Err(crate::tools::ToolRegistrationError::DuplicateName(name));
        }
        binding.security.namespace_visibility = crate::tools::NamespaceVisibility::CallerNamespace;
        // Tag the gate before publishing to the LLM-visible registry so there
        // is no concurrent window where the scoped tool appears global.
        let (_agent_ns, tool_ns) = self.namespaces_for_group(Some(group));
        if let Some(ns) = tool_ns {
            self.syscall_gate.register_tool_namespace(name.clone(), ns);
            if let Err(error) = self.tool_registry.register_namespace_scoped(binding) {
                self.syscall_gate.unregister_tool_namespace(&name);
                return Err(error);
            }
        } else {
            return Err(crate::tools::ToolRegistrationError::UnboundNamespace);
        }
        Ok(())
    }

    /// Check whether a registered tool is visible inside `group` without
    /// requiring an agent record to exist yet. Missing and foreign-scoped tools
    /// deliberately collapse to the same `false` result so package validation
    /// cannot use this as a cross-namespace registry oracle.
    pub(crate) fn tool_visible_to_group(&self, group: Option<&str>, tool_name: &str) -> bool {
        let _publication = self
            .group_tool_publication_lock
            .lock()
            .expect("group tool publication lock poisoned");
        // Resolve the caller namespaces before looking up the tool.  This keeps
        // package validation from exposing a side-effect/timing distinction
        // between a missing name and a name scoped to another group.
        let (_agent_namespace, tool_namespace) = self.namespaces_for_group(group);
        let registered = self.tool_registry.has_tool(tool_name);
        let namespace_visible = tool_namespace.is_some_and(|namespace| {
            self.syscall_gate
                .tool_visible_in_namespace(tool_name, namespace)
        });
        // Deliberately use non-short-circuit evaluation: both missing and
        // foreign-scoped names perform registry and gate lookups before the
        // generic unavailable result is produced.
        registered & namespace_visible
    }

    /// Grant one exact, single-use tool approval from a trusted in-process
    /// operator/UI. This API is deliberately absent from the remote syscall,
    /// package, SDK-data, and MCP surfaces.
    pub fn approve_tool_call(
        &self,
        agent_id: AgentId,
        tool_name: &str,
        arguments: &serde_json::Value,
        approval: crate::tools::ApprovalPolicy,
    ) -> Result<(), KernelError> {
        let prepared = self
            .tool_registry
            .prepare_execution(agent_id, tool_name, arguments)
            .map_err(KernelError::Policy)?;
        if prepared.authorization.security.approval_policy == crate::tools::ApprovalPolicy::None {
            return Err(KernelError::Policy(format!(
                "tool '{tool_name}' does not require approval"
            )));
        }
        if !approval.satisfies(prepared.authorization.security.approval_policy) {
            return Err(KernelError::Policy(format!(
                "{approval:?} approval is insufficient for tool '{tool_name}'"
            )));
        }
        if !self.syscall_gate.grant_tool_approval_contract(
            agent_id,
            tool_name,
            prepared.authorization.resource,
            &prepared.approval_contract_digest,
            approval,
        ) {
            return Err(KernelError::Policy(format!(
                "cannot approve tool '{tool_name}' for an unknown agent"
            )));
        }
        Ok(())
    }

    /// Resolve the (Agent, Tool) namespaces for a group, creating them lazily.
    /// `None` → the registry's shared defaults.
    fn namespaces_for_group(
        &self,
        group: Option<&str>,
    ) -> (Option<NamespaceId>, Option<NamespaceId>) {
        match group {
            None => (
                self.os.namespaces.default_ns(NamespaceType::Agent),
                self.os.namespaces.default_ns(NamespaceType::Tool),
            ),
            Some(g) => {
                // Atomic get-or-create so two agents created concurrently for a
                // new group land in the SAME namespaces (no over-isolation race).
                let e = self
                    .group_namespaces
                    .entry(g.to_string())
                    .or_insert_with(|| {
                        (
                            self.os.namespaces.create(NamespaceType::Agent, None),
                            self.os.namespaces.create(NamespaceType::Tool, None),
                        )
                    });
                (Some(e.0), Some(e.1))
            }
        }
    }

    async fn create_agent_grouped(
        &self,
        mut config: AgentConfig,
        group: Option<&str>,
        tenant_id: &str,
    ) -> Result<AgentHandle, KernelError> {
        let _operator_mutation = self.operator_control.mutation_guard().await;
        let max_agents = self.operator_control.max_agents();
        if max_agents > 0
            && u64::try_from(self.agent_manager.list_agents(None).len()).unwrap_or(u64::MAX)
                >= max_agents
        {
            return Err(KernelError::Policy(format!(
                "agent admission quota exceeded: kernel.max_agents is {max_agents}"
            )));
        }
        // Absence means the secure managed default, never host-unconfined. Only
        // in-process operator code can explicitly request IsolationLevel::Trusted;
        // the wire and package formats do not expose that bypass.
        let managed_sandbox = config.sandbox_config.is_none();
        if managed_sandbox {
            config.sandbox_config = Some(SandboxManagerImpl::default_config());
        }
        // 1. Create agent via agent manager
        let handle = self.agent_manager.create_agent(config.clone()).await?;
        let agent_id = handle.id;

        // 2. Assign permission profile
        PermissionSystem::assign_profile(
            &*self.permission_manager,
            agent_id,
            &config.permission_profile,
        );

        // 3. Create context
        if let Err(error) = ContextManager::create_context(&*self.context_manager, agent_id).await {
            self.rollback_created_agent(agent_id).await;
            return Err(KernelError::Context(error));
        }

        // 4. Create the mandatory sandbox. Managed workspaces are owned and
        // removed by lifecycle cleanup; explicit operator workspaces are not.
        let sandbox_config = config
            .sandbox_config
            .as_ref()
            .expect("secure default installed above");
        let sandbox_result = if managed_sandbox {
            self.sandbox_manager
                .create_managed_sandbox(agent_id, sandbox_config)
        } else {
            self.sandbox_manager
                .create_sandbox(agent_id, sandbox_config)
        };
        if let Err(error) = sandbox_result {
            self.rollback_created_agent(agent_id).await;
            return Err(KernelError::Sandbox(error));
        }

        // 5. Admit the agent to the scheduler (non-blocking). Creation is
        //    admission to the *system*, not the CPU — an agent that was just
        //    created is not executing, so this must not block on the
        //    concurrent-execution gate. The running slot is taken/released
        //    around each actual turn in `send_message`; concurrent execution is
        //    bounded by the rate limiter. (Previously this called the blocking
        //    `schedule()`, so creating the 11th live agent stalled ~10s then
        //    failed with `QueueFull` — see #38.)
        self.scheduler.admit(&handle);

        // 6–8. Place the agent in IPC / syscall gate / namespaces / CFS / procfs,
        //       in its tenant's cgroup + namespace group.
        if let Err(error) = self
            .place_agent_in_subsystems(agent_id, &config, group, tenant_id)
            .await
        {
            self.rollback_created_agent(agent_id).await;
            return Err(error);
        }

        // 9. Persist the agent's durable identity (incl. tenant) so it survives a
        //    restart, then broadcast the creation event. Persistence commits
        //    immediately, so even an abrupt stop recovers this agent + its tenant.
        if let Err(error) = self.persist_agent_registry(agent_id, &config, tenant_id) {
            self.rollback_created_agent(agent_id).await;
            return Err(error);
        }
        let _ = self.event_tx.send(KernelEvent::AgentCreated(agent_id));

        Ok(handle)
    }

    /// Place an already-existing agent (id + config) into the OS-level
    /// subsystems: syscall gate (capabilities + profile cgroup), MAC label, the
    /// group's Agent/Tool namespaces, the CFS run queue, and procfs. Shared by
    /// the live create path and boot-time rehydration so a restored agent is
    /// enforced exactly like a freshly-created one.
    async fn place_agent_in_subsystems(
        &self,
        agent_id: AgentId,
        config: &AgentConfig,
        group: Option<&str>,
        tenant_id: &str,
    ) -> Result<(), KernelError> {
        // Build and validate the complete hierarchy before publishing any gate
        // record or ancillary subsystem state.
        let cgroup = self.cgroup_for_agent(tenant_id, &config.permission_profile, agent_id)?;
        let caps = caps_for_profile(&config.permission_profile);
        let pid = self
            .syscall_gate
            .try_register_managed_agent(agent_id, caps, cgroup)
            .map_err(|error| {
                KernelError::Policy(format!(
                    "cannot register agent {agent_id} with syscall gate: {error}"
                ))
            })?;

        self.budget_enforcer
            .register_agent_tenant(agent_id, tenant_id);

        // Register IPC mailbox.
        self.ipc.register_agent(agent_id);

        // MAC: label the agent by its permission profile so an enforcing policy
        // can discriminate by subject (e.g. "profile:read-only").
        self.syscall_gate
            .label_mac_agent(pid, format!("profile:{}", config.permission_profile))
            .await;

        // Join the Agent + Tool namespaces for this agent's group.
        let (agent_ns, tool_ns) = self.namespaces_for_group(group);
        let mut agent_ns_ids = Vec::new();
        if let Some(ns) = agent_ns {
            self.os.namespaces.join(ns, pid);
            agent_ns_ids.push(ns);
        }
        if let Some(ns) = tool_ns {
            self.os.namespaces.join(ns, pid);
            agent_ns_ids.push(ns);
        }
        // Mirror namespace memberships into the gate so namespace-scoped tool
        // resolution and inter-agent IPC visibility deny foreign-namespace access.
        self.syscall_gate
            .set_agent_namespaces(agent_id, agent_ns_ids);
        {
            let mut sched = self.os.cfs.lock().await;
            sched.enqueue(pid, 0, SchedClass::Normal);
        }
        {
            let mut procfs = self.os.procfs.lock().await;
            procfs.set_agent_info(pid, "name".into(), config.name.clone());
            procfs.set_agent_info(pid, "uuid".into(), agent_id.to_string());
            procfs.set_agent_info(pid, "state".into(), "running".into());
        }
        Ok(())
    }

    /// Write the agent's durable identity + config to the `agents` table via
    /// the single SQLite handle. Creation cannot succeed until this commit
    /// succeeds; otherwise the caller would receive a live identity that
    /// disappears after restart.
    fn persist_agent_registry(
        &self,
        agent_id: AgentId,
        config: &AgentConfig,
        tenant_id: &str,
    ) -> Result<(), KernelError> {
        let state = self
            .agent_manager
            .get_agent_state(agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        let status = serde_json::to_string(&state).map_err(|error| {
            KernelError::Policy(format!(
                "cannot serialize durable state for agent {agent_id}: {error}"
            ))
        })?;
        let now = chrono::Utc::now();
        let sandbox_config_json = config
            .sandbox_config
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| {
                KernelError::Policy(format!(
                    "cannot serialize durable sandbox config for agent {agent_id}: {error}"
                ))
            })?;
        let record = crate::context::PersistedAgent {
            id: agent_id,
            session_id: self
                .agent_manager
                .list_agents(None)
                .into_iter()
                .find(|a| a.id == agent_id)
                .and_then(|a| a.session_id)
                .ok_or(AgentError::NotFound(agent_id))?,
            tenant_id: tenant_id.to_string(),
            name: config.name.clone(),
            task: config.task.clone(),
            llm_provider: config.llm_provider.clone(),
            permission_profile: config.permission_profile.clone(),
            priority: config.priority.value(),
            status,
            sandbox_config_json,
            created_at: now,
            last_activity_at: now,
        };
        self.context_manager.save_agent(&record)?;
        Ok(())
    }

    /// Rehydrate the agent registry from the persistent DB on boot.
    ///
    /// Reads every row from the `agents` table, reinserts each agent into the
    /// in-memory [`AgentManager`] (preserving id/session/config/timestamps), and
    /// re-places it into the syscall gate / cgroups / namespaces / CFS / procfs
    /// so a restored agent is enforced exactly like a freshly-created one. Idempotent
    /// and best-effort per agent: a malformed row is skipped, not fatal. Returns
    /// the ids that were brought back. A fresh / empty DB rehydrates nothing.
    pub async fn rehydrate_agents(&self) -> Result<Vec<AgentId>, KernelError> {
        // Rehydrate tenancy first so an agent's tenant is known to the AuthSystem
        // by the time the agent is re-placed into its tenant's namespace/cgroup.
        self.rehydrate_tenancy().await;
        let persisted = self
            .context_manager
            .load_all_agents()
            .map_err(KernelError::Context)?;
        let active_managed_workspaces = persisted
            .iter()
            .filter(|record| {
                matches!(
                    serde_json::from_str::<AgentState>(&record.status),
                    Ok(AgentState::Running | AgentState::Paused)
                )
            })
            .filter_map(|record| record.sandbox_config_json.as_deref())
            .filter_map(|serialized| serde_json::from_str::<SandboxConfig>(serialized).ok())
            .filter(SandboxManagerImpl::is_managed_config)
            .map(|config| config.workspace_dir)
            .collect::<std::collections::HashSet<_>>();
        self.sandbox_manager
            .reconcile_managed_workspaces(&active_managed_workspaces)
            .map_err(KernelError::Sandbox)?;
        let mut restored = Vec::new();
        for p in persisted {
            // An explicit reconciliation pass may run after boot. Treat an
            // identity already present in the live registry as successfully
            // reconciled instead of trying to create a second sandbox and
            // incorrectly reporting a restore failure.
            if self.agent_manager.get_agent_state(p.id).is_some() {
                restored.push(p.id);
                continue;
            }
            let priority = Priority::new(p.priority).unwrap_or_default();
            let sandbox_config = p
                .sandbox_config_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<SandboxConfig>(s).ok())
                .unwrap_or_else(SandboxManagerImpl::default_config);
            let config = AgentConfig {
                name: p.name.clone(),
                task: p.task.clone(),
                llm_provider: p.llm_provider.clone(),
                permission_profile: p.permission_profile.clone(),
                priority,
                sandbox_config: Some(sandbox_config.clone()),
            };
            let persisted_state = match serde_json::from_str::<AgentState>(&p.status) {
                Ok(state) => state,
                Err(error) => {
                    // A corrupt lifecycle row must never become runnable. Keep
                    // it durable for operator repair while omitting it from all
                    // live kernel registries.
                    tracing::warn!(
                        "Skipping persisted agent {} because lifecycle state is invalid: {}",
                        p.id,
                        error
                    );
                    continue;
                }
            };
            // A process restart is the recovery boundary for incomplete
            // lifecycle transitions. Creation never committed, so preserve the
            // identity as terminal error history. A requested stop wins across
            // a crash and completes as Stopped. Neither state is re-admitted.
            let state = match persisted_state.clone() {
                AgentState::Initializing => {
                    AgentState::Error("initialization interrupted by process restart".into())
                }
                AgentState::Stopping => AgentState::Stopped,
                state => state,
            };
            if state != persisted_state {
                self.context_manager
                    .update_agent_status(p.id, &state)
                    .map_err(KernelError::Context)?;
            }
            let terminal = matches!(state, AgentState::Stopped | AgentState::Error(_));
            if terminal {
                // Terminal registry rows are durable history, not live kernel
                // processes. Restore the identity/status only: no sandbox,
                // mailbox, scheduler entry, namespace, cgroup, or procfs row.
                self.agent_manager.restore_agent(
                    p.id,
                    p.session_id,
                    config,
                    state,
                    p.created_at,
                    p.last_activity_at,
                );
                restored.push(p.id);
                continue;
            }
            let sandbox_result = if SandboxManagerImpl::is_managed_config(&sandbox_config) {
                self.sandbox_manager
                    .create_managed_sandbox(p.id, &sandbox_config)
            } else {
                self.sandbox_manager.create_sandbox(p.id, &sandbox_config)
            };
            if let Err(error) = sandbox_result {
                tracing::warn!("Skipping agent {}: sandbox restore failed: {error}", p.id);
                continue;
            }
            // Rebuild the in-memory agent only after its mandatory isolation has
            // been restored, so a sandbox failure cannot leave a live unconfined
            // registry entry.
            self.agent_manager.restore_agent(
                p.id,
                p.session_id,
                config.clone(),
                state.clone(),
                p.created_at,
                p.last_activity_at,
            );
            // Re-admit to the priority scheduler and re-place into OS subsystems,
            // re-arming the agent's tenant isolation: a tenanted agent rejoins its
            // tenant's namespace group + cgroup exactly as at creation, so
            // cross-tenant isolation survives the restart.
            self.scheduler.admit_id(p.id);
            let group = if p.tenant_id == crate::context::DEFAULT_TENANT {
                None
            } else {
                Some(p.tenant_id.as_str())
            };
            if let Err(error) = self
                .place_agent_in_subsystems(p.id, &config, group, &p.tenant_id)
                .await
            {
                tracing::warn!(
                    "Skipping persisted agent {} because enforcement could not be restored: {}",
                    p.id,
                    error
                );
                let _ = self.cleanup_agent_resources(p.id).await;
                self.agent_manager.purge_agent(p.id);
                continue;
            }
            if state == AgentState::Paused {
                self.scheduler.set_paused(p.id);
            }
            let _ = self.event_tx.send(KernelEvent::AgentCreated(p.id));
            restored.push(p.id);
        }
        Ok(restored)
    }

    /// Rehydrate the multi-tenant auth state (tenants, users, hashed api-keys,
    /// hashed sessions) from the persistent DB into the in-memory `AuthSystem` so
    /// tenancy + credentials survive a restart. Best-effort: a read error leaves
    /// the AuthSystem empty rather than failing the boot.
    pub async fn rehydrate_tenancy(&self) {
        let loaded = match self.context_manager.load_tenancy() {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to load tenancy state: {e}");
                return;
            }
        };
        let (tenants, users, api_keys, sessions) = loaded;
        let mut auth = self.auth.write().await;
        for t in tenants {
            auth.insert_tenant(t);
        }
        for u in users {
            auth.insert_user(u);
        }
        for k in api_keys {
            auth.insert_api_key(k);
        }
        for s in sessions {
            auth.insert_session(s);
        }
    }

    /// Create a tenant and persist it, returning its id. The tenant's namespace
    /// group + cgroup are created lazily when its first agent is created.
    pub async fn create_tenant(&self, name: &str) -> Result<String, KernelError> {
        let _mutation = self.auth_mutation_lock.lock().await;
        let mut auth = self.auth.write().await;
        let id = auth.create_tenant(name);
        let record = auth
            .get_tenant(&id)
            .cloned()
            .expect("newly-created tenant must be present");
        if let Err(error) = self.context_manager.save_tenant(&record) {
            auth.revoke_tenant(&id);
            return Err(KernelError::Context(error));
        }
        Ok(id)
    }

    /// Register a user under a tenant and persist it. Returns the user id, or an
    /// error if the tenant is unknown.
    pub async fn register_user(
        &self,
        tenant_id: &str,
        username: &str,
        email: &str,
        role: crate::auth::Role,
    ) -> Result<String, KernelError> {
        let _mutation = self.auth_mutation_lock.lock().await;
        let mut auth = self.auth.write().await;
        let id = match auth.register(tenant_id, username, email, role) {
            Some(id) => id,
            None => {
                return Err(KernelError::Context(crate::ContextError::StorageError(
                    format!("unknown tenant: {tenant_id}"),
                )))
            }
        };
        let record = auth
            .get_user(&id)
            .cloned()
            .expect("newly-created user must be present");
        if let Err(error) = self.context_manager.save_user(&record) {
            auth.revoke_user(&id);
            return Err(KernelError::Context(error));
        }
        Ok(id)
    }

    /// Issue an API key for a user and persist it (hashed). Returns the
    /// **plaintext** key (shown once). Errors if the user is unknown.
    pub async fn issue_api_key(&self, user_id: &str, name: &str) -> Result<String, KernelError> {
        let _mutation = self.auth_mutation_lock.lock().await;
        let mut auth = self.auth.write().await;
        let key = match auth.create_api_key(user_id, name) {
            Some(k) => k,
            None => {
                return Err(KernelError::Context(crate::ContextError::StorageError(
                    format!("unknown user: {user_id}"),
                )))
            }
        };
        // The stored record is keyed by the hash of the returned plaintext.
        let principal = auth
            .authenticate(&key)
            .expect("newly-created API key must authenticate");
        let record = crate::auth::ApiKey {
            key_hash: crate::auth::hash_secret(&key),
            name: name.to_string(),
            user_id: principal.user_id,
            tenant_id: principal.tenant_id,
            created_at: chrono::Utc::now(),
        };
        if let Err(error) = self.context_manager.save_api_key(&record) {
            auth.revoke_api_key(&key);
            return Err(KernelError::Context(error));
        }
        Ok(key)
    }

    /// Open a session (login) for a user and persist it (hashed). Returns the
    /// **plaintext** session token (shown once). Errors if the user is unknown.
    pub async fn open_session(&self, user_id: &str) -> Result<String, KernelError> {
        let _mutation = self.auth_mutation_lock.lock().await;
        let mut auth = self.auth.write().await;
        let token = match auth.create_session(user_id) {
            Some(t) => t,
            None => {
                return Err(KernelError::Context(crate::ContextError::StorageError(
                    format!("unknown user: {user_id}"),
                )))
            }
        };
        let principal = auth
            .authenticate(&token)
            .expect("newly-created session must authenticate");
        let record = crate::auth::Session {
            token_hash: crate::auth::hash_secret(&token),
            user_id: principal.user_id,
            tenant_id: principal.tenant_id,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        };
        if let Err(error) = self.context_manager.save_session(&record) {
            auth.revoke_session(&token);
            return Err(KernelError::Context(error));
        }
        Ok(token)
    }

    async fn drain_revoked_credentials(
        &self,
        drains: Vec<crate::auth::CredentialDrain>,
    ) -> Result<(), KernelError> {
        if drains.is_empty() {
            return Ok(());
        }
        let mut drain_task = tokio::spawn(async move {
            let mut waiters = tokio::task::JoinSet::new();
            for drain in drains {
                waiters.spawn(drain.wait());
            }
            let mut completed = true;
            while let Some(result) = waiters.join_next().await {
                completed &= result.is_ok();
            }
            completed
        });
        match tokio::time::timeout(Self::CREDENTIAL_DRAIN_TIMEOUT, &mut drain_task).await {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false) | Err(_)) => Err(KernelError::CredentialRevocationIncomplete {
                timeout_ms: u64::try_from(Self::CREDENTIAL_DRAIN_TIMEOUT.as_millis())
                    .unwrap_or(u64::MAX),
            }),
            Err(_) => {
                // Durable and in-memory revocation committed before this wait.
                // Never reopen on timeout. Dropping the JoinHandle detaches the
                // owned drain task and its concurrent per-credential waiters,
                // so every eventual guard release can evict its exact entry
                // independently of other stuck credentials.
                Err(KernelError::CredentialRevocationIncomplete {
                    timeout_ms: u64::try_from(Self::CREDENTIAL_DRAIN_TIMEOUT.as_millis())
                        .unwrap_or(u64::MAX),
                })
            }
        }
    }

    /// Revoke a session durably. New requests for this credential are closed
    /// before its durable/in-memory records are removed; a successful return
    /// means already-admitted requests drained. Unrelated credentials remain
    /// available.
    pub async fn revoke_session(&self, token: &str) -> Result<bool, KernelError> {
        let identity = crate::auth::CredentialIdentity {
            kind: crate::auth::CredentialKind::Session,
            id: crate::auth::hash_secret(token),
        };
        let (persisted, removed, drain) = {
            let _mutation = self.auth_mutation_lock.lock().await;
            let mut auth = self.auth.write().await;
            let drain = self.credential_leases.close(&identity);
            let persisted = match self.context_manager.revoke_session_hash(&identity.id) {
                Ok(persisted) => persisted,
                Err(error) => {
                    self.credential_leases.reopen(&identity);
                    return Err(KernelError::Context(error));
                }
            };
            let removed = auth.revoke_session_identity(&identity);
            (persisted, removed, drain)
        };
        self.drain_revoked_credentials(vec![drain]).await?;
        Ok(removed || persisted)
    }

    /// Revoke an API key with the same per-credential drain boundary as session
    /// revocation.
    pub async fn revoke_api_key(&self, key: &str) -> Result<bool, KernelError> {
        let identity = crate::auth::CredentialIdentity {
            kind: crate::auth::CredentialKind::ApiKey,
            id: crate::auth::hash_secret(key),
        };
        let (persisted, removed, drain) = {
            let _mutation = self.auth_mutation_lock.lock().await;
            let mut auth = self.auth.write().await;
            let drain = self.credential_leases.close(&identity);
            let persisted = match self.context_manager.revoke_api_key_hash(&identity.id) {
                Ok(persisted) => persisted,
                Err(error) => {
                    self.credential_leases.reopen(&identity);
                    return Err(KernelError::Context(error));
                }
            };
            let removed = auth.revoke_api_key_identity(&identity);
            (persisted, removed, drain)
        };
        self.drain_revoked_credentials(vec![drain]).await?;
        Ok(removed || persisted)
    }

    /// Revoke a user and all of that user's credentials atomically and durably.
    pub async fn revoke_user(&self, user_id: &str) -> Result<bool, KernelError> {
        let (persisted, removed, drains) = {
            let _mutation = self.auth_mutation_lock.lock().await;
            let mut auth = self.auth.write().await;
            let live_identities = auth.credential_identities_for_user(user_id);
            let mut identities: std::collections::HashSet<_> =
                live_identities.iter().cloned().collect();
            identities.extend(
                self.credential_leases
                    .credential_identities_for_user(user_id),
            );
            let identities: Vec<_> = identities.into_iter().collect();
            let drains = self.credential_leases.close_many(&identities);
            let persisted = match self.context_manager.revoke_user_identity(user_id) {
                Ok(persisted) => persisted,
                Err(error) => {
                    // Only identities still live in AuthSystem may reopen.
                    // Owner-tracked entries can belong to credentials already
                    // committed as revoked by an overlapping narrower revoke.
                    self.credential_leases.reopen_many(&live_identities);
                    return Err(KernelError::Context(error));
                }
            };
            let removed = auth.revoke_user(user_id);
            (persisted, removed, drains)
        };
        self.drain_revoked_credentials(drains).await?;
        Ok(removed || persisted)
    }

    /// Revoke a tenant identity boundary and all tenant credentials atomically.
    /// Agent/data records remain durable but inaccessible to tenant callers.
    pub async fn revoke_tenant(&self, tenant_id: &str) -> Result<bool, KernelError> {
        let (persisted, removed, drains) = {
            let _mutation = self.auth_mutation_lock.lock().await;
            let mut auth = self.auth.write().await;
            let live_identities = auth.credential_identities_for_tenant(tenant_id);
            let mut identities: std::collections::HashSet<_> =
                live_identities.iter().cloned().collect();
            identities.extend(
                self.credential_leases
                    .credential_identities_for_tenant(tenant_id),
            );
            let identities: Vec<_> = identities.into_iter().collect();
            let drains = self.credential_leases.close_many(&identities);
            let persisted = match self.context_manager.revoke_tenant_identity(tenant_id) {
                Ok(persisted) => persisted,
                Err(error) => {
                    // Never reopen an owner-tracked credential that an earlier
                    // session/API-key revoke already removed.
                    self.credential_leases.reopen_many(&live_identities);
                    return Err(KernelError::Context(error));
                }
            };
            let removed = auth.revoke_tenant(tenant_id);
            (persisted, removed, drains)
        };
        self.drain_revoked_credentials(drains).await?;
        Ok(removed || persisted)
    }

    fn invalid_erasure_subject(kind: &str) -> KernelError {
        KernelError::Context(crate::ContextError::PersistenceFailed(format!(
            "{kind} erasure requires a non-empty identifier"
        )))
    }

    fn credential_identities_for_tenant(
        &self,
        auth: &crate::auth::AuthSystem,
        tenant_id: &str,
    ) -> (
        Vec<crate::auth::CredentialIdentity>,
        Vec<crate::auth::CredentialIdentity>,
    ) {
        let live = auth.credential_identities_for_tenant(tenant_id);
        let mut all: std::collections::HashSet<_> = live.iter().cloned().collect();
        all.extend(
            self.credential_leases
                .credential_identities_for_tenant(tenant_id),
        );
        (live, all.into_iter().collect())
    }

    fn credential_identities_for_user(
        &self,
        auth: &crate::auth::AuthSystem,
        user_id: &str,
    ) -> (
        Vec<crate::auth::CredentialIdentity>,
        Vec<crate::auth::CredentialIdentity>,
    ) {
        let live = auth.credential_identities_for_user(user_id);
        let mut all: std::collections::HashSet<_> = live.iter().cloned().collect();
        all.extend(
            self.credential_leases
                .credential_identities_for_user(user_id),
        );
        (live, all.into_iter().collect())
    }

    async fn drain_credentials_for_erasure(
        &self,
        live_identities: &[crate::auth::CredentialIdentity],
        identities: &[crate::auth::CredentialIdentity],
    ) -> Result<(), KernelError> {
        let drains = self.credential_leases.close_many(identities);
        if let Err(error) = self.drain_revoked_credentials(drains).await {
            self.credential_leases.reopen_many(live_identities);
            return Err(error);
        }
        Ok(())
    }

    async fn begin_managed_backup_erasure(
        &self,
    ) -> Result<Option<crate::storage::BackupErasureGuard>, KernelError> {
        let manager = Arc::clone(&self.context_manager);
        let maintenance = Arc::clone(&self.backup_maintenance);
        tokio::task::spawn_blocking(move || maintenance.begin_erasure_purge(&manager))
            .await
            .map_err(|error| {
                KernelError::Context(ContextError::StorageError(format!(
                    "managed backup erasure worker failed: {error}"
                )))
            })?
            .map_err(KernelError::Context)
    }

    /// Erase one agent through the supported hot-operation boundary.
    ///
    /// Tenant credentials are briefly fenced and drained, service ownership is
    /// disabled, active turns and external tool calls quiesce, every live
    /// subsystem is removed, and only then does the transactional SQLite
    /// erasure commit. Existing tenant credentials reopen after the operation.
    pub async fn erase_agent_data(
        &self,
        agent_id: AgentId,
    ) -> Result<Option<crate::context::DeletionReceipt>, KernelError> {
        if agent_id.is_nil() {
            return Err(Self::invalid_erasure_subject("agent"));
        }
        let _service_operation = self.service_operation_lock.lock().await;
        let _auth_mutation = self.auth_mutation_lock.lock().await;
        let tenant_id = self.context_manager.agent_tenant(agent_id)?;
        let (live_identities, identities) = if let Some(tenant_id) = tenant_id.as_deref() {
            let auth = self.auth.read().await;
            self.credential_identities_for_tenant(&auth, tenant_id)
        } else {
            (Vec::new(), Vec::new())
        };
        self.drain_credentials_for_erasure(&live_identities, &identities)
            .await?;
        crash_live_erasure_after_step_for_test("agent.credentials_drained");

        let result = async {
            let service_names = self
                .os
                .init
                .lock()
                .await
                .list_runtime()
                .into_iter()
                .filter(|service| service.agent_id == Some(agent_id))
                .map(|service| service.name)
                .collect::<Vec<_>>();
            for service_name in service_names {
                self.stop_service_inner(&service_name, false).await?;
            }
            crash_live_erasure_after_step_for_test("agent.services_stopped");

            let _erasure = self.erasure_barrier.write().await;
            let _operator_mutation = self.operator_control.mutation_guard().await;
            crash_live_erasure_after_step_for_test("agent.barriers_acquired");
            let backup_erasure = self.begin_managed_backup_erasure().await?;
            let managed_backups_deleted = backup_erasure
                .as_ref()
                .map_or(0, crate::storage::BackupErasureGuard::deleted_count);
            crash_live_erasure_after_step_for_test("agent.backups_purged");
            self.prepare_live_agent_for_erasure(agent_id).await?;
            crash_live_erasure_after_step_for_test("agent.live_resources_removed");
            let receipt = self
                .context_manager
                .erase_agent_data_after_backup_purge(agent_id, managed_backups_deleted)
                .map_err(KernelError::Context)?;
            crash_live_erasure_after_step_for_test("agent.sqlite_committed");
            drop(backup_erasure);
            Ok(receipt)
        }
        .await;
        self.credential_leases.reopen_many(&live_identities);
        result
    }

    /// Erase one user after closing and draining every session/API-key lease.
    /// No user-owned runtime agent exists in the current ownership model.
    pub async fn erase_user_data(
        &self,
        user_id: &str,
    ) -> Result<Option<crate::context::DeletionReceipt>, KernelError> {
        if user_id.trim().is_empty() {
            return Err(Self::invalid_erasure_subject("user"));
        }
        let _auth_mutation = self.auth_mutation_lock.lock().await;
        let (live_identities, identities) = {
            let auth = self.auth.read().await;
            self.credential_identities_for_user(&auth, user_id)
        };
        self.drain_credentials_for_erasure(&live_identities, &identities)
            .await?;
        crash_live_erasure_after_step_for_test("user.credentials_drained");

        let _erasure = self.erasure_barrier.write().await;
        crash_live_erasure_after_step_for_test("user.barrier_acquired");
        let backup_erasure = match self.begin_managed_backup_erasure().await {
            Ok(guard) => guard,
            Err(error) => {
                self.credential_leases.reopen_many(&live_identities);
                return Err(error);
            }
        };
        let managed_backups_deleted = backup_erasure
            .as_ref()
            .map_or(0, crate::storage::BackupErasureGuard::deleted_count);
        crash_live_erasure_after_step_for_test("user.backups_purged");
        let receipt = match self
            .context_manager
            .erase_user_data_after_backup_purge(user_id, managed_backups_deleted)
        {
            Ok(receipt) => receipt,
            Err(error) => {
                self.credential_leases.reopen_many(&live_identities);
                return Err(KernelError::Context(error));
            }
        };
        crash_live_erasure_after_step_for_test("user.sqlite_committed");
        drop(backup_erasure);
        self.auth.write().await.revoke_user(user_id);
        crash_live_erasure_after_step_for_test("user.auth_revoked");
        Ok(receipt)
    }

    /// Erase a tenant after disabling its supervised services, draining every
    /// tenant credential, and removing all tenant agents from live subsystems.
    pub async fn erase_tenant_data(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::context::DeletionReceipt>, KernelError> {
        if tenant_id.trim().is_empty() {
            return Err(Self::invalid_erasure_subject("tenant"));
        }
        let _service_operation = self.service_operation_lock.lock().await;
        let _auth_mutation = self.auth_mutation_lock.lock().await;
        let (live_identities, identities) = {
            let auth = self.auth.read().await;
            self.credential_identities_for_tenant(&auth, tenant_id)
        };
        self.drain_credentials_for_erasure(&live_identities, &identities)
            .await?;
        crash_live_erasure_after_step_for_test("tenant.credentials_drained");

        let result = async {
            let service_names = {
                let init = self.os.init.lock().await;
                init.boot_order()
                    .iter()
                    .filter_map(|name| {
                        init.state(name)
                            .filter(|state| state.def.policy.tenant_id == tenant_id)
                            .map(|_| name.clone())
                    })
                    .collect::<Vec<_>>()
            };
            for service_name in service_names {
                self.stop_service_inner(&service_name, false).await?;
            }
            crash_live_erasure_after_step_for_test("tenant.services_stopped");

            let _erasure = self.erasure_barrier.write().await;
            let _operator_mutation = self.operator_control.mutation_guard().await;
            crash_live_erasure_after_step_for_test("tenant.barriers_acquired");
            let backup_erasure = self.begin_managed_backup_erasure().await?;
            let managed_backups_deleted = backup_erasure
                .as_ref()
                .map_or(0, crate::storage::BackupErasureGuard::deleted_count);
            crash_live_erasure_after_step_for_test("tenant.backups_purged");
            let agent_ids = self.context_manager.list_agents_for_tenant(tenant_id)?;
            for agent_id in agent_ids {
                self.prepare_live_agent_for_erasure(agent_id).await?;
            }
            crash_live_erasure_after_step_for_test("tenant.live_agents_removed");
            let receipt = self
                .context_manager
                .erase_tenant_data_after_backup_purge(tenant_id, managed_backups_deleted)?;
            crash_live_erasure_after_step_for_test("tenant.sqlite_committed");
            drop(backup_erasure);
            self.auth.write().await.revoke_tenant(tenant_id);
            crash_live_erasure_after_step_for_test("tenant.auth_revoked");
            Ok(receipt)
        }
        .await;
        if result.is_err() {
            self.credential_leases.reopen_many(&live_identities);
        }
        result
    }

    /// Resolve a presented secret (API key or session token) to a
    /// [`Principal`](crate::auth::Principal): the full
    /// `(user, tenant, role, credential identity)` the connection acts as.
    /// `None` if the secret or any referenced tenant/user record is
    /// unknown, expired, inconsistent, or revoked.
    pub async fn resolve_principal(&self, secret: &str) -> Option<crate::auth::Principal> {
        self.auth.read().await.authenticate(secret)
    }

    /// Admit one request for a non-secret credential identity, then resolve its
    /// current tenant/user/role under a short auth read lock. The returned lease
    /// must remain alive through dispatch.
    pub(crate) async fn acquire_credential_principal(
        &self,
        identity: &crate::auth::CredentialIdentity,
    ) -> Option<(crate::auth::Principal, crate::auth::CredentialLeaseGuard)> {
        let lease = self.credential_leases.acquire(identity)?;
        let auth = self.auth.read().await;
        let principal = auth.authenticate_identity(identity)?;
        if !lease.bind_owner(&principal.user_id, &principal.tenant_id) {
            return None;
        }
        drop(auth);
        Some((principal, lease))
    }

    /// Synchronous wrapper around [`rehydrate_agents`](Self::rehydrate_agents)
    /// for use from the sync constructors (`with_db_path`/`from_config`).
    ///
    /// Rehydration is async (it locks the kernel's Tokio mutexes when re-placing
    /// agents into CFS/MAC/procfs), but the constructors are sync and may be
    /// called from any runtime flavor (the CLI's multi-thread `#[tokio::main]`,
    /// a current-thread `#[tokio::test]`, or no runtime at all). To work under
    /// all of them without nested-runtime panics, the async work runs on a
    /// dedicated thread with its own current-thread runtime, and we join it.
    /// Best-effort: a rehydration error is logged, not fatal, so a kernel still
    /// boots on a partially-readable DB.
    fn rehydrate_agents_blocking(&self) {
        // SAFETY/scoping: `std::thread::scope` lets the spawned thread borrow
        // `self` for its lifetime, so no `'static`/`Arc` is required here.
        let result = std::thread::scope(|s| {
            s.spawn(|| {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt.block_on(self.rehydrate_agents()),
                    Err(e) => Err(KernelError::Context(crate::ContextError::StorageError(
                        format!("runtime build for rehydration failed: {e}"),
                    ))),
                }
            })
            .join()
        });
        match result {
            Ok(Ok(ids)) if !ids.is_empty() => {
                tracing::info!("Rehydrated {} agent(s) from persistent store", ids.len());
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!("Agent rehydration failed: {e}"),
            Err(_) => tracing::warn!("Agent rehydration thread panicked"),
        }
    }

    /// Rebind durable service ownership only after agent rehydration. A live
    /// persisted instance is reused; a missing/terminal instance is marked for
    /// supervised recovery, preventing duplicate agents after a crash.
    fn restore_service_runtime_from_store(&self) -> Result<(), KernelError> {
        let mut runtime = self
            .context_manager
            .load_service_runtime()
            .map_err(KernelError::Context)?;
        let configured = self
            .os
            .init
            .try_lock()
            .map_err(|_| {
                KernelError::Policy(
                    "service supervisor was unexpectedly busy during recovery".into(),
                )
            })?
            .definitions()
            .into_iter()
            .map(|definition| definition.name)
            .collect::<std::collections::HashSet<_>>();
        let removed = runtime
            .iter()
            .filter(|service| !configured.contains(&service.name))
            .cloned()
            .collect::<Vec<_>>();
        if !removed.is_empty() {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(|error| {
                                KernelError::Context(crate::ContextError::StorageError(format!(
                                    "runtime build for removed-service cleanup failed: {error}"
                                )))
                            })?;
                        runtime.block_on(async {
                            for service in &removed {
                                if let Some(agent_id) = service.agent_id {
                                    if !matches!(
                                        self.agent_manager.get_agent_state(agent_id),
                                        None | Some(AgentState::Stopped)
                                    ) {
                                        self.stop_agent(agent_id).await?;
                                    }
                                }
                            }
                            Ok::<_, KernelError>(())
                        })
                    })
                    .join()
            })
            .map_err(|_| {
                KernelError::LifecycleCleanup(
                    "removed-service recovery cleanup thread panicked".into(),
                )
            })??;
            for service in &removed {
                self.context_manager
                    .remove_service_runtime(
                        &service.name,
                        "definition was removed while the supervisor was offline",
                    )
                    .map_err(KernelError::Context)?;
            }
            runtime.retain(|service| configured.contains(&service.name));
        }
        for service in &mut runtime {
            let Some(agent_id) = service.agent_id else {
                if service.desired_running {
                    service.status = ServiceStatus::Failed;
                    service.ready = false;
                    service.healthy = false;
                    service.last_failure =
                        Some("service had no durable owner after process restart".into());
                }
                continue;
            };
            match self.agent_manager.get_agent_state(agent_id) {
                Some(AgentState::Running) => {
                    service.status = ServiceStatus::Running;
                    service.healthy = true;
                }
                Some(AgentState::Paused) => {
                    service.status = ServiceStatus::Running;
                    service.ready = false;
                    service.healthy = false;
                    service.last_failure =
                        Some("service owner recovered paused; liveness recovery required".into());
                }
                Some(AgentState::Stopped | AgentState::Error(_)) | None => {
                    service.status = ServiceStatus::Failed;
                    service.ready = false;
                    service.healthy = false;
                    service.last_failure =
                        Some("service owner was terminal after process restart".into());
                }
                Some(AgentState::Initializing | AgentState::Stopping) => {
                    service.status = ServiceStatus::Failed;
                    service.ready = false;
                    service.healthy = false;
                    service.last_failure =
                        Some("service owner had an incomplete lifecycle after restart".into());
                }
            }
        }
        let mut init = self.os.init.try_lock().map_err(|_| {
            KernelError::Policy("service supervisor was unexpectedly busy during recovery".into())
        })?;
        init.restore_runtime(&runtime);
        let recovered = init.list_runtime();
        drop(init);
        for service in &recovered {
            if runtime.iter().any(|stored| stored.name == service.name) {
                self.context_manager
                    .save_service_runtime(
                        service,
                        "process_recovered",
                        service.last_failure.as_deref(),
                    )
                    .map_err(KernelError::Context)?;
            }
        }
        Ok(())
    }

    fn lifecycle_lock(&self, agent_id: AgentId) -> Arc<tokio::sync::Mutex<()>> {
        self.lifecycle_locks
            .entry(agent_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn record_lifecycle(
        &self,
        agent_id: AgentId,
        operation: LifecycleOperation,
        outcome: LifecycleOutcome,
    ) {
        self.lifecycle_counters.record(operation, outcome);
        let _ = self.event_tx.send(KernelEvent::AgentLifecycle {
            agent_id,
            operation,
            outcome,
        });
    }

    fn record_lifecycle_result<T>(
        &self,
        agent_id: AgentId,
        operation: LifecycleOperation,
        result: &Result<T, KernelError>,
        started: std::time::Instant,
    ) {
        let outcome = match result {
            Ok(_) if operation == LifecycleOperation::Kill => LifecycleOutcome::Forced,
            Ok(_) => LifecycleOutcome::Completed,
            Err(KernelError::LifecycleTimeout(_)) => LifecycleOutcome::TimedOut,
            Err(_) => LifecycleOutcome::Failed,
        };
        self.lifecycle_counters
            .record_duration(operation, started.elapsed());
        self.record_lifecycle(agent_id, operation, outcome);
    }

    /// Reclaim the process-local per-agent cgroup after gate membership has
    /// been removed (or when registration never succeeded). Durable quota rows
    /// are keyed by the stable scope and intentionally remain in SQLite.
    fn reclaim_agent_cgroup(&self, agent_id: AgentId) -> Result<(), String> {
        // Lock order is kernel tree lock → CgroupManager tree lock, matching
        // cgroup_for_agent. Gate mutation/membership removal has already
        // completed before this method is called.
        let _tree = self.cgroup_tree_lock.lock().map_err(|_| {
            format!("cannot reclaim per-agent cgroup for {agent_id}: hierarchy lock is poisoned")
        })?;
        let cgroup_id = match self.agent_cgroups.remove(&agent_id) {
            Some((_, cgroup_id)) => cgroup_id,
            None => return Ok(()),
        };
        let profile_id = self.cgroups.get(cgroup_id).and_then(|leaf| leaf.parent);

        match self.cgroups.try_remove_empty_leaf(cgroup_id) {
            Ok(()) => {
                if let Some(profile_id) = profile_id {
                    self.reclaim_empty_owned_profile(profile_id);
                }
            }
            Err(crate::cgroups::CgroupError::GroupNotFound(_)) => {}
            Err(error) => {
                // Preserve the lookup if the leaf still exists so a later
                // idempotent cleanup can retry without orphaning the node.
                self.agent_cgroups.insert(agent_id, cgroup_id);
                return Err(format!(
                    "per-agent cgroup cleanup failed for {agent_id}: {error}"
                ));
            }
        }
        Ok(())
    }

    /// Reclaim empty aggregate nodes created by `cgroup_for_agent`. Exact map
    /// ownership checks ensure arbitrary operator-created cgroups are never
    /// deleted merely because they happen to be empty.
    ///
    /// The caller holds `cgroup_tree_lock`, so aggregate maps and manager
    /// structure cannot race another kernel create/cleanup transaction.
    fn reclaim_empty_owned_profile(&self, profile_id: CgroupId) {
        let Some(profile) = self.cgroups.get(profile_id) else {
            return;
        };
        if self
            .profile_cgroups
            .get(&profile.quota_scope)
            .map(|mapped| *mapped)
            != Some(profile_id)
        {
            return;
        }
        let tenant_id = profile.parent;
        match self.cgroups.try_remove_empty_leaf(profile_id) {
            Ok(()) => {
                self.profile_cgroups.remove(&profile.quota_scope);
            }
            Err(crate::cgroups::CgroupError::GroupNotEmpty(_)) => return,
            Err(error) => {
                tracing::warn!(
                    "profile cgroup cleanup failed for {}: {error}",
                    profile.quota_scope
                );
                return;
            }
        }

        let Some(tenant_id) = tenant_id else {
            return;
        };
        let Some(tenant) = self.cgroups.get(tenant_id) else {
            return;
        };
        if self
            .tenant_cgroups
            .get(&tenant.quota_scope)
            .map(|mapped| *mapped)
            != Some(tenant_id)
        {
            return;
        }
        match self.cgroups.try_remove_empty_leaf(tenant_id) {
            Ok(()) => {
                self.tenant_cgroups.remove(&tenant.quota_scope);
            }
            Err(crate::cgroups::CgroupError::GroupNotEmpty(_)) => {}
            Err(error) => {
                tracing::warn!(
                    "tenant cgroup cleanup failed for {}: {error}",
                    tenant.quota_scope
                );
            }
        }
    }

    async fn cleanup_agent_resources(&self, agent_id: AgentId) -> Result<(), KernelError> {
        self.cleanup_agent_resources_with_mode(agent_id, false)
            .await
    }

    /// Forced cleanup revokes already-admitted tool reservations before
    /// tearing down the remaining subsystems. Cooperative work is cancelled by
    /// the lifecycle caller; any stale reservation guard that eventually drops
    /// is inert and cannot corrupt cgroup accounting.
    async fn force_cleanup_agent_resources(&self, agent_id: AgentId) -> Result<(), KernelError> {
        self.cleanup_agent_resources_with_mode(agent_id, true).await
    }

    async fn cleanup_agent_resources_with_mode(
        &self,
        agent_id: AgentId,
        forced: bool,
    ) -> Result<(), KernelError> {
        let mut failures = Vec::new();
        let gate_info = self.syscall_gate.agent_info(agent_id);
        let gate_registered = gate_info.is_some();
        let mut cgroup_membership_released = !gate_registered;
        if forced && gate_registered {
            match self.syscall_gate.force_unregister_agent(agent_id) {
                Ok(()) => cgroup_membership_released = true,
                Err(error) => {
                    failures.push(format!(
                        "forced syscall-gate cleanup failed for {agent_id}: {error}"
                    ));
                }
            }
        } else if gate_registered {
            if let Err(error) = self
                .syscall_gate
                .close_tool_admission_and_wait(agent_id)
                .await
            {
                failures.push(format!(
                    "cannot quiesce syscall-gate tool admission for {agent_id}: {error}"
                ));
            }
        }
        self.scheduler.deschedule(agent_id);
        self.scheduler.release_resource_access(agent_id);
        self.ipc.unregister_agent(agent_id);
        self.permission_manager.purge_agent(agent_id);
        self.active_cancellations.remove(&agent_id);
        self.executors.remove(&agent_id);

        if let Some(info) = gate_info {
            self.os.cfs.lock().await.dequeue(info.pid);
            self.os.procfs.lock().await.remove_agent(info.pid);
            for namespace in info.namespaces {
                self.os.namespaces.leave(namespace, info.pid);
            }
        }

        if let Some(sandbox_id) = self.sandbox_manager.get_sandbox_for_agent(agent_id) {
            if let Err(error) = self.sandbox_manager.destroy_sandbox(sandbox_id) {
                failures.push(format!("sandbox cleanup failed for {agent_id}: {error}"));
            }
        }
        self.observability.purge_agent(agent_id);
        self.budget_enforcer.unregister_agent(agent_id);
        if gate_registered && !forced {
            if let Err(error) = self.syscall_gate.try_unregister_agent(agent_id) {
                failures.push(format!(
                    "syscall-gate cleanup failed for {agent_id}: {error}"
                ));
            } else {
                cgroup_membership_released = true;
            }
        }
        if cgroup_membership_released {
            // `agent_cgroups` always names the private leaf allocated at
            // creation. The gate may now name a shared/custom destination
            // after a move; unregister releases that membership, while only
            // the original private leaf is structurally reclaimed here.
            if let Err(error) = self.reclaim_agent_cgroup(agent_id) {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(KernelError::LifecycleCleanup(failures.join("; ")))
        }
    }

    /// Put a live agent behind the same non-runnable durable marker and bounded
    /// cleanup boundary used by normal lifecycle operations, then remove its
    /// process-local registry history. The caller holds the global erasure and
    /// operator mutation barriers, so no new public request or agent creation
    /// can race this transition.
    async fn prepare_live_agent_for_erasure(&self, agent_id: AgentId) -> Result<bool, KernelError> {
        let lock = self.lifecycle_lock(agent_id);
        let _lifecycle = lock.lock().await;
        let Some(state) = self.agent_manager.get_agent_state(agent_id) else {
            return Ok(false);
        };

        if !matches!(state, AgentState::Stopping | AgentState::Stopped) {
            self.quiesce_agent(agent_id).await?;
            self.drain_agent_tool_calls(agent_id).await?;
            if let Err(error) = self
                .context_manager
                .update_agent_status(agent_id, &AgentState::Stopping)
            {
                let _ = self.syscall_gate.reopen_tool_admission(agent_id);
                return Err(KernelError::Context(error));
            }
            self.agent_manager.force_stopping(agent_id)?;
        }

        self.cleanup_agent_resources(agent_id).await?;
        if self.agent_manager.get_agent_state(agent_id) != Some(AgentState::Stopped) {
            self.agent_manager.force_stopped(agent_id)?;
        }
        self.agent_manager.purge_agent(agent_id);
        self.syscall_gate.purge_agent_stats(agent_id);
        Ok(true)
    }

    /// Roll back a creation that failed after the AgentManager allocated an
    /// identity. Unlike normal lifecycle termination, rollback removes all
    /// in-memory and durable history because the creation never committed.
    pub(crate) async fn rollback_created_agent(&self, agent_id: AgentId) {
        let lock = self.lifecycle_lock(agent_id);
        let _guard = lock.lock().await;
        if self.agent_manager.get_agent_state(agent_id).is_some() {
            let _ = self.agent_manager.force_stopped(agent_id);
        }
        let _ = self.quiesce_agent(agent_id).await;
        let _ = self.cleanup_agent_resources(agent_id).await;
        self.agent_manager.purge_agent(agent_id);
        self.syscall_gate.purge_agent_stats(agent_id);
        let _ = self.context_manager.purge_agent_data(agent_id);
        self.lifecycle_locks.remove(&agent_id);
    }

    async fn persist_service_transition(
        &self,
        name: &str,
        event: &str,
        reason: Option<&str>,
    ) -> Result<(), KernelError> {
        let runtime = self
            .os
            .init
            .lock()
            .await
            .list_runtime()
            .into_iter()
            .find(|service| service.name == name)
            .ok_or_else(|| KernelError::Policy(format!("service '{name}' not found")))?;
        self.context_manager
            .save_service_runtime(&runtime, event, reason)
            .map_err(KernelError::Context)?;
        let _ = self.event_tx.send(KernelEvent::ServiceStateChanged {
            name: name.to_string(),
            status: runtime.status,
            reason: reason.map(str::to_string),
        });
        Ok(())
    }

    pub fn list_service_history(
        &self,
        name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::init_system::ServiceHistoryEntry>, KernelError> {
        self.context_manager
            .list_service_history(name, limit)
            .map_err(KernelError::Context)
    }

    /// Reload the explicitly configured service directory. The complete graph
    /// is parsed and validated before any live state changes. Changed/removed
    /// services stop in reverse dependency order, new definitions publish as
    /// one replacement, and affected desired services start in the new order.
    /// A failed rollout restores the prior graph and desired instances.
    pub async fn reload_configured_services(&self) -> Result<Vec<String>, KernelError> {
        let path = self
            .service_directory
            .read()
            .map_err(|_| KernelError::Policy("service directory lock is poisoned".into()))?
            .clone()
            .ok_or_else(|| {
                KernelError::Policy("no service directory is configured for reload".into())
            })?;
        self.reload_service_directory(&path).await
    }

    pub async fn reload_service_directory(
        &self,
        path: &std::path::Path,
    ) -> Result<Vec<String>, KernelError> {
        let definitions = InitSystem::read_directory_checked(path).map_err(KernelError::Policy)?;
        let _operation = self.service_operation_lock.lock().await;
        let (old_definitions, old_order, old_runtime, new_order) = {
            let init = self.os.init.lock().await;
            let new_order = init
                .validate_replacement(definitions.clone())
                .map_err(KernelError::Policy)?;
            (
                init.definitions(),
                init.boot_order().to_vec(),
                init.list_runtime(),
                new_order,
            )
        };
        let old_by_name = old_definitions
            .iter()
            .map(|definition| (definition.name.clone(), definition.clone()))
            .collect::<std::collections::HashMap<_, _>>();
        let new_by_name = definitions
            .iter()
            .map(|definition| (definition.name.clone(), definition.clone()))
            .collect::<std::collections::HashMap<_, _>>();
        let directly_changed = old_by_name
            .iter()
            .filter(|(name, definition)| new_by_name.get(*name) != Some(*definition))
            .map(|(name, _)| name.clone())
            .collect::<std::collections::HashSet<_>>();
        let mut affected = directly_changed;
        loop {
            let before = affected.len();
            for (name, definition) in old_by_name.iter().chain(new_by_name.iter()) {
                if definition
                    .dependencies
                    .requires
                    .iter()
                    .any(|required| affected.contains(required))
                {
                    affected.insert(name.clone());
                }
            }
            if affected.len() == before {
                break;
            }
        }
        let old_desired = old_runtime
            .iter()
            .filter(|runtime| runtime.desired_running)
            .map(|runtime| runtime.name.as_str())
            .collect::<std::collections::HashSet<_>>();
        let old_active = old_runtime
            .iter()
            .filter(|runtime| runtime.status == ServiceStatus::Running)
            .map(|runtime| runtime.name.as_str())
            .collect::<std::collections::HashSet<_>>();
        let changed_or_removed = old_order
            .iter()
            .rev()
            .filter(|name| affected.contains(*name))
            .cloned()
            .collect::<Vec<_>>();
        let mut stopped = Vec::new();
        for name in &changed_or_removed {
            if let Err(error) = self.stop_service_inner(name, false).await {
                for old_name in &old_order {
                    if stopped.contains(old_name) && old_active.contains(old_name.as_str()) {
                        let _ = self.start_service_inner(old_name).await;
                    }
                }
                return Err(KernelError::Policy(format!(
                    "rolling service reload could not quiesce '{name}' and restored stopped services: {error}"
                )));
            }
            stopped.push(name.clone());
        }
        {
            let mut init = self.os.init.lock().await;
            init.replace_definitions(definitions)
                .map_err(KernelError::Policy)?;
        }
        let mut started = Vec::new();
        for name in &new_order {
            let is_added = !old_by_name.contains_key(name);
            let should_roll = affected.contains(name) && old_desired.contains(name.as_str());
            if is_added || should_roll {
                match self.start_service_inner(name).await {
                    Ok(_) => started.push(name.clone()),
                    Err(error) => {
                        for started_name in started.iter().rev() {
                            let _ = self.stop_service_inner(started_name, false).await;
                        }
                        {
                            let mut init = self.os.init.lock().await;
                            let _ = init.replace_definitions(old_definitions.clone());
                            init.restore_runtime(&old_runtime);
                        }
                        for added_name in new_by_name.keys() {
                            if !old_by_name.contains_key(added_name) {
                                let _ = self.context_manager.remove_service_runtime(
                                    added_name,
                                    "removed by rolling reload rollback",
                                );
                            }
                        }
                        for old_name in &old_order {
                            if old_active.contains(old_name.as_str()) {
                                let _ = self.start_service_inner(old_name).await;
                            }
                        }
                        return Err(KernelError::Policy(format!(
                            "rolling service reload failed at '{name}' and restored the previous graph: {error}"
                        )));
                    }
                }
            }
        }
        for name in old_by_name.keys() {
            if !new_by_name.contains_key(name) {
                self.context_manager
                    .remove_service_runtime(name, "removed by validated rolling reload")
                    .map_err(KernelError::Context)?;
            }
        }
        *self
            .service_directory
            .write()
            .map_err(|_| KernelError::Policy("service directory lock is poisoned".into()))? =
            Some(path.to_path_buf());
        for service in self.list_services().await {
            self.persist_service_transition(
                &service.name,
                "configuration_reloaded",
                Some("validated rolling configuration published"),
            )
            .await?;
        }
        Ok(new_order)
    }

    pub async fn list_services(&self) -> Vec<ServiceRuntimeInfo> {
        self.os.init.lock().await.list_runtime()
    }

    /// Start one validated service through the same full agent admission path
    /// as every other agent. Required dependencies must be running and ready.
    pub async fn start_service(&self, name: &str) -> Result<AgentId, KernelError> {
        let _operation = self.service_operation_lock.lock().await;
        {
            let mut init = self.os.init.lock().await;
            let state = init
                .state(name)
                .ok_or_else(|| KernelError::Policy(format!("service '{name}' not found")))?;
            if state.status == ServiceStatus::Failed || state.restart_exhausted {
                init.reset_restart_budget(name);
            }
        }
        self.start_service_inner(name).await
    }

    async fn start_service_inner(&self, name: &str) -> Result<AgentId, KernelError> {
        let state = self
            .os
            .init
            .lock()
            .await
            .state(name)
            .ok_or_else(|| KernelError::Policy(format!("service '{name}' not found")))?;
        {
            let mut init = self.os.init.lock().await;
            for required in &state.def.dependencies.requires {
                let dependency = init.state(required);
                if !dependency.is_some_and(|dependency| {
                    dependency.status == ServiceStatus::Running
                        && dependency.ready
                        && dependency.healthy
                }) {
                    let reason = format!("required service '{required}' is not running and ready");
                    init.record_dependency_block(name, reason.clone());
                    drop(init);
                    self.persist_service_transition(name, "dependency_blocked", Some(&reason))
                        .await?;
                    return Err(KernelError::Policy(format!(
                        "service '{name}' is blocked by required service '{required}'"
                    )));
                }
            }
        }
        if state.status == ServiceStatus::Running {
            if let Some(agent_id) = state.agent_id {
                if let Ok(agent_state) = self.get_agent_status(agent_id) {
                    if agent_state == AgentState::Running && state.ready && state.healthy {
                        return Ok(agent_id);
                    }
                }
            }
        }
        if let Some(stale_agent_id) = state.agent_id {
            if !matches!(
                self.agent_manager.get_agent_state(stale_agent_id),
                Some(AgentState::Stopped)
            ) {
                self.stop_agent(stale_agent_id).await?;
            }
            self.os.init.lock().await.clear_instance_for_restart(name);
            self.persist_service_transition(
                name,
                "stale_owner_cleaned",
                Some("previous service owner was terminal or no longer healthy"),
            )
            .await?;
        }
        self.os.init.lock().await.mark_starting(name);
        self.persist_service_transition(name, "starting", None)
            .await?;

        let provider = if state.def.exec.provider.trim().is_empty() {
            "stub".to_string()
        } else {
            state.def.exec.provider.clone()
        };
        if provider != "stub"
            && !self
                .connector
                .list_providers()
                .iter()
                .any(|registered| registered.id == provider)
        {
            let reason = format!("provider '{provider}' is not registered");
            self.os
                .init
                .lock()
                .await
                .mark_failed_reason(name, 1, reason.clone());
            self.persist_service_transition(name, "startup_failed", Some(&reason))
                .await?;
            return Err(KernelError::Policy(format!("service '{name}' {reason}")));
        }
        if state.def.policy.tenant_id != crate::context::DEFAULT_TENANT
            && self
                .auth
                .read()
                .await
                .get_tenant(&state.def.policy.tenant_id)
                .is_none()
        {
            let reason = format!("tenant '{}' is not registered", state.def.policy.tenant_id);
            self.os
                .init
                .lock()
                .await
                .mark_failed_reason(name, 1, reason.clone());
            self.persist_service_transition(name, "startup_failed", Some(&reason))
                .await?;
            return Err(KernelError::Policy(format!("service '{name}' {reason}")));
        }
        let task = state
            .def
            .description
            .clone()
            .filter(|description| !description.trim().is_empty())
            .unwrap_or_else(|| {
                if state.def.exec.system_prompt.trim().is_empty() {
                    format!("run service {name}")
                } else {
                    state.def.exec.system_prompt.clone()
                }
            });
        let nice = state.def.resources.nice.unwrap_or(0);
        let priority_value = match nice {
            -20..=-12 => 1,
            -11..=-4 => 2,
            -3..=4 => 3,
            5..=12 => 4,
            _ => 5,
        };
        let namespace_group = state.def.policy.namespace.as_ref().map(|namespace| {
            format!(
                "service:{}:{namespace}",
                quota_scope_segment(&state.def.policy.tenant_id)
            )
        });
        let tenant_group = if state.def.policy.tenant_id == crate::context::DEFAULT_TENANT {
            None
        } else {
            Some(state.def.policy.tenant_id.clone())
        };
        let group = namespace_group.as_deref().or(tenant_group.as_deref());
        let startup_started = std::time::Instant::now();
        let startup_timeout = std::time::Duration::from_millis(state.def.health.startup_timeout_ms);
        let create = self.create_agent_grouped(
            AgentConfig {
                name: format!("service:{name}"),
                task,
                llm_provider: provider,
                permission_profile: state.def.policy.profile.clone(),
                priority: Priority::new(priority_value).unwrap_or_default(),
                sandbox_config: state.def.policy.sandbox.clone(),
            },
            group,
            &state.def.policy.tenant_id,
        );
        let created = tokio::time::timeout(startup_timeout, create).await;
        match created {
            Ok(Ok(handle)) => {
                let policy = (|| {
                    let gate_info = self.syscall_gate.agent_info(handle.id).ok_or_else(|| {
                        KernelError::Policy(format!(
                            "service '{name}' disappeared from the syscall gate"
                        ))
                    })?;
                    let mut limits = self
                        .cgroups
                        .get(gate_info.cgroup)
                        .map(|group| group.limits)
                        .ok_or_else(|| {
                            KernelError::Policy(format!(
                                "service '{name}' has no enforceable cgroup after creation"
                            ))
                        })?;
                    if let Some(tokens_per_min) = state
                        .def
                        .token_budget_per_minute()
                        .map_err(|error| KernelError::Policy(format!("service '{name}' {error}")))?
                    {
                        limits.tokens_per_min = tokens_per_min;
                    }
                    if let Some(max_context) = state.def.resources.max_context {
                        limits.max_context_tokens = max_context;
                    }
                    if let Some(max_tools) = state.def.resources.max_concurrent_tool_calls {
                        limits.max_concurrent_tool_calls = max_tools;
                    }
                    Ok::<_, KernelError>((gate_info.cgroup, limits))
                })();
                let (cgroup_id, limits) = match policy {
                    Ok(policy) => policy,
                    Err(error) => {
                        let reason = error.to_string();
                        self.fail_service_start(name, handle.id, "startup_failed", &reason)
                            .await?;
                        return Err(error);
                    }
                };
                if let Err(error) = self.cgroups.update_limits(cgroup_id, limits) {
                    let reason = format!("resource policy could not be enforced: {error}");
                    self.fail_service_start(name, handle.id, "startup_failed", &reason)
                        .await?;
                    return Err(KernelError::Policy(format!("service '{name}' {reason}")));
                }
                if state.def.resources.nice.is_some() {
                    if let Err(error) = self.set_nice(handle.id, nice).await {
                        self.fail_service_start(
                            name,
                            handle.id,
                            "startup_failed",
                            &error.to_string(),
                        )
                        .await?;
                        return Err(error);
                    }
                }
                self.os.init.lock().await.mark_started(name, handle.id);
                self.persist_service_transition(name, "started", None)
                    .await?;
                let remaining = startup_timeout.saturating_sub(startup_started.elapsed());
                let readiness = tokio::time::timeout(remaining, async {
                    if state.def.health.readiness_delay_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            state.def.health.readiness_delay_ms,
                        ))
                        .await;
                    }
                    self.get_agent_status(handle.id)
                })
                .await;
                let agent_state = match readiness {
                    Ok(Ok(agent_state)) => agent_state,
                    Ok(Err(error)) => {
                        self.fail_service_start(
                            name,
                            handle.id,
                            "readiness_failed",
                            &error.to_string(),
                        )
                        .await?;
                        return Err(error);
                    }
                    Err(_) => {
                        let reason =
                            format!("startup exceeded {}ms", state.def.health.startup_timeout_ms);
                        self.fail_service_start(name, handle.id, "startup_timeout", &reason)
                            .await?;
                        return Err(KernelError::LifecycleTimeout(format!(
                            "service '{name}' {reason}"
                        )));
                    }
                };
                if agent_state != AgentState::Running {
                    let reason = format!("service owner was {agent_state:?} at readiness check");
                    self.fail_service_start(name, handle.id, "readiness_failed", &reason)
                        .await?;
                    return Err(KernelError::Policy(format!(
                        "service '{name}' readiness failed"
                    )));
                }
                self.os.init.lock().await.mark_ready(name);
                self.service_health_checks
                    .insert(name.to_string(), std::time::Instant::now());
                self.persist_service_transition(name, "ready", None).await?;
                Ok(handle.id)
            }
            Ok(Err(error)) => {
                self.os
                    .init
                    .lock()
                    .await
                    .mark_failed_reason(name, 1, error.to_string());
                self.persist_service_transition(name, "startup_failed", Some(&error.to_string()))
                    .await?;
                Err(error)
            }
            Err(_) => {
                let reason = format!("startup exceeded {}ms", state.def.health.startup_timeout_ms);
                self.os
                    .init
                    .lock()
                    .await
                    .mark_failed_reason(name, 1, reason.clone());
                self.persist_service_transition(name, "startup_timeout", Some(&reason))
                    .await?;
                Err(KernelError::LifecycleTimeout(format!(
                    "service '{name}' {reason}"
                )))
            }
        }
    }

    async fn fail_service_start(
        &self,
        name: &str,
        agent_id: AgentId,
        event: &str,
        reason: &str,
    ) -> Result<(), KernelError> {
        let cleanup = self.kill_agent(agent_id).await;
        self.os
            .init
            .lock()
            .await
            .mark_failed_reason(name, 1, reason.to_string());
        self.os.init.lock().await.clear_instance(name);
        self.persist_service_transition(name, event, Some(reason))
            .await?;
        cleanup.map(|_| ())
    }

    pub async fn stop_service(&self, name: &str) -> Result<(), KernelError> {
        let _operation = self.service_operation_lock.lock().await;
        let order = self.os.init.lock().await.dependents_of(name);
        if order.is_empty() {
            return Err(KernelError::Policy(format!("service '{name}' not found")));
        }
        for service in order {
            self.stop_service_inner(&service, false).await?;
        }
        Ok(())
    }

    async fn stop_service_inner(
        &self,
        name: &str,
        desired_running: bool,
    ) -> Result<(), KernelError> {
        let state = self
            .os
            .init
            .lock()
            .await
            .state(name)
            .ok_or_else(|| KernelError::Policy(format!("service '{name}' not found")))?;
        if state.status == ServiceStatus::Inactive {
            self.os
                .init
                .lock()
                .await
                .mark_stopped_with_desired(name, desired_running);
            self.persist_service_transition(name, "stopped", None)
                .await?;
            return Ok(());
        }
        self.os.init.lock().await.mark_stopping(name);
        self.persist_service_transition(name, "stopping", None)
            .await?;
        if let Some(agent_id) = state.agent_id {
            let graceful = tokio::time::timeout(
                std::time::Duration::from_millis(state.def.health.shutdown_timeout_ms),
                self.stop_agent(agent_id),
            )
            .await;
            match graceful {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    self.os
                        .init
                        .lock()
                        .await
                        .mark_failed_reason(name, 1, error.to_string());
                    self.persist_service_transition(
                        name,
                        "shutdown_failed",
                        Some(&error.to_string()),
                    )
                    .await?;
                    return Err(error);
                }
                Err(_) => {
                    self.kill_agent(agent_id).await?;
                    self.persist_service_transition(
                        name,
                        "shutdown_forced",
                        Some("graceful shutdown deadline exceeded"),
                    )
                    .await?;
                }
            }
        }
        self.os
            .init
            .lock()
            .await
            .mark_stopped_with_desired(name, desired_running);
        self.service_health_checks.remove(name);
        self.persist_service_transition(name, "stopped", None)
            .await?;
        Ok(())
    }

    pub async fn restart_service(&self, name: &str) -> Result<AgentId, KernelError> {
        let _operation = self.service_operation_lock.lock().await;
        let (state, reverse_order, desired) = {
            let init = self.os.init.lock().await;
            let state = init
                .state(name)
                .ok_or_else(|| KernelError::Policy(format!("service '{name}' not found")))?;
            let reverse_order = init.dependents_of(name);
            let desired = reverse_order
                .iter()
                .filter_map(|service| {
                    init.state(service)
                        .map(|state| (service.clone(), state.desired_running))
                })
                .collect::<std::collections::HashMap<_, _>>();
            (state, reverse_order, desired)
        };
        for service in &reverse_order {
            let keep_desired = service == name || desired.get(service).copied().unwrap_or(false);
            self.stop_service_inner(service, keep_desired).await?;
        }
        for service in &reverse_order {
            if service == name || desired.get(service).copied().unwrap_or(false) {
                let mut init = self.os.init.lock().await;
                init.reset_restart_budget(service);
                init.record_restart(service);
                drop(init);
                let reason = if service == name {
                    "operator requested restart"
                } else {
                    "required dependency was manually restarted"
                };
                self.persist_service_transition(service, "manual_restart", Some(reason))
                    .await?;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            state
                .def
                .service
                .restart_delay_ms
                .min(state.def.service.restart_max_delay_ms),
        ))
        .await;
        let mut target = None;
        for service in reverse_order.iter().rev() {
            if service == name || desired.get(service).copied().unwrap_or(false) {
                let agent_id = self.start_service_inner(service).await?;
                if service == name {
                    target = Some(agent_id);
                }
            }
        }
        target.ok_or_else(|| KernelError::Policy(format!("service '{name}' restart was skipped")))
    }

    /// Start all services in validated dependency order. A failure rolls back
    /// services started by this attempt in reverse order.
    pub async fn boot_services(&self) -> Result<Vec<AgentId>, KernelError> {
        let _operation = self.service_operation_lock.lock().await;
        let order = self.os.init.lock().await.boot_order().to_vec();
        let mut active = Vec::new();
        let mut started_by_attempt = Vec::new();
        for name in order {
            let recovered = self
                .os
                .init
                .lock()
                .await
                .state(&name)
                .expect("boot order only contains configured services");
            if recovered.desired_running {
                let dependencies_ready = {
                    let init = self.os.init.lock().await;
                    recovered.def.dependencies.requires.iter().all(|required| {
                        init.state(required).is_some_and(|dependency| {
                            dependency.status == ServiceStatus::Running
                                && dependency.ready
                                && dependency.healthy
                        })
                    })
                };
                if recovered.status == ServiceStatus::Running
                    && recovered.ready
                    && recovered.healthy
                    && dependencies_ready
                {
                    if let Some(agent_id) = recovered.agent_id {
                        active.push(agent_id);
                    }
                }
                // Any other desired state is crash-recovery work. Preserve its
                // durable delay/exhaustion and let the runtime supervisor
                // reconcile it instead of bypassing policy during boot.
                continue;
            }
            match self.start_service_inner(&name).await {
                Ok(agent_id) => {
                    active.push(agent_id);
                    started_by_attempt.push(name);
                }
                Err(error) => {
                    for started_name in started_by_attempt.iter().rev() {
                        let _ = self.stop_service_inner(started_name, false).await;
                    }
                    return Err(error);
                }
            }
        }
        Ok(active)
    }

    /// One liveness/restart reconciliation pass. The runtime calls this on a
    /// bounded interval; the global operation lock prevents overlap with
    /// operator lifecycle and rolling reload.
    pub(crate) async fn service_supervisor_sweep(&self) -> Result<(), KernelError> {
        let Ok(_operation) = self.service_operation_lock.try_lock() else {
            return Ok(());
        };
        let now = chrono::Utc::now();
        let names = self.os.init.lock().await.boot_order().to_vec();

        // Required-dependency failure propagates from dependents backwards.
        for name in names.iter().rev() {
            let Some(state) = self.os.init.lock().await.state(name) else {
                continue;
            };
            if !state.desired_running || state.status != ServiceStatus::Running {
                continue;
            }
            let dependency_failure = {
                let init = self.os.init.lock().await;
                state.def.dependencies.requires.iter().find_map(|required| {
                    let dependency = init.state(required)?;
                    (!(dependency.status == ServiceStatus::Running
                        && dependency.ready
                        && dependency.healthy))
                        .then(|| required.clone())
                })
            };
            if let Some(required) = dependency_failure {
                let reason = format!("required service '{required}' became unavailable");
                self.stop_service_inner(name, true).await?;
                {
                    let mut init = self.os.init.lock().await;
                    init.mark_failed_reason(name, 1, reason.clone());
                    init.record_dependency_block(name, reason.clone());
                    let _ = init.schedule_restart(name, now);
                }
                self.persist_service_transition(name, "dependency_failed", Some(&reason))
                    .await?;
            }
        }

        for name in names {
            let Some(state) = self.os.init.lock().await.state(&name) else {
                continue;
            };
            if !state.desired_running {
                continue;
            }
            if state.status == ServiceStatus::Running {
                let liveness_interval =
                    std::time::Duration::from_millis(state.def.health.liveness_interval_ms);
                if self
                    .service_health_checks
                    .get(&name)
                    .is_some_and(|last_check| last_check.elapsed() < liveness_interval)
                {
                    continue;
                }
                self.service_health_checks
                    .insert(name.clone(), std::time::Instant::now());
                let live = state.agent_id.and_then(|agent_id| {
                    self.agent_manager
                        .get_agent_state(agent_id)
                        .map(|agent_state| (agent_id, agent_state))
                });
                match live {
                    Some((_, AgentState::Running)) if state.ready && state.healthy => continue,
                    Some((_, AgentState::Running)) => {
                        self.os.init.lock().await.mark_ready(&name);
                        self.persist_service_transition(&name, "health_recovered", None)
                            .await?;
                        continue;
                    }
                    Some((agent_id, agent_state)) => {
                        let reason = format!("liveness failed: owner state is {agent_state:?}");
                        let mut init = self.os.init.lock().await;
                        init.mark_failed_reason(&name, 1, reason.clone());
                        let _ = init.schedule_restart(&name, now);
                        drop(init);
                        if !matches!(agent_state, AgentState::Stopped) {
                            self.stop_agent(agent_id).await?;
                        }
                        self.os.init.lock().await.clear_instance(&name);
                        self.persist_service_transition(&name, "liveness_failed", Some(&reason))
                            .await?;
                    }
                    None => {
                        let reason = "liveness failed: durable owner is missing".to_string();
                        let mut init = self.os.init.lock().await;
                        init.mark_failed_reason(&name, 1, reason.clone());
                        let _ = init.schedule_restart(&name, now);
                        drop(init);
                        self.persist_service_transition(&name, "liveness_failed", Some(&reason))
                            .await?;
                    }
                }
            } else if state.status == ServiceStatus::Failed && state.next_restart_at.is_none() {
                let mut init = self.os.init.lock().await;
                let scheduled = init.schedule_restart(&name, now);
                drop(init);
                if scheduled.is_some() {
                    self.persist_service_transition(
                        &name,
                        "restart_scheduled",
                        state.last_failure.as_deref(),
                    )
                    .await?;
                }
            }

            let due = self.os.init.lock().await.restart_due(&name, now);
            if !due {
                continue;
            }
            let required_ready = {
                let init = self.os.init.lock().await;
                let state = init.state(&name).expect("service exists during sweep");
                state.def.dependencies.requires.iter().all(|required| {
                    init.state(required).is_some_and(|dependency| {
                        dependency.status == ServiceStatus::Running
                            && dependency.ready
                            && dependency.healthy
                    })
                })
            };
            if !required_ready {
                let reason = "restart deferred until required dependencies are ready".to_string();
                self.os.init.lock().await.defer_restart(
                    &name,
                    std::time::Duration::from_millis(state.def.health.liveness_interval_ms.max(50)),
                    reason.clone(),
                );
                self.persist_service_transition(&name, "restart_deferred", Some(&reason))
                    .await?;
                continue;
            }
            if let Some(agent_id) = state.agent_id {
                if !matches!(
                    self.agent_manager.get_agent_state(agent_id),
                    Some(AgentState::Stopped)
                ) {
                    let cleanup = self.stop_agent(agent_id).await;
                    if let Err(error) = cleanup {
                        self.os.init.lock().await.defer_restart(
                            &name,
                            std::time::Duration::from_millis(
                                state.def.health.liveness_interval_ms.max(50),
                            ),
                            format!("restart cleanup failed: {error}"),
                        );
                        self.persist_service_transition(
                            &name,
                            "restart_cleanup_failed",
                            Some(&error.to_string()),
                        )
                        .await?;
                        continue;
                    }
                }
            }
            {
                let mut init = self.os.init.lock().await;
                init.clear_instance_for_restart(&name);
                init.record_restart(&name);
            }
            self.persist_service_transition(
                &name,
                "restart_attempt",
                state.last_failure.as_deref(),
            )
            .await?;
            if let Err(error) = self.start_service_inner(&name).await {
                let reason = format!("restart attempt failed: {error}");
                let mut init = self.os.init.lock().await;
                init.mark_failed_reason(&name, 1, reason.clone());
                let _ = init.schedule_restart(&name, chrono::Utc::now());
                drop(init);
                self.persist_service_transition(&name, "restart_failed", Some(&reason))
                    .await?;
            }
        }
        Ok(())
    }

    /// Cancel an active turn and wait until the per-agent executor is idle.
    /// Callers hold the lifecycle lock, which prevents resume or new admission;
    /// `send_message` never waits for that lock while holding the executor.
    async fn quiesce_agent(&self, agent_id: AgentId) -> Result<(), KernelError> {
        if let Some(token) = self.active_cancellations.get(&agent_id) {
            token.cancel();
        }
        let executor = self
            .executors
            .get(&agent_id)
            .map(|entry| Arc::clone(entry.value()));
        if let Some(executor) = executor {
            let idle = tokio::time::timeout(Self::TOOL_DRAIN_TIMEOUT, executor.lock())
                .await
                .map_err(|_| {
                    KernelError::LifecycleTimeout(format!(
                        "timed out waiting for active agent turn to quiesce for agent {agent_id}"
                    ))
                })?;
            drop(idle);
        }
        Ok(())
    }

    /// Stop new external tool admission and wait a bounded interval for
    /// already-running syscall/MCP/resource bindings. On timeout the lifecycle
    /// transition is not committed and admission is reopened; an operator can
    /// retry after the binding returns without leaking its cgroup hierarchy.
    async fn drain_agent_tool_calls(&self, agent_id: AgentId) -> Result<(), KernelError> {
        if self.syscall_gate.agent_info(agent_id).is_none() {
            return Ok(());
        }
        let drain = tokio::time::timeout(
            Self::TOOL_DRAIN_TIMEOUT,
            self.syscall_gate.close_tool_admission_and_wait(agent_id),
        )
        .await;
        match drain {
            Ok(result) => result.map_err(|error| KernelError::Policy(error.to_string())),
            Err(_) => {
                // The lifecycle transition did not commit. Restore the live
                // agent's admission state so a timed-out stop/kill attempt does
                // not leave it half-disabled; a later retry closes it again.
                let _ = self.syscall_gate.reopen_tool_admission(agent_id);
                Err(KernelError::LifecycleTimeout(format!(
                    "timed out draining active external tool calls for agent {agent_id}"
                )))
            }
        }
    }

    /// Pause admission for an agent and cooperatively cancel any active turn.
    /// Repeating a pause is idempotent.
    pub async fn pause_agent(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        let started = std::time::Instant::now();
        self.record_lifecycle(
            agent_id,
            LifecycleOperation::Pause,
            LifecycleOutcome::Requested,
        );
        let result = self.pause_agent_inner(agent_id).await;
        self.record_lifecycle_result(agent_id, LifecycleOperation::Pause, &result, started);
        result
    }

    async fn pause_agent_inner(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        let _operator_mutation = self.operator_control.mutation_guard().await;
        let lock = self.lifecycle_lock(agent_id);
        let _guard = lock.lock().await;
        let state = self
            .agent_manager
            .get_agent_state(agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        if state == AgentState::Paused {
            return Ok(state);
        }
        if state != AgentState::Running {
            return Err(AgentError::InvalidTransition {
                from: state,
                to: AgentState::Paused,
            }
            .into());
        }
        self.agent_manager.pause_agent(agent_id).await?;
        self.scheduler.set_paused(agent_id);
        self.context_manager
            .update_agent_status(agent_id, &AgentState::Paused)?;
        self.quiesce_agent(agent_id).await?;
        Ok(AgentState::Paused)
    }

    /// Resume admission for a paused agent. The next turn receives a fresh
    /// cancellation token; repeating resume on Running is idempotent.
    pub async fn resume_agent(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        let started = std::time::Instant::now();
        self.record_lifecycle(
            agent_id,
            LifecycleOperation::Resume,
            LifecycleOutcome::Requested,
        );
        let result = self.resume_agent_inner(agent_id).await;
        self.record_lifecycle_result(agent_id, LifecycleOperation::Resume, &result, started);
        result
    }

    async fn resume_agent_inner(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        let _operator_mutation = self.operator_control.mutation_guard().await;
        let lock = self.lifecycle_lock(agent_id);
        let _guard = lock.lock().await;
        let state = self
            .agent_manager
            .get_agent_state(agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        if state == AgentState::Running {
            return Ok(state);
        }
        self.agent_manager.resume_agent(agent_id).await?;
        self.scheduler.set_queued(agent_id);
        self.context_manager
            .update_agent_status(agent_id, &AgentState::Running)?;
        Ok(AgentState::Running)
    }

    /// Gracefully stop an agent and atomically remove its live subsystem state.
    /// Durable conversations, facts, usage, and the terminal registry row are
    /// retained; repeating stop is idempotent.
    pub async fn stop_agent(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        let started = std::time::Instant::now();
        self.record_lifecycle(
            agent_id,
            LifecycleOperation::Stop,
            LifecycleOutcome::Requested,
        );
        let result = self.stop_agent_inner(agent_id).await;
        self.record_lifecycle_result(agent_id, LifecycleOperation::Stop, &result, started);
        result
    }

    async fn stop_agent_inner(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        let _operator_mutation = self.operator_control.mutation_guard().await;
        let lock = self.lifecycle_lock(agent_id);
        let _guard = lock.lock().await;
        let state = self
            .agent_manager
            .get_agent_state(agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        if state == AgentState::Stopped {
            self.cleanup_agent_resources(agent_id).await?;
            self.context_manager
                .update_agent_status(agent_id, &AgentState::Stopped)?;
            return Ok(state);
        }
        if state != AgentState::Stopping {
            if !matches!(
                state,
                AgentState::Running | AgentState::Paused | AgentState::Error(_)
            ) {
                return Err(AgentError::InvalidTransition {
                    from: state,
                    to: AgentState::Stopping,
                }
                .into());
            }
            self.quiesce_agent(agent_id).await?;
            self.drain_agent_tool_calls(agent_id).await?;
            if let Err(error) = self
                .context_manager
                .update_agent_status(agent_id, &AgentState::Stopping)
            {
                // A successful drain closes admission. If durable staging
                // fails, the in-memory agent is still runnable, so restore
                // admission before returning the persistence error.
                let _ = self.syscall_gate.reopen_tool_admission(agent_id);
                return Err(error.into());
            }
            self.agent_manager.force_stopping(agent_id)?;
        }
        self.cleanup_agent_resources(agent_id).await?;
        self.context_manager
            .update_agent_status(agent_id, &AgentState::Stopped)?;
        self.agent_manager.force_stopped(agent_id)?;
        Ok(AgentState::Stopped)
    }

    /// Force a terminal state from any non-terminal lifecycle state. Unlike
    /// graceful stop, kill does not wait for an uncooperative turn or external
    /// binding: it cancels execution, revokes admitted tool guards, and tears
    /// down every live subsystem immediately.
    pub async fn kill_agent(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        let started = std::time::Instant::now();
        self.record_lifecycle(
            agent_id,
            LifecycleOperation::Kill,
            LifecycleOutcome::Requested,
        );
        let result = self.kill_agent_inner(agent_id).await;
        self.record_lifecycle_result(agent_id, LifecycleOperation::Kill, &result, started);
        result
    }

    async fn kill_agent_inner(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        let _operator_mutation = self.operator_control.mutation_guard().await;
        let lock = self.lifecycle_lock(agent_id);
        let _guard = lock.lock().await;
        let state = self
            .agent_manager
            .get_agent_state(agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        if state == AgentState::Stopped {
            self.force_cleanup_agent_resources(agent_id).await?;
            self.context_manager
                .update_agent_status(agent_id, &AgentState::Stopped)?;
            return Ok(state);
        }
        if state != AgentState::Stopping {
            // The durable non-runnable marker commits before forced revocation.
            // A crash can therefore never re-admit a partially killed agent.
            self.context_manager
                .update_agent_status(agent_id, &AgentState::Stopping)?;
            self.agent_manager.force_stopping(agent_id)?;
        }
        if let Some(token) = self.active_cancellations.get(&agent_id) {
            token.cancel();
        }
        self.force_cleanup_agent_resources(agent_id).await?;
        self.context_manager
            .update_agent_status(agent_id, &AgentState::Stopped)?;
        self.agent_manager.force_stopped(agent_id)?;
        Ok(AgentState::Stopped)
    }

    pub fn get_agent_status(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        self.agent_manager
            .get_agent_state(agent_id)
            .ok_or_else(|| AgentError::NotFound(agent_id).into())
    }

    pub async fn wait_agent(
        &self,
        agent_id: AgentId,
        timeout: std::time::Duration,
    ) -> Result<AgentState, KernelError> {
        let started = std::time::Instant::now();
        self.record_lifecycle(
            agent_id,
            LifecycleOperation::Wait,
            LifecycleOutcome::Requested,
        );
        let result = self.wait_agent_inner(agent_id, timeout).await;
        self.record_lifecycle_result(agent_id, LifecycleOperation::Wait, &result, started);
        result
    }

    async fn wait_agent_inner(
        &self,
        agent_id: AgentId,
        timeout: std::time::Duration,
    ) -> Result<AgentState, KernelError> {
        tokio::time::timeout(timeout, async {
            loop {
                let state = self.get_agent_status(agent_id)?;
                if matches!(state, AgentState::Stopped | AgentState::Error(_)) {
                    return Ok(state);
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| KernelError::LifecycleTimeout("wait_agent timed out".into()))?
    }

    /// Force-clean active turns that have made no recorded progress within the
    /// watchdog bound. Idle runnable agents are deliberately excluded: only an
    /// agent with a live cancellation token can be classified as unresponsive.
    pub(crate) async fn watchdog_sweep(&self) -> Vec<AgentId> {
        let cutoff = chrono::Utc::now()
            - chrono::Duration::from_std(Self::WATCHDOG_TIMEOUT)
                .expect("fixed watchdog timeout is representable");
        let candidates = self
            .agent_manager
            .list_agents(None)
            .into_iter()
            .filter(|agent| self.active_cancellations.contains_key(&agent.id))
            .filter(|agent| self.agent_manager.is_unresponsive_since(agent.id, cutoff))
            .map(|agent| agent.id)
            .collect::<Vec<_>>();
        let mut terminated = Vec::new();
        for agent_id in candidates {
            // Recheck active membership immediately before the coordinator
            // call. A turn that completed while the sweep was being assembled
            // must not be killed merely because its previous timestamp aged.
            if self.active_cancellations.contains_key(&agent_id)
                && self.kill_agent(agent_id).await.is_ok()
            {
                terminated.push(agent_id);
            }
        }
        terminated
    }

    /// Latest active durable turn checkpoint for an agent, if any.
    pub fn latest_generation_checkpoint(
        &self,
        agent_id: AgentId,
    ) -> Result<Option<crate::context::GenerationCheckpointMetadata>, KernelError> {
        let tenant = self
            .context_manager
            .agent_tenant(agent_id)?
            .ok_or(AgentError::NotFound(agent_id))?;
        Ok(self
            .context_manager
            .list_generation_checkpoints(&tenant, Some(agent_id))?
            .into_iter()
            .next())
    }

    /// Content-free durable and live context-pressure usage for one agent.
    pub fn context_pressure_stats(
        &self,
        agent_id: AgentId,
    ) -> Result<crate::context::ContextPressureStats, KernelError> {
        let mut stats = self.context_manager.context_pressure_stats(agent_id)?;
        let active = self.context_admission.usage(agent_id, &stats.tenant_id);
        stats.agent_active_tokens = active.agent_tokens;
        stats.agent_active_limit = active.per_agent_limit;
        stats.tenant_active_tokens = active.tenant_tokens;
        stats.tenant_active_limit = active.per_tenant_limit;
        stats.global_active_tokens = active.global_tokens;
        stats.global_active_limit = active.global_limit;
        stats.active_rejection_count = active.rejection_count;
        Ok(stats)
    }

    /// Resume the newest (or explicitly selected) durable in-flight turn while
    /// holding lifecycle admission. Returns the completed output, or a new
    /// checkpoint id if another pause interrupted the continuation.
    pub async fn resume_agent_from_checkpoint(
        &self,
        agent_id: AgentId,
        checkpoint_id: Option<uuid::Uuid>,
    ) -> Result<(AgentState, Option<AgentOutput>, Option<uuid::Uuid>), KernelError> {
        let started = std::time::Instant::now();
        self.record_lifecycle(
            agent_id,
            LifecycleOperation::Resume,
            LifecycleOutcome::Requested,
        );
        let result = self
            .resume_agent_from_checkpoint_inner(agent_id, checkpoint_id)
            .await;
        self.record_lifecycle_result(agent_id, LifecycleOperation::Resume, &result, started);
        result
    }

    async fn resume_agent_from_checkpoint_inner(
        &self,
        agent_id: AgentId,
        checkpoint_id: Option<uuid::Uuid>,
    ) -> Result<(AgentState, Option<AgentOutput>, Option<uuid::Uuid>), KernelError> {
        let _operator_mutation = self.operator_control.mutation_guard().await;
        let lifecycle_lock = self.lifecycle_lock(agent_id);
        let lifecycle_guard = lifecycle_lock.lock().await;
        let state = self.get_agent_status(agent_id)?;
        if state == AgentState::Running && checkpoint_id.is_none() {
            return Ok((state, None, None));
        }
        if state != AgentState::Paused {
            return Err(AgentError::InvalidTransition {
                from: state,
                to: AgentState::Running,
            }
            .into());
        }
        let tenant = self
            .context_manager
            .agent_tenant(agent_id)?
            .ok_or(AgentError::NotFound(agent_id))?;
        let checkpoint_id = match checkpoint_id {
            Some(id) => Some(id),
            None => self
                .context_manager
                .list_generation_checkpoints(&tenant, Some(agent_id))?
                .into_iter()
                .next()
                .map(|checkpoint| checkpoint.id),
        };

        // A pause that won a completion race legitimately has no turn to
        // restore. It still behaves as a normal lifecycle resume.
        let Some(checkpoint_id) = checkpoint_id else {
            self.agent_manager.resume_agent(agent_id).await?;
            self.scheduler.set_queued(agent_id);
            self.context_manager
                .update_agent_status(agent_id, &AgentState::Running)?;
            return Ok((AgentState::Running, None, None));
        };

        let stored =
            self.context_manager
                .claim_generation_checkpoint(checkpoint_id, agent_id, &tenant)?;
        let executor = match self.ensure_executor(agent_id).await {
            Ok(executor) => executor,
            Err(error) => {
                self.context_manager
                    .release_generation_checkpoint(checkpoint_id)?;
                return Err(error);
            }
        };
        let mut executor = executor.lock().await;
        if executor.provider_id() != stored.metadata.provider_id
            || executor.model_id() != stored.metadata.model_id
        {
            let actual = format!("{}/{}", executor.provider_id(), executor.model_id());
            let expected = format!(
                "{}/{}",
                stored.metadata.provider_id, stored.metadata.model_id
            );
            drop(executor);
            self.context_manager
                .release_generation_checkpoint(checkpoint_id)?;
            return Err(KernelError::Policy(format!(
                "checkpoint provider/model mismatch: expected {expected}, current {actual}; restore the original config or delete the checkpoint"
            )));
        }

        self.agent_manager.resume_agent(agent_id).await?;
        self.scheduler.set_queued(agent_id);
        self.context_manager
            .update_agent_status(agent_id, &AgentState::Running)?;
        let cancellation = executor.renew_cancel_token();
        self.agent_manager.record_activity(agent_id);
        self.active_cancellations.insert(agent_id, cancellation);
        drop(lifecycle_guard);

        let admission_cancellation = executor.cancel_token();
        let _turn_slot = match self.syscall_gate.pid_of(agent_id) {
            Some(pid) => match self
                .turn_admission
                .acquire_cancellable(pid, &self.os.cfs, &admission_cancellation)
                .await
            {
                Ok(slot) => Some(slot),
                Err(SchedulerError::AdmissionCancelled(_)) => None,
                Err(error) => {
                    self.active_cancellations.remove(&agent_id);
                    return Err(error.into());
                }
            },
            None => None,
        };
        self.scheduler.set_running(agent_id);
        let baseline = stored.checkpoint.clone();
        let run_result = executor.resume(stored.checkpoint).await;
        self.active_cancellations.remove(&agent_id);
        match self.agent_manager.get_agent_state(agent_id) {
            Some(AgentState::Running) => self.scheduler.set_queued(agent_id),
            Some(AgentState::Paused) => self.scheduler.set_paused(agent_id),
            _ => self.scheduler.deschedule(agent_id),
        }
        drop(_turn_slot);
        drop(executor);

        match run_result {
            Ok(TurnResult::Completed(output)) => {
                self.context_manager
                    .consume_generation_checkpoint(checkpoint_id)?;
                self.record_output_since(
                    agent_id,
                    &output,
                    baseline.tokens_used,
                    baseline.tool_calls_made,
                    baseline.usage,
                )
                .await?;
                Ok((self.get_agent_status(agent_id)?, Some(output), None))
            }
            Ok(TurnResult::Paused(checkpoint)) => {
                if self.get_agent_status(agent_id)? != AgentState::Paused {
                    self.context_manager
                        .release_generation_checkpoint(checkpoint_id)?;
                    return Err(KernelError::Policy(
                        "checkpoint resume cancelled by terminal lifecycle operation".into(),
                    ));
                }
                let executor = self
                    .executors
                    .get(&agent_id)
                    .map(|entry| Arc::clone(entry.value()))
                    .ok_or(AgentError::NotFound(agent_id))?;
                let executor = executor.lock().await;
                let new_id = self.context_manager.save_generation_checkpoint(
                    &tenant,
                    executor.provider_id(),
                    executor.model_id(),
                    &checkpoint,
                    std::time::Duration::from_secs(24 * 60 * 60),
                )?;
                let output = AgentOutput {
                    content: format!("Paused at durable checkpoint {new_id}."),
                    tool_calls_made: checkpoint.tool_calls_made,
                    tokens_used: checkpoint.tokens_used,
                    provider_id: executor.provider_id().to_string(),
                    model_id: executor.model_id().to_string(),
                    estimated_cost_usd: checkpoint.usage.charged_cost_micros as f64 / 1_000_000.0,
                    usage: checkpoint.usage,
                };
                drop(executor);
                self.context_manager
                    .consume_generation_checkpoint(checkpoint_id)?;
                self.record_output_since(
                    agent_id,
                    &output,
                    baseline.tokens_used,
                    baseline.tool_calls_made,
                    baseline.usage,
                )
                .await?;
                Ok((AgentState::Paused, Some(output), Some(new_id)))
            }
            Err(error) => {
                self.context_manager
                    .release_generation_checkpoint(checkpoint_id)?;
                let lifecycle_guard = lifecycle_lock.lock().await;
                if self.get_agent_status(agent_id)? == AgentState::Running {
                    self.agent_manager.pause_agent(agent_id).await?;
                    self.scheduler.set_paused(agent_id);
                    self.context_manager
                        .update_agent_status(agent_id, &AgentState::Paused)?;
                }
                drop(lifecycle_guard);
                Err(error)
            }
        }
    }

    /// Create and configure the per-agent executor. Callers serialize this with
    /// the lifecycle lock, so provider sessions cannot be created after stop.
    async fn ensure_executor(
        &self,
        agent_id: AgentId,
    ) -> Result<Arc<tokio::sync::Mutex<AgentExecutor>>, KernelError> {
        if let Some(executor) = self.executors.get(&agent_id) {
            return Ok(Arc::clone(executor.value()));
        }
        let provider_id = self
            .agent_manager
            .get_agent_provider(agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        let session = self
            .connector
            .connect_resilient(agent_id, &provider_id)
            .await
            .map_err(KernelError::Connector)?;
        let mut executor = AgentExecutor::new(
            agent_id,
            session,
            self.resource_broker.clone() as Arc<dyn ResourceBroker>,
            self.tool_registry.clone(),
            self.context_manager.clone(),
            self.syscall_gate.clone(),
            "You are a helpful AI assistant. Use the available tools to help the user.".into(),
        );
        executor.set_budget_enforcer(self.budget_enforcer.clone());
        executor.set_rate_limiter(self.rate_limiter.clone());
        executor.set_context_budget(self.context_budget_tokens);
        let tenant_id = self
            .context_manager
            .agent_tenant(agent_id)?
            .unwrap_or_else(|| crate::context::DEFAULT_TENANT.to_string());
        executor.set_context_admission(self.context_admission.clone(), tenant_id);
        executor.set_max_tool_calls(self.max_tool_calls_per_turn);
        executor.set_max_output_tokens_per_request(self.max_output_tokens_per_request);
        executor.set_provider_request_timeout(self.provider_request_timeout);
        if let Some(pid) = self.syscall_gate.pid_of(agent_id) {
            let nice = self.os.cfs.lock().await.nice_of(pid).unwrap_or(0);
            executor.set_llm_scheduler(self.llm_scheduler.clone(), pid, nice);
        }
        let executor = Arc::new(tokio::sync::Mutex::new(executor));
        self.executors.insert(agent_id, Arc::clone(&executor));
        Ok(executor)
    }

    async fn record_output_since(
        &self,
        agent_id: AgentId,
        output: &AgentOutput,
        baseline_tokens: u32,
        baseline_tools: usize,
        baseline_usage: crate::execution::UsageTelemetry,
    ) -> Result<(), KernelError> {
        let tokens = output.tokens_used.saturating_sub(baseline_tokens);
        let tools = output.tool_calls_made.saturating_sub(baseline_tools);
        let usage = crate::execution::UsageTelemetry {
            input_tokens: output
                .usage
                .input_tokens
                .saturating_sub(baseline_usage.input_tokens),
            output_tokens: output
                .usage
                .output_tokens
                .saturating_sub(baseline_usage.output_tokens),
            cached_tokens: output
                .usage
                .cached_tokens
                .saturating_sub(baseline_usage.cached_tokens),
            llm_requests: output
                .usage
                .llm_requests
                .saturating_sub(baseline_usage.llm_requests),
            retries: output.usage.retries.saturating_sub(baseline_usage.retries),
            provider_latency_ms: output
                .usage
                .provider_latency_ms
                .saturating_sub(baseline_usage.provider_latency_ms),
            provider_reported_requests: output
                .usage
                .provider_reported_requests
                .saturating_sub(baseline_usage.provider_reported_requests),
            estimated_requests: output
                .usage
                .estimated_requests
                .saturating_sub(baseline_usage.estimated_requests),
            charged_cost_micros: output
                .usage
                .charged_cost_micros
                .saturating_sub(baseline_usage.charged_cost_micros),
        };
        self.agent_manager.record_activity(agent_id);
        ObservabilityEngine::record_metrics(
            &*self.observability,
            agent_id,
            u64::from(tokens),
            u64::from(usage.llm_requests),
        );
        self.context_manager.log_usage(
            agent_id,
            &UsageRecord {
                tokens_used: tokens,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cached_tokens: usage.cached_tokens,
                llm_requests: usage.llm_requests,
                retries: usage.retries,
                provider_latency_ms: usage.provider_latency_ms,
                provider_reported_requests: usage.provider_reported_requests,
                estimated_requests: usage.estimated_requests,
                provider: output.provider_id.clone(),
                model: output.model_id.clone(),
                tool_calls: tools,
                estimated_cost_usd: usage.charged_cost_micros as f64 / 1_000_000.0,
                cost_micros: usage.charged_cost_micros,
            },
        )?;
        if let Some(pid) = self.syscall_gate.pid_of(agent_id) {
            let yielded = {
                let mut scheduler = self.os.cfs.lock().await;
                scheduler.account_tokens(pid, u64::from(tokens));
                let yielded = scheduler.time_slice_expired(pid);
                if yielded {
                    // The live contract yields only at a completed turn
                    // boundary; this is not CPU or mid-future preemption.
                    scheduler.reset_slice(pid);
                }
                yielded
            };
            if yielded {
                self.turn_admission.record_cooperative_yield();
            }
        }
        Ok(())
    }

    /// Send a message to an agent and get a response.
    /// Creates an executor on first message using the agent's LLM provider.
    pub async fn send_message(
        &self,
        agent_id: AgentId,
        message: &str,
    ) -> Result<AgentOutput, KernelError> {
        self.send_message_inner(agent_id, message, None, None).await
    }

    /// Send a message while publishing bounded execution events and registering
    /// an exact request id that a separately authenticated connection can
    /// cancel. Request ids are scoped by agent ownership.
    pub async fn send_message_stream(
        &self,
        agent_id: AgentId,
        message: &str,
        request_id: &str,
        events: tokio::sync::mpsc::Sender<crate::execution::StreamEvent>,
    ) -> Result<AgentOutput, KernelError> {
        if request_id.is_empty() || request_id.len() > 128 {
            return Err(KernelError::Policy(
                "request id must contain 1..=128 bytes".into(),
            ));
        }
        self.send_message_inner(
            agent_id,
            message,
            Some(request_id.to_string()),
            Some(events),
        )
        .await
    }

    /// Signal one exact active streaming request. The public wire authorizes
    /// the agent before calling this method, so a request id alone is never an
    /// ambient cancellation capability.
    pub fn cancel_request(&self, agent_id: AgentId, request_id: &str) -> bool {
        let key = (agent_id, request_id.to_string());
        let Some(token) = self.active_requests.get(&key) else {
            return false;
        };
        token.cancel();
        true
    }

    async fn send_message_inner(
        &self,
        agent_id: AgentId,
        message: &str,
        request_id: Option<String>,
        events: Option<tokio::sync::mpsc::Sender<crate::execution::StreamEvent>>,
    ) -> Result<AgentOutput, KernelError> {
        // Serialize executor creation against pause/stop/kill and reject work
        // unless the agent is currently runnable.
        let lifecycle_lock = self.lifecycle_lock(agent_id);
        let lifecycle_guard = lifecycle_lock.lock().await;
        let state = self.get_agent_status(agent_id)?;
        if state != AgentState::Running {
            return Err(AgentError::InvalidTransition {
                from: state,
                to: AgentState::Running,
            }
            .into());
        }

        // Ensure executor exists for this agent. The lifecycle lock makes the
        // check-and-insert atomic without holding a DashMap shard across await.
        let executor = self.ensure_executor(agent_id).await?;
        drop(lifecycle_guard);

        // Serialize same-agent turns before consuming any global admission,
        // rate-limit, or LLM capacity. A second request for this agent waits on
        // its executor mutex without occupying scarce system slots.
        // Acquire lifecycle + executor without ever waiting for lifecycle while
        // holding the executor. This ordering lets pause/stop cancel and then
        // wait for an active turn without deadlocking a queued same-agent turn.
        let mut executor = loop {
            let lifecycle_guard = lifecycle_lock.lock().await;
            let state = self.get_agent_status(agent_id)?;
            if state != AgentState::Running {
                return Err(AgentError::InvalidTransition {
                    from: state,
                    to: AgentState::Running,
                }
                .into());
            }
            match executor.try_lock() {
                Ok(mut executor_guard) => {
                    let cancellation = executor_guard.renew_cancel_token();
                    self.agent_manager.record_activity(agent_id);
                    self.active_cancellations
                        .insert(agent_id, cancellation.clone());
                    if let Some(request_id) = request_id.as_ref() {
                        self.active_requests
                            .insert((agent_id, request_id.clone()), cancellation);
                    }
                    drop(lifecycle_guard);
                    break executor_guard;
                }
                Err(_) => {
                    drop(lifecycle_guard);
                    // Wait for the active turn to finish, immediately release,
                    // then retry the state+lock pair atomically.
                    let busy = executor.lock().await;
                    drop(busy);
                }
            }
        };
        let registration = ActiveTurnRegistration {
            kernel: self,
            agent_id,
            request_id: request_id.clone(),
        };
        if let Some(events) = events {
            executor.set_event_channel(events.clone());
            if let Some(request_id) = request_id.as_ref() {
                let _ = events
                    .send(crate::execution::StreamEvent::Started {
                        request_id: request_id.clone(),
                    })
                    .await;
            }
        }

        // CFS-ordered turn admission: under contention (more agents than
        // `max_concurrent` slots) the next freed slot goes to the
        // lowest-vruntime / highest-priority waiter, so nice values decide who
        // runs next — not just FIFO. Uncontended turns admit immediately. Held
        // for the whole turn; released on drop. Keyed by the agent's CFS PID.
        let admission_cancellation = executor.cancel_token();
        let _turn_slot = match self.syscall_gate.pid_of(agent_id) {
            Some(pid) => match self
                .turn_admission
                .acquire_cancellable(pid, &self.os.cfs, &admission_cancellation)
                .await
            {
                Ok(slot) => Some(slot),
                Err(SchedulerError::AdmissionCancelled(_)) => None,
                Err(error) => {
                    executor.clear_event_channel();
                    drop(registration);
                    return Err(error.into());
                }
            },
            None => None,
        };

        // Run the execution loop. Provider-attempt RPM/TPM/concurrency is
        // enforced inside the executor; this outer gate is turn admission only.
        // Mark the agent as actively executing for the duration of this turn so
        // `running_agents` reflects real concurrency, then return it to Queued.
        // Set/clear around `run` (not via `?`) so the slot is freed even when
        // the turn errors.
        self.scheduler.set_running(agent_id);
        let run_result = executor.run_resumable(message).await;
        executor.clear_event_channel();
        drop(registration);
        let output = match run_result? {
            TurnResult::Completed(output) => output,
            TurnResult::Paused(checkpoint) => {
                if self.get_agent_status(agent_id)? != AgentState::Paused {
                    return Err(KernelError::Policy(
                        "agent turn cancelled by terminal lifecycle operation".into(),
                    ));
                }
                let tenant = self
                    .context_manager
                    .agent_tenant(agent_id)?
                    .ok_or(AgentError::NotFound(agent_id))?;
                let checkpoint_id = self.context_manager.save_generation_checkpoint(
                    &tenant,
                    executor.provider_id(),
                    executor.model_id(),
                    &checkpoint,
                    std::time::Duration::from_secs(24 * 60 * 60),
                )?;
                AgentOutput {
                    content: format!("Paused at durable checkpoint {checkpoint_id}."),
                    tool_calls_made: checkpoint.tool_calls_made,
                    tokens_used: checkpoint.tokens_used,
                    provider_id: executor.provider_id().to_string(),
                    model_id: executor.model_id().to_string(),
                    estimated_cost_usd: checkpoint.usage.charged_cost_micros as f64 / 1_000_000.0,
                    usage: checkpoint.usage,
                }
            }
        };

        self.record_output_since(
            agent_id,
            &output,
            0,
            0,
            crate::execution::UsageTelemetry::default(),
        )
        .await?;

        Ok(output)
    }

    /// Update an agent's nice value (priority hint for the CFS scheduler).
    /// Range: -20 (highest priority) to +19 (lowest). Linux semantics.
    pub async fn set_nice(&self, agent_id: AgentId, nice: i8) -> Result<(), KernelError> {
        let pid = self
            .syscall_gate
            .pid_of(agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        let mut sched = self.os.cfs.lock().await;
        if sched.update_nice(pid, nice) {
            Ok(())
        } else {
            Err(AgentError::NotFound(agent_id).into())
        }
    }

    /// Look up which agent CFS would pick next. Useful for fairness tests
    /// and for callers that want admission control.
    pub async fn next_runnable_agent(&self) -> Option<AgentId> {
        let mut sched = self.os.cfs.lock().await;
        let pid = sched.pick_next()?;
        // Reverse PID → UUID lookup. Linear scan is fine given the
        // typical fleet size (10s, not 10K).
        for entry in self.executors.iter() {
            let kid = *entry.key();
            if self.syscall_gate.pid_of(kid) == Some(pid) {
                return Some(kid);
            }
        }
        // Agents may exist without an executor (created but never sent a
        // message); fall back to scanning the agent manager.
        for info in self.agent_manager.list_agents(None) {
            if self.syscall_gate.pid_of(info.id) == Some(pid) {
                return Some(info.id);
            }
        }
        None
    }

    /// Graceful shutdown — persist all agent states, terminate sessions.
    pub async fn shutdown(&self) -> Result<Vec<AgentId>, KernelError> {
        let _ = self.event_tx.send(KernelEvent::ShutdownInitiated);

        let mut stopped = Vec::new();
        let mut failures = Vec::new();

        // Coordinated services stop first in reverse dependency order. Their
        // agents become terminal through `stop_agent`, so the general pass
        // below naturally skips them.
        {
            let _operation = self.service_operation_lock.lock().await;
            let service_shutdown_order = {
                let init = self.os.init.lock().await;
                init.reverse_boot_order()
            };
            for service in service_shutdown_order {
                let agent_id = self
                    .os
                    .init
                    .lock()
                    .await
                    .state(&service)
                    .and_then(|state| state.agent_id);
                match self.stop_service_inner(&service, false).await {
                    Ok(()) => {
                        if let Some(agent_id) = agent_id {
                            stopped.push(agent_id);
                        }
                    }
                    Err(error) => {
                        failures.push(format!("service {service}: {error}"));
                    }
                }
            }
        }

        let agents = self.agent_manager.list_agents(None);

        for info in agents {
            if stopped.contains(&info.id) || info.state == AgentState::Stopped {
                continue;
            }
            let mut result = match info.state {
                AgentState::Running | AgentState::Paused | AgentState::Error(_) => {
                    self.stop_agent(info.id).await
                }
                AgentState::Initializing | AgentState::Stopping => self.kill_agent(info.id).await,
                AgentState::Stopped => unreachable!("stopped agents are skipped above"),
            };
            if matches!(&result, Err(KernelError::LifecycleTimeout(_))) {
                // Shutdown is terminal: an uncooperative provider/tool binding
                // must not keep the process alive indefinitely. Escalate only
                // bounded graceful timeouts; structural cleanup faults remain
                // visible to the caller and retryable.
                result = self.kill_agent(info.id).await;
            }
            match result {
                Ok(_) => stopped.push(info.id),
                Err(error) => failures.push(format!("agent {}: {error}", info.id)),
            }
        }

        // Flush the WAL into the main DB file so a subsequent open recovers a
        // fully-consolidated, consistent database. Best-effort. (Crash recovery
        // does NOT depend on this — committed transactions are already durable;
        // this just truncates the WAL on a clean exit.)
        if let Err(error) = self.context_manager.checkpoint() {
            failures.push(format!("WAL checkpoint: {error}"));
        }

        if failures.is_empty() {
            Ok(stopped)
        } else {
            Err(KernelError::LifecycleCleanup(format!(
                "shutdown incomplete ({} agent(s) stopped): {}",
                stopped.len(),
                failures.join("; ")
            )))
        }
    }

    /// Subscribe to kernel events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<KernelEvent> {
        self.event_tx.subscribe()
    }

    /// Spawn the kernel's scheduler observer, which publishes the CFS pick to
    /// procfs as `current_agent`. Durable fixed-epoch quota windows need no
    /// background reset timer. Returns the
    /// [`KernelRuntime`](crate::runtime::KernelRuntime) so the caller can
    /// `stop()` it on shutdown. Starting the returned runtime more than once is
    /// idempotent and does not create duplicate background loops.
    pub fn start_runtime(self: &Arc<Self>) -> crate::runtime::KernelRuntime {
        let runtime = crate::runtime::KernelRuntime::new(self.clone());
        let _handles = runtime.start();
        // Handles are intentionally dropped — `running` flag drives the loop
        // exit. Keep the runtime so callers can call `stop()`.
        runtime
    }
}

/// Documented top-level entry point: construct the kernel from config and
/// spawn its background tasks. Both the CLI and Tauri app should use this
/// instead of poking at `AgentKernelImpl::from_config` + `start_runtime`
/// separately.
pub fn boot(config: &crate::config::Config) -> Result<Arc<AgentKernelImpl>, KernelError> {
    let kernel = Arc::new(AgentKernelImpl::from_config(config)?);
    let _runtime = kernel.start_runtime();
    // The background tasks are detached: each holds its own clone of the
    // runtime's `running` flag, so dropping the `KernelRuntime` here does NOT
    // stop them — they run for the life of the process (the intended behavior
    // for a long-lived daemon). Callers that need graceful shutdown should call
    // `start_runtime()` themselves and hold the returned `KernelRuntime` to call
    // `stop()` (which flips `running` and lets the loops exit on next tick).
    Ok(kernel)
}

/// In-memory variant of [`boot`] for tests and quick scripts.
pub fn boot_in_memory() -> Result<Arc<AgentKernelImpl>, KernelError> {
    let kernel = Arc::new(AgentKernelImpl::new()?);
    let _runtime = kernel.start_runtime();
    Ok(kernel)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle_test_config(name: &str) -> AgentConfig {
        AgentConfig {
            name: name.into(),
            task: "lifecycle atomicity regression".into(),
            llm_provider: "test".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        }
    }

    fn durable_agent_status(context: &SqliteContextManager, agent_id: AgentId) -> AgentState {
        let persisted = context
            .load_all_agents()
            .unwrap()
            .into_iter()
            .find(|agent| agent.id == agent_id)
            .expect("agent registry row");
        serde_json::from_str(&persisted.status).expect("typed durable lifecycle state")
    }

    #[test]
    fn invalid_budget_config_is_rejected_before_creating_the_data_directory() {
        let root =
            std::env::temp_dir().join(format!("agentos-invalid-budget-{}", uuid::Uuid::new_v4()));
        let config = crate::config::Config {
            data_dir: root.join("nested"),
            budgets: crate::config::BudgetConfig {
                default_token_pricing: Some(crate::config::TokenPricing {
                    input_usd_per_1k_tokens: f64::NAN,
                    cached_input_usd_per_1k_tokens: 0.0,
                    output_usd_per_1k_tokens: 1.0,
                }),
                ..crate::config::BudgetConfig::default()
            },
            ..crate::config::Config::default()
        };

        let error = AgentKernelImpl::from_config(&config)
            .err()
            .expect("invalid pricing must fail startup");
        assert!(error.to_string().contains("invalid budget configuration"));
        assert!(
            !root.exists(),
            "validation must run before data-directory side effects"
        );
    }

    #[test]
    fn scheduled_backup_config_is_applied_and_invalid_policy_has_no_storage_side_effect() {
        let root =
            std::env::temp_dir().join(format!("agentos-backup-config-{}", uuid::Uuid::new_v4()));
        let invalid = crate::config::Config {
            data_dir: root.join("invalid-data"),
            backup: crate::config::BackupScheduleConfig {
                enabled: true,
                root: None,
                ..crate::config::BackupScheduleConfig::default()
            },
            ..crate::config::Config::default()
        };
        let error = AgentKernelImpl::from_config(&invalid)
            .err()
            .expect("missing scheduled backup root must fail startup");
        assert!(error.to_string().contains("backup.root"));
        assert!(!root.exists());

        let config = crate::config::Config {
            data_dir: root.join("data"),
            backup: crate::config::BackupScheduleConfig {
                enabled: true,
                root: Some(root.join("backups")),
                interval_seconds: 300,
                run_on_start: false,
                keep_latest: 4,
                max_age_seconds: 86_400,
                ..crate::config::BackupScheduleConfig::default()
            },
            ..crate::config::Config::default()
        };
        let kernel = AgentKernelImpl::from_config(&config).unwrap();
        let status = kernel.backup_maintenance.status();
        let expected_backup_root = root.join("backups").to_string_lossy().into_owned();
        assert!(status.enabled);
        assert_eq!(status.interval_seconds, 300);
        assert_eq!(status.keep_latest, 4);
        assert_eq!(
            status.backup_root.as_deref(),
            Some(expected_backup_root.as_str())
        );
        drop(kernel);
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn hot_erasure_purges_managed_backups_before_agent_user_and_tenant_commits() {
        let root = std::env::temp_dir().join(format!(
            "agentos-managed-backup-erasure-{}",
            uuid::Uuid::new_v4()
        ));
        let backup_root = root.join("backups");
        let config = crate::config::Config {
            data_dir: root.join("data"),
            backup: crate::config::BackupScheduleConfig {
                root: Some(backup_root.clone()),
                ..crate::config::BackupScheduleConfig::default()
            },
            ..crate::config::Config::default()
        };
        let kernel = AgentKernelImpl::from_config(&config).unwrap();
        let tenant = kernel.create_tenant("managed-erasure").await.unwrap();
        let user = kernel
            .register_user(
                &tenant,
                "managed-erasure-user",
                "managed-erasure@example.test",
                crate::auth::Role::User,
            )
            .await
            .unwrap();
        let agent = kernel
            .create_agent_for_tenant(&tenant, lifecycle_test_config("managed-erasure-agent"))
            .await
            .unwrap()
            .id;

        kernel
            .backup_maintenance
            .create_backup(&kernel.context_manager, &backup_root, "before_agent")
            .unwrap();
        let agent_receipt = kernel
            .erase_agent_data(agent)
            .await
            .unwrap()
            .expect("agent data existed");
        assert_eq!(
            agent_receipt.deleted_rows.get("managed_backup_copies"),
            Some(&1)
        );
        assert!(!backup_root.join("before_agent").exists());

        kernel
            .backup_maintenance
            .create_backup(&kernel.context_manager, &backup_root, "before_user")
            .unwrap();
        let user_receipt = kernel
            .erase_user_data(&user)
            .await
            .unwrap()
            .expect("user data existed");
        assert_eq!(
            user_receipt.deleted_rows.get("managed_backup_copies"),
            Some(&1)
        );
        assert!(!backup_root.join("before_user").exists());

        kernel
            .backup_maintenance
            .create_backup(&kernel.context_manager, &backup_root, "before_tenant")
            .unwrap();
        let tenant_receipt = kernel
            .erase_tenant_data(&tenant)
            .await
            .unwrap()
            .expect("tenant data existed");
        assert_eq!(
            tenant_receipt.deleted_rows.get("managed_backup_copies"),
            Some(&1)
        );
        assert!(!backup_root.join("before_tenant").exists());
        let status = kernel.backup_maintenance.status();
        assert_eq!(status.erasure_purge_attempts_total, 3);
        assert_eq!(status.erasure_purge_successes_total, 3);
        assert_eq!(status.erasure_purge_failures_total, 0);
        assert_eq!(status.erasure_purge_deleted_total, 3);

        drop(kernel);
        let restarted = AgentKernelImpl::from_config(&config).unwrap();
        assert!(restarted
            .context_manager
            .agent_tenant(agent)
            .unwrap()
            .is_none());
        assert!(restarted.auth.read().await.get_user(&user).is_none());
        assert!(restarted.auth.read().await.get_tenant(&tenant).is_none());
        restarted
            .backup_maintenance
            .create_backup(
                &restarted.context_manager,
                &backup_root,
                "post_erasure_clean",
            )
            .unwrap();
        assert!(backup_root.join("post_erasure_clean").exists());
        drop(restarted);
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn unsafe_managed_backup_root_aborts_before_live_or_durable_erasure() {
        let root = std::env::temp_dir().join(format!(
            "agentos-managed-backup-refusal-{}",
            uuid::Uuid::new_v4()
        ));
        let backup_root = root.join("backups");
        let config = crate::config::Config {
            data_dir: root.join("data"),
            backup: crate::config::BackupScheduleConfig {
                root: Some(backup_root.clone()),
                ..crate::config::BackupScheduleConfig::default()
            },
            ..crate::config::Config::default()
        };
        let kernel = AgentKernelImpl::from_config(&config).unwrap();
        let tenant = kernel.create_tenant("managed-refusal").await.unwrap();
        let agent = kernel
            .create_agent_for_tenant(&tenant, lifecycle_test_config("managed-refusal-agent"))
            .await
            .unwrap()
            .id;
        kernel
            .backup_maintenance
            .create_backup(&kernel.context_manager, &backup_root, "known_backup")
            .unwrap();
        std::fs::write(backup_root.join("operator_notes"), b"unknown root entry").unwrap();

        let error = kernel.erase_agent_data(agent).await.unwrap_err();
        assert!(error.to_string().contains("not a real backup directory"));
        assert_eq!(
            kernel.context_manager.agent_tenant(agent).unwrap(),
            Some(tenant)
        );
        assert!(kernel.agent_manager.get_agent_state(agent).is_some());
        assert!(kernel.syscall_gate.agent_info(agent).is_some());
        assert!(backup_root.join("known_backup").exists());
        let status = kernel.backup_maintenance.status();
        assert_eq!(status.erasure_purge_attempts_total, 1);
        assert_eq!(status.erasure_purge_successes_total, 0);
        assert_eq!(status.erasure_purge_failures_total, 1);
        assert_eq!(status.erasure_purge_deleted_total, 0);

        std::fs::remove_file(backup_root.join("operator_notes")).unwrap();
        let receipt = kernel
            .erase_agent_data(agent)
            .await
            .unwrap()
            .expect("agent data existed on retry");
        assert_eq!(receipt.deleted_rows.get("managed_backup_copies"), Some(&1));
        drop(kernel);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn encrypted_config_persists_restarts_and_rejects_wrong_or_missing_keys() {
        let root =
            std::env::temp_dir().join(format!("agentos-encrypted-config-{}", uuid::Uuid::new_v4()));
        let key_dir = root.join("operator-keys");
        std::fs::create_dir_all(&key_dir).unwrap();
        let key_path = key_dir.join("storage.json");
        crate::storage_encryption::generate_storage_encryption_key_file(
            "storage-generation-1",
            &key_path,
        )
        .unwrap();
        let config = crate::config::Config {
            data_dir: root.join("data"),
            storage_encryption: crate::config::StorageEncryptionConfig {
                required: true,
                key_path: Some(key_path.clone()),
                retired_key_paths: Vec::new(),
            },
            ..crate::config::Config::default()
        };
        let database_path = config.data_dir.join("agent_os.db");
        let secret = "sensitive-agent-context-must-not-appear-in-sqlite-pages";

        {
            let kernel = AgentKernelImpl::from_config(&config).unwrap();
            assert_eq!(
                kernel.context_manager.storage_encryption_key_id(),
                Some("storage-generation-1")
            );
            kernel
                .context_manager
                .conn
                .lock()
                .unwrap()
                .execute_batch(&format!(
                    "CREATE TABLE encryption_restart_probe (value TEXT NOT NULL);
                     INSERT INTO encryption_restart_probe VALUES ('{secret}');"
                ))
                .unwrap();
        }

        let encrypted_bytes = std::fs::read(&database_path).unwrap();
        assert!(
            !encrypted_bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "sensitive context must not be visible in encrypted SQLite pages"
        );

        {
            let restarted = AgentKernelImpl::from_config(&config).unwrap();
            let persisted: String = restarted
                .context_manager
                .conn
                .lock()
                .unwrap()
                .query_row("SELECT value FROM encryption_restart_probe", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(persisted, secret);
        }
        let stable_database = std::fs::read(&database_path).unwrap();

        let wrong_key_path = key_dir.join("wrong.json");
        crate::storage_encryption::generate_storage_encryption_key_file(
            "storage-generation-wrong",
            &wrong_key_path,
        )
        .unwrap();
        let mut wrong_config = config.clone();
        wrong_config.storage_encryption.key_path = Some(wrong_key_path);
        let wrong_error = AgentKernelImpl::from_config(&wrong_config)
            .err()
            .expect("a wrong storage key must fail startup");
        assert!(
            wrong_error.to_string().contains("cannot authenticate"),
            "{wrong_error}"
        );
        assert_eq!(std::fs::read(&database_path).unwrap(), stable_database);

        std::fs::remove_file(&key_path).unwrap();
        let missing_error = AgentKernelImpl::from_config(&config)
            .err()
            .expect("a missing required storage key must fail startup");
        assert!(
            missing_error
                .to_string()
                .contains("failed to open storage key"),
            "{missing_error}"
        );
        assert_eq!(std::fs::read(&database_path).unwrap(), stable_database);

        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn in_memory_kernel_uses_production_mac_defaults() {
        let kernel = AgentKernelImpl::new().unwrap();
        assert!(kernel.syscall_gate.mac_is_enforcing().await);
    }

    struct LiveErasureCrashDatabase {
        root: std::path::PathBuf,
        path: std::path::PathBuf,
    }

    impl LiveErasureCrashDatabase {
        fn new(scope: &str, step: &str) -> Self {
            let safe_step = step.replace('.', "-");
            let root = std::env::temp_dir().join(format!(
                "agentos-live-erasure-{scope}-{safe_step}-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("agent_os.db");
            Self { root, path }
        }

        fn config(&self) -> crate::config::Config {
            crate::config::Config {
                data_dir: self.root.clone(),
                backup: crate::config::BackupScheduleConfig {
                    root: Some(self.root.join("backups")),
                    ..crate::config::BackupScheduleConfig::default()
                },
                ..crate::config::Config::default()
            }
        }

        fn backup_root(&self) -> std::path::PathBuf {
            self.root.join("backups")
        }
    }

    impl Drop for LiveErasureCrashDatabase {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    fn isolated_live_erasure_config(path: &std::path::Path, name: &str) -> AgentConfig {
        let mut config = lifecycle_test_config(name);
        config.sandbox_config = Some(SandboxConfig {
            workspace_dir: path
                .parent()
                .expect("live erasure database has a parent")
                .join(format!("workspace-{}", uuid::Uuid::new_v4())),
            allowed_network_hosts: Some(Vec::new()),
            max_disk_usage_bytes: Some(100 * 1024 * 1024),
            max_memory_bytes: Some(256 * 1024 * 1024),
            isolation_level: IsolationLevel::Filesystem,
            container_image: None,
        });
        config
    }

    async fn seed_live_erasure_crash_database(
        database: &LiveErasureCrashDatabase,
        scope: &str,
    ) -> (String, String, AgentId) {
        let kernel = AgentKernelImpl::from_config(&database.config()).unwrap();
        let tenant = kernel
            .create_tenant(&format!("{scope}-live-erasure"))
            .await
            .unwrap();
        let user = kernel
            .register_user(
                &tenant,
                "live-erasure-user",
                &format!("{scope}-live-erasure@example.test"),
                crate::auth::Role::User,
            )
            .await
            .unwrap();
        let _session = kernel.open_session(&user).await.unwrap();
        let agent = kernel
            .create_agent_for_tenant(
                &tenant,
                isolated_live_erasure_config(
                    &database.path,
                    &format!("{scope}-live-erasure-agent"),
                ),
            )
            .await
            .unwrap()
            .id;
        if scope == "tenant" {
            kernel
                .create_agent_for_tenant(
                    &tenant,
                    isolated_live_erasure_config(&database.path, "tenant-live-erasure-sibling"),
                )
                .await
                .unwrap();
        }
        kernel.context_manager.checkpoint().unwrap();
        kernel
            .backup_maintenance
            .create_backup(
                &kernel.context_manager,
                &database.backup_root(),
                "before_erasure",
            )
            .unwrap();
        (tenant, user, agent)
    }

    fn tenant_live_erasure_service(
        tenant_id: &str,
        database_path: &std::path::Path,
    ) -> crate::init_system::ServiceDef {
        let sandbox = isolated_live_erasure_config(database_path, "tenant-live-erasure-service")
            .sandbox_config;
        crate::init_system::ServiceDef {
            name: "tenant-live-erasure-service".into(),
            description: Some("live erasure crash qualification service".into()),
            exec: crate::init_system::ExecConfig {
                provider: "stub".into(),
                system_prompt: "exercise tenant service shutdown before erasure".into(),
                tools: Vec::new(),
                model: None,
            },
            service: crate::init_system::ServiceConfig::default(),
            dependencies: crate::init_system::DependencyConfig::default(),
            resources: crate::init_system::ResourceConfig::default(),
            policy: crate::init_system::ServicePolicyConfig {
                tenant_id: tenant_id.into(),
                sandbox,
                ..crate::init_system::ServicePolicyConfig::default()
            },
            health: crate::init_system::HealthConfig::default(),
        }
    }

    fn run_live_erasure_crash_child(
        database: &LiveErasureCrashDatabase,
        scope: &str,
        subject: &str,
        step: &str,
    ) {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--ignored")
            .arg("live_erasure_crash_child_only")
            .env("AIAGENTOS_TEST_EXIT_LIVE_ERASURE_AFTER_STEP", step)
            .env("AIAGENTOS_TEST_LIVE_ERASURE_DATABASE", &database.path)
            .env("AIAGENTOS_TEST_LIVE_ERASURE_SCOPE", scope)
            .env("AIAGENTOS_TEST_LIVE_ERASURE_SUBJECT", subject)
            // Rehydration reconciles the process-local managed workspace root.
            // Give every crash child its own root so it cannot classify a
            // concurrently running test process's workspaces as orphaned.
            .env("TMPDIR", &database.root)
            .env("TMP", &database.root)
            .env("TEMP", &database.root)
            .status()
            .unwrap();
        assert_eq!(
            child.code(),
            Some(88),
            "child did not terminate at live erasure crash point {step}"
        );
    }

    fn deletion_receipt_count(kernel: &AgentKernelImpl, subject_kind: &str) -> i64 {
        kernel
            .context_manager
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM deletion_receipts WHERE subject_kind = ?1",
                [subject_kind],
                |row| row.get(0),
            )
            .unwrap()
    }

    const AGENT_LIVE_ERASURE_CRASH_STEPS: &[&str] = &[
        "agent.credentials_drained",
        "agent.services_stopped",
        "agent.barriers_acquired",
        "agent.backups_purged",
        "agent.live_resources_removed",
        "agent.sqlite_committed",
    ];
    const USER_LIVE_ERASURE_CRASH_STEPS: &[&str] = &[
        "user.credentials_drained",
        "user.barrier_acquired",
        "user.backups_purged",
        "user.sqlite_committed",
        "user.auth_revoked",
    ];
    const TENANT_LIVE_ERASURE_CRASH_STEPS: &[&str] = &[
        "tenant.credentials_drained",
        "tenant.services_stopped",
        "tenant.barriers_acquired",
        "tenant.backups_purged",
        "tenant.live_agents_removed",
        "tenant.sqlite_committed",
        "tenant.auth_revoked",
    ];

    #[tokio::test]
    async fn process_exit_at_every_live_erasure_coordinator_boundary_is_retryable() {
        for step in AGENT_LIVE_ERASURE_CRASH_STEPS {
            let database = LiveErasureCrashDatabase::new("agent", step);
            let (_tenant, _user, agent) =
                seed_live_erasure_crash_database(&database, "agent").await;
            run_live_erasure_crash_child(&database, "agent", &agent.to_string(), step);

            let kernel = AgentKernelImpl::from_config(&database.config()).unwrap();
            let _ = kernel.erase_agent_data(agent).await.unwrap();
            assert!(kernel
                .context_manager
                .agent_tenant(agent)
                .unwrap()
                .is_none());
            assert!(kernel.agent_manager.get_agent_state(agent).is_none());
            assert!(kernel.syscall_gate.agent_info(agent).is_none());
            assert_eq!(deletion_receipt_count(&kernel, "agent"), 1);
            assert!(!database.backup_root().join("before_erasure").exists());
        }

        for step in USER_LIVE_ERASURE_CRASH_STEPS {
            let database = LiveErasureCrashDatabase::new("user", step);
            let (_tenant, user, _agent) = seed_live_erasure_crash_database(&database, "user").await;
            run_live_erasure_crash_child(&database, "user", &user, step);

            let kernel = AgentKernelImpl::from_config(&database.config()).unwrap();
            let _ = kernel.erase_user_data(&user).await.unwrap();
            assert!(kernel.auth.read().await.get_user(&user).is_none());
            assert_eq!(deletion_receipt_count(&kernel, "user"), 1);
            assert!(!database.backup_root().join("before_erasure").exists());
        }

        for step in TENANT_LIVE_ERASURE_CRASH_STEPS {
            let database = LiveErasureCrashDatabase::new("tenant", step);
            let (tenant, _user, _agent) =
                seed_live_erasure_crash_database(&database, "tenant").await;
            run_live_erasure_crash_child(&database, "tenant", &tenant, step);

            let kernel = AgentKernelImpl::from_config(&database.config()).unwrap();
            let _ = kernel.erase_tenant_data(&tenant).await.unwrap();
            assert!(kernel.auth.read().await.get_tenant(&tenant).is_none());
            assert!(kernel
                .context_manager
                .list_agents_for_tenant(&tenant)
                .unwrap()
                .is_empty());
            assert_eq!(deletion_receipt_count(&kernel, "tenant"), 1);
            assert!(!database.backup_root().join("before_erasure").exists());
        }
    }

    #[tokio::test]
    #[ignore = "child-process helper for live-erasure coordinator crash regression"]
    async fn live_erasure_crash_child_only() {
        let Some(database) = std::env::var_os("AIAGENTOS_TEST_LIVE_ERASURE_DATABASE") else {
            return;
        };
        let scope = std::env::var("AIAGENTOS_TEST_LIVE_ERASURE_SCOPE")
            .expect("live erasure crash helper requires a scope");
        let subject = std::env::var("AIAGENTOS_TEST_LIVE_ERASURE_SUBJECT")
            .expect("live erasure crash helper requires a subject");
        let database_path = std::path::Path::new(&database);
        let config = crate::config::Config {
            data_dir: database_path
                .parent()
                .expect("live erasure database has a parent")
                .to_path_buf(),
            backup: crate::config::BackupScheduleConfig {
                root: Some(
                    database_path
                        .parent()
                        .expect("live erasure database has a parent")
                        .join("backups"),
                ),
                ..crate::config::BackupScheduleConfig::default()
            },
            ..crate::config::Config::default()
        };
        let kernel = AgentKernelImpl::from_config(&config).unwrap();
        if scope == "tenant" {
            kernel
                .os
                .init
                .lock()
                .await
                .replace_definitions(vec![tenant_live_erasure_service(
                    &subject,
                    std::path::Path::new(&database),
                )])
                .unwrap();
            kernel
                .start_service("tenant-live-erasure-service")
                .await
                .unwrap();
        }
        match scope.as_str() {
            "agent" => {
                let agent = uuid::Uuid::parse_str(&subject)
                    .expect("agent erasure crash helper requires an agent UUID");
                let _ = kernel.erase_agent_data(agent).await.unwrap();
            }
            "user" => {
                let _ = kernel.erase_user_data(&subject).await.unwrap();
            }
            "tenant" => {
                let _ = kernel.erase_tenant_data(&subject).await.unwrap();
            }
            other => panic!("unsupported live erasure crash scope {other:?}"),
        }
        panic!("live erasure crash helper did not terminate at the requested boundary");
    }

    #[tokio::test]
    async fn agent_erasure_drains_tenant_requests_and_removes_every_live_boundary() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let tenant = kernel.create_tenant("agent-erasure").await.unwrap();
        let user = kernel
            .register_user(
                &tenant,
                "alice",
                "alice@agent-erasure.test",
                crate::auth::Role::User,
            )
            .await
            .unwrap();
        let token = kernel.open_session(&user).await.unwrap();
        let identity = kernel
            .resolve_principal(&token)
            .await
            .unwrap()
            .credential
            .unwrap();
        let (_principal, in_flight) = kernel
            .acquire_credential_principal(&identity)
            .await
            .expect("request lease");
        let agent = kernel
            .create_agent_for_tenant(&tenant, lifecycle_test_config("erase-live"))
            .await
            .unwrap()
            .id;

        let erase_kernel = Arc::clone(&kernel);
        let erasure = tokio::spawn(async move { erase_kernel.erase_agent_data(agent).await });
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while kernel
                .acquire_credential_principal(&identity)
                .await
                .is_some()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("agent erasure did not close tenant credential admission");
        assert!(
            kernel
                .context_manager
                .agent_tenant(agent)
                .unwrap()
                .is_some(),
            "durable erasure committed before an admitted tenant request drained"
        );
        assert!(!erasure.is_finished());

        drop(in_flight);
        let receipt = tokio::time::timeout(std::time::Duration::from_secs(1), erasure)
            .await
            .expect("agent erasure did not finish after request drain")
            .unwrap()
            .unwrap()
            .expect("agent data existed");
        assert_eq!(
            receipt.subject_kind,
            crate::context::DeletionSubjectKind::Agent
        );
        assert!(kernel
            .context_manager
            .agent_tenant(agent)
            .unwrap()
            .is_none());
        assert!(kernel.agent_manager.get_agent_state(agent).is_none());
        assert!(kernel.syscall_gate.agent_info(agent).is_none());
        assert!(
            kernel
                .acquire_credential_principal(&identity)
                .await
                .is_some(),
            "agent erasure did not reopen the unaffected tenant credential"
        );
    }

    #[tokio::test]
    async fn user_erasure_waits_for_credentials_then_removes_identity() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let tenant = kernel.create_tenant("user-erasure").await.unwrap();
        let user = kernel
            .register_user(
                &tenant,
                "alice",
                "alice@user-erasure.test",
                crate::auth::Role::User,
            )
            .await
            .unwrap();
        let token = kernel.open_session(&user).await.unwrap();
        let identity = kernel
            .resolve_principal(&token)
            .await
            .unwrap()
            .credential
            .unwrap();
        let (_principal, in_flight) = kernel
            .acquire_credential_principal(&identity)
            .await
            .expect("request lease");

        let erase_kernel = Arc::clone(&kernel);
        let erased_user = user.clone();
        let erasure = tokio::spawn(async move { erase_kernel.erase_user_data(&erased_user).await });
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while kernel
                .acquire_credential_principal(&identity)
                .await
                .is_some()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("user erasure did not close credential admission");
        assert!(
            kernel.auth.read().await.get_user(&user).is_some(),
            "user disappeared before the admitted request drained"
        );
        assert!(!erasure.is_finished());

        drop(in_flight);
        let receipt = tokio::time::timeout(std::time::Duration::from_secs(1), erasure)
            .await
            .expect("user erasure did not finish after request drain")
            .unwrap()
            .unwrap()
            .expect("user data existed");
        assert_eq!(
            receipt.subject_kind,
            crate::context::DeletionSubjectKind::User
        );
        assert!(kernel.auth.read().await.get_user(&user).is_none());
        assert!(kernel.resolve_principal(&token).await.is_none());
        assert!(kernel.context_manager.load_tenancy().unwrap().1.is_empty());
    }

    #[tokio::test]
    async fn tenant_erasure_removes_live_agents_and_preserves_other_tenants() {
        let kernel = AgentKernelImpl::new().unwrap();
        let erased_tenant = kernel.create_tenant("erase-tenant").await.unwrap();
        let retained_tenant = kernel.create_tenant("retain-tenant").await.unwrap();
        let erased_user = kernel
            .register_user(
                &erased_tenant,
                "alice",
                "alice@erase-tenant.test",
                crate::auth::Role::User,
            )
            .await
            .unwrap();
        let retained_user = kernel
            .register_user(
                &retained_tenant,
                "bob",
                "bob@retain-tenant.test",
                crate::auth::Role::User,
            )
            .await
            .unwrap();
        let erased_token = kernel.open_session(&erased_user).await.unwrap();
        let retained_token = kernel.open_session(&retained_user).await.unwrap();
        let erased_agent = kernel
            .create_agent_for_tenant(&erased_tenant, lifecycle_test_config("erase-tenant-agent"))
            .await
            .unwrap()
            .id;
        let retained_agent = kernel
            .create_agent_for_tenant(
                &retained_tenant,
                lifecycle_test_config("retain-tenant-agent"),
            )
            .await
            .unwrap()
            .id;

        let receipt = kernel
            .erase_tenant_data(&erased_tenant)
            .await
            .unwrap()
            .expect("tenant data existed");
        assert_eq!(
            receipt.subject_kind,
            crate::context::DeletionSubjectKind::Tenant
        );
        assert!(kernel
            .auth
            .read()
            .await
            .get_tenant(&erased_tenant)
            .is_none());
        assert!(kernel.resolve_principal(&erased_token).await.is_none());
        assert!(kernel.agent_manager.get_agent_state(erased_agent).is_none());
        assert!(kernel.syscall_gate.agent_info(erased_agent).is_none());
        assert!(kernel
            .context_manager
            .list_agents_for_tenant(&erased_tenant)
            .unwrap()
            .is_empty());

        assert!(kernel
            .auth
            .read()
            .await
            .get_tenant(&retained_tenant)
            .is_some());
        assert!(kernel.resolve_principal(&retained_token).await.is_some());
        assert!(kernel
            .agent_manager
            .get_agent_state(retained_agent)
            .is_some());
        assert_eq!(
            kernel
                .context_manager
                .list_agents_for_tenant(&retained_tenant)
                .unwrap(),
            vec![retained_agent]
        );
    }

    #[tokio::test]
    async fn builtin_network_provider_does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = first.read(&mut request).await.unwrap();
            first
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{address}/followed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            match tokio::time::timeout(std::time::Duration::from_millis(250), listener.accept())
                .await
            {
                Ok(Ok((mut followed, _))) => {
                    let _ = followed.read(&mut request).await.unwrap();
                    followed
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nfollowed",
                        )
                        .await
                        .unwrap();
                    true
                }
                _ => false,
            }
        });

        let response = BuiltinNetworkProvider
            .execute(
                "get",
                &serde_json::json!({"url": format!("http://{address}/start")}),
            )
            .await
            .unwrap();
        assert_eq!(response["status"], 302);
        assert_eq!(response["body"], "");
        assert!(
            !server.await.unwrap(),
            "provider followed an unapproved redirect target"
        );
    }

    #[tokio::test]
    async fn credential_revocation_timeout_is_explicit_and_never_reopens_admission() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let tenant = kernel.create_tenant("drain-timeout").await.unwrap();
        let user = kernel
            .register_user(
                &tenant,
                "alice",
                "alice@drain-timeout.test",
                crate::auth::Role::User,
            )
            .await
            .unwrap();
        let token = kernel.open_session(&user).await.unwrap();
        let identity = kernel
            .resolve_principal(&token)
            .await
            .unwrap()
            .credential
            .unwrap();
        let (_principal, in_flight) = kernel
            .acquire_credential_principal(&identity)
            .await
            .expect("request lease");

        let revoke_kernel = Arc::clone(&kernel);
        let revoke_token = token.clone();
        let revocation =
            tokio::spawn(async move { revoke_kernel.revoke_session(&revoke_token).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while kernel.resolve_principal(&token).await.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("revocation did not commit");
        assert!(
            kernel
                .acquire_credential_principal(&identity)
                .await
                .is_none(),
            "closed identity admitted new work while its old lease was active"
        );

        let error = revocation.await.unwrap().unwrap_err();
        assert!(matches!(
            error,
            KernelError::CredentialRevocationIncomplete { .. }
        ));
        assert!(kernel.resolve_principal(&token).await.is_none());
        assert!(
            kernel
                .acquire_credential_principal(&identity)
                .await
                .is_none(),
            "drain timeout reopened a revoked credential"
        );

        drop(in_flight);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while kernel.credential_leases.entry_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached credential drain did not eventually evict its idle entry");
        assert_eq!(kernel.credential_leases.entry_count(), 0);
        assert!(kernel.resolve_principal(&token).await.is_none());
    }

    #[tokio::test]
    async fn one_stuck_credential_does_not_block_other_drain_cleanup() {
        let kernel = AgentKernelImpl::new().unwrap();
        let stuck = crate::auth::CredentialIdentity {
            kind: crate::auth::CredentialKind::Session,
            id: "stuck-drain".into(),
        };
        let idle = crate::auth::CredentialIdentity {
            kind: crate::auth::CredentialKind::ApiKey,
            id: "idle-drain".into(),
        };
        let stuck_guard = kernel
            .credential_leases
            .acquire(&stuck)
            .expect("stuck lease");
        let drains = vec![
            kernel.credential_leases.close(&stuck),
            kernel.credential_leases.close(&idle),
        ];

        let error = kernel.drain_revoked_credentials(drains).await.unwrap_err();
        assert!(matches!(
            error,
            KernelError::CredentialRevocationIncomplete { .. }
        ));
        assert_eq!(
            kernel.credential_leases.entry_count(),
            1,
            "an unrelated idle closed entry stayed queued behind a stuck drain"
        );

        drop(stuck_guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while kernel.credential_leases.entry_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached stuck drain did not eventually clean up");
    }

    #[tokio::test]
    async fn user_revoke_waits_for_a_session_removed_by_an_earlier_timed_out_revoke() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let tenant = kernel
            .create_tenant("cross-scope-user-drain")
            .await
            .unwrap();
        let user = kernel
            .register_user(
                &tenant,
                "alice",
                "alice@cross-scope-user-drain.test",
                crate::auth::Role::User,
            )
            .await
            .unwrap();
        let token = kernel.open_session(&user).await.unwrap();
        let identity = kernel
            .resolve_principal(&token)
            .await
            .unwrap()
            .credential
            .unwrap();
        let (_principal, in_flight) = kernel
            .acquire_credential_principal(&identity)
            .await
            .expect("request lease");

        let first_kernel = Arc::clone(&kernel);
        let first_token = token.clone();
        let first_revoke =
            tokio::spawn(async move { first_kernel.revoke_session(&first_token).await });
        let first_error = first_revoke.await.unwrap().unwrap_err();
        assert!(matches!(
            first_error,
            KernelError::CredentialRevocationIncomplete { .. }
        ));

        let user_kernel = Arc::clone(&kernel);
        let revoked_user = user.clone();
        let user_revoke = tokio::spawn(async move { user_kernel.revoke_user(&revoked_user).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while kernel.auth.read().await.get_user(&user).is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("user revocation did not commit");
        assert!(
            !user_revoke.is_finished(),
            "user revocation returned before an overlapping removed credential drained"
        );

        drop(in_flight);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), user_revoke)
                .await
                .expect("user revocation did not finish after lease release")
                .unwrap()
                .unwrap()
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while kernel.credential_leases.entry_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shared session drain entry was not evicted");
    }

    #[tokio::test]
    async fn tenant_revoke_waits_for_session_and_key_removed_by_timed_out_revokes() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let tenant = kernel
            .create_tenant("cross-scope-tenant-drain")
            .await
            .unwrap();
        let user = kernel
            .register_user(
                &tenant,
                "alice",
                "alice@cross-scope-tenant-drain.test",
                crate::auth::Role::User,
            )
            .await
            .unwrap();
        let token = kernel.open_session(&user).await.unwrap();
        let key = kernel.issue_api_key(&user, "in-flight").await.unwrap();
        let session_identity = kernel
            .resolve_principal(&token)
            .await
            .unwrap()
            .credential
            .unwrap();
        let key_identity = kernel
            .resolve_principal(&key)
            .await
            .unwrap()
            .credential
            .unwrap();
        let (_session_principal, session_in_flight) = kernel
            .acquire_credential_principal(&session_identity)
            .await
            .expect("session request lease");
        let (_key_principal, key_in_flight) = kernel
            .acquire_credential_principal(&key_identity)
            .await
            .expect("API-key request lease");

        let session_kernel = Arc::clone(&kernel);
        let revoked_token = token.clone();
        let session_revoke =
            tokio::spawn(async move { session_kernel.revoke_session(&revoked_token).await });
        let key_kernel = Arc::clone(&kernel);
        let revoked_key = key.clone();
        let key_revoke = tokio::spawn(async move { key_kernel.revoke_api_key(&revoked_key).await });
        for revocation in [session_revoke, key_revoke] {
            let error = revocation.await.unwrap().unwrap_err();
            assert!(matches!(
                error,
                KernelError::CredentialRevocationIncomplete { .. }
            ));
        }

        let tenant_kernel = Arc::clone(&kernel);
        let revoked_tenant = tenant.clone();
        let tenant_revoke =
            tokio::spawn(async move { tenant_kernel.revoke_tenant(&revoked_tenant).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while kernel.auth.read().await.get_tenant(&tenant).is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("tenant revocation did not commit");
        assert!(
            !tenant_revoke.is_finished(),
            "tenant revocation returned before removed credentials drained"
        );

        drop(session_in_flight);
        tokio::task::yield_now().await;
        assert!(
            !tenant_revoke.is_finished(),
            "tenant revocation ignored the still-active API-key lease"
        );
        drop(key_in_flight);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), tenant_revoke)
                .await
                .expect("tenant revocation did not finish after both lease releases")
                .unwrap()
                .unwrap()
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while kernel.credential_leases.entry_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shared tenant drain entries were not evicted");
    }

    #[tokio::test]
    async fn failed_credential_resolution_evicts_its_unbound_idle_lease() {
        let kernel = AgentKernelImpl::new().unwrap();
        let unknown = crate::auth::CredentialIdentity {
            kind: crate::auth::CredentialKind::Session,
            id: "unknown-credential".into(),
        };
        assert!(kernel
            .acquire_credential_principal(&unknown)
            .await
            .is_none());
        assert_eq!(kernel.credential_leases.entry_count(), 0);
    }

    #[tokio::test]
    async fn concurrent_group_tool_registration_keeps_the_winner_scoped() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let binding = || crate::tools::ToolBinding {
            name: "raced_group_notes".into(),
            description: "Read group-local notes".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]
            }),
            resource_type: crate::resources::ResourceType::Filesystem,
            operation: "read".into(),
            security: crate::tools::ToolSecurity::argument(
                crate::tools::SecurityAction::Read,
                "path",
            ),
        };

        let kernel_a = kernel.clone();
        let barrier_a = barrier.clone();
        let binding_a = binding();
        let registration_a = std::thread::spawn(move || {
            barrier_a.wait();
            kernel_a.register_group_tool("group-a", binding_a)
        });
        let kernel_b = kernel.clone();
        let barrier_b = barrier;
        let binding_b = binding();
        let registration_b = std::thread::spawn(move || {
            barrier_b.wait();
            kernel_b.register_group_tool("group-b", binding_b)
        });
        let result_a = registration_a.join().unwrap();
        let result_b = registration_b.join().unwrap();
        assert_ne!(
            result_a.is_ok(),
            result_b.is_ok(),
            "exactly one competing group registration must win"
        );
        let winner_group = if result_a.is_ok() {
            "group-a"
        } else {
            "group-b"
        };
        let loser_group = if result_a.is_ok() {
            "group-b"
        } else {
            "group-a"
        };

        let config = |name: &str| AgentConfig {
            name: name.into(),
            task: "namespace race regression".into(),
            llm_provider: "test".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        };
        let winner = kernel
            .create_agent_in_namespace(config("winner"), winner_group)
            .await
            .unwrap();
        let loser = kernel
            .create_agent_in_namespace(config("loser"), loser_group)
            .await
            .unwrap();
        let ungrouped = kernel.create_agent_full(config("ungrouped")).await.unwrap();
        let sees_raced_tool = |agent_id| {
            kernel
                .tool_registry
                .definitions_for_agent(&kernel.syscall_gate, agent_id)
                .iter()
                .any(|tool| tool.name == "raced_group_notes")
        };

        assert!(sees_raced_tool(winner.id));
        assert!(!sees_raced_tool(loser.id));
        assert!(
            !sees_raced_tool(ungrouped.id),
            "loser rollback must never remove the winner's namespace tag"
        );
    }

    #[tokio::test]
    async fn ipc_name_lookup_hides_missing_foreign_and_ambiguous_recipients() {
        let kernel = AgentKernelImpl::new().unwrap();
        let config = |name: &str| AgentConfig {
            name: name.into(),
            task: "IPC recipient lookup".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        };
        let caller = kernel
            .create_agent_in_namespace(config("caller"), "visible-team")
            .await
            .unwrap();
        let foreign = kernel
            .create_agent_in_namespace(config("hidden-peer"), "foreign-team")
            .await
            .unwrap();
        kernel
            .create_agent_in_namespace(config("ambiguous-peer"), "visible-team")
            .await
            .unwrap();
        kernel
            .create_agent_in_namespace(config("ambiguous-peer"), "visible-team")
            .await
            .unwrap();
        async fn probe(
            kernel: &AgentKernelImpl,
            operation: &str,
            caller: AgentId,
            recipient: &str,
        ) -> String {
            let (tool, arguments) = match operation {
                "send" => (
                    "send_agent_message",
                    serde_json::json!({
                        "to": recipient,
                        "message": {"probe": true}
                    }),
                ),
                "delegate" => (
                    "delegate_task",
                    serde_json::json!({
                        "to": recipient,
                        "task": "probe"
                    }),
                ),
                _ => unreachable!(),
            };
            let (prepared, _tool_slot) = kernel
                .tool_registry
                .authorize_and_acquire_call(&kernel.syscall_gate, caller, tool, &arguments)
                .await
                .expect("IPC probe must pass gate admission");
            let response = kernel
                .resource_broker
                .execute(prepared.request)
                .await
                .expect("provider failure is returned as a response");
            assert!(!response.success);
            response.error.expect("hidden recipient probe must fail")
        }

        let missing_id = uuid::Uuid::new_v4();
        for operation in ["send", "delegate"] {
            let missing = probe(&kernel, operation, caller.id, "missing-peer").await;
            let hidden = probe(&kernel, operation, caller.id, "hidden-peer").await;
            let ambiguous = probe(&kernel, operation, caller.id, "ambiguous-peer").await;
            let missing_uuid = probe(&kernel, operation, caller.id, &missing_id.to_string()).await;
            let foreign_uuid = probe(&kernel, operation, caller.id, &foreign.id.to_string()).await;
            assert_eq!(missing, hidden);
            assert_eq!(missing, ambiguous);
            assert_eq!(missing, missing_uuid);
            assert_eq!(missing, foreign_uuid);
            assert!(
                !missing.contains("missing-peer")
                    && !missing.contains("hidden-peer")
                    && !missing.contains("ambiguous-peer")
                    && !missing.contains(&foreign.id.to_string())
                    && !missing.contains(&missing_id.to_string()),
                "{operation} reflected hidden recipient identity: {missing}"
            );
        }
    }

    #[tokio::test]
    async fn agent_registry_commit_failure_rolls_back_every_live_subsystem() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let kernel = AgentKernelImpl::with_context_manager(
            context.clone(),
            &crate::config::BudgetConfig::default(),
            true,
            &[],
        )
        .unwrap();
        context.fail_next_agent_save_for_test();

        let error = kernel
            .create_agent_full(AgentConfig {
                name: "must-not-escape".into(),
                task: "persistence fault injection".into(),
                llm_provider: "test".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            })
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("injected agent-registry save failure"));
        assert!(kernel.agent_manager.list_agents(None).is_empty());
        assert!(context.load_all_agents().unwrap().is_empty());
        assert!(kernel.agent_cgroups.is_empty());
        assert!(kernel.profile_cgroups.is_empty());
        assert!(kernel.tenant_cgroups.is_empty());
        assert_eq!(kernel.cgroups.structural_counts(), (1, 1));
        assert_eq!(kernel.sandbox_manager.structural_counts(), (0, 0));
    }

    #[tokio::test]
    async fn stopping_persistence_failure_restores_live_admission_before_retry() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let kernel = AgentKernelImpl::with_context_manager(
            context.clone(),
            &crate::config::BudgetConfig::default(),
            true,
            &[],
        )
        .unwrap();
        let agent = kernel
            .create_agent_full(lifecycle_test_config("staging-failure"))
            .await
            .unwrap();
        context.fail_agent_status_update_on_nth_call_for_test(1);

        let error = kernel.stop_agent(agent.id).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("injected agent-status update failure"));
        assert_eq!(
            kernel.get_agent_status(agent.id).unwrap(),
            AgentState::Running
        );
        assert_eq!(
            durable_agent_status(&context, agent.id),
            AgentState::Running
        );
        assert!(kernel.scheduler.contains(agent.id));
        assert!(kernel.ipc.is_registered(agent.id));
        assert!(kernel.syscall_gate.agent_info(agent.id).is_some());
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent.id)
            .is_some());
        drop(
            kernel
                .syscall_gate
                .acquire_tool_call(agent.id)
                .expect("failed staging must reopen tool admission"),
        );

        assert_eq!(
            kernel.stop_agent(agent.id).await.unwrap(),
            AgentState::Stopped
        );
        assert_eq!(
            durable_agent_status(&context, agent.id),
            AgentState::Stopped
        );
    }

    #[tokio::test]
    async fn terminal_persistence_failure_stays_non_runnable_until_retry() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let kernel = AgentKernelImpl::with_context_manager(
            context.clone(),
            &crate::config::BudgetConfig::default(),
            true,
            &[],
        )
        .unwrap();
        let agent = kernel
            .create_agent_full(lifecycle_test_config("terminal-failure"))
            .await
            .unwrap();
        context.fail_agent_status_update_on_nth_call_for_test(2);

        let error = kernel.kill_agent(agent.id).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("injected agent-status update failure"));
        assert_eq!(
            kernel.get_agent_status(agent.id).unwrap(),
            AgentState::Stopping
        );
        assert_eq!(
            durable_agent_status(&context, agent.id),
            AgentState::Stopping
        );
        assert!(!kernel.scheduler.contains(agent.id));
        assert!(!kernel.ipc.is_registered(agent.id));
        assert!(kernel.syscall_gate.agent_info(agent.id).is_none());
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent.id)
            .is_none());
        assert!(!kernel.agent_cgroups.contains_key(&agent.id));

        assert_eq!(
            kernel.kill_agent(agent.id).await.unwrap(),
            AgentState::Stopped
        );
        assert_eq!(
            durable_agent_status(&context, agent.id),
            AgentState::Stopped
        );
    }

    #[tokio::test]
    async fn sandbox_cleanup_failure_is_reported_and_retryable() {
        let context = Arc::new(SqliteContextManager::in_memory().unwrap());
        let kernel = AgentKernelImpl::with_context_manager(
            context.clone(),
            &crate::config::BudgetConfig::default(),
            true,
            &[],
        )
        .unwrap();
        let agent = kernel
            .create_agent_full(lifecycle_test_config("sandbox-failure"))
            .await
            .unwrap();
        kernel.sandbox_manager.fail_next_destroy_for_test();

        let error = kernel.stop_agent(agent.id).await.unwrap_err();
        assert!(matches!(error, KernelError::LifecycleCleanup(_)));
        assert!(error
            .to_string()
            .contains("injected sandbox destruction failure"));
        assert_eq!(
            kernel.get_agent_status(agent.id).unwrap(),
            AgentState::Stopping
        );
        assert_eq!(
            durable_agent_status(&context, agent.id),
            AgentState::Stopping
        );
        assert!(!kernel.scheduler.contains(agent.id));
        assert!(!kernel.ipc.is_registered(agent.id));
        assert!(kernel.syscall_gate.agent_info(agent.id).is_none());
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent.id)
            .is_some());

        assert_eq!(
            kernel.stop_agent(agent.id).await.unwrap(),
            AgentState::Stopped
        );
        assert_eq!(
            durable_agent_status(&context, agent.id),
            AgentState::Stopped
        );
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent.id)
            .is_none());
    }

    #[test]
    fn only_explicit_full_access_has_unlimited_token_and_tool_limits() {
        let budgets = crate::config::BudgetConfig {
            agent_tokens_per_min: 100,
            max_concurrent_tool_calls: 3,
            max_context_tokens: 4_096,
            ..crate::config::BudgetConfig::default()
        };
        let managed = CgroupLimits {
            tokens_per_min: 100,
            max_concurrent_tool_calls: 3,
            max_context_tokens: 4_096,
            max_agents: 0,
        };

        assert_eq!(agent_cgroup_limits("", &budgets), managed);
        assert_eq!(agent_cgroup_limits("custom-profile", &budgets), managed);
        assert_eq!(
            agent_cgroup_limits("full-access", &budgets),
            CgroupLimits {
                tokens_per_min: 0,
                max_concurrent_tool_calls: 0,
                max_context_tokens: 4_096,
                max_agents: 0,
            }
        );
        assert_eq!(
            agent_cgroup_limits("elevated", &budgets),
            CgroupLimits {
                tokens_per_min: 400,
                max_concurrent_tool_calls: 3,
                max_context_tokens: 4_096,
                max_agents: 0,
            }
        );
    }

    #[test]
    fn zero_max_concurrent_is_unlimited_in_both_kernel_admission_layers() {
        let budgets = crate::config::BudgetConfig {
            max_concurrent: 0,
            ..crate::config::BudgetConfig::default()
        };
        let kernel = AgentKernelImpl::with_context_manager(
            Arc::new(SqliteContextManager::in_memory().unwrap()),
            &budgets,
            true,
            &[],
        )
        .unwrap();

        assert_eq!(kernel.turn_admission.capacity(), usize::MAX);
        assert_eq!(kernel.rate_limiter.stats().max_concurrent, 0);
        assert_eq!(kernel.rate_limiter.stats().concurrent_available, 0);
    }

    #[test]
    fn configured_turn_waiter_limit_is_applied() {
        let budgets = crate::config::BudgetConfig {
            max_concurrent: 2,
            max_waiting_turns: 7,
            ..crate::config::BudgetConfig::default()
        };
        let kernel = AgentKernelImpl::with_context_manager(
            Arc::new(SqliteContextManager::in_memory().unwrap()),
            &budgets,
            true,
            &[],
        )
        .unwrap();

        let metrics = kernel.turn_admission.metrics();
        assert_eq!(metrics.capacity, 2);
        assert_eq!(metrics.queue_capacity, 7);
    }

    #[tokio::test]
    async fn stopped_and_rolled_back_agents_do_not_leak_cgroup_leaves() {
        let kernel = AgentKernelImpl::new().unwrap();
        let config = |name: String| AgentConfig {
            name,
            task: "cgroup lifecycle regression".into(),
            llm_provider: "test".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        };

        // A live agent creates tenant/profile/leaf nodes. Once the last agent
        // stops, all three kernel-owned nodes are reclaimed.
        for index in 0..4 {
            let handle = kernel
                .create_agent_full(config(format!("cleanup-{index}")))
                .await
                .unwrap();
            assert_eq!(kernel.agent_cgroups.len(), 1);
            assert_eq!(kernel.cgroups.structural_counts(), (4, 4));
            kernel.stop_agent(handle.id).await.unwrap();
            assert!(kernel.agent_cgroups.is_empty());
            assert!(kernel.profile_cgroups.is_empty());
            assert!(kernel.tenant_cgroups.is_empty());
            assert_eq!(kernel.cgroups.structural_counts(), (1, 1));
        }

        // Model failure after hierarchy allocation but before syscall-gate
        // registration. Rollback must reclaim the empty leaf as well.
        for _ in 0..4 {
            let agent_id = uuid::Uuid::new_v4();
            kernel
                .cgroup_for_agent(crate::context::DEFAULT_TENANT, "standard", agent_id)
                .unwrap();
            assert_eq!(kernel.agent_cgroups.len(), 1);
            assert_eq!(kernel.cgroups.structural_counts(), (4, 4));
            kernel.rollback_created_agent(agent_id).await;
            assert!(kernel.agent_cgroups.is_empty());
            assert!(kernel.profile_cgroups.is_empty());
            assert!(kernel.tenant_cgroups.is_empty());
            assert_eq!(kernel.cgroups.structural_counts(), (1, 1));
        }

        // Accepted custom profile names remain unbounded in variety without
        // leaking one aggregate node/map entry per historical profile.
        for index in 0..12 {
            let mut custom = config(format!("custom-{index}"));
            custom.permission_profile = format!("custom-profile-{index}");
            let handle = kernel.create_agent_full(custom).await.unwrap();
            assert_eq!(kernel.profile_cgroups.len(), 1);
            assert_eq!(kernel.cgroups.structural_counts(), (4, 4));
            kernel.stop_agent(handle.id).await.unwrap();
            assert!(kernel.agent_cgroups.is_empty());
            assert!(kernel.profile_cgroups.is_empty());
            assert!(kernel.tenant_cgroups.is_empty());
            assert_eq!(kernel.cgroups.structural_counts(), (1, 1));
        }

        // A raw gate move must not let a kernel-managed agent discard its
        // root→tenant→profile→private-agent quota chain. The unrelated custom
        // destination remains untouched when the agent is later reclaimed.
        let shared = kernel
            .cgroups
            .create_scoped(
                "shared-custom".into(),
                kernel.cgroups.root(),
                "/shared-custom".into(),
                CgroupLimits::default(),
            )
            .unwrap();
        let moved = kernel
            .create_agent_full(config("moved-agent".into()))
            .await
            .unwrap();
        let original_leaf = *kernel.agent_cgroups.get(&moved.id).unwrap();
        let original_snapshot = kernel
            .syscall_gate
            .cgroup_quota_constraints(moved.id)
            .unwrap();
        assert!(matches!(
            kernel.syscall_gate.try_set_cgroup(moved.id, shared),
            Err(crate::syscall_gate::GateMutationError::ManagedCgroupImmutable(id))
                if id == moved.id
        ));
        assert_eq!(
            kernel.syscall_gate.agent_info(moved.id).unwrap().cgroup,
            original_leaf
        );
        assert_eq!(
            kernel
                .syscall_gate
                .cgroup_quota_constraints(moved.id)
                .unwrap(),
            original_snapshot
        );
        assert_eq!(original_snapshot.constraints.len(), 4);
        assert!(kernel.cgroups.get(original_leaf).is_some());
        kernel.stop_agent(moved.id).await.unwrap();
        assert!(kernel.agent_cgroups.is_empty());
        assert!(kernel.cgroups.get(original_leaf).is_none());
        assert!(kernel.cgroups.get(shared).is_some());
        assert!(kernel.profile_cgroups.is_empty());
        assert!(kernel.tenant_cgroups.is_empty());
        assert_eq!(kernel.cgroups.structural_counts(), (2, 2));
    }

    #[tokio::test]
    async fn terminal_lifecycle_drains_external_tool_guards_without_leaks_or_hangs() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let config = |name: &str| AgentConfig {
            name: name.into(),
            task: "external tool drain".into(),
            llm_provider: "test".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        };

        let agent = kernel.create_agent_full(config("drain")).await.unwrap();
        let guard = kernel.syscall_gate.acquire_tool_call(agent.id).unwrap();
        let stopping_kernel = kernel.clone();
        let stopping = tokio::spawn(async move { stopping_kernel.stop_agent(agent.id).await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !stopping.is_finished(),
            "stop must wait for an admitted external binding"
        );
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), stopping)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(kernel.cgroups.structural_counts(), (1, 1));

        let hung = kernel.create_agent_full(config("timeout")).await.unwrap();
        let original_state = kernel.get_agent_status(hung.id).unwrap();
        let hung_guard = kernel.syscall_gate.acquire_tool_call(hung.id).unwrap();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            kernel.stop_agent(hung.id),
        )
        .await
        .expect("stop has a finite external-tool drain contract")
        .unwrap_err();
        assert!(error.to_string().contains("timed out draining"));
        assert_eq!(kernel.get_agent_status(hung.id).unwrap(), original_state);
        let reopened = kernel
            .syscall_gate
            .acquire_tool_call(hung.id)
            .expect("failed terminal transition must restore admission");
        drop(reopened);
        kernel.kill_agent(hung.id).await.unwrap();
        assert_eq!(kernel.cgroups.structural_counts(), (1, 1));
        drop(hung_guard);
        assert_eq!(
            kernel
                .cgroups
                .get(kernel.cgroups.root())
                .unwrap()
                .usage
                .active_tool_calls,
            0,
            "late guard drop after forced kill must not double-decrement accounting"
        );
    }

    #[tokio::test]
    async fn terminal_lifecycle_times_out_when_an_active_turn_cannot_quiesce() {
        struct IdleSession {
            id: ProviderId,
        }

        #[async_trait::async_trait]
        impl crate::connector::LlmSession for IdleSession {
            async fn send(
                &self,
                _messages: Vec<crate::connector::StandardMessage>,
            ) -> Result<crate::connector::LlmResponse, ConnectorError> {
                unreachable!("the regression holds the executor lock directly")
            }

            async fn send_with_tools(
                &self,
                _messages: Vec<crate::connector::StandardMessage>,
                _tools: &[crate::connector::ToolDefinition],
            ) -> Result<crate::connector::LlmResponse, ConnectorError> {
                unreachable!("the regression holds the executor lock directly")
            }

            fn provider_id(&self) -> &ProviderId {
                &self.id
            }
        }

        let kernel = AgentKernelImpl::new().unwrap();
        let agent = kernel
            .create_agent_full(AgentConfig {
                name: "hung-turn".into(),
                task: "quiesce timeout regression".into(),
                llm_provider: "test".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            })
            .await
            .unwrap();
        let executor = Arc::new(tokio::sync::Mutex::new(
            crate::execution::AgentExecutor::new(
                agent.id,
                Box::new(IdleSession { id: "test".into() }),
                kernel.resource_broker.clone(),
                kernel.tool_registry.clone(),
                kernel.context_manager.clone(),
                kernel.syscall_gate.clone(),
                "system".into(),
            ),
        ));
        kernel.executors.insert(agent.id, executor.clone());
        let held = executor.lock().await;
        let original_state = kernel.get_agent_status(agent.id).unwrap();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            kernel.stop_agent(agent.id),
        )
        .await
        .expect("terminal quiesce must have a finite bound")
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("timed out waiting for active agent turn"));
        assert_eq!(kernel.get_agent_status(agent.id).unwrap(), original_state);

        kernel.kill_agent(agent.id).await.unwrap();
        assert_eq!(kernel.cgroups.structural_counts(), (1, 1));
        drop(held);
    }

    #[tokio::test]
    async fn kill_during_provider_request_releases_every_admission_layer() {
        struct BlockingLifecycleSession {
            id: ProviderId,
            entered: Arc<tokio::sync::Notify>,
            release: Arc<tokio::sync::Notify>,
        }

        #[async_trait::async_trait]
        impl crate::connector::LlmSession for BlockingLifecycleSession {
            async fn send(
                &self,
                messages: Vec<crate::connector::StandardMessage>,
            ) -> Result<crate::connector::LlmResponse, ConnectorError> {
                self.send_with_tools(messages, &[]).await
            }

            async fn send_with_tools(
                &self,
                _messages: Vec<crate::connector::StandardMessage>,
                _tools: &[crate::connector::ToolDefinition],
            ) -> Result<crate::connector::LlmResponse, ConnectorError> {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(crate::connector::LlmResponse {
                    content: "must be cancelled".into(),
                    finish_reason: Some("stop".into()),
                    tokens_used: 1,
                    usage: crate::connector::LlmUsage::reported(1, 1, 0),
                    tool_calls: Vec::new(),
                })
            }

            fn provider_id(&self) -> &ProviderId {
                &self.id
            }
        }

        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let agent = kernel
            .create_agent_full(lifecycle_test_config("provider-kill"))
            .await
            .unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let mut executor = AgentExecutor::new(
            agent.id,
            Box::new(BlockingLifecycleSession {
                id: "blocking-lifecycle".into(),
                entered: entered.clone(),
                release: Arc::new(tokio::sync::Notify::new()),
            }),
            kernel.resource_broker.clone(),
            kernel.tool_registry.clone(),
            kernel.context_manager.clone(),
            kernel.syscall_gate.clone(),
            "system".into(),
        );
        executor.set_rate_limiter(kernel.rate_limiter.clone());
        let pid = kernel.syscall_gate.pid_of(agent.id).unwrap();
        let nice = kernel.os.cfs.lock().await.nice_of(pid).unwrap_or(0);
        executor.set_llm_scheduler(kernel.llm_scheduler.clone(), pid, nice);
        kernel
            .executors
            .insert(agent.id, Arc::new(tokio::sync::Mutex::new(executor)));

        let turn_kernel = kernel.clone();
        let turn = tokio::spawn(async move {
            turn_kernel
                .send_message(agent.id, "block in provider")
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("provider request did not start");
        assert_eq!(kernel.llm_scheduler.metrics().in_flight, 1);
        assert_eq!(kernel.turn_admission.metrics().running, 1);

        let killed = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            kernel.kill_agent(agent.id),
        )
        .await
        .expect("forced kill waited for the provider")
        .unwrap();
        assert_eq!(killed, AgentState::Stopped);
        let turn_error = tokio::time::timeout(std::time::Duration::from_secs(1), turn)
            .await
            .expect("cancelled provider turn did not finish")
            .unwrap()
            .unwrap_err();
        assert!(turn_error
            .to_string()
            .contains("cancelled by terminal lifecycle operation"));
        assert!(kernel
            .latest_generation_checkpoint(agent.id)
            .unwrap()
            .is_none());
        assert_eq!(kernel.llm_scheduler.metrics().in_flight, 0);
        assert_eq!(kernel.turn_admission.metrics().running, 0);
        assert!(!kernel.active_cancellations.contains_key(&agent.id));
        assert!(!kernel.scheduler.contains(agent.id));
        assert!(!kernel.ipc.is_registered(agent.id));
        assert!(kernel.syscall_gate.agent_info(agent.id).is_none());
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent.id)
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_stop_pause_and_message_races_do_not_deadlock_or_leak() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        for round in 0..32 {
            let agent = kernel
                .create_agent_full(lifecycle_test_config(&format!("race-{round}")))
                .await
                .unwrap();
            let agent_id = agent.id;
            let barrier = Arc::new(tokio::sync::Barrier::new(4));

            let pause_kernel = kernel.clone();
            let pause_barrier = barrier.clone();
            let pause = tokio::spawn(async move {
                pause_barrier.wait().await;
                pause_kernel.pause_agent(agent_id).await
            });

            let stop_kernel = kernel.clone();
            let stop_barrier = barrier.clone();
            let stop = tokio::spawn(async move {
                stop_barrier.wait().await;
                stop_kernel.stop_agent(agent_id).await
            });

            let message_kernel = kernel.clone();
            let message_barrier = barrier.clone();
            let message = tokio::spawn(async move {
                message_barrier.wait().await;
                message_kernel.send_message(agent_id, "race").await
            });

            barrier.wait().await;
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let _ = tokio::join!(pause, stop, message);
            })
            .await
            .expect("lifecycle/message race deadlocked");

            kernel.kill_agent(agent_id).await.unwrap();
            assert_eq!(
                kernel.get_agent_status(agent_id).unwrap(),
                AgentState::Stopped
            );
            assert!(!kernel.scheduler.contains(agent_id));
            assert!(!kernel.ipc.is_registered(agent_id));
            assert!(kernel.syscall_gate.agent_info(agent_id).is_none());
            assert!(kernel
                .sandbox_manager
                .get_sandbox_for_agent(agent_id)
                .is_none());
            assert!(!kernel.active_cancellations.contains_key(&agent_id));
            assert!(!kernel.executors.contains_key(&agent_id));
        }
        assert_eq!(kernel.cgroups.structural_counts(), (1, 1));
    }

    #[tokio::test]
    async fn shutdown_surfaces_cleanup_failure_and_retry_completes() {
        let kernel = AgentKernelImpl::new().unwrap();
        let agent = kernel
            .create_agent_full(lifecycle_test_config("shutdown-failure"))
            .await
            .unwrap();
        kernel.sandbox_manager.fail_next_destroy_for_test();

        let error = kernel.shutdown().await.unwrap_err();
        assert!(matches!(error, KernelError::LifecycleCleanup(_)));
        assert!(error
            .to_string()
            .contains("injected sandbox destruction failure"));
        assert_eq!(
            kernel.get_agent_status(agent.id).unwrap(),
            AgentState::Stopping
        );

        let stopped = kernel.shutdown().await.unwrap();
        assert_eq!(stopped, vec![agent.id]);
        assert_eq!(
            kernel.get_agent_status(agent.id).unwrap(),
            AgentState::Stopped
        );
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent.id)
            .is_none());
    }

    #[tokio::test]
    async fn shutdown_escalates_graceful_tool_timeout_to_forced_cleanup() {
        let kernel = AgentKernelImpl::new().unwrap();
        let agent = kernel
            .create_agent_full(lifecycle_test_config("shutdown-force"))
            .await
            .unwrap();
        let held = kernel.syscall_gate.acquire_tool_call(agent.id).unwrap();

        assert_eq!(kernel.shutdown().await.unwrap(), vec![agent.id]);
        assert_eq!(
            kernel.get_agent_status(agent.id).unwrap(),
            AgentState::Stopped
        );
        assert!(kernel.syscall_gate.agent_info(agent.id).is_none());
        assert_eq!(kernel.cgroups.structural_counts(), (1, 1));
        drop(held);
        assert_eq!(
            kernel
                .cgroups
                .get(kernel.cgroups.root())
                .unwrap()
                .usage
                .active_tool_calls,
            0
        );
    }

    #[tokio::test]
    async fn shutdown_cleans_agents_already_in_error_state() {
        let kernel = AgentKernelImpl::new().unwrap();
        let agent = kernel
            .create_agent_full(lifecycle_test_config("shutdown-error"))
            .await
            .unwrap();
        kernel
            .agent_manager
            .transition_state(agent.id, AgentState::Error("injected".into()))
            .unwrap();

        assert_eq!(kernel.shutdown().await.unwrap(), vec![agent.id]);
        assert_eq!(
            kernel.get_agent_status(agent.id).unwrap(),
            AgentState::Stopped
        );
        assert!(!kernel.scheduler.contains(agent.id));
        assert!(!kernel.ipc.is_registered(agent.id));
        assert!(kernel.syscall_gate.agent_info(agent.id).is_none());
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent.id)
            .is_none());
    }

    #[tokio::test]
    async fn watchdog_uses_forced_coordinator_and_ignores_idle_agents() {
        let kernel = AgentKernelImpl::new().unwrap();
        let active = kernel
            .create_agent_full(AgentConfig {
                name: "watchdog-active".into(),
                task: "watchdog cleanup regression".into(),
                llm_provider: "test".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            })
            .await
            .unwrap();
        let idle = kernel
            .create_agent_full(AgentConfig {
                name: "watchdog-idle".into(),
                task: "idle agents are not hung".into(),
                llm_provider: "test".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            })
            .await
            .unwrap();
        let active_guard = kernel.syscall_gate.acquire_tool_call(active.id).unwrap();
        kernel
            .active_cancellations
            .insert(active.id, tokio_util::sync::CancellationToken::new());
        let stale = chrono::Utc::now() - chrono::Duration::seconds(31);
        kernel
            .agent_manager
            .set_last_activity_for_test(active.id, stale);
        kernel
            .agent_manager
            .set_last_activity_for_test(idle.id, stale);

        assert_eq!(kernel.watchdog_sweep().await, vec![active.id]);
        assert_eq!(
            kernel.get_agent_status(active.id).unwrap(),
            AgentState::Stopped
        );
        assert_eq!(
            kernel.get_agent_status(idle.id).unwrap(),
            AgentState::Running,
            "a runnable agent with no active turn is intentionally idle"
        );
        assert!(!kernel.scheduler.contains(active.id));
        assert!(!kernel.ipc.is_registered(active.id));
        assert!(kernel.syscall_gate.agent_info(active.id).is_none());
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(active.id)
            .is_none());
        drop(active_guard);
        assert_eq!(
            kernel
                .cgroups
                .get(kernel.cgroups.root())
                .unwrap()
                .usage
                .active_tool_calls,
            0
        );
    }

    #[tokio::test]
    async fn trusted_kernel_approval_api_grants_one_exact_registered_call() {
        let kernel = AgentKernelImpl::new().unwrap();
        let agent = uuid::Uuid::new_v4();
        let pid = kernel
            .syscall_gate
            .register_agent(agent, CapabilitySet::all(), None);
        kernel
            .syscall_gate
            .label_mac_agent(pid, "profile:full-access".into())
            .await;
        let arguments = serde_json::json!({"command": "echo", "args": ["ok"]});

        assert!(matches!(
            kernel
                .tool_registry
                .authorize_and_acquire_call(&kernel.syscall_gate, agent, "run_command", &arguments,)
                .await,
            Err(crate::tools::ToolAuthorizationError::Denied(
                crate::syscall_gate::GateDenial::ApprovalRequired { .. }
            ))
        ));
        kernel
            .approve_tool_call(
                agent,
                "run_command",
                &arguments,
                crate::tools::ApprovalPolicy::User,
            )
            .unwrap();
        let (_, guard) = kernel
            .tool_registry
            .authorize_and_acquire_call(&kernel.syscall_gate, agent, "run_command", &arguments)
            .await
            .unwrap();
        drop(guard);
    }

    #[tokio::test]
    async fn filesystem_provider_creates_directories_without_process_execution() {
        let path = std::env::temp_dir().join(format!("agentos-mkdir-{}", uuid::Uuid::new_v4()));
        let result = BuiltinFilesystemProvider
            .execute(
                "create_dir",
                &serde_json::json!({"path": path.to_string_lossy()}),
            )
            .await
            .unwrap();
        assert_eq!(result["created"], true);
        assert!(path.is_dir());
        std::fs::remove_dir(&path).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_application_provider_kills_descendant_process_tree() {
        let marker =
            std::env::temp_dir().join(format!("agentos-kill-on-drop-{}", uuid::Uuid::new_v4()));
        let parameters = serde_json::json!({
            "command": "/bin/sh",
            "args": [
                "-c",
                "(sleep 0.3; touch \"$1\") & wait",
                "agentos-child",
                marker.to_string_lossy()
            ]
        });
        let task =
            tokio::spawn(async move { BuiltinAppProvider.execute("launch", &parameters).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        task.abort();
        let _ = task.await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert!(
            !marker.exists(),
            "a dropped process tool must kill background descendants before their delayed side effect"
        );
    }

    #[test]
    fn priority_valid_range() {
        for v in 1..=5 {
            assert!(Priority::new(v).is_some());
            assert_eq!(Priority::new(v).unwrap().value(), v);
        }
    }

    #[test]
    fn priority_invalid_range() {
        assert!(Priority::new(0).is_none());
        assert!(Priority::new(6).is_none());
        assert!(Priority::new(255).is_none());
    }

    #[test]
    fn priority_default_is_3() {
        assert_eq!(Priority::default().value(), 3);
    }

    #[test]
    fn priority_ordering() {
        let p1 = Priority::new(1).unwrap();
        let p5 = Priority::new(5).unwrap();
        assert!(p1 < p5);
    }

    #[test]
    fn kernel_error_from_agent_error() {
        let agent_err = AgentError::CreationTimeout;
        let kernel_err: KernelError = agent_err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Agent(AgentError::CreationTimeout)
        ));
    }

    #[test]
    fn kernel_error_from_scheduler_error() {
        let err = SchedulerError::QueueFull;
        let kernel_err: KernelError = err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Scheduler(SchedulerError::QueueFull)
        ));
    }

    #[test]
    fn kernel_error_from_context_error() {
        let err = ContextError::StorageError("disk full".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Context(ContextError::StorageError(_))
        ));
    }

    #[test]
    fn kernel_error_from_resource_error() {
        let err = ResourceError::Timeout;
        let kernel_err: KernelError = err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Resource(ResourceError::Timeout)
        ));
    }

    #[test]
    fn kernel_error_from_permission_error() {
        let err = PermissionError::AccessDenied("no access".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Permission(PermissionError::AccessDenied(_))
        ));
    }

    #[test]
    fn kernel_error_from_connector_error() {
        let err = ConnectorError::ProviderUnavailable("openai".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Connector(ConnectorError::ProviderUnavailable(_))
        ));
    }

    #[test]
    fn kernel_error_from_module_error() {
        let err = ModuleError::NotFound("my-module".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Module(ModuleError::NotFound(_))
        ));
    }

    #[test]
    fn kernel_error_from_ipc_error() {
        let err = IpcError::ChannelClosed;
        let kernel_err: KernelError = err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Ipc(IpcError::ChannelClosed)
        ));
    }

    #[test]
    fn kernel_error_from_sandbox_error() {
        let err = SandboxError::BoundaryViolation("path traversal".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(
            kernel_err,
            KernelError::Sandbox(SandboxError::BoundaryViolation(_))
        ));
    }

    #[test]
    fn agent_state_equality() {
        assert_eq!(AgentState::Running, AgentState::Running);
        assert_ne!(AgentState::Running, AgentState::Paused);
        assert_eq!(
            AgentState::Error("oops".to_string()),
            AgentState::Error("oops".to_string())
        );
    }

    #[test]
    fn agent_command_variants() {
        let cmds = [
            AgentCommand::Pause,
            AgentCommand::Resume,
            AgentCommand::Stop,
            AgentCommand::Execute("do something".to_string()),
        ];
        assert_eq!(cmds.len(), 4);
    }

    #[test]
    fn agent_config_construction() {
        let config = AgentConfig {
            name: "test-agent".to_string(),
            task: "organize files".to_string(),
            llm_provider: "openai".to_string(),
            permission_profile: "standard".to_string(),
            priority: Priority::new(2).unwrap(),
            sandbox_config: None,
        };
        assert_eq!(config.name, "test-agent");
        assert_eq!(config.priority.value(), 2);
        assert!(config.sandbox_config.is_none());
    }

    #[test]
    fn kernel_event_variants() {
        let id = uuid::Uuid::new_v4();
        let events = [
            KernelEvent::AgentCreated(id),
            KernelEvent::AgentStateChanged {
                agent_id: id,
                old: AgentState::Initializing,
                new: AgentState::Running,
            },
            KernelEvent::AgentLifecycle {
                agent_id: id,
                operation: LifecycleOperation::Stop,
                outcome: LifecycleOutcome::Completed,
            },
            KernelEvent::ResourceRequested {
                agent_id: id,
                resource: "filesystem".to_string(),
                operation: "read".to_string(),
            },
            KernelEvent::ShutdownInitiated,
        ];
        assert_eq!(events.len(), 5);
    }

    #[tokio::test]
    async fn completed_turn_slice_exhaustion_records_a_cooperative_yield() {
        let kernel = AgentKernelImpl::new().unwrap();
        let agent = kernel
            .create_agent_full(lifecycle_test_config("cooperative-yield"))
            .await
            .unwrap();
        let output = AgentOutput {
            content: "completed at a turn boundary".into(),
            tool_calls_made: 0,
            tokens_used: 1_001,
            provider_id: "test".into(),
            model_id: "test-model".into(),
            estimated_cost_usd: 0.0,
            usage: crate::execution::UsageTelemetry {
                output_tokens: 1_001,
                ..crate::execution::UsageTelemetry::default()
            },
        };

        kernel
            .record_output_since(
                agent.id,
                &output,
                0,
                0,
                crate::execution::UsageTelemetry::default(),
            )
            .await
            .unwrap();

        assert_eq!(kernel.turn_admission.metrics().cooperative_yields_total, 1);
        let pid = kernel.syscall_gate.pid_of(agent.id).unwrap();
        assert_eq!(kernel.os.cfs.lock().await.tokens_used_of(pid), Some(0));
    }
}
