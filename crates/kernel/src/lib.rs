//! AI Agent OS Kernel
//!
//! Core types, error hierarchy, and module declarations for the Agent Kernel.

pub mod agent;
pub mod agent_hub;
pub mod agent_package;
pub mod agent_struct;
pub mod agent_syscalls;
pub mod agentctl;
pub mod agentpkg;
pub mod agentps;
pub mod auth;
pub mod budget;
pub mod cfs;
pub mod cgroups;
pub mod config;
pub mod connector;
pub mod context;
pub mod context_paging;
pub mod custom_tools;
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
pub mod shell;
pub mod syscall_gate;
pub mod syscall_interface;
pub mod syscall_server;
pub mod sysctl;
pub mod tool_descriptors;
pub mod tool_registry_share;
pub mod tools;
pub mod vision;
pub mod voice;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub workspace_dir: std::path::PathBuf,
    pub allowed_network_hosts: Option<Vec<String>>,
    pub max_disk_usage_bytes: Option<u64>,
    pub max_memory_bytes: Option<u64>,
    pub isolation_level: IsolationLevel,
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
    ResourceRequested {
        agent_id: AgentId,
        resource: String,
        operation: String,
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

/// Per-profile cgroup limits, derived from the operator's budget config.
/// `full-access` (and the empty profile) is unlimited; every other profile —
/// including unknown/custom ones — is bounded so that `CgroupQuota` actually
/// fires on the live agent-creation path. `elevated` gets a wider budget.
fn cgroup_for_profile(profile: &str, budgets: &crate::config::BudgetConfig) -> CgroupLimits {
    match profile {
        "full-access" | "" => CgroupLimits::default(), // all zeros = unlimited
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
        vec!["send".into(), "receive".into()]
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
        let resolve_recipient = |key: &str| -> Result<uuid::Uuid, ResourceError> {
            let s = params.get(key).and_then(|v| v.as_str()).unwrap_or("");
            if let Ok(id) = uuid::Uuid::parse_str(s) {
                return Ok(id);
            }
            self.agents
                .list_agents(None)
                .into_iter()
                .find(|a| a.name == s)
                .map(|a| a.id)
                .ok_or_else(|| {
                    ResourceError::OperationFailed(format!("no agent with id or name '{s}'"))
                })
        };
        match operation {
            "send" => {
                let from = parse_uuid("from")?;
                let to = resolve_recipient("to")?;
                let payload = params
                    .get("payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                self.ipc
                    .send(from, to, payload)
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
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
                let to = resolve_recipient("to")?;
                let description = params
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let task_id = self
                    .ipc
                    .delegate(from, to, description)
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
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
        let client = reqwest::Client::new();
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
        _operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError> {
        let cmd = params
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ResourceError::OperationFailed("Missing 'command'".into()))?;
        let args: Vec<&str> = params
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let output = tokio::process::Command::new(cmd)
            .args(&args)
            .output()
            .await
            .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
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
    pub permission_manager: Arc<PermissionManager>,
    pub sandbox_manager: Arc<SandboxManagerImpl>,
    pub ipc: Arc<IpcManager>,
    pub observability: Arc<ObservabilityEngineImpl>,
    pub connector: Arc<AgentConnectorImpl>,
    pub resource_broker: Arc<ResourceBrokerImpl>,
    pub tool_registry: Arc<ToolRegistry>,
    /// Shared fixed-epoch clock. The cgroup hierarchy uses the same source when
    /// durable hierarchical quota accounting is enabled.
    pub quota_clock: Arc<dyn crate::quota_clock::QuotaClock>,
    pub rate_limiter: Arc<RateLimiter>,
    pub cgroups: Arc<CgroupManager>,
    pub syscall_gate: Arc<SyscallGate>,
    /// Hard cumulative USD spend ceiling on the LLM path (the cgroup quota only
    /// bounds per-minute tokens, not lifetime cost). Inert unless config sets a
    /// price + ceiling. Installed on each executor in `send_message`.
    pub budget_enforcer: Arc<crate::budget::BudgetEnforcer>,
    /// Active-context token budget applied to each executor (from
    /// `budgets.max_context_tokens`; 0 = unbounded). Drives context paging.
    context_budget_tokens: u32,
    /// Cumulative tool-call ceiling for one logical turn, including calls made
    /// before a durable pause/resume boundary. `0` means unlimited.
    max_tool_calls_per_turn: u32,
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
    /// One cgroup per permission profile, created at boot with budget-derived
    /// limits. Agents are placed into their profile's cgroup at creation so
    /// `CgroupQuota` enforcement is live on the real agent-creation path
    /// (rather than every agent landing in the unlimited root cgroup).
    profile_cgroups: std::collections::HashMap<String, CgroupId>,
    /// Agent+Tool namespaces per agent group, created lazily. Agents created via
    /// `create_agent_in_namespace` with the same group share these (and can
    /// see/message each other); ungrouped agents use the registry defaults.
    group_namespaces: DashMap<String, (NamespaceId, NamespaceId)>,
    /// Multi-tenant auth/identity. Owned by the kernel (behind a `RwLock` — auth
    /// resolution is read-heavy), persisted + rehydrated through the single
    /// SQLite handle. Resolves an API key / session token to a `(user, tenant,
    /// role)`; the tenant then maps onto the namespace group + cgroup below.
    pub auth: Arc<tokio::sync::RwLock<crate::auth::AuthSystem>>,
    /// One cgroup per tenant (token budget), created lazily so one tenant can't
    /// exhaust another's per-minute quota. Sibling to `profile_cgroups` under the
    /// root; a tenant's agents are placed in *its tenant's* cgroup.
    tenant_cgroups: DashMap<String, CgroupId>,
    /// Per-minute token budget applied to each tenant's cgroup at creation,
    /// derived from the kernel's `BudgetConfig` (`tokens_per_min`).
    tenant_budget: CgroupLimits,
    executors: DashMap<AgentId, Arc<tokio::sync::Mutex<AgentExecutor>>>,
    lifecycle_locks: DashMap<AgentId, Arc<tokio::sync::Mutex<()>>>,
    active_cancellations: DashMap<AgentId, tokio_util::sync::CancellationToken>,
    event_tx: broadcast::Sender<KernelEvent>,
}

impl AgentKernelImpl {
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
        let context_manager =
            Arc::new(SqliteContextManager::new(db_path).map_err(KernelError::Context)?);
        let security = crate::config::Config::default();
        let kernel = Self::with_context_manager(
            context_manager,
            &security.budgets,
            security.mac_enforcing,
            &security.mac_rules,
        )?;
        // Bring back any agents persisted by a previous run on this DB so a
        // restart restores the full registry (and re-arms enforcement).
        kernel.rehydrate_agents_blocking();
        Ok(kernel)
    }

    /// Create a kernel from config (uses config.data_dir for persistence and
    /// config.budgets for cgroup/rate-limit quotas).
    pub fn from_config(config: &crate::config::Config) -> Result<Self, KernelError> {
        config.budgets.validate().map_err(|error| {
            KernelError::Policy(format!("invalid budget configuration: {error}"))
        })?;
        set_max_browse_chars(config.max_browse_chars);
        let db_path = config.data_dir.join("agent_os.db");
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let context_manager =
            Arc::new(SqliteContextManager::new(&db_path).map_err(KernelError::Context)?);
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
        let kernel = Self::with_context_manager(
            context_manager,
            &config.budgets,
            mac_enforcing,
            &mac_rules,
        )?;
        if let Some(service_dir) = &config.service_dir {
            let mut init = kernel.os.init.try_lock().map_err(|_| {
                KernelError::Policy("service supervisor was unexpectedly busy during boot".into())
            })?;
            init.load_directory_checked(service_dir)
                .map_err(KernelError::Policy)?;
        }
        // Bring back any agents persisted by a previous run on this DB so a
        // restart restores the full registry (and re-arms enforcement).
        kernel.rehydrate_agents_blocking();
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
        budgets.validate().map_err(|error| {
            KernelError::Policy(format!("invalid budget configuration: {error}"))
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
        // One child cgroup per permission profile with budget-derived limits,
        // so agents created through the live path inherit a real token quota.
        let mut profile_cgroups = std::collections::HashMap::new();
        for profile in ["read-only", "standard", "elevated", "full-access"] {
            let cg = cgroups.create(
                format!("profile/{profile}"),
                cgroups.root(),
                cgroup_for_profile(profile, budgets),
            );
            profile_cgroups.insert(profile.to_string(), cg);
        }
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
            permission_manager,
            sandbox_manager,
            ipc,
            observability,
            connector: Arc::new(AgentConnectorImpl::new()),
            resource_broker,
            tool_registry,
            quota_clock,
            rate_limiter,
            cgroups,
            syscall_gate,
            budget_enforcer,
            context_budget_tokens: budgets.max_context_tokens.min(u32::MAX as u64) as u32,
            max_tool_calls_per_turn: budgets.max_tool_calls,
            turn_admission: Arc::new(TurnAdmission::new(budgets.max_concurrent as usize)),
            llm_scheduler: Arc::new(LlmScheduler::new(DEFAULT_LLM_CORES)),
            os,
            profile_cgroups,
            group_namespaces: DashMap::new(),
            auth: Arc::new(tokio::sync::RwLock::new(crate::auth::AuthSystem::new())),
            tenant_cgroups: DashMap::new(),
            // Each tenant's cgroup caps per-minute tokens at the configured TPM so
            // one tenant exhausting its budget can't starve another (whose cgroup
            // is independent). 0 = unlimited, matching the rest of the budget model.
            tenant_budget: CgroupLimits {
                tokens_per_min: budgets.tpm,
                max_concurrent_tool_calls: budgets.max_concurrent_tool_calls,
                max_context_tokens: budgets.max_context_tokens,
                ..Default::default()
            },
            executors: DashMap::new(),
            lifecycle_locks: DashMap::new(),
            active_cancellations: DashMap::new(),
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

    /// Get-or-create the cgroup that bounds a tenant's per-minute token budget.
    /// `DEFAULT_TENANT` keeps the prior behavior (profile cgroups); every other
    /// tenant gets its own sibling cgroup under the root so budgets are isolated.
    fn tenant_cgroup(&self, tenant_id: &str) -> Option<CgroupId> {
        if tenant_id == crate::context::DEFAULT_TENANT {
            return None;
        }
        let entry = self
            .tenant_cgroups
            .entry(tenant_id.to_string())
            .or_insert_with(|| {
                self.cgroups.create(
                    format!("tenant/{tenant_id}"),
                    self.cgroups.root(),
                    self.tenant_budget.clone(),
                )
            });
        Some(*entry)
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
            .prepare_call(tool_name, arguments)
            .map_err(KernelError::Policy)?;
        if prepared.security.approval_policy == crate::tools::ApprovalPolicy::None {
            return Err(KernelError::Policy(format!(
                "tool '{tool_name}' does not require approval"
            )));
        }
        if !approval.satisfies(prepared.security.approval_policy) {
            return Err(KernelError::Policy(format!(
                "{approval:?} approval is insufficient for tool '{tool_name}'"
            )));
        }
        if !self.syscall_gate.grant_tool_approval(
            agent_id,
            tool_name,
            prepared.resource,
            &prepared.security,
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
        self.place_agent_in_subsystems(agent_id, &config, group, tenant_id)
            .await;

        // 9. Persist the agent's durable identity (incl. tenant) so it survives a
        //    restart, then broadcast the creation event. Persistence commits
        //    immediately, so even an abrupt stop recovers this agent + its tenant.
        self.persist_agent_registry(agent_id, &config, tenant_id);
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
    ) {
        self.budget_enforcer
            .register_agent_tenant(agent_id, tenant_id);

        // Register IPC mailbox.
        self.ipc.register_agent(agent_id);

        // Register with the syscall gate (capabilities derived from the
        // permission profile; unknown profiles receive no capabilities).
        let caps = caps_for_profile(&config.permission_profile);
        // Choose the cgroup: a tenanted agent goes in its tenant's cgroup so its
        // tokens count against the tenant's budget (and one tenant exhausting its
        // quota can't starve another). Un-tenanted agents fall back to the
        // permission-profile cgroup (prior behavior). Unknown profiles remain
        // capability/MAC denied even though they use the standard resource quota.
        let cgroup = self.tenant_cgroup(tenant_id).or_else(|| {
            self.profile_cgroups
                .get(&config.permission_profile)
                .or_else(|| self.profile_cgroups.get("standard"))
                .copied()
        });
        let pid = self.syscall_gate.register_agent(agent_id, caps, cgroup);

        // MAC: label the agent by its permission profile so an enforcing policy
        // can discriminate by subject (e.g. "profile:read-only").
        {
            let mut mac = self.syscall_gate.mac.lock().await;
            mac.label_agent(pid, format!("profile:{}", config.permission_profile));
        }

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
    }

    /// Write the agent's durable identity + config to the `agents` table via the
    /// single SQLite handle. Best-effort: a persistence failure is logged but
    /// does not fail agent creation (the in-memory agent is still live).
    fn persist_agent_registry(&self, agent_id: AgentId, config: &AgentConfig, tenant_id: &str) {
        let state = self
            .agent_manager
            .get_agent_state(agent_id)
            .unwrap_or(AgentState::Running);
        let status = serde_json::to_string(&state).unwrap_or_else(|_| "\"Running\"".to_string());
        let now = chrono::Utc::now();
        let sandbox_config_json = config
            .sandbox_config
            .as_ref()
            .and_then(|s| serde_json::to_string(s).ok());
        let record = crate::context::PersistedAgent {
            id: agent_id,
            session_id: self
                .agent_manager
                .list_agents(None)
                .into_iter()
                .find(|a| a.id == agent_id)
                .and_then(|a| a.session_id)
                .unwrap_or(agent_id),
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
        if let Err(e) = self.context_manager.save_agent(&record) {
            tracing::warn!("Failed to persist agent {agent_id} to registry: {e}");
        }
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
            let state: AgentState = serde_json::from_str(&p.status).unwrap_or(AgentState::Running);
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
            self.place_agent_in_subsystems(p.id, &config, group, &p.tenant_id)
                .await;
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

    /// Revoke a session durably. The auth write lock is held across the SQLite
    /// delete and in-memory mutation, so a wire request either completes before
    /// revocation or observes the revoked state; once this returns there is no
    /// post-revocation authorization window.
    pub async fn revoke_session(&self, token: &str) -> Result<bool, KernelError> {
        let token_hash = crate::auth::hash_secret(token);
        let mut auth = self.auth.write().await;
        let persisted = self
            .context_manager
            .revoke_session_hash(&token_hash)
            .map_err(KernelError::Context)?;
        Ok(auth.revoke_session(token) || persisted)
    }

    /// Revoke an API key durably with the same linearizable boundary as session
    /// revocation.
    pub async fn revoke_api_key(&self, key: &str) -> Result<bool, KernelError> {
        let key_hash = crate::auth::hash_secret(key);
        let mut auth = self.auth.write().await;
        let persisted = self
            .context_manager
            .revoke_api_key_hash(&key_hash)
            .map_err(KernelError::Context)?;
        Ok(auth.revoke_api_key(key) || persisted)
    }

    /// Revoke a user and all of that user's credentials atomically and durably.
    pub async fn revoke_user(&self, user_id: &str) -> Result<bool, KernelError> {
        let mut auth = self.auth.write().await;
        let persisted = self
            .context_manager
            .revoke_user_identity(user_id)
            .map_err(KernelError::Context)?;
        Ok(auth.revoke_user(user_id) || persisted)
    }

    /// Revoke a tenant identity boundary and all tenant credentials atomically.
    /// Agent/data records remain durable but inaccessible to tenant callers.
    pub async fn revoke_tenant(&self, tenant_id: &str) -> Result<bool, KernelError> {
        let mut auth = self.auth.write().await;
        let persisted = self
            .context_manager
            .revoke_tenant_identity(tenant_id)
            .map_err(KernelError::Context)?;
        Ok(auth.revoke_tenant(tenant_id) || persisted)
    }

    /// Resolve a presented secret (API key or session token) to a
    /// [`Principal`](crate::auth::Principal): the full
    /// `(user, tenant, role, credential identity)` the connection acts as.
    /// `None` if the secret or any referenced tenant/user record is
    /// unknown, expired, inconsistent, or revoked.
    pub async fn resolve_principal(&self, secret: &str) -> Option<crate::auth::Principal> {
        self.auth.read().await.authenticate(secret)
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

    fn lifecycle_lock(&self, agent_id: AgentId) -> Arc<tokio::sync::Mutex<()>> {
        self.lifecycle_locks
            .entry(agent_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    async fn cleanup_agent_resources(&self, agent_id: AgentId) {
        let gate_info = self.syscall_gate.agent_info(agent_id);
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
                tracing::warn!("sandbox cleanup failed for {agent_id}: {error}");
            }
        }
        self.observability.purge_agent(agent_id);
        self.budget_enforcer.unregister_agent(agent_id);
        self.syscall_gate.unregister_agent(agent_id);
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
        self.quiesce_agent(agent_id).await;
        self.cleanup_agent_resources(agent_id).await;
        self.agent_manager.purge_agent(agent_id);
        let _ = self.context_manager.purge_agent_data(agent_id);
        self.lifecycle_locks.remove(&agent_id);
    }

    /// Reload a complete service directory atomically. This validates parsing,
    /// duplicate names, required dependencies, ordering, and cycles before the
    /// live definition set is replaced.
    pub async fn reload_service_directory(
        &self,
        path: &std::path::Path,
    ) -> Result<Vec<String>, KernelError> {
        let mut init = self.os.init.lock().await;
        if init.list_runtime().iter().any(|service| {
            !matches!(
                service.status,
                ServiceStatus::Inactive | ServiceStatus::Failed
            )
        }) {
            return Err(KernelError::Policy(
                "service reload requires all services to be inactive or failed; stop them before retrying"
                    .into(),
            ));
        }
        init.load_directory_checked(path)
            .map_err(KernelError::Policy)
    }

    pub async fn list_services(&self) -> Vec<ServiceRuntimeInfo> {
        self.os.init.lock().await.list_runtime()
    }

    /// Start one validated service through the same full agent admission path
    /// as every other agent. Required dependencies must already be running.
    pub async fn start_service(&self, name: &str) -> Result<AgentId, KernelError> {
        let state = self
            .os
            .init
            .lock()
            .await
            .state(name)
            .ok_or_else(|| KernelError::Policy(format!("service '{name}' not found")))?;
        if state.status == ServiceStatus::Running {
            if let Some(agent_id) = state.agent_id {
                if let Ok(agent_state) = self.get_agent_status(agent_id) {
                    if !matches!(agent_state, AgentState::Stopped | AgentState::Error(_)) {
                        return Ok(agent_id);
                    }
                }
            }
        }
        {
            let init = self.os.init.lock().await;
            for required in &state.def.dependencies.requires {
                if init.status(required) != Some(ServiceStatus::Running) {
                    return Err(KernelError::Policy(format!(
                        "service '{name}' is blocked by required service '{required}'"
                    )));
                }
            }
        }
        self.os.init.lock().await.mark_starting(name);

        let provider = if state.def.exec.provider.trim().is_empty() {
            "stub".to_string()
        } else {
            state.def.exec.provider.clone()
        };
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
        let nice = state.def.resources.nice.unwrap_or(0).clamp(-20, 19);
        let priority_value = match nice {
            -20..=-12 => 1,
            -11..=-4 => 2,
            -3..=4 => 3,
            5..=12 => 4,
            _ => 5,
        };
        let created = self
            .create_agent_full(AgentConfig {
                name: format!("service:{name}"),
                task,
                llm_provider: provider,
                permission_profile: "standard".into(),
                priority: Priority::new(priority_value).unwrap_or_default(),
                sandbox_config: None,
            })
            .await;
        match created {
            Ok(handle) => {
                if state.def.resources.nice.is_some() {
                    if let Err(error) = self.set_nice(handle.id, nice).await {
                        let _ = self.kill_agent(handle.id).await;
                        self.os.init.lock().await.mark_failed(name, 1);
                        return Err(error);
                    }
                }
                self.os.init.lock().await.mark_started(name, handle.id);
                Ok(handle.id)
            }
            Err(error) => {
                self.os.init.lock().await.mark_failed(name, 1);
                Err(error)
            }
        }
    }

    pub async fn stop_service(&self, name: &str) -> Result<(), KernelError> {
        let state = self
            .os
            .init
            .lock()
            .await
            .state(name)
            .ok_or_else(|| KernelError::Policy(format!("service '{name}' not found")))?;
        if state.status == ServiceStatus::Inactive {
            return Ok(());
        }
        self.os.init.lock().await.mark_stopping(name);
        if let Some(agent_id) = state.agent_id {
            if let Err(error) = self.stop_agent(agent_id).await {
                self.os.init.lock().await.mark_failed(name, 1);
                return Err(error);
            }
        }
        self.os.init.lock().await.mark_stopped(name);
        Ok(())
    }

    pub async fn restart_service(&self, name: &str) -> Result<AgentId, KernelError> {
        let state = self
            .os
            .init
            .lock()
            .await
            .state(name)
            .ok_or_else(|| KernelError::Policy(format!("service '{name}' not found")))?;
        self.stop_service(name).await?;
        self.os.init.lock().await.record_restart(name);
        tokio::time::sleep(std::time::Duration::from_millis(
            state.def.service.restart_delay_ms.min(30_000),
        ))
        .await;
        self.start_service(name).await
    }

    /// Start all services in validated dependency order. A failure rolls back
    /// services started by this attempt in reverse order.
    pub async fn boot_services(&self) -> Result<Vec<AgentId>, KernelError> {
        let order = self.os.init.lock().await.boot_order().to_vec();
        let mut started = Vec::new();
        for name in order {
            match self.start_service(&name).await {
                Ok(agent_id) => started.push((name, agent_id)),
                Err(error) => {
                    for (started_name, _) in started.iter().rev() {
                        let _ = self.stop_service(started_name).await;
                    }
                    return Err(error);
                }
            }
        }
        Ok(started.into_iter().map(|(_, agent_id)| agent_id).collect())
    }

    /// Cancel an active turn and wait until the per-agent executor is idle.
    /// Callers hold the lifecycle lock, which prevents resume or new admission;
    /// `send_message` never waits for that lock while holding the executor.
    async fn quiesce_agent(&self, agent_id: AgentId) {
        if let Some(token) = self.active_cancellations.get(&agent_id) {
            token.cancel();
        }
        let executor = self
            .executors
            .get(&agent_id)
            .map(|entry| Arc::clone(entry.value()));
        if let Some(executor) = executor {
            let _idle = executor.lock().await;
        }
    }

    /// Pause admission for an agent and cooperatively cancel any active turn.
    /// Repeating a pause is idempotent.
    pub async fn pause_agent(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
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
        self.quiesce_agent(agent_id).await;
        Ok(AgentState::Paused)
    }

    /// Resume admission for a paused agent. The next turn receives a fresh
    /// cancellation token; repeating resume on Running is idempotent.
    pub async fn resume_agent(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
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
        let lock = self.lifecycle_lock(agent_id);
        let _guard = lock.lock().await;
        let state = self
            .agent_manager
            .get_agent_state(agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        if state == AgentState::Stopped {
            return Ok(state);
        }
        self.agent_manager.stop_agent(agent_id).await?;
        self.context_manager
            .update_agent_status(agent_id, &AgentState::Stopped)?;
        self.quiesce_agent(agent_id).await;
        self.cleanup_agent_resources(agent_id).await;
        Ok(AgentState::Stopped)
    }

    /// Force a terminal state from any non-terminal lifecycle state, then run
    /// the exact same cleanup invariant as graceful stop.
    pub async fn kill_agent(&self, agent_id: AgentId) -> Result<AgentState, KernelError> {
        let lock = self.lifecycle_lock(agent_id);
        let _guard = lock.lock().await;
        let state = self
            .agent_manager
            .get_agent_state(agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        if state == AgentState::Stopped {
            return Ok(state);
        }
        self.agent_manager.force_stopped(agent_id)?;
        self.context_manager
            .update_agent_status(agent_id, &AgentState::Stopped)?;
        self.quiesce_agent(agent_id).await;
        self.cleanup_agent_resources(agent_id).await;
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
        .map_err(|_| KernelError::Policy("wait_agent timed out".into()))?
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

    /// Resume the newest (or explicitly selected) durable in-flight turn while
    /// holding lifecycle admission. Returns the completed output, or a new
    /// checkpoint id if another pause interrupted the continuation.
    pub async fn resume_agent_from_checkpoint(
        &self,
        agent_id: AgentId,
        checkpoint_id: Option<uuid::Uuid>,
    ) -> Result<(AgentState, Option<AgentOutput>, Option<uuid::Uuid>), KernelError> {
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
        let session = AgentConnector::connect(&*self.connector, agent_id, &provider_id)
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
        executor.set_max_tool_calls(self.max_tool_calls_per_turn);
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
            self.os
                .cfs
                .lock()
                .await
                .account_tokens(pid, u64::from(tokens));
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
                    self.active_cancellations.insert(agent_id, cancellation);
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
                    self.active_cancellations.remove(&agent_id);
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
        self.active_cancellations.remove(&agent_id);
        match self.agent_manager.get_agent_state(agent_id) {
            Some(AgentState::Running) => self.scheduler.set_queued(agent_id),
            Some(AgentState::Paused) => self.scheduler.set_paused(agent_id),
            _ => self.scheduler.deschedule(agent_id),
        }
        let output = match run_result? {
            TurnResult::Completed(output) => output,
            TurnResult::Paused(checkpoint) => {
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

        // Coordinated services stop first in reverse dependency order. Their
        // agents become terminal through `stop_agent`, so the general pass
        // below naturally skips them.
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
            if self.stop_service(&service).await.is_ok() {
                if let Some(agent_id) = agent_id {
                    stopped.push(agent_id);
                }
            }
        }

        let agents = self.agent_manager.list_agents(None);

        for info in agents {
            match info.state {
                AgentState::Stopped | AgentState::Error(_) => {}
                AgentState::Running | AgentState::Paused => {
                    if self.stop_agent(info.id).await.is_ok() {
                        stopped.push(info.id);
                    }
                }
                AgentState::Initializing | AgentState::Stopping => {
                    if self.kill_agent(info.id).await.is_ok() {
                        stopped.push(info.id);
                    }
                }
            }
        }

        // Flush the WAL into the main DB file so a subsequent open recovers a
        // fully-consolidated, consistent database. Best-effort. (Crash recovery
        // does NOT depend on this — committed transactions are already durable;
        // this just truncates the WAL on a clean exit.)
        if let Err(e) = self.context_manager.checkpoint() {
            tracing::warn!("WAL checkpoint on shutdown failed: {e}");
        }

        Ok(stopped)
    }

    /// Subscribe to kernel events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<KernelEvent> {
        self.event_tx.subscribe()
    }

    /// Spawn the kernel's background tasks: scheduler observer (publishes the
    /// CFS pick to procfs as `current_agent`) and the cgroup minute-counter
    /// reset timer. Returns the [`KernelRuntime`] so the caller can `stop()`
    /// it on shutdown. Idempotent — calling twice spawns two sets, so call
    /// once at startup.
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

    #[tokio::test]
    async fn in_memory_kernel_uses_production_mac_defaults() {
        let kernel = AgentKernelImpl::new().unwrap();
        assert!(kernel.syscall_gate.mac.lock().await.is_enforcing());
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
            .mac
            .lock()
            .await
            .label_agent(pid, "profile:full-access".into());
        let arguments = serde_json::json!({"command": "echo", "args": ["ok"]});

        assert!(matches!(
            kernel
                .tool_registry
                .authorize_call(&kernel.syscall_gate, agent, "run_command", &arguments)
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
        assert!(kernel
            .tool_registry
            .authorize_call(&kernel.syscall_gate, agent, "run_command", &arguments)
            .await
            .is_ok());
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
            KernelEvent::ResourceRequested {
                agent_id: id,
                resource: "filesystem".to_string(),
                operation: "read".to_string(),
            },
            KernelEvent::ShutdownInitiated,
        ];
        assert_eq!(events.len(), 4);
    }
}
