//! AI Agent OS Kernel
//!
//! Core types, error hierarchy, and module declarations for the Agent Kernel.

pub mod agent;
pub mod config;
pub mod connector;
pub mod context;
pub mod ipc;
pub mod models;
pub mod modules;
pub mod observability;
pub mod permissions;
pub mod resources;
pub mod sandbox;
pub mod scheduler;
pub mod prerequisites;
pub mod tools;
pub mod custom_tools;
pub mod execution;

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

struct BuiltinFilesystemProvider;

#[async_trait::async_trait]
impl ResourceProvider for BuiltinFilesystemProvider {
    fn resource_type(&self) -> ResourceType { ResourceType::Filesystem }
    fn supported_operations(&self) -> Vec<String> { vec!["read".into(), "write".into(), "create".into(), "delete".into(), "list".into()] }
    async fn execute(&self, operation: &str, params: &serde_json::Value) -> Result<serde_json::Value, ResourceError> {
        let path = params.get("path").and_then(|v| v.as_str())
            .ok_or_else(|| ResourceError::OperationFailed("Missing 'path'".into()))?;
        match operation {
            "read" => {
                let content = tokio::fs::read_to_string(path).await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"content": content}))
            }
            "write" | "create" => {
                let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("");
                tokio::fs::write(path, content).await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"written": true}))
            }
            "delete" => {
                tokio::fs::remove_file(path).await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"deleted": true}))
            }
            "list" => {
                let mut entries = Vec::new();
                let mut dir = tokio::fs::read_dir(path).await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                while let Some(entry) = dir.next_entry().await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))? {
                    entries.push(entry.file_name().to_string_lossy().to_string());
                }
                Ok(serde_json::json!({"entries": entries}))
            }
            _ => Err(ResourceError::OperationFailed(format!("Unknown op: {}", operation))),
        }
    }
}

struct BuiltinNetworkProvider;

#[async_trait::async_trait]
impl ResourceProvider for BuiltinNetworkProvider {
    fn resource_type(&self) -> ResourceType { ResourceType::Network }
    fn supported_operations(&self) -> Vec<String> { vec!["get".into(), "post".into()] }
    async fn execute(&self, operation: &str, params: &serde_json::Value) -> Result<serde_json::Value, ResourceError> {
        let url = params.get("url").and_then(|v| v.as_str())
            .ok_or_else(|| ResourceError::OperationFailed("Missing 'url'".into()))?;
        let client = reqwest::Client::new();
        let resp = match operation {
            "get" => client.get(url).send().await,
            "post" => {
                let body = params.get("body").cloned().unwrap_or(serde_json::Value::Null);
                client.post(url).json(&body).send().await
            }
            _ => return Err(ResourceError::OperationFailed(format!("Unknown op: {}", operation))),
        }.map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
        Ok(serde_json::json!({"status": status, "body": body}))
    }
}

struct BuiltinAppProvider;

#[async_trait::async_trait]
impl ResourceProvider for BuiltinAppProvider {
    fn resource_type(&self) -> ResourceType { ResourceType::Application }
    fn supported_operations(&self) -> Vec<String> { vec!["launch".into()] }
    async fn execute(&self, _operation: &str, params: &serde_json::Value) -> Result<serde_json::Value, ResourceError> {
        let cmd = params.get("command").and_then(|v| v.as_str())
            .ok_or_else(|| ResourceError::OperationFailed("Missing 'command'".into()))?;
        let args: Vec<&str> = params.get("args").and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
        let output = tokio::process::Command::new(cmd).args(&args).output().await
            .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
        Ok(serde_json::json!({
            "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
            "stderr": String::from_utf8_lossy(&output.stderr).to_string(),
            "exit_code": output.status.code(),
        }))
    }
}

// ─── Kernel Orchestrator ─────────────────────────────────────────────────────

use std::sync::Arc;
use tokio::sync::broadcast;
use dashmap::DashMap;

use crate::agent::{AgentKernel, AgentManager};
use crate::connector::{AgentConnector, AgentConnectorImpl, LlmProviderAdapter};
use crate::context::{ContextManager, SqliteContextManager};
use crate::execution::{AgentExecutor, AgentOutput};
use crate::ipc::IpcManager;
use crate::observability::{ObservabilityEngine, ObservabilityEngineImpl};
use crate::permissions::{PermissionManager, PermissionSystem};
use crate::resources::{ResourceBroker, ResourceBrokerImpl};
use crate::sandbox::{SandboxManager, SandboxManagerImpl};
use crate::scheduler::{AgentScheduler, PriorityScheduler};
use crate::tools::ToolRegistry;

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
    executors: DashMap<AgentId, tokio::sync::Mutex<AgentExecutor>>,
    event_tx: broadcast::Sender<KernelEvent>,
}

impl AgentKernelImpl {
    /// Create a new kernel with all subsystems wired together (in-memory DB for testing).
    pub fn new() -> Result<Self, KernelError> {
        let context_manager = Arc::new(
            SqliteContextManager::in_memory()
                .map_err(|e| KernelError::Context(e))?
        );
        Self::with_context_manager(context_manager)
    }

    /// Create a kernel with persistent SQLite storage at the given path.
    pub fn with_db_path(db_path: &std::path::Path) -> Result<Self, KernelError> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let context_manager = Arc::new(
            SqliteContextManager::new(db_path)
                .map_err(|e| KernelError::Context(e))?
        );
        Self::with_context_manager(context_manager)
    }

    /// Create a kernel from config (uses config.data_dir for persistence).
    pub fn from_config(config: &crate::config::Config) -> Result<Self, KernelError> {
        let db_path = config.data_dir.join("agent_os.db");
        Self::with_db_path(&db_path)
    }

    fn with_context_manager(context_manager: Arc<SqliteContextManager>) -> Result<Self, KernelError> {
        let (event_tx, _) = broadcast::channel(256);
        let permission_manager = Arc::new(PermissionManager::new());
        let resource_broker = Arc::new(ResourceBrokerImpl::new(permission_manager.clone()));

        // Register built-in resource providers
        resource_broker.register_provider(Box::new(BuiltinFilesystemProvider));
        resource_broker.register_provider(Box::new(BuiltinNetworkProvider));
        resource_broker.register_provider(Box::new(BuiltinAppProvider));

        Ok(Self {
            agent_manager: Arc::new(AgentManager::new(256)),
            scheduler: Arc::new(PriorityScheduler::new()),
            context_manager,
            permission_manager,
            sandbox_manager: Arc::new(SandboxManagerImpl::new()),
            ipc: Arc::new(IpcManager::new()),
            observability: Arc::new(ObservabilityEngineImpl::new()),
            connector: Arc::new(AgentConnectorImpl::new()),
            resource_broker,
            tool_registry: Arc::new(ToolRegistry::new()),
            executors: DashMap::new(),
            event_tx,
        })
    }

    /// Register an LLM provider adapter.
    pub fn register_provider(&self, adapter: Arc<dyn LlmProviderAdapter>) -> Result<(), KernelError> {
        self.connector.register_provider(adapter)
            .map_err(|e| KernelError::Connector(e))
    }

    /// Create agent with full subsystem coordination.
    pub async fn create_agent_full(&self, config: AgentConfig) -> Result<AgentHandle, KernelError> {
        // 1. Create agent via agent manager
        let handle = self.agent_manager.create_agent(config.clone()).await?;
        let agent_id = handle.id;

        // 2. Assign permission profile
        PermissionSystem::assign_profile(&*self.permission_manager, agent_id, &config.permission_profile);

        // 3. Create context
        ContextManager::create_context(&*self.context_manager, agent_id).await
            .map_err(|e| KernelError::Context(e))?;

        // 4. Create sandbox if configured
        if let Some(ref sandbox_config) = config.sandbox_config {
            self.sandbox_manager.create_sandbox(agent_id, sandbox_config)
                .map_err(|e| KernelError::Sandbox(e))?;
        }

        // 5. Schedule agent
        AgentScheduler::schedule(&*self.scheduler, &handle).await
            .map_err(|e| KernelError::Scheduler(e))?;

        // 6. Register IPC mailbox
        self.ipc.register_agent(agent_id);

        // 7. Broadcast event
        let _ = self.event_tx.send(KernelEvent::AgentCreated(agent_id));

        Ok(handle)
    }

    /// Send a message to an agent and get a response.
    /// Creates an executor on first message using the agent's LLM provider.
    pub async fn send_message(&self, agent_id: AgentId, message: &str) -> Result<AgentOutput, KernelError> {
        // Ensure executor exists for this agent
        if !self.executors.contains_key(&agent_id) {
            // Get agent's LLM provider from its config
            let provider_id = self.agent_manager
                .get_agent_provider(agent_id)
                .ok_or(AgentError::NotFound(agent_id))?;

            // Connect to LLM provider
            let session = AgentConnector::connect(&*self.connector, agent_id, &provider_id).await
                .map_err(|e| KernelError::Connector(e))?;

            let executor = AgentExecutor::new(
                agent_id,
                session,
                self.resource_broker.clone() as Arc<dyn ResourceBroker>,
                self.tool_registry.clone(),
                self.context_manager.clone(),
                "You are a helpful AI assistant. Use the available tools to help the user.".into(),
            );

            self.executors.insert(agent_id, tokio::sync::Mutex::new(executor));
        }

        // Run the execution loop
        let executor_entry = self.executors.get(&agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        let mut executor = executor_entry.lock().await;
        let output = executor.run(message).await?;

        // Record activity
        self.agent_manager.record_activity(agent_id);

        // Record metrics
        ObservabilityEngine::record_metrics(&*self.observability, agent_id, output.tokens_used as u64, 1);

        Ok(output)
    }

    /// Graceful shutdown — persist all agent states, terminate sessions.
    pub async fn shutdown(&self) -> Result<Vec<AgentId>, KernelError> {
        let _ = self.event_tx.send(KernelEvent::ShutdownInitiated);

        let agents = self.agent_manager.list_agents(None);
        let mut stopped = Vec::new();

        for info in &agents {
            if info.state != AgentState::Stopped {
                let _ = self.agent_manager.stop_agent(info.id).await;
                stopped.push(info.id);
            }
        }

        Ok(stopped)
    }

    /// Subscribe to kernel events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<KernelEvent> {
        self.event_tx.subscribe()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(kernel_err, KernelError::Agent(AgentError::CreationTimeout)));
    }

    #[test]
    fn kernel_error_from_scheduler_error() {
        let err = SchedulerError::QueueFull;
        let kernel_err: KernelError = err.into();
        assert!(matches!(kernel_err, KernelError::Scheduler(SchedulerError::QueueFull)));
    }

    #[test]
    fn kernel_error_from_context_error() {
        let err = ContextError::StorageError("disk full".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(kernel_err, KernelError::Context(ContextError::StorageError(_))));
    }

    #[test]
    fn kernel_error_from_resource_error() {
        let err = ResourceError::Timeout;
        let kernel_err: KernelError = err.into();
        assert!(matches!(kernel_err, KernelError::Resource(ResourceError::Timeout)));
    }

    #[test]
    fn kernel_error_from_permission_error() {
        let err = PermissionError::AccessDenied("no access".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(kernel_err, KernelError::Permission(PermissionError::AccessDenied(_))));
    }

    #[test]
    fn kernel_error_from_connector_error() {
        let err = ConnectorError::ProviderUnavailable("openai".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(kernel_err, KernelError::Connector(ConnectorError::ProviderUnavailable(_))));
    }

    #[test]
    fn kernel_error_from_module_error() {
        let err = ModuleError::NotFound("my-module".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(kernel_err, KernelError::Module(ModuleError::NotFound(_))));
    }

    #[test]
    fn kernel_error_from_ipc_error() {
        let err = IpcError::ChannelClosed;
        let kernel_err: KernelError = err.into();
        assert!(matches!(kernel_err, KernelError::Ipc(IpcError::ChannelClosed)));
    }

    #[test]
    fn kernel_error_from_sandbox_error() {
        let err = SandboxError::BoundaryViolation("path traversal".to_string());
        let kernel_err: KernelError = err.into();
        assert!(matches!(kernel_err, KernelError::Sandbox(SandboxError::BoundaryViolation(_))));
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
        let cmds = vec![
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
        let events = vec![
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
