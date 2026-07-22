//! Syscall server — exposes the kernel over a socket as an agent↔kernel boundary.
//!
//! This is the network/IPC face of [`AgentKernelImpl`] ("kernel-as-server").
//! Agents — in-process, or in separate Rust processes via the SDK — drive the
//! kernel by sending **syscalls** (newline-delimited JSON) over a connection;
//! each is dispatched to the same kernel methods the in-process CLI uses, so
//! every syscall still flows through the syscall gate's enforcement.
//!
//! Transport is deliberately dependency-light (tokio + serde_json, both already
//! in the workspace): one JSON [`Syscall`] per line, one JSON [`SyscallReply`]
//! per line. The wire format is plain JSON, so the boundary is language-neutral,
//! but the SDK and clients we ship are Rust. The numbered, in-process
//! [`crate::syscall_interface`] ABI remains a separate concern; this module is
//! the live remoting boundary.
//!
//! The syscall surface spans agent lifecycle (create / list / send / agent
//! info), the LLM core (the [`Syscall::SendMessage`] turn + [`Syscall::ListProviders`]),
//! the memory/storage subsystem ([`Syscall::MemoryStore`] / [`Syscall::MemoryQuery`],
//! backed by the durable SQLite facts store), tools ([`Syscall::CallTool`]), and
//! enforcement ([`Syscall::GateStats`]). Both TCP and Unix-domain-socket
//! transports are supported; an optional shared-secret token gates a connection
//! (required before any other syscall when configured) for non-loopback use.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, Lines};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

use crate::agent::AgentKernel;
use crate::auth::{Principal, Role};
use crate::connector::{AgentConnector, ToolCall};
use crate::context::{ContextManager, ContextPressureStats, Fact, FactCategory};
use crate::observability::{AgentAction, ObservabilityEngine};
use crate::resources::ResourceBroker;
use crate::{AgentConfig, AgentKernelImpl, Priority};

/// The wire-protocol version this build speaks.
///
/// The `Syscall`/`SyscallReply` schema is versioned independently of the crate
/// release: bump this whenever a wire-breaking change lands (a removed/renamed
/// variant or field, or a changed serialization). Additive, backward-compatible
/// changes (a new optional syscall) do **not** bump it. A client negotiates with
/// [`Syscall::Hello`] and learns the server's `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]`
/// support window; an out-of-range client gets a clear error rather than silent
/// breakage. See `RELEASING.md` ("Toward a stable API").
pub const PROTOCOL_VERSION: u32 = 2;

/// The oldest wire-protocol version this server still accepts. Version 1 keeps
/// the released prose-only error reply; version 2 adds typed public errors.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

fn default_provider() -> String {
    "stub".to_string()
}
fn default_profile() -> String {
    "standard".to_string()
}
fn default_priority() -> u8 {
    3
}

/// A syscall request from an agent / SDK to the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Syscall {
    /// Create an agent through the full kernel path (gate registration, cgroup,
    /// namespaces, scheduler admission, procfs).
    CreateAgent {
        name: String,
        task: String,
        #[serde(default = "default_provider")]
        provider: String,
        #[serde(default = "default_profile")]
        profile: String,
        #[serde(default = "default_priority")]
        priority: u8,
    },
    /// List all agents the kernel knows about.
    ListAgents,
    /// Pause new work and cooperatively cancel an in-flight turn.
    PauseAgent {
        agent_id: String,
    },
    /// Make a paused agent runnable again.
    ResumeAgent {
        agent_id: String,
    },
    /// Gracefully transition an agent to its terminal state and clean up all
    /// live kernel resources.
    StopAgent {
        agent_id: String,
    },
    /// Force a terminal transition and run the same cleanup invariant as stop.
    KillAgent {
        agent_id: String,
    },
    /// Return the current durable lifecycle state.
    GetAgentStatus {
        agent_id: String,
    },
    /// Wait until an agent becomes terminal or the timeout expires.
    WaitAgent {
        agent_id: String,
        timeout_ms: u64,
    },
    /// List resumable in-flight turn checkpoints for one agent. Only metadata is
    /// returned; prompt/tool payloads remain protected in SQLite.
    ListGenerationCheckpoints {
        agent_id: String,
    },
    /// Resume an explicit durable checkpoint instead of the latest one.
    ResumeGenerationCheckpoint {
        agent_id: String,
        checkpoint_id: String,
    },
    /// Delete an inactive checkpoint before its retention expiry.
    DeleteGenerationCheckpoint {
        agent_id: String,
        checkpoint_id: String,
    },
    /// Drive one think→act→observe turn for an agent (LLM-backed).
    SendMessage {
        agent_id: String,
        message: String,
    },
    /// Invoke a single tool as an agent. Goes through the syscall gate
    /// (capability / MAC / cgroup / namespace) before the resource broker, so a
    /// denial is returned as an `Error` — enforcement applies over the wire.
    CallTool {
        agent_id: String,
        tool: String,
        #[serde(default)]
        args: serde_json::Value,
    },
    /// Snapshot of the syscall gate's enforcement counters.
    GateStats,
    /// Read-only introspection of one agent's enforcement state: the
    /// capabilities and namespaces the gate grants it. Answers "what am I
    /// allowed to do?" without side effects.
    AgentInfo {
        agent_id: String,
    },
    /// List the LLM providers registered with the kernel connector — the LLM
    /// backends an agent can be created against and driven through
    /// [`SendMessage`](Self::SendMessage).
    ListProviders,
    /// Store a fact in an agent's long-term memory (the durable SQLite facts
    /// store). `category` is one of `preference` / `learned_pattern` / `fact` /
    /// `instruction`; it defaults to `fact`.
    MemoryStore {
        agent_id: String,
        content: String,
        #[serde(default)]
        category: Option<String>,
    },
    /// Query an agent's long-term memory by substring, newest first.
    MemoryQuery {
        agent_id: String,
        query: String,
    },
    /// Put (insert-or-overwrite) a value into the agent's durable key/value
    /// store (the per-agent `agent_kv` table). `value` is an opaque string —
    /// callers may JSON-encode structured data.
    StoragePut {
        agent_id: String,
        key: String,
        value: String,
    },
    /// Get a value from the agent's key/value store (reply carries
    /// `value: None` when the key is absent).
    StorageGet {
        agent_id: String,
        key: String,
    },
    /// List the keys in the agent's key/value store.
    StorageList {
        agent_id: String,
    },
    /// Inspect bounded active-context usage and durable spill/error counters.
    /// Spill payload content is intentionally not returned.
    ContextPressure {
        agent_id: String,
    },
    /// Delete a key from the agent's key/value store (reply reports whether it
    /// existed).
    StorageDelete {
        agent_id: String,
        key: String,
    },
    /// Capture the agent's current working context under `label` (a point-in-time
    /// snapshot in the `context_snapshots` table). Overwrites an existing label.
    SnapshotContext {
        agent_id: String,
        label: String,
    },
    /// Restore a previously captured snapshot, making it the agent's current
    /// context. Replies with the restored token count (`SnapshotRestored`).
    RestoreSnapshot {
        agent_id: String,
        label: String,
    },
    /// List the snapshot labels stored for an agent, newest first.
    ListSnapshots {
        agent_id: String,
    },
    /// Delete a snapshot by label (reply reports whether it existed).
    DeleteSnapshot {
        agent_id: String,
        label: String,
    },
    /// Negotiate the wire-protocol version. Optional opening handshake: a client
    /// announces the protocol version it speaks; the server replies with
    /// [`SyscallReply::Hello`] (its support window + crate version) when the
    /// client is in range, or a version-appropriate error when incompatible.
    /// Allowed before [`Authenticate`](Syscall::Authenticate) so a client can
    /// check compatibility before presenting credentials. Has no side effects.
    Hello {
        protocol_version: u32,
    },
    /// Authenticate the connection with the server's shared secret. Required as
    /// the first syscall when the server is configured with a token; a no-op
    /// (always accepted) when it is not.
    Authenticate {
        token: String,
    },
    /// Load an agent package from a TOML manifest (see `crate::agent_package`):
    /// parse + validate, then create the agent through the full admission path
    /// and seed its memory. Replies with the new agent's id (`AgentCreated`).
    /// Running the package's entry prompt is left to the in-process runner.
    LoadPackage {
        manifest_toml: String,
    },
    /// Read-only node load/health, for distributed placement. Reports how many
    /// agents this kernel node hosts (total + currently running) so a cluster
    /// client can pick the least-loaded node. No side effects.
    NodeInfo,
    /// Pull the kernel's operational metrics as a Prometheus text exposition
    /// (format version 0.0.4), rendered from the syscall-gate enforcement
    /// counters, agent counts, system token/api totals, and process uptime.
    /// Read-only; lets an SDK/client scrape metrics over the existing protocol
    /// without an HTTP endpoint. Reply: [`SyscallReply::Metrics`].
    Metrics,
    /// Capture a timestamped live operations view. Tenant credentials receive
    /// only their agents and no global counters/services; trusted system
    /// callers receive the global scheduler/gate snapshot as well.
    OperatorSnapshot,
    /// System-scoped service supervisor operations. Tenant credentials cannot
    /// access these until service ownership is tenant-aware.
    ListServices,
    StartService {
        name: String,
    },
    StopService {
        name: String,
    },
    RestartService {
        name: String,
    },
}

/// A short, serializable view of an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub state: String,
}

/// A short, serializable view of a registered LLM provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSummary {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    pub available: bool,
}

/// A short, serializable view of a long-term-memory fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactSummary {
    pub id: String,
    pub content: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationCheckpointSummary {
    pub id: String,
    pub agent_id: String,
    pub version: u32,
    pub provider_id: String,
    pub model_id: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorAgentSnapshot {
    pub id: String,
    pub name: String,
    pub state: String,
    pub priority: u8,
    pub scheduler_state: String,
    pub sandbox_active: bool,
    pub capabilities: Vec<String>,
    pub namespaces: Vec<u64>,
    pub checkpoint_count: usize,
    pub context_pressure: ContextPressureStats,
    pub latest_usage: Option<crate::context::UsageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorServiceSnapshot {
    pub name: String,
    pub state: String,
    pub agent_id: Option<String>,
    pub restart_count: u32,
    pub last_exit_code: Option<i32>,
}

/// Timestamped remote operations view. `system_metrics` and `services` are
/// absent for tenant-bound callers to avoid leaking global population/activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSnapshot {
    pub captured_at: String,
    pub consistency: String,
    pub scope: String,
    pub kernel_version: String,
    pub protocol_version: u32,
    pub agents: Vec<OperatorAgentSnapshot>,
    pub providers: Vec<ProviderSummary>,
    pub services: Option<Vec<OperatorServiceSnapshot>>,
    pub system_metrics: Option<crate::metrics::MetricsSnapshot>,
    pub global_spend_usd: Option<f64>,
}

/// Stable, machine-readable error categories on the public wire. New detail
/// may be added to a category without forcing clients to parse prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireErrorCode {
    AuthenticationRequired,
    AuthenticationFailed,
    AuthorizationDenied,
    InvalidRequest,
    InvalidArgument,
    NotFound,
    PermissionDenied,
    QuotaExceeded,
    SandboxDenied,
    Conflict,
    Unavailable,
    Timeout,
    Cancelled,
    IncompatibleVersion,
    Provider,
    Lifecycle,
    Internal,
}

impl WireErrorCode {
    fn classify(message: &str) -> (Self, bool) {
        let message = message.to_ascii_lowercase();
        if message.contains("incompatible wire-protocol") {
            (Self::IncompatibleVersion, false)
        } else if message.contains("authentication required") {
            (Self::AuthenticationRequired, false)
        } else if message.contains("authentication failed") {
            (Self::AuthenticationFailed, false)
        } else if message.contains("authorization denied") {
            (Self::AuthorizationDenied, false)
        } else if message.contains("bad request") {
            (Self::InvalidRequest, false)
        } else if message.contains("invalid agent id") || message.contains("invalid ") {
            (Self::InvalidArgument, false)
        } else if message.contains("sandbox") {
            (Self::SandboxDenied, false)
        } else if message.contains("quota")
            || message.contains("budget")
            || message.contains("rate limit")
            || message.contains("queue is full")
            || message.contains("admission")
        {
            (Self::QuotaExceeded, true)
        } else if message.contains("timeout") || message.contains("timed out") {
            (Self::Timeout, true)
        } else if message.contains("cancel") {
            (Self::Cancelled, false)
        } else if message.contains("provider") || message.contains("connector") {
            (Self::Provider, true)
        } else if message.contains("not found") || message.contains("unknown agent") {
            (Self::NotFound, false)
        } else if message.contains("permission") || message.contains("denied") {
            (Self::PermissionDenied, false)
        } else if message.contains("transition")
            || message.contains("paused")
            || message.contains("stopped")
        {
            (Self::Lifecycle, false)
        } else if message.contains("busy")
            || message.contains("conflict")
            || message.contains("already")
            || message.contains("claimed")
        {
            (Self::Conflict, true)
        } else if message.contains("unavailable") || message.contains("not registered") {
            (Self::Unavailable, true)
        } else {
            (Self::Internal, false)
        }
    }
}

/// The kernel's reply to a [`Syscall`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SyscallReply {
    AgentCreated {
        id: String,
    },
    Agents {
        agents: Vec<AgentSummary>,
    },
    /// Lifecycle state returned by pause/resume/stop/kill/status/wait.
    AgentStatus {
        state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        checkpoint_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resumed_content: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resumed_tool_calls: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resumed_tokens: Option<u32>,
    },
    GenerationCheckpoints {
        checkpoints: Vec<GenerationCheckpointSummary>,
    },
    GenerationCheckpointDeleted {
        existed: bool,
    },
    Message {
        content: String,
        tool_calls: usize,
        tokens: u32,
    },
    ToolResult {
        data: serde_json::Value,
    },
    GateStats {
        allowed: u64,
        denied_capability: u64,
        denied_mac: u64,
        denied_cgroup: u64,
        denied_namespace: u64,
        denied_unknown: u64,
        audited: u64,
    },
    /// Read-only enforcement state for one agent (reply to [`Syscall::AgentInfo`]).
    AgentInfo {
        pid: u64,
        capabilities: Vec<String>,
        namespaces: Vec<u64>,
    },
    /// The LLM providers registered with the kernel (reply to [`Syscall::ListProviders`]).
    Providers {
        providers: Vec<ProviderSummary>,
    },
    /// A fact was stored (reply to [`Syscall::MemoryStore`]); carries its id.
    MemoryStored {
        id: String,
    },
    /// Facts matching a memory query (reply to [`Syscall::MemoryQuery`]).
    Memory {
        facts: Vec<FactSummary>,
    },
    /// A value was written to the key/value store (reply to [`Syscall::StoragePut`]).
    StorageOk,
    /// A value read from the key/value store (reply to [`Syscall::StorageGet`]);
    /// `None` when the key is absent.
    StorageValue {
        value: Option<String>,
    },
    /// The keys in an agent's key/value store (reply to [`Syscall::StorageList`]).
    StorageKeys {
        keys: Vec<String>,
    },
    /// Non-sensitive context-pressure counters for one tenant-scoped agent.
    ContextPressure {
        stats: ContextPressureStats,
    },
    /// Whether the deleted key existed (reply to [`Syscall::StorageDelete`]).
    StorageDeleted {
        existed: bool,
    },
    /// A snapshot was captured (reply to [`Syscall::SnapshotContext`]).
    SnapshotSaved,
    /// A snapshot was restored and is now the agent's current context (reply to
    /// [`Syscall::RestoreSnapshot`]); carries the restored context's token count.
    SnapshotRestored {
        tokens: u32,
    },
    /// The snapshot labels stored for an agent (reply to [`Syscall::ListSnapshots`]).
    Snapshots {
        labels: Vec<String>,
    },
    /// Whether the deleted snapshot existed (reply to [`Syscall::DeleteSnapshot`]).
    SnapshotDeleted {
        existed: bool,
    },
    /// Protocol negotiation succeeded (reply to a compatible [`Syscall::Hello`]).
    /// Reports the server's supported wire-protocol window and crate version so
    /// the client can record what it negotiated.
    Hello {
        /// The newest wire-protocol version the server speaks ([`PROTOCOL_VERSION`]).
        protocol_version: u32,
        /// The oldest wire-protocol version the server still accepts.
        min_protocol_version: u32,
        /// The server's crate version (`CARGO_PKG_VERSION`), informational.
        server_version: String,
    },
    /// The connection is authenticated (reply to [`Syscall::Authenticate`]).
    Authenticated,
    /// Node load/health (reply to [`Syscall::NodeInfo`]).
    NodeInfo {
        agent_count: usize,
        running_agents: usize,
        live_agents: usize,
        queued_agents: usize,
        paused_agents: usize,
        stopped_agents: usize,
        active_turns: usize,
        waiting_turns: usize,
        turn_capacity: usize,
        llm_requests_in_flight: usize,
        llm_requests_waiting: usize,
        llm_core_capacity: usize,
    },
    /// The kernel's operational metrics (reply to [`Syscall::Metrics`]). Carries
    /// the rendered Prometheus text exposition plus a couple of the headline
    /// numbers as structured fields, so a client can use either form.
    Metrics {
        /// The full `text/plain; version=0.0.4` Prometheus exposition.
        prometheus: String,
        /// Total agents the kernel hosts (also present in `prometheus`).
        agent_count: usize,
        /// System-wide tokens consumed (also present in `prometheus`).
        tokens_consumed: u64,
    },
    OperatorSnapshot {
        snapshot: Box<OperatorSnapshot>,
    },
    Services {
        services: Vec<crate::init_system::ServiceRuntimeInfo>,
    },
    Service {
        service: crate::init_system::ServiceRuntimeInfo,
    },
    /// Any error is surfaced to the caller rather than dropping the connection.
    Error {
        message: String,
    },
    /// Public wire error with a stable category and retry hint. The legacy
    /// `Error` variant remains an internal/compatibility representation and is
    /// converted to this form before a server reply is serialized.
    TypedError {
        code: WireErrorCode,
        message: String,
        retryable: bool,
    },
}

impl SyscallReply {
    fn into_public_wire(self, negotiated_version: u32) -> Self {
        match self {
            Self::Error { message } if negotiated_version >= 2 => {
                let (code, retryable) = WireErrorCode::classify(&message);
                Self::TypedError {
                    code,
                    message,
                    retryable,
                }
            }
            reply => reply,
        }
    }
}

const AUTHORIZATION_DENIED: &str = "resource not found or access denied";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessLevel {
    ReadOnly,
    User,
    Admin,
    /// Trusted local/open-server or shared-secret operator only. Tenant-bound
    /// principals cannot read global counters until tenant-scoped equivalents
    /// exist, even when their role is Admin.
    System,
}

fn role_allows(role: Role, required: AccessLevel) -> bool {
    match required {
        AccessLevel::ReadOnly => true,
        AccessLevel::User => matches!(role, Role::User | Role::Admin),
        AccessLevel::Admin => matches!(role, Role::Admin),
        AccessLevel::System => false,
    }
}

fn syscall_policy(call: &Syscall) -> (AccessLevel, &'static str, Option<&str>) {
    match call {
        Syscall::CreateAgent { .. } => (AccessLevel::User, "agent.create", None),
        Syscall::ListAgents => (AccessLevel::ReadOnly, "agent.list", None),
        Syscall::PauseAgent { agent_id } => (AccessLevel::User, "agent.pause", Some(agent_id)),
        Syscall::ResumeAgent { agent_id } => (AccessLevel::User, "agent.resume", Some(agent_id)),
        Syscall::StopAgent { agent_id } => (AccessLevel::User, "agent.stop", Some(agent_id)),
        Syscall::KillAgent { agent_id } => (AccessLevel::Admin, "agent.kill", Some(agent_id)),
        Syscall::GetAgentStatus { agent_id } => {
            (AccessLevel::ReadOnly, "agent.status", Some(agent_id))
        }
        Syscall::WaitAgent { agent_id, .. } => {
            (AccessLevel::ReadOnly, "agent.wait", Some(agent_id))
        }
        Syscall::ListGenerationCheckpoints { agent_id } => {
            (AccessLevel::ReadOnly, "checkpoint.list", Some(agent_id))
        }
        Syscall::ResumeGenerationCheckpoint { agent_id, .. } => {
            (AccessLevel::User, "checkpoint.resume", Some(agent_id))
        }
        Syscall::DeleteGenerationCheckpoint { agent_id, .. } => {
            (AccessLevel::User, "checkpoint.delete", Some(agent_id))
        }
        Syscall::SendMessage { agent_id, .. } => {
            (AccessLevel::User, "agent.send_message", Some(agent_id))
        }
        Syscall::CallTool { agent_id, .. } => {
            (AccessLevel::User, "agent.call_tool", Some(agent_id))
        }
        Syscall::GateStats => (AccessLevel::System, "system.gate_stats", None),
        Syscall::AgentInfo { agent_id } => (AccessLevel::ReadOnly, "agent.info", Some(agent_id)),
        Syscall::ListProviders => (AccessLevel::ReadOnly, "provider.list", None),
        Syscall::MemoryStore { agent_id, .. } => {
            (AccessLevel::User, "memory.store", Some(agent_id))
        }
        Syscall::MemoryQuery { agent_id, .. } => {
            (AccessLevel::ReadOnly, "memory.query", Some(agent_id))
        }
        Syscall::StoragePut { agent_id, .. } => (AccessLevel::User, "storage.put", Some(agent_id)),
        Syscall::StorageGet { agent_id, .. } => {
            (AccessLevel::ReadOnly, "storage.get", Some(agent_id))
        }
        Syscall::StorageList { agent_id } => {
            (AccessLevel::ReadOnly, "storage.list", Some(agent_id))
        }
        Syscall::ContextPressure { agent_id } => {
            (AccessLevel::ReadOnly, "context.pressure", Some(agent_id))
        }
        Syscall::StorageDelete { agent_id, .. } => {
            (AccessLevel::User, "storage.delete", Some(agent_id))
        }
        Syscall::SnapshotContext { agent_id, .. } => {
            (AccessLevel::User, "snapshot.create", Some(agent_id))
        }
        Syscall::RestoreSnapshot { agent_id, .. } => {
            (AccessLevel::User, "snapshot.restore", Some(agent_id))
        }
        Syscall::ListSnapshots { agent_id } => {
            (AccessLevel::ReadOnly, "snapshot.list", Some(agent_id))
        }
        Syscall::DeleteSnapshot { agent_id, .. } => {
            (AccessLevel::User, "snapshot.delete", Some(agent_id))
        }
        Syscall::Hello { .. } => (AccessLevel::ReadOnly, "protocol.hello", None),
        Syscall::Authenticate { .. } => (AccessLevel::ReadOnly, "auth.authenticate", None),
        Syscall::LoadPackage { .. } => (AccessLevel::Admin, "package.load", None),
        Syscall::NodeInfo => (AccessLevel::System, "system.node_info", None),
        Syscall::Metrics => (AccessLevel::System, "system.metrics", None),
        Syscall::OperatorSnapshot => (AccessLevel::ReadOnly, "operator.snapshot", None),
        Syscall::ListServices => (AccessLevel::System, "service.list", None),
        Syscall::StartService { .. } => (AccessLevel::System, "service.start", None),
        Syscall::StopService { .. } => (AccessLevel::System, "service.stop", None),
        Syscall::RestartService { .. } => (AccessLevel::System, "service.restart", None),
    }
}

fn authorization_error() -> SyscallReply {
    SyscallReply::Error {
        message: AUTHORIZATION_DENIED.to_string(),
    }
}

fn audit_authorization_denial(
    kernel: &AgentKernelImpl,
    principal: &Principal,
    action: &str,
    agent_id: Option<uuid::Uuid>,
    reason: &str,
) {
    let resource = agent_id
        .map(|id| format!("agent:{id}"))
        .unwrap_or_else(|| "system".to_string());
    tracing::warn!(
        target: "agentos::authorization",
        user_id = %principal.user_id,
        tenant_id = %principal.tenant_id,
        role = principal.role.as_str(),
        action,
        resource,
        reason,
        "authorization denied"
    );
    if let Some(agent_id) = agent_id {
        kernel.observability.log_action(
            agent_id,
            AgentAction {
                id: uuid::Uuid::new_v4(),
                action_type: "authorization_deny".into(),
                description: format!(
                    "Denied {action} for user {} in tenant {} ({reason})",
                    principal.user_id, principal.tenant_id
                ),
                resources_accessed: vec![resource],
                reasoning: None,
                plan_context: None,
                timestamp: chrono::Utc::now(),
            },
        );
    }
}

async fn authorize(
    kernel: &AgentKernelImpl,
    principal: Option<&Principal>,
    call: &Syscall,
) -> Result<(), SyscallReply> {
    // Open and shared-secret connections are explicit trusted-system callers.
    // Tenant credentials always take the fail-closed path below.
    let Some(principal) = principal else {
        return Ok(());
    };
    let (required, action, target) = syscall_policy(call);
    let target_id = target.and_then(|value| uuid::Uuid::parse_str(value).ok());

    if !role_allows(principal.role, required) {
        audit_authorization_denial(kernel, principal, action, target_id, "insufficient role");
        return Err(authorization_error());
    }

    if let Some(target) = target {
        let Ok(agent_id) = uuid::Uuid::parse_str(target) else {
            audit_authorization_denial(kernel, principal, action, None, "invalid resource id");
            return Err(authorization_error());
        };
        let owned = matches!(
            kernel.context_manager.agent_tenant(agent_id),
            Ok(Some(ref tenant_id)) if tenant_id == &principal.tenant_id
        );
        if !owned {
            audit_authorization_denial(
                kernel,
                principal,
                action,
                Some(agent_id),
                "resource is absent or belongs to another tenant",
            );
            return Err(authorization_error());
        }
    }

    Ok(())
}

async fn dispatch_lifecycle<F, Fut>(agent_id: String, action: F) -> SyscallReply
where
    F: FnOnce(uuid::Uuid) -> Fut,
    Fut: std::future::Future<Output = Result<crate::AgentState, crate::KernelError>>,
{
    let id = match uuid::Uuid::parse_str(&agent_id) {
        Ok(id) => id,
        Err(_) => {
            return SyscallReply::Error {
                message: format!("invalid agent id: {agent_id}"),
            }
        }
    };
    match action(id).await {
        Ok(state) => SyscallReply::AgentStatus {
            state: format!("{state:?}"),
            checkpoint_id: None,
            resumed_content: None,
            resumed_tool_calls: None,
            resumed_tokens: None,
        },
        Err(error) => SyscallReply::Error {
            message: error.to_string(),
        },
    }
}

/// Dispatch a single syscall against the kernel. Pure routing — every call goes
/// through the same `AgentKernelImpl` methods the in-process paths use, so the
/// syscall gate's capability/MAC/cgroup/namespace checks still apply.
///
/// Tenant-agnostic entry point (no bound tenant): equivalent to
/// [`dispatch_scoped`] with `None`. Used by the MCP server and any caller that
/// doesn't carry a tenant context.
pub async fn dispatch(kernel: &AgentKernelImpl, call: Syscall) -> SyscallReply {
    dispatch_scoped(kernel, call, None).await
}

/// Dispatch a syscall on behalf of an optional authenticated principal. A
/// tenant principal is centrally authorized before operation-specific routing;
/// trusted open/shared-secret connections use `None` as the system caller.
pub async fn dispatch_scoped(
    kernel: &AgentKernelImpl,
    call: Syscall,
    principal: Option<&Principal>,
) -> SyscallReply {
    if let Err(reply) = authorize(kernel, principal, &call).await {
        return reply;
    }
    let tenant = principal.map(|principal| principal.tenant_id.as_str());
    match call {
        Syscall::CreateAgent {
            name,
            task,
            provider,
            profile,
            priority,
        } => {
            let prio = Priority::new(priority).unwrap_or_else(|| Priority::new(3).unwrap());
            let config = AgentConfig {
                name,
                task,
                llm_provider: provider,
                permission_profile: profile,
                priority: prio,
                sandbox_config: None,
            };
            // A tenant-bound connection creates agents inside its tenant (own
            // namespace + cgroup); otherwise the un-tenanted full path.
            let created = match tenant {
                Some(t) => kernel.create_agent_for_tenant(t, config).await,
                None => kernel.create_agent_full(config).await,
            };
            match created {
                Ok(handle) => SyscallReply::AgentCreated {
                    id: handle.id.to_string(),
                },
                Err(e) => SyscallReply::Error {
                    message: e.to_string(),
                },
            }
        }
        Syscall::ListAgents => {
            // Scope the listing to the bound tenant's agents (from the registry's
            // tenant column) so a tenant-A connection never sees tenant-B agents.
            let ids: Option<std::collections::HashSet<uuid::Uuid>> = tenant.map(|t| {
                kernel
                    .context_manager
                    .list_agents_for_tenant(t)
                    .unwrap_or_default()
                    .into_iter()
                    .collect()
            });
            let agents = kernel
                .agent_manager
                .list_agents(None)
                .into_iter()
                .filter(|a| match &ids {
                    Some(set) => set.contains(&a.id),
                    None => true,
                })
                .map(|a| AgentSummary {
                    id: a.id.to_string(),
                    name: a.name,
                    state: format!("{:?}", a.state),
                })
                .collect();
            SyscallReply::Agents { agents }
        }
        Syscall::PauseAgent { agent_id } => match uuid::Uuid::parse_str(&agent_id) {
            Ok(id) => match kernel.pause_agent(id).await {
                Ok(state) => match kernel.latest_generation_checkpoint(id) {
                    Ok(checkpoint) => SyscallReply::AgentStatus {
                        state: format!("{state:?}"),
                        checkpoint_id: checkpoint.map(|checkpoint| checkpoint.id.to_string()),
                        resumed_content: None,
                        resumed_tool_calls: None,
                        resumed_tokens: None,
                    },
                    Err(error) => SyscallReply::Error {
                        message: error.to_string(),
                    },
                },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            },
            Err(_) => SyscallReply::Error {
                message: format!("invalid agent id: {agent_id}"),
            },
        },
        Syscall::ResumeAgent { agent_id } => match uuid::Uuid::parse_str(&agent_id) {
            Ok(id) => match kernel.resume_agent_from_checkpoint(id, None).await {
                Ok((state, output, checkpoint_id)) => SyscallReply::AgentStatus {
                    state: format!("{state:?}"),
                    checkpoint_id: checkpoint_id.map(|id| id.to_string()),
                    resumed_content: output.as_ref().map(|output| output.content.clone()),
                    resumed_tool_calls: output.as_ref().map(|output| output.tool_calls_made),
                    resumed_tokens: output.as_ref().map(|output| output.tokens_used),
                },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            },
            Err(_) => SyscallReply::Error {
                message: format!("invalid agent id: {agent_id}"),
            },
        },
        Syscall::StopAgent { agent_id } => {
            dispatch_lifecycle(agent_id, |id| kernel.stop_agent(id)).await
        }
        Syscall::KillAgent { agent_id } => {
            dispatch_lifecycle(agent_id, |id| kernel.kill_agent(id)).await
        }
        Syscall::GetAgentStatus { agent_id } => match uuid::Uuid::parse_str(&agent_id) {
            Ok(id) => match kernel.get_agent_status(id) {
                Ok(state) => SyscallReply::AgentStatus {
                    state: format!("{state:?}"),
                    checkpoint_id: None,
                    resumed_content: None,
                    resumed_tool_calls: None,
                    resumed_tokens: None,
                },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            },
            Err(_) => SyscallReply::Error {
                message: format!("invalid agent id: {agent_id}"),
            },
        },
        Syscall::WaitAgent {
            agent_id,
            timeout_ms,
        } => match uuid::Uuid::parse_str(&agent_id) {
            Ok(id) => match kernel
                .wait_agent(id, std::time::Duration::from_millis(timeout_ms))
                .await
            {
                Ok(state) => SyscallReply::AgentStatus {
                    state: format!("{state:?}"),
                    checkpoint_id: None,
                    resumed_content: None,
                    resumed_tool_calls: None,
                    resumed_tokens: None,
                },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            },
            Err(_) => SyscallReply::Error {
                message: format!("invalid agent id: {agent_id}"),
            },
        },
        Syscall::ListGenerationCheckpoints { agent_id } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            let tenant = match kernel.context_manager.agent_tenant(id) {
                Ok(Some(tenant)) => tenant,
                Ok(None) => return authorization_error(),
                Err(error) => {
                    return SyscallReply::Error {
                        message: error.to_string(),
                    }
                }
            };
            match kernel
                .context_manager
                .list_generation_checkpoints(&tenant, Some(id))
            {
                Ok(checkpoints) => SyscallReply::GenerationCheckpoints {
                    checkpoints: checkpoints
                        .into_iter()
                        .map(|checkpoint| GenerationCheckpointSummary {
                            id: checkpoint.id.to_string(),
                            agent_id: checkpoint.agent_id.to_string(),
                            version: checkpoint.version,
                            provider_id: checkpoint.provider_id,
                            model_id: checkpoint.model_id,
                            created_at: checkpoint.created_at.to_rfc3339(),
                            expires_at: checkpoint.expires_at.to_rfc3339(),
                        })
                        .collect(),
                },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::ResumeGenerationCheckpoint {
            agent_id,
            checkpoint_id,
        } => {
            let parsed = uuid::Uuid::parse_str(&agent_id).and_then(|agent| {
                uuid::Uuid::parse_str(&checkpoint_id).map(|checkpoint| (agent, checkpoint))
            });
            match parsed {
                Ok((agent, checkpoint)) => match kernel
                    .resume_agent_from_checkpoint(agent, Some(checkpoint))
                    .await
                {
                    Ok((state, output, next_checkpoint)) => SyscallReply::AgentStatus {
                        state: format!("{state:?}"),
                        checkpoint_id: next_checkpoint.map(|id| id.to_string()),
                        resumed_content: output.as_ref().map(|output| output.content.clone()),
                        resumed_tool_calls: output.as_ref().map(|output| output.tool_calls_made),
                        resumed_tokens: output.as_ref().map(|output| output.tokens_used),
                    },
                    Err(error) => SyscallReply::Error {
                        message: error.to_string(),
                    },
                },
                Err(_) => SyscallReply::Error {
                    message: "invalid agent or checkpoint id".into(),
                },
            }
        }
        Syscall::DeleteGenerationCheckpoint {
            agent_id,
            checkpoint_id,
        } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => return authorization_error(),
            };
            let checkpoint = match uuid::Uuid::parse_str(&checkpoint_id) {
                Ok(id) => id,
                Err(_) => return authorization_error(),
            };
            let tenant = match kernel.context_manager.agent_tenant(id) {
                Ok(Some(tenant)) => tenant,
                _ => return authorization_error(),
            };
            match kernel
                .context_manager
                .delete_generation_checkpoint(checkpoint, &tenant)
            {
                Ok(existed) => SyscallReply::GenerationCheckpointDeleted { existed },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::SendMessage { agent_id, message } => match uuid::Uuid::parse_str(&agent_id) {
            Ok(id) => match kernel.send_message(id, &message).await {
                Ok(out) => SyscallReply::Message {
                    content: out.content,
                    tool_calls: out.tool_calls_made,
                    tokens: out.tokens_used,
                },
                Err(e) => SyscallReply::Error {
                    message: e.to_string(),
                },
            },
            Err(_) => SyscallReply::Error {
                message: format!("invalid agent id: {agent_id}"),
            },
        },
        Syscall::CallTool {
            agent_id,
            tool,
            args,
        } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            // Token estimate plus the registry's declared resource extractor,
            // shared with executor/MCP so policy cannot drift by entry point.
            let est_tokens = (args.to_string().len() as u64 / 4)
                .saturating_add(tool.len() as u64 / 4)
                .saturating_add(10);
            let (security, resource) = match kernel.tool_registry.security_context(&tool, &args) {
                Ok(context) => context,
                Err(error) => {
                    return SyscallReply::Error {
                        message: format!("tool '{tool}' denied by kernel: {error}"),
                    }
                }
            };

            // Enforcement first — a denial never reaches the broker.
            if let Err(denial) = kernel
                .syscall_gate
                .check_tool_call_declared(id, &tool, &resource, est_tokens, &security)
                .await
            {
                return SyscallReply::Error {
                    message: format!("tool '{tool}' denied by kernel: {}", denial.message()),
                };
            }
            let _tool_slot = match kernel.syscall_gate.acquire_tool_call(id) {
                Ok(slot) => slot,
                Err(denial) => {
                    return SyscallReply::Error {
                        message: format!("tool '{tool}' denied by kernel: {}", denial.message()),
                    }
                }
            };

            let call = ToolCall {
                id: "syscall".into(),
                name: tool.clone(),
                arguments: args,
            };
            let reply = match kernel.tool_registry.resolve(id, &call) {
                Some(request) => match kernel.resource_broker.execute(request).await {
                    Ok(resp) if resp.success => SyscallReply::ToolResult { data: resp.data },
                    Ok(resp) => SyscallReply::Error {
                        message: format!(
                            "tool '{tool}' failed: {}",
                            resp.error.unwrap_or_default()
                        ),
                    },
                    Err(e) => SyscallReply::Error {
                        message: format!("tool '{tool}' error: {e}"),
                    },
                },
                None => SyscallReply::Error {
                    message: format!("unknown tool '{tool}'"),
                },
            };
            reply
        }
        Syscall::GateStats => {
            let s = kernel.syscall_gate.stats();
            SyscallReply::GateStats {
                allowed: s.allowed,
                denied_capability: s.denied_capability,
                denied_mac: s.denied_mac,
                denied_cgroup: s.denied_cgroup,
                denied_namespace: s.denied_namespace,
                denied_unknown: s.denied_unknown,
                audited: s.audited,
            }
        }
        Syscall::AgentInfo { agent_id } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.syscall_gate.agent_info(id) {
                Some(info) => SyscallReply::AgentInfo {
                    pid: info.pid,
                    capabilities: info.capabilities,
                    namespaces: info.namespaces,
                },
                None => SyscallReply::Error {
                    message: format!("unknown agent: {agent_id}"),
                },
            }
        }
        Syscall::ListProviders => {
            let providers = kernel
                .connector
                .list_providers()
                .into_iter()
                .map(|p| ProviderSummary {
                    id: p.id,
                    name: p.name,
                    provider_type: format!("{:?}", p.provider_type),
                    available: p.available,
                })
                .collect();
            SyscallReply::Providers { providers }
        }
        Syscall::MemoryStore {
            agent_id,
            content,
            category,
        } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            let now = chrono::Utc::now();
            let fact = Fact {
                id: uuid::Uuid::new_v4(),
                content,
                category: parse_fact_category(category.as_deref()),
                created_at: now,
                last_accessed_at: now,
                embedding: None,
            };
            let fact_id = fact.id.to_string();
            match kernel.context_manager.store_fact(id, fact).await {
                Ok(()) => SyscallReply::MemoryStored { id: fact_id },
                Err(e) => SyscallReply::Error {
                    message: format!("memory store failed: {e}"),
                },
            }
        }
        Syscall::MemoryQuery { agent_id, query } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.query_memory(id, &query).await {
                Ok(facts) => SyscallReply::Memory {
                    facts: facts
                        .into_iter()
                        .map(|f| FactSummary {
                            id: f.id.to_string(),
                            content: f.content,
                            category: format!("{:?}", f.category),
                        })
                        .collect(),
                },
                Err(e) => SyscallReply::Error {
                    message: format!("memory query failed: {e}"),
                },
            }
        }
        Syscall::StoragePut {
            agent_id,
            key,
            value,
        } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.kv_put(id, &key, &value) {
                Ok(()) => SyscallReply::StorageOk,
                Err(e) => SyscallReply::Error {
                    message: format!("storage put failed: {e}"),
                },
            }
        }
        Syscall::StorageGet { agent_id, key } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.kv_get(id, &key) {
                Ok(value) => SyscallReply::StorageValue { value },
                Err(e) => SyscallReply::Error {
                    message: format!("storage get failed: {e}"),
                },
            }
        }
        Syscall::StorageList { agent_id } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.kv_list(id) {
                Ok(keys) => SyscallReply::StorageKeys { keys },
                Err(e) => SyscallReply::Error {
                    message: format!("storage list failed: {e}"),
                },
            }
        }
        Syscall::ContextPressure { agent_id } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.context_pressure_stats(id) {
                Ok(stats) => SyscallReply::ContextPressure { stats },
                Err(error) => SyscallReply::Error {
                    message: format!("context pressure inspection failed: {error}"),
                },
            }
        }
        Syscall::StorageDelete { agent_id, key } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.kv_delete(id, &key) {
                Ok(existed) => SyscallReply::StorageDeleted { existed },
                Err(e) => SyscallReply::Error {
                    message: format!("storage delete failed: {e}"),
                },
            }
        }
        Syscall::SnapshotContext { agent_id, label } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.snapshot_context(id, &label) {
                Ok(()) => SyscallReply::SnapshotSaved,
                Err(e) => SyscallReply::Error {
                    message: format!("snapshot failed: {e}"),
                },
            }
        }
        Syscall::RestoreSnapshot { agent_id, label } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.restore_snapshot(id, &label) {
                Ok(ctx) => SyscallReply::SnapshotRestored {
                    tokens: ctx.token_count,
                },
                Err(e) => SyscallReply::Error {
                    message: format!("restore snapshot failed: {e}"),
                },
            }
        }
        Syscall::ListSnapshots { agent_id } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.list_snapshots(id) {
                Ok(labels) => SyscallReply::Snapshots { labels },
                Err(e) => SyscallReply::Error {
                    message: format!("list snapshots failed: {e}"),
                },
            }
        }
        Syscall::DeleteSnapshot { agent_id, label } => {
            let id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.delete_snapshot(id, &label) {
                Ok(existed) => SyscallReply::SnapshotDeleted { existed },
                Err(e) => SyscallReply::Error {
                    message: format!("delete snapshot failed: {e}"),
                },
            }
        }
        // Authentication is handled at the connection layer (see
        // `SyscallServer::handle`); reaching dispatch means it is accepted.
        Syscall::Authenticate { .. } => SyscallReply::Authenticated,
        // Protocol negotiation is likewise handled in the connection layer; if a
        // Hello reaches dispatch (e.g. the in-process dispatch path), answer with
        // this server's support window rather than re-validating.
        Syscall::Hello { .. } => SyscallReply::Hello {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        Syscall::LoadPackage { manifest_toml } => {
            match crate::agent_package::AgentManifest::from_toml_str(&manifest_toml) {
                Ok(manifest) => {
                    let loaded = match tenant {
                        Some(tenant_id) => {
                            crate::agent_package::load_package_for_tenant(
                                kernel, tenant_id, &manifest,
                            )
                            .await
                        }
                        None => crate::agent_package::load_package(kernel, &manifest).await,
                    };
                    match loaded {
                        Ok(handle) => SyscallReply::AgentCreated {
                            id: handle.id.to_string(),
                        },
                        Err(e) => SyscallReply::Error {
                            message: format!("load package failed: {e}"),
                        },
                    }
                }
                Err(e) => SyscallReply::Error {
                    message: format!("invalid package: {e}"),
                },
            }
        }
        Syscall::NodeInfo => {
            let snapshot = crate::metrics::MetricsSnapshot::collect(kernel);
            SyscallReply::NodeInfo {
                agent_count: snapshot.agent_count as usize,
                running_agents: snapshot.running_agents as usize,
                live_agents: snapshot.live_agents as usize,
                queued_agents: snapshot.queued_agents as usize,
                paused_agents: snapshot.paused_agents as usize,
                stopped_agents: snapshot.stopped_agents as usize,
                active_turns: snapshot.active_turns as usize,
                waiting_turns: kernel.turn_admission.waiting(),
                turn_capacity: snapshot.turn_capacity as usize,
                llm_requests_in_flight: snapshot.llm_requests_in_flight as usize,
                llm_requests_waiting: snapshot.llm_requests_waiting as usize,
                llm_core_capacity: snapshot.llm_core_capacity as usize,
            }
        }
        Syscall::Metrics => {
            let snap = crate::metrics::MetricsSnapshot::collect(kernel);
            SyscallReply::Metrics {
                prometheus: snap.render_prometheus(),
                agent_count: snap.agent_count as usize,
                tokens_consumed: snap.tokens_consumed,
            }
        }
        Syscall::OperatorSnapshot => {
            let allowed_ids: Option<std::collections::HashSet<uuid::Uuid>> = tenant.map(|tenant| {
                kernel
                    .context_manager
                    .list_agents_for_tenant(tenant)
                    .unwrap_or_default()
                    .into_iter()
                    .collect()
            });
            let mut agents = Vec::new();
            for agent in kernel
                .agent_manager
                .list_agents(None)
                .into_iter()
                .filter(|agent| {
                    allowed_ids
                        .as_ref()
                        .is_none_or(|allowed| allowed.contains(&agent.id))
                })
            {
                let gate = kernel.syscall_gate.agent_info(agent.id);
                let checkpoint_count = kernel
                    .context_manager
                    .agent_tenant(agent.id)
                    .ok()
                    .flatten()
                    .and_then(|tenant| {
                        kernel
                            .context_manager
                            .list_generation_checkpoints(&tenant, Some(agent.id))
                            .ok()
                    })
                    .map_or(0, |checkpoints| checkpoints.len());
                let context_pressure = kernel
                    .context_manager
                    .context_pressure_stats(agent.id)
                    .unwrap_or_else(|_| ContextPressureStats {
                        agent_id: agent.id,
                        active_tokens: 0,
                        budget_tokens: 0,
                        spill_count: 0,
                        evicted_messages: 0,
                        stored_spills: 0,
                        stored_spill_bytes: 0,
                        error_count: 0,
                        last_error: Some("pressure statistics unavailable".into()),
                        updated_at: chrono::Utc::now(),
                    });
                agents.push(OperatorAgentSnapshot {
                    id: agent.id.to_string(),
                    name: agent.name,
                    state: format!("{:?}", agent.state),
                    priority: agent.priority.value(),
                    scheduler_state: kernel
                        .scheduler
                        .schedule_state(agent.id)
                        .unwrap_or("stopped")
                        .to_string(),
                    sandbox_active: crate::sandbox::SandboxManager::get_sandbox_for_agent(
                        kernel.sandbox_manager.as_ref(),
                        agent.id,
                    )
                    .is_some(),
                    capabilities: gate
                        .as_ref()
                        .map(|info| info.capabilities.clone())
                        .unwrap_or_default(),
                    namespaces: gate
                        .as_ref()
                        .map(|info| info.namespaces.clone())
                        .unwrap_or_default(),
                    checkpoint_count,
                    context_pressure,
                    latest_usage: kernel.context_manager.latest_usage(agent.id),
                });
            }
            agents.sort_by(|a, b| a.id.cmp(&b.id));

            let providers = kernel
                .connector
                .probe_providers()
                .await
                .into_iter()
                .map(|provider| ProviderSummary {
                    id: provider.id,
                    name: provider.name,
                    provider_type: format!("{:?}", provider.provider_type),
                    available: provider.available,
                })
                .collect();
            let trusted_system = principal.is_none();
            let services = if trusted_system {
                let mut services = kernel
                    .os
                    .init
                    .lock()
                    .await
                    .list_runtime()
                    .into_iter()
                    .map(|service| OperatorServiceSnapshot {
                        name: service.name,
                        state: format!("{:?}", service.status),
                        agent_id: service.agent_id.map(|id| id.to_string()),
                        restart_count: service.restart_count,
                        last_exit_code: service.last_exit_code,
                    })
                    .collect::<Vec<_>>();
                services.sort_by(|a, b| a.name.cmp(&b.name));
                Some(services)
            } else {
                None
            };
            SyscallReply::OperatorSnapshot {
                snapshot: Box::new(OperatorSnapshot {
                    captured_at: chrono::Utc::now().to_rfc3339(),
                    consistency:
                        "single collection pass; subsystem counters may advance during sampling"
                            .into(),
                    scope: tenant
                        .map(|tenant| format!("tenant:{tenant}"))
                        .unwrap_or_else(|| "system".into()),
                    kernel_version: env!("CARGO_PKG_VERSION").into(),
                    protocol_version: PROTOCOL_VERSION,
                    agents,
                    providers,
                    services,
                    system_metrics: trusted_system
                        .then(|| crate::metrics::MetricsSnapshot::collect(kernel)),
                    global_spend_usd: trusted_system
                        .then(|| kernel.budget_enforcer.current_spend()),
                }),
            }
        }
        Syscall::ListServices => SyscallReply::Services {
            services: kernel.list_services().await,
        },
        Syscall::StartService { name } => match kernel.start_service(&name).await {
            Ok(_) => match kernel
                .list_services()
                .await
                .into_iter()
                .find(|service| service.name == name)
            {
                Some(service) => SyscallReply::Service { service },
                None => SyscallReply::Error {
                    message: format!("service '{name}' disappeared after start"),
                },
            },
            Err(error) => SyscallReply::Error {
                message: error.to_string(),
            },
        },
        Syscall::StopService { name } => match kernel.stop_service(&name).await {
            Ok(()) => match kernel
                .list_services()
                .await
                .into_iter()
                .find(|service| service.name == name)
            {
                Some(service) => SyscallReply::Service { service },
                None => SyscallReply::Error {
                    message: format!("service '{name}' disappeared after stop"),
                },
            },
            Err(error) => SyscallReply::Error {
                message: error.to_string(),
            },
        },
        Syscall::RestartService { name } => match kernel.restart_service(&name).await {
            Ok(_) => match kernel
                .list_services()
                .await
                .into_iter()
                .find(|service| service.name == name)
            {
                Some(service) => SyscallReply::Service { service },
                None => SyscallReply::Error {
                    message: format!("service '{name}' disappeared after restart"),
                },
            },
            Err(error) => SyscallReply::Error {
                message: error.to_string(),
            },
        },
    }
}

/// Map a wire category string onto a [`FactCategory`], defaulting to `Fact`.
fn parse_fact_category(s: Option<&str>) -> FactCategory {
    match s.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("preference") => FactCategory::Preference,
        Some("learned_pattern") | Some("learnedpattern") => FactCategory::LearnedPattern,
        Some("instruction") => FactCategory::Instruction,
        _ => FactCategory::Fact,
    }
}

/// Build a [`rustls::ServerConfig`] (no client auth) from a PEM certificate
/// chain and a PEM private key — the common case for terminating TLS on the
/// syscall server. `cert_pem` may contain a full chain (leaf first); `key_pem`
/// is a PKCS#8, PKCS#1, or SEC1 private key. Pass the result to
/// [`SyscallServer::bind_tls`].
pub fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> std::io::Result<rustls::ServerConfig> {
    // Ensure a process-wide crypto provider is installed (idempotent — a second
    // install returns an error we ignore). Lets callers build a config without
    // naming the rustls crypto provider themselves.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no certificates found in cert_pem",
        ));
    }
    let key = match rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem))? {
        Some(key) => key,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no private key found in key_pem",
            ))
        }
    };
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}

/// The transport a [`SyscallServer`] is bound to.
enum Listener {
    Tcp(TcpListener),
    /// TCP listener whose accepted streams are wrapped in a rustls server-side
    /// TLS session before being handed to the (generic) connection handler.
    Tls(TcpListener, tokio_rustls::TlsAcceptor),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

/// A bound kernel syscall server. Construct with [`bind`](Self::bind) (TCP) or
/// [`bind_unix`](Self::bind_unix), optionally [`with_auth_token`](Self::with_auth_token),
/// inspect [`local_addr`](Self::local_addr), then run [`serve`](Self::serve).
pub struct SyscallServer {
    kernel: Arc<AgentKernelImpl>,
    listener: Listener,
    /// When set, a connection must [`Authenticate`](Syscall::Authenticate) with
    /// this token before any other syscall is dispatched.
    auth_token: Option<Arc<String>>,
}

impl SyscallServer {
    /// Bind a TCP listener to `addr` (e.g. `"127.0.0.1:0"` for an ephemeral port).
    pub async fn bind(
        kernel: Arc<AgentKernelImpl>,
        addr: impl ToSocketAddrs,
    ) -> std::io::Result<Self> {
        Ok(Self {
            kernel,
            listener: Listener::Tcp(TcpListener::bind(addr).await?),
            auth_token: None,
        })
    }

    /// Bind a Unix-domain-socket listener at `path`. Loopback-equivalent: the
    /// socket's filesystem permissions are the access control, so auth is
    /// optional here (set one anyway with [`with_auth_token`](Self::with_auth_token)
    /// if the path is broadly accessible).
    #[cfg(unix)]
    pub async fn bind_unix(
        kernel: Arc<AgentKernelImpl>,
        path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            kernel,
            listener: Listener::Unix(tokio::net::UnixListener::bind(path)?),
            auth_token: None,
        })
    }

    /// Bind a TLS listener to `addr`, terminating rustls on every accepted TCP
    /// connection before handing the encrypted stream to the same generic
    /// [`handle`](Self::handle) loop used by the plaintext transports.
    ///
    /// `config` is a fully-built [`rustls::ServerConfig`] (certificate chain +
    /// private key, ALPN, client-auth policy, …). Build it however you like; a
    /// convenience constructor from a PEM cert chain + key is provided by
    /// [`server_config_from_pem`]. Shared-secret auth composes on top — call
    /// [`with_auth_token`](Self::with_auth_token) as usual and the
    /// [`Authenticate`](Syscall::Authenticate) handshake runs *inside* the TLS
    /// session.
    pub async fn bind_tls(
        kernel: Arc<AgentKernelImpl>,
        addr: impl ToSocketAddrs,
        config: rustls::ServerConfig,
    ) -> std::io::Result<Self> {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        Ok(Self {
            kernel,
            listener: Listener::Tls(TcpListener::bind(addr).await?, acceptor),
            auth_token: None,
        })
    }

    /// Require connections to authenticate with `token` before any other
    /// syscall. Recommended for any non-loopback TCP bind.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(Arc::new(token.into()));
        self
    }

    /// The actually-bound TCP address (resolves an ephemeral `:0` port). Errors
    /// for a Unix-socket server, which has no `SocketAddr`.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match &self.listener {
            Listener::Tcp(l) => l.local_addr(),
            Listener::Tls(l, _) => l.local_addr(),
            #[cfg(unix)]
            Listener::Unix(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unix-socket server has no SocketAddr",
            )),
        }
    }

    /// Accept connections forever, handling each on its own task. Each
    /// connection is a stream of newline-delimited [`Syscall`] requests.
    pub async fn serve(self) -> std::io::Result<()> {
        match self.listener {
            Listener::Tcp(listener) => loop {
                let (stream, _peer) = listener.accept().await?;
                let kernel = self.kernel.clone();
                let auth = self.auth_token.clone();
                tokio::spawn(async move {
                    let (read, write) = stream.into_split();
                    let _ = Self::handle(kernel, read, write, auth).await;
                });
            },
            Listener::Tls(listener, acceptor) => loop {
                let (stream, _peer) = listener.accept().await?;
                let kernel = self.kernel.clone();
                let auth = self.auth_token.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // Perform the rustls handshake; a failed handshake drops the
                    // connection without affecting the accept loop.
                    let tls = match acceptor.accept(stream).await {
                        Ok(tls) => tls,
                        Err(_) => return,
                    };
                    // The TLS stream is one AsyncRead+AsyncWrite object; split it
                    // into halves so it drops into the existing generic handler.
                    let (read, write) = tokio::io::split(tls);
                    let _ = Self::handle(kernel, read, write, auth).await;
                });
            },
            #[cfg(unix)]
            Listener::Unix(listener) => loop {
                let (stream, _peer) = listener.accept().await?;
                let kernel = self.kernel.clone();
                let auth = self.auth_token.clone();
                tokio::spawn(async move {
                    let (read, write) = stream.into_split();
                    let _ = Self::handle(kernel, read, write, auth).await;
                });
            },
        }
    }

    /// Serve one connection: a stream of newline-delimited syscalls over any
    /// async read/write pair. Generic over the transport so TCP and Unix sockets
    /// share one code path. When `auth` is set, every syscall before a
    /// successful [`Authenticate`](Syscall::Authenticate) is rejected.
    async fn handle<R, W>(
        kernel: Arc<AgentKernelImpl>,
        read: R,
        mut write: W,
        auth: Option<Arc<String>>,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut lines = BufReader::new(read).lines();
        // No shared-secret token configured ⇒ authenticated from the start.
        let mut authed = auth.is_none();
        // A client that skips Hello receives the released v1 response shape.
        // Negotiation upgrades only this connection, preserving old clients.
        let mut negotiated_version = MIN_PROTOCOL_VERSION;
        // The presented tenant credential is retained and re-resolved before
        // every syscall so revocation takes effect without a reconnect window.
        let mut credential: Option<String> = None;
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let reply = match serde_json::from_str::<Syscall>(&line) {
                // Protocol negotiation. Allowed before auth so a client can
                // confirm compatibility before presenting credentials; has no
                // side effects and never changes authentication state.
                Ok(Syscall::Hello { protocol_version }) => {
                    if (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&protocol_version) {
                        negotiated_version = protocol_version;
                        SyscallReply::Hello {
                            protocol_version: PROTOCOL_VERSION,
                            min_protocol_version: MIN_PROTOCOL_VERSION,
                            server_version: env!("CARGO_PKG_VERSION").to_string(),
                        }
                    } else {
                        SyscallReply::Error {
                            message: format!(
                                "incompatible wire-protocol version: client speaks v{protocol_version}, \
                                 server supports v{MIN_PROTOCOL_VERSION}..=v{PROTOCOL_VERSION}"
                            ),
                        }
                    }
                }
                // Authentication accepts two credentials, tried in order:
                //   1. the server's shared secret (unchanged legacy path), and
                //   2. an AuthSystem API key / session token, which additionally
                //      binds this connection to the credential's tenant.
                Ok(Syscall::Authenticate { token }) => {
                    // An AuthSystem credential always wins first so that the
                    // connection binds to its tenant — even on an open server.
                    if kernel.resolve_principal(&token).await.is_some() {
                        authed = true;
                        credential = Some(token);
                        SyscallReply::Authenticated
                    } else {
                        // Otherwise fall back to the legacy shared-secret check
                        // (or accept outright when no secret is configured).
                        let shared_ok = match &auth {
                            Some(expected) => token == **expected,
                            // An open server is already a trusted-system mode;
                            // presenting an unknown credential must never turn
                            // it into a new system credential or let a revoked
                            // tenant token escape back to unscoped authority.
                            None => false,
                        };
                        if shared_ok {
                            authed = true;
                            credential = None;
                            SyscallReply::Authenticated
                        } else {
                            SyscallReply::Error {
                                message: "authentication failed".into(),
                            }
                        }
                    }
                }
                Ok(_) if !authed => SyscallReply::Error {
                    message: "authentication required".into(),
                },
                Ok(call) => {
                    // Re-resolve tenant credentials for every request. Revoked,
                    // expired, deleted, or role-changed credentials never keep
                    // the authority captured at login time.
                    if let Some(token) = credential.as_deref() {
                        match kernel.resolve_principal(token).await {
                            Some(resolved) => dispatch_scoped(&kernel, call, Some(&resolved)).await,
                            None => {
                                authed = false;
                                credential = None;
                                SyscallReply::Error {
                                    message: "authentication required".into(),
                                }
                            }
                        }
                    } else {
                        dispatch_scoped(&kernel, call, None).await
                    }
                }
                Err(e) => SyscallReply::Error {
                    message: format!("bad request: {e}"),
                },
            };
            let reply = reply.into_public_wire(negotiated_version);
            let mut buf = serde_json::to_vec(&reply).unwrap_or_else(|_| {
                br#"{"status":"error","message":"serialization failed"}"#.to_vec()
            });
            buf.push(b'\n');
            write.write_all(&buf).await?;
            write.flush().await?;
        }
        Ok(())
    }
}

/// A thin client for the syscall server (used by the Rust SDK and round-trip
/// tests). The wire format is plain JSON, so any client could speak it. The IO
/// halves are boxed so one client type works over both TCP and Unix sockets.
pub struct SyscallClient {
    reader: Lines<BufReader<Box<dyn AsyncRead + Unpin + Send>>>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
}

impl SyscallClient {
    /// Connect over TCP.
    pub async fn connect(addr: impl ToSocketAddrs) -> std::io::Result<Self> {
        let (read, writer) = TcpStream::connect(addr).await?.into_split();
        Ok(Self::from_halves(Box::new(read), Box::new(writer)))
    }

    /// Connect over a Unix-domain socket.
    #[cfg(unix)]
    pub async fn connect_unix(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let (read, writer) = tokio::net::UnixStream::connect(path).await?.into_split();
        Ok(Self::from_halves(Box::new(read), Box::new(writer)))
    }

    /// Connect over TLS: open a TCP connection to `addr`, perform the rustls
    /// client handshake (verifying the server certificate against `config`'s
    /// root store and matching `server_name`), then speak the same JSON
    /// protocol over the encrypted stream. The TLS stream's split halves are
    /// boxed into the existing transport-agnostic client, so every typed call
    /// works unchanged over TLS.
    ///
    /// `server_name` is the DNS name presented for certificate verification
    /// (e.g. `"localhost"`); it must match a SAN in the server's certificate.
    pub async fn connect_tls(
        addr: impl ToSocketAddrs,
        server_name: impl Into<String>,
        config: rustls::ClientConfig,
    ) -> std::io::Result<Self> {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = server_name.into();
        let dns = rustls::pki_types::ServerName::try_from(name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let tcp = TcpStream::connect(addr).await?;
        let tls = connector.connect(dns, tcp).await?;
        let (read, write) = tokio::io::split(tls);
        Ok(Self::from_halves(Box::new(read), Box::new(write)))
    }

    fn from_halves(
        read: Box<dyn AsyncRead + Unpin + Send>,
        writer: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> Self {
        Self {
            reader: BufReader::new(read).lines(),
            writer,
        }
    }

    /// Authenticate the connection with the server's shared secret. Convenience
    /// wrapper over [`Syscall::Authenticate`].
    pub async fn authenticate(
        &mut self,
        token: impl Into<String>,
    ) -> std::io::Result<SyscallReply> {
        self.call(Syscall::Authenticate {
            token: token.into(),
        })
        .await
    }

    /// Send one syscall and await its reply.
    pub async fn call(&mut self, call: Syscall) -> std::io::Result<SyscallReply> {
        let mut buf = serde_json::to_vec(&call).map_err(std::io::Error::other)?;
        buf.push(b'\n');
        self.writer.write_all(&buf).await?;
        self.writer.flush().await?;
        let line = self.reader.next_line().await?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "server closed")
        })?;
        serde_json::from_str(&line).map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn v1_error_fixture_and_v2_typed_error_are_both_served() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut v1 = SyscallClient::connect(addr).await.unwrap();
        assert!(matches!(
            v1.call(Syscall::Hello {
                protocol_version: 1
            })
            .await
            .unwrap(),
            SyscallReply::Hello { .. }
        ));
        assert!(matches!(
            v1.call(Syscall::GetAgentStatus {
                agent_id: "not-a-uuid".into()
            })
            .await
            .unwrap(),
            SyscallReply::Error { .. }
        ));

        let mut v2 = SyscallClient::connect(addr).await.unwrap();
        assert!(matches!(
            v2.call(Syscall::Hello {
                protocol_version: 2
            })
            .await
            .unwrap(),
            SyscallReply::Hello { .. }
        ));
        assert!(matches!(
            v2.call(Syscall::GetAgentStatus {
                agent_id: "not-a-uuid".into()
            })
            .await
            .unwrap(),
            SyscallReply::TypedError {
                code: WireErrorCode::InvalidArgument,
                retryable: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn roundtrip_create_list_and_gate_stats() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .expect("bind");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut client = SyscallClient::connect(addr).await.expect("connect");

        // create_agent over the wire → real kernel create_agent_full.
        let reply = client
            .call(Syscall::CreateAgent {
                name: "alpha".into(),
                task: "demo".into(),
                provider: "stub".into(),
                profile: "standard".into(),
                priority: 3,
            })
            .await
            .unwrap();
        let id = match reply {
            SyscallReply::AgentCreated { id } => id,
            other => panic!("expected AgentCreated, got {other:?}"),
        };

        // list_agents reflects it.
        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Agents { agents } => {
                assert!(
                    agents.iter().any(|a| a.id == id && a.name == "alpha"),
                    "created agent should appear in the list: {agents:?}"
                );
            }
            other => panic!("expected Agents, got {other:?}"),
        }

        // gate stats round-trips (the enforcement chokepoint is reachable).
        assert!(matches!(
            client.call(Syscall::GateStats).await.unwrap(),
            SyscallReply::GateStats { .. }
        ));
    }

    #[tokio::test]
    async fn enforcement_applies_over_the_wire() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        // A read-only agent lacks CAP_FILE_WRITE.
        let id = match client
            .call(Syscall::CreateAgent {
                name: "ro".into(),
                task: "t".into(),
                provider: "stub".into(),
                profile: "read-only".into(),
                priority: 3,
            })
            .await
            .unwrap()
        {
            SyscallReply::AgentCreated { id } => id,
            other => panic!("expected AgentCreated, got {other:?}"),
        };

        // write_file is gate-denied — and that denial is delivered over the wire.
        match client
            .call(Syscall::CallTool {
                agent_id: id,
                tool: "write_file".into(),
                args: serde_json::json!({"path": "/tmp/x", "content": "y"}),
            })
            .await
            .unwrap()
        {
            SyscallReply::Error { message } => assert!(
                message.contains("denied by kernel"),
                "expected a kernel denial, got: {message}"
            ),
            other => panic!("expected Error denial, got {other:?}"),
        }

        // The gate's counters reflect the denial happening on the syscall path.
        match client.call(Syscall::GateStats).await.unwrap() {
            SyscallReply::GateStats {
                denied_capability, ..
            } => assert!(
                denied_capability >= 1,
                "gate should have denied a capability"
            ),
            other => panic!("expected GateStats, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn agent_info_reports_enforcement_state_over_the_wire() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        // A read-only agent: no CAP_FILE_WRITE.
        let id = match client
            .call(Syscall::CreateAgent {
                name: "introspect".into(),
                task: "t".into(),
                provider: "stub".into(),
                profile: "read-only".into(),
                priority: 3,
            })
            .await
            .unwrap()
        {
            SyscallReply::AgentCreated { id } => id,
            other => panic!("expected AgentCreated, got {other:?}"),
        };

        // AgentInfo reports the gate's view of the agent's capabilities.
        match client
            .call(Syscall::AgentInfo {
                agent_id: id.clone(),
            })
            .await
            .unwrap()
        {
            SyscallReply::AgentInfo {
                pid, capabilities, ..
            } => {
                assert!(pid >= 1, "agent should have a real PID");
                assert!(
                    !capabilities.contains(&"CAP_FILE_WRITE".to_string()),
                    "read-only agent must not be granted CAP_FILE_WRITE: {capabilities:?}"
                );
            }
            other => panic!("expected AgentInfo, got {other:?}"),
        }

        // An unknown agent id yields an Error, not a panic / disconnect.
        match client
            .call(Syscall::AgentInfo {
                agent_id: uuid::Uuid::new_v4().to_string(),
            })
            .await
            .unwrap()
        {
            SyscallReply::Error { message } => {
                assert!(message.contains("unknown agent"), "got: {message}")
            }
            other => panic!("expected Error for unknown agent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bad_request_yields_error_not_disconnect() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        // Send a malformed line directly, then a valid one — the connection
        // must survive the bad request and still answer the good one.
        let (read, mut write) = TcpStream::connect(addr).await.unwrap().into_split();
        let mut lines = BufReader::new(read).lines();
        write.write_all(b"{not json}\n").await.unwrap();
        write.flush().await.unwrap();
        let err_line = lines.next_line().await.unwrap().unwrap();
        let reply: SyscallReply = serde_json::from_str(&err_line).unwrap();
        assert!(matches!(reply, SyscallReply::Error { .. }));

        write
            .write_all(b"{\"op\":\"list_agents\"}\n")
            .await
            .unwrap();
        write.flush().await.unwrap();
        let ok_line = lines.next_line().await.unwrap().unwrap();
        assert!(matches!(
            serde_json::from_str::<SyscallReply>(&ok_line).unwrap(),
            SyscallReply::Agents { .. }
        ));
    }

    #[tokio::test]
    async fn memory_store_and_query_roundtrip() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        let id = match client
            .call(Syscall::CreateAgent {
                name: "mem".into(),
                task: "t".into(),
                provider: "stub".into(),
                profile: "standard".into(),
                priority: 3,
            })
            .await
            .unwrap()
        {
            SyscallReply::AgentCreated { id } => id,
            other => panic!("expected AgentCreated, got {other:?}"),
        };

        // Store a fact, then find it by substring.
        match client
            .call(Syscall::MemoryStore {
                agent_id: id.clone(),
                content: "the deploy key lives in vault".into(),
                category: Some("instruction".into()),
            })
            .await
            .unwrap()
        {
            SyscallReply::MemoryStored { id } => assert!(!id.is_empty()),
            other => panic!("expected MemoryStored, got {other:?}"),
        }

        match client
            .call(Syscall::MemoryQuery {
                agent_id: id,
                query: "deploy key".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::Memory { facts } => {
                assert!(
                    facts
                        .iter()
                        .any(|f| f.content.contains("deploy key") && f.category == "Instruction"),
                    "stored fact should be retrievable with its category: {facts:?}"
                );
            }
            other => panic!("expected Memory, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn storage_put_get_list_delete_roundtrip() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        let id = match client
            .call(Syscall::CreateAgent {
                name: "kv".into(),
                task: "t".into(),
                provider: "stub".into(),
                profile: "standard".into(),
                priority: 3,
            })
            .await
            .unwrap()
        {
            SyscallReply::AgentCreated { id } => id,
            other => panic!("expected AgentCreated, got {other:?}"),
        };

        // Missing key → StorageValue { value: None }.
        match client
            .call(Syscall::StorageGet {
                agent_id: id.clone(),
                key: "color".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::StorageValue { value } => assert_eq!(value, None),
            other => panic!("expected StorageValue, got {other:?}"),
        }

        // Put a value.
        assert!(matches!(
            client
                .call(Syscall::StoragePut {
                    agent_id: id.clone(),
                    key: "color".into(),
                    value: "blue".into(),
                })
                .await
                .unwrap(),
            SyscallReply::StorageOk
        ));

        // Get it back.
        match client
            .call(Syscall::StorageGet {
                agent_id: id.clone(),
                key: "color".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::StorageValue { value } => assert_eq!(value.as_deref(), Some("blue")),
            other => panic!("expected StorageValue, got {other:?}"),
        }

        // List shows the key.
        match client
            .call(Syscall::StorageList {
                agent_id: id.clone(),
            })
            .await
            .unwrap()
        {
            SyscallReply::StorageKeys { keys } => assert_eq!(keys, vec!["color".to_string()]),
            other => panic!("expected StorageKeys, got {other:?}"),
        }

        // Delete it → existed: true; deleting again → false.
        match client
            .call(Syscall::StorageDelete {
                agent_id: id.clone(),
                key: "color".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::StorageDeleted { existed } => assert!(existed),
            other => panic!("expected StorageDeleted, got {other:?}"),
        }
        match client
            .call(Syscall::StorageDelete {
                agent_id: id.clone(),
                key: "color".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::StorageDeleted { existed } => assert!(!existed),
            other => panic!("expected StorageDeleted, got {other:?}"),
        }

        // An invalid agent id is an error, not a disconnect.
        match client
            .call(Syscall::StorageGet {
                agent_id: "not-a-uuid".into(),
                key: "color".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::Error { message } => assert!(message.contains("invalid agent id")),
            other => panic!("expected Error for bad id, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn snapshot_context_roundtrip() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        // create_agent_full seeds an initial (default) context, so it is
        // snapshottable immediately.
        let id = match client
            .call(Syscall::CreateAgent {
                name: "snap".into(),
                task: "t".into(),
                provider: "stub".into(),
                profile: "standard".into(),
                priority: 3,
            })
            .await
            .unwrap()
        {
            SyscallReply::AgentCreated { id } => id,
            other => panic!("expected AgentCreated, got {other:?}"),
        };

        // Snapshot the current (token_count == 0) context.
        assert!(matches!(
            client
                .call(Syscall::SnapshotContext {
                    agent_id: id.clone(),
                    label: "start".into(),
                })
                .await
                .unwrap(),
            SyscallReply::SnapshotSaved
        ));

        // List shows the label.
        match client
            .call(Syscall::ListSnapshots {
                agent_id: id.clone(),
            })
            .await
            .unwrap()
        {
            SyscallReply::Snapshots { labels } => assert_eq!(labels, vec!["start".to_string()]),
            other => panic!("expected Snapshots, got {other:?}"),
        }

        // Restore reports the snapshot's token count (0 for the fresh context).
        match client
            .call(Syscall::RestoreSnapshot {
                agent_id: id.clone(),
                label: "start".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::SnapshotRestored { tokens } => assert_eq!(tokens, 0),
            other => panic!("expected SnapshotRestored, got {other:?}"),
        }

        // Delete → existed: true; deleting again → false.
        match client
            .call(Syscall::DeleteSnapshot {
                agent_id: id.clone(),
                label: "start".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::SnapshotDeleted { existed } => assert!(existed),
            other => panic!("expected SnapshotDeleted, got {other:?}"),
        }
        match client
            .call(Syscall::DeleteSnapshot {
                agent_id: id.clone(),
                label: "start".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::SnapshotDeleted { existed } => assert!(!existed),
            other => panic!("expected SnapshotDeleted, got {other:?}"),
        }

        // Restoring a missing snapshot is an error, not a disconnect.
        match client
            .call(Syscall::RestoreSnapshot {
                agent_id: id.clone(),
                label: "nope".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::Error { message } => {
                assert!(message.contains("restore snapshot failed"), "{message}")
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // An invalid agent id is an error, not a disconnect.
        match client
            .call(Syscall::SnapshotContext {
                agent_id: "not-a-uuid".into(),
                label: "x".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::Error { message } => assert!(message.contains("invalid agent id")),
            other => panic!("expected Error for bad id, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn node_info_reports_agent_load() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        // Fresh node: zero agents.
        match client.call(Syscall::NodeInfo).await.unwrap() {
            SyscallReply::NodeInfo { agent_count, .. } => assert_eq!(agent_count, 0),
            other => panic!("expected NodeInfo, got {other:?}"),
        }

        // After creating two agents, the node reports the load.
        for n in ["a", "b"] {
            client
                .call(Syscall::CreateAgent {
                    name: n.into(),
                    task: "t".into(),
                    provider: "stub".into(),
                    profile: "standard".into(),
                    priority: 3,
                })
                .await
                .unwrap();
        }
        match client.call(Syscall::NodeInfo).await.unwrap() {
            SyscallReply::NodeInfo { agent_count, .. } => assert_eq!(agent_count, 2),
            other => panic!("expected NodeInfo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hello_negotiates_compatible_version() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        match client
            .call(Syscall::Hello {
                protocol_version: PROTOCOL_VERSION,
            })
            .await
            .unwrap()
        {
            SyscallReply::Hello {
                protocol_version,
                min_protocol_version,
                server_version,
            } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
                assert_eq!(min_protocol_version, MIN_PROTOCOL_VERSION);
                assert_eq!(server_version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hello_rejects_incompatible_version_with_clear_error() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        // A future protocol version the server doesn't understand: clear error,
        // not a dropped connection or silent acceptance.
        match client
            .call(Syscall::Hello {
                protocol_version: PROTOCOL_VERSION + 99,
            })
            .await
            .unwrap()
        {
            SyscallReply::Error { message } => {
                assert!(
                    message.contains("incompatible wire-protocol version"),
                    "{message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // The connection survives the rejection: a follow-up syscall still works.
        match client.call(Syscall::NodeInfo).await.unwrap() {
            SyscallReply::NodeInfo { .. } => {}
            other => panic!("expected NodeInfo after rejected Hello, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hello_is_allowed_before_authentication() {
        // With a shared-secret token set, every syscall except Authenticate is
        // rejected until authed — except Hello, which must work pre-auth so a
        // client can check compatibility before presenting credentials.
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .unwrap()
            .with_auth_token("sekret");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        // Hello before auth: negotiates fine.
        match client
            .call(Syscall::Hello {
                protocol_version: PROTOCOL_VERSION,
            })
            .await
            .unwrap()
        {
            SyscallReply::Hello { .. } => {}
            other => panic!("expected Hello pre-auth, got {other:?}"),
        }

        // A non-Hello, non-Authenticate syscall is still gated until auth.
        match client.call(Syscall::NodeInfo).await.unwrap() {
            SyscallReply::TypedError {
                code: WireErrorCode::AuthenticationRequired,
                message,
                retryable: false,
            } => assert!(message.contains("authentication required")),
            other => panic!("expected typed auth-required error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn metrics_syscall_roundtrips_and_reflects_gate_counters() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        // A read-only agent: it can read but lacks CAP_FILE_WRITE.
        let agent_id = match client
            .call(Syscall::CreateAgent {
                name: "ro".into(),
                task: "t".into(),
                provider: "stub".into(),
                profile: "read-only".into(),
                priority: 3,
            })
            .await
            .unwrap()
        {
            SyscallReply::AgentCreated { id } => id,
            other => panic!("expected AgentCreated, got {other:?}"),
        };

        // Allowed: read_file passes the gate (the broker may still error, but the
        // gate counts the allow first).
        let _ = client
            .call(Syscall::CallTool {
                agent_id: agent_id.clone(),
                tool: "read_file".into(),
                args: serde_json::json!({ "path": "/etc/hosts" }),
            })
            .await
            .unwrap();

        // Denied: write_file requires CAP_FILE_WRITE, which read-only lacks.
        match client
            .call(Syscall::CallTool {
                agent_id: agent_id.clone(),
                tool: "write_file".into(),
                args: serde_json::json!({ "path": "/tmp/x", "content": "y" }),
            })
            .await
            .unwrap()
        {
            SyscallReply::Error { message } => assert!(message.contains("denied by kernel")),
            other => panic!("expected denial Error, got {other:?}"),
        }

        // The Metrics syscall round-trips and the exposition reflects the gate.
        match client.call(Syscall::Metrics).await.unwrap() {
            SyscallReply::Metrics {
                prometheus,
                agent_count,
                ..
            } => {
                assert_eq!(agent_count, 1);
                assert!(prometheus.contains("# TYPE agentos_syscall_gate_total counter"));
                assert!(
                    prometheus.contains("agentos_syscall_gate_total{result=\"allowed\"} 1"),
                    "exposition:\n{prometheus}"
                );
                assert!(
                    prometheus
                        .contains("agentos_syscall_gate_total{result=\"denied_capability\"} 1"),
                    "exposition:\n{prometheus}"
                );
                assert!(prometheus.contains("agentos_agents 1"));
            }
            other => panic!("expected Metrics, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn load_package_over_the_wire() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        let manifest = r#"
name = "packaged"
task = "do packaged work"
profile = "read-only"
priority = 2
memory = ["remember this"]
"#;
        let id = match client
            .call(Syscall::LoadPackage {
                manifest_toml: manifest.into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::AgentCreated { id } => id,
            other => panic!("expected AgentCreated from LoadPackage, got {other:?}"),
        };

        // The packaged agent is live and listed.
        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Agents { agents } => {
                assert!(agents.iter().any(|a| a.id == id && a.name == "packaged"))
            }
            other => panic!("expected Agents, got {other:?}"),
        }

        // A malformed manifest is an error over the wire, not a disconnect.
        match client
            .call(Syscall::LoadPackage {
                manifest_toml: "name = \"x\"".into(), // missing required `task`
            })
            .await
            .unwrap()
        {
            SyscallReply::Error { message } => assert!(message.contains("invalid package")),
            other => panic!("expected Error for bad manifest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_providers_roundtrips() {
        // No providers registered in the bare test kernel, but the syscall must
        // round-trip the (possibly empty) provider list rather than error.
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        assert!(matches!(
            client.call(Syscall::ListProviders).await.unwrap(),
            SyscallReply::Providers { .. }
        ));
    }

    #[tokio::test]
    async fn auth_token_gates_syscalls() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .unwrap()
            .with_auth_token("s3cret");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        // Before auth, any syscall is rejected.
        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Error { message } => {
                assert!(
                    message.contains("authentication required"),
                    "got: {message}"
                )
            }
            other => panic!("expected auth-required error, got {other:?}"),
        }

        // Wrong token is refused.
        match client.authenticate("wrong").await.unwrap() {
            SyscallReply::Error { message } => {
                assert!(message.contains("authentication failed"), "got: {message}")
            }
            other => panic!("expected auth-failed error, got {other:?}"),
        }

        // Correct token unlocks the connection.
        assert!(matches!(
            client.authenticate("s3cret").await.unwrap(),
            SyscallReply::Authenticated
        ));
        assert!(matches!(
            client.call(Syscall::ListAgents).await.unwrap(),
            SyscallReply::Agents { .. }
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_roundtrip() {
        let dir = std::env::temp_dir();
        // Unique-ish path without Math.random/time deps: use the pid.
        let path = dir.join(format!("agentos-syscall-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind_unix(kernel, &path).await.unwrap();
        tokio::spawn(server.serve());

        let mut client = SyscallClient::connect_unix(&path).await.unwrap();
        let reply = client
            .call(Syscall::CreateAgent {
                name: "over-unix".into(),
                task: "t".into(),
                provider: "stub".into(),
                profile: "standard".into(),
                priority: 3,
            })
            .await
            .unwrap();
        assert!(matches!(reply, SyscallReply::AgentCreated { .. }));
        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Agents { agents } => {
                assert!(agents.iter().any(|a| a.name == "over-unix"))
            }
            other => panic!("expected Agents over unix socket, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Generate a self-signed cert for `localhost`, returning the server config
    /// and a client root store that trusts exactly that cert.
    fn self_signed_tls() -> (rustls::ServerConfig, rustls::RootCertStore) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
            .expect("private key der");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server config");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("trust self-signed cert");

        (server_config, roots)
    }

    #[tokio::test]
    async fn tls_roundtrip_create_and_list() {
        // Install the ring crypto provider for the process (idempotent across
        // tests — a second install is a no-op error we ignore).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_config, roots) = self_signed_tls();

        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind_tls(kernel.clone(), "127.0.0.1:0", server_config)
            .await
            .expect("bind_tls");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = SyscallClient::connect_tls(addr, "localhost", client_config)
            .await
            .expect("connect_tls");

        // CreateAgent over the encrypted transport → real kernel path.
        let id = match client
            .call(Syscall::CreateAgent {
                name: "tls-alpha".into(),
                task: "demo".into(),
                provider: "stub".into(),
                profile: "standard".into(),
                priority: 3,
            })
            .await
            .unwrap()
        {
            SyscallReply::AgentCreated { id } => id,
            other => panic!("expected AgentCreated over TLS, got {other:?}"),
        };

        // ListAgents reflects it — round-trip over TLS confirmed.
        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Agents { agents } => assert!(
                agents.iter().any(|a| a.id == id && a.name == "tls-alpha"),
                "created agent should appear over TLS: {agents:?}"
            ),
            other => panic!("expected Agents over TLS, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tls_composes_with_auth_token() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server_config, roots) = self_signed_tls();

        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind_tls(kernel, "127.0.0.1:0", server_config)
            .await
            .expect("bind_tls")
            .with_auth_token("s3cret");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = SyscallClient::connect_tls(addr, "localhost", client_config)
            .await
            .expect("connect_tls");

        // Auth still gates syscalls inside the TLS session.
        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Error { message } => {
                assert!(
                    message.contains("authentication required"),
                    "got: {message}"
                )
            }
            other => panic!("expected auth-required error over TLS, got {other:?}"),
        }
        assert!(matches!(
            client.authenticate("s3cret").await.unwrap(),
            SyscallReply::Authenticated
        ));
        assert!(matches!(
            client.call(Syscall::ListAgents).await.unwrap(),
            SyscallReply::Agents { .. }
        ));
    }

    fn assert_authorization_denied(reply: SyscallReply) {
        match reply {
            SyscallReply::Error { message } => assert_eq!(message, AUTHORIZATION_DENIED),
            other => panic!("expected stable authorization denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tenant_authorizer_denies_every_foreign_agent_operation() {
        let kernel = AgentKernelImpl::new().expect("kernel new");
        let tenant_a = kernel.create_tenant("a").await.unwrap();
        let tenant_b = kernel.create_tenant("b").await.unwrap();
        let user_a = kernel
            .register_user(&tenant_a, "alice", "alice@a.test", Role::User)
            .await
            .unwrap();
        let principal_a = Principal {
            user_id: user_a,
            tenant_id: tenant_a,
            role: Role::User,
        };
        let foreign = kernel
            .create_agent_for_tenant(
                &tenant_b,
                AgentConfig {
                    name: "foreign".into(),
                    task: "private".into(),
                    llm_provider: "stub".into(),
                    permission_profile: "standard".into(),
                    priority: Priority::default(),
                    sandbox_config: None,
                },
            )
            .await
            .unwrap();
        let id = foreign.id.to_string();

        let calls = vec![
            Syscall::SendMessage {
                agent_id: id.clone(),
                message: "probe".into(),
            },
            Syscall::CallTool {
                agent_id: id.clone(),
                tool: "read_file".into(),
                args: serde_json::json!({"path": "/tmp/x"}),
            },
            Syscall::AgentInfo {
                agent_id: id.clone(),
            },
            Syscall::MemoryStore {
                agent_id: id.clone(),
                content: "poison".into(),
                category: None,
            },
            Syscall::MemoryQuery {
                agent_id: id.clone(),
                query: "private".into(),
            },
            Syscall::StoragePut {
                agent_id: id.clone(),
                key: "k".into(),
                value: "v".into(),
            },
            Syscall::StorageGet {
                agent_id: id.clone(),
                key: "k".into(),
            },
            Syscall::StorageList {
                agent_id: id.clone(),
            },
            Syscall::ContextPressure {
                agent_id: id.clone(),
            },
            Syscall::StorageDelete {
                agent_id: id.clone(),
                key: "k".into(),
            },
            Syscall::SnapshotContext {
                agent_id: id.clone(),
                label: "x".into(),
            },
            Syscall::RestoreSnapshot {
                agent_id: id.clone(),
                label: "x".into(),
            },
            Syscall::ListSnapshots {
                agent_id: id.clone(),
            },
            Syscall::DeleteSnapshot {
                agent_id: id,
                label: "x".into(),
            },
        ];

        for call in calls {
            assert_authorization_denied(dispatch_scoped(&kernel, call, Some(&principal_a)).await);
        }
        assert!(
            kernel
                .observability
                .get_activity_log(foreign.id, None)
                .iter()
                .any(|entry| entry.action_type == "authorization_deny"),
            "foreign-resource denials must be auditable"
        );
    }

    #[tokio::test]
    async fn operator_snapshot_is_live_and_tenant_scoped() {
        let kernel = AgentKernelImpl::new().expect("kernel new");
        let tenant_a = kernel.create_tenant("ops-a").await.unwrap();
        let tenant_b = kernel.create_tenant("ops-b").await.unwrap();
        let user_a = kernel
            .register_user(&tenant_a, "operator", "ops@a.test", Role::ReadOnly)
            .await
            .unwrap();
        let principal_a = Principal {
            user_id: user_a,
            tenant_id: tenant_a.clone(),
            role: Role::ReadOnly,
        };
        let own = kernel
            .create_agent_for_tenant(
                &tenant_a,
                AgentConfig {
                    name: "visible".into(),
                    task: "owned".into(),
                    llm_provider: "stub".into(),
                    permission_profile: "standard".into(),
                    priority: Priority::default(),
                    sandbox_config: None,
                },
            )
            .await
            .unwrap();
        let foreign = kernel
            .create_agent_for_tenant(
                &tenant_b,
                AgentConfig {
                    name: "secret-foreign-name".into(),
                    task: "private".into(),
                    llm_provider: "stub".into(),
                    permission_profile: "standard".into(),
                    priority: Priority::default(),
                    sandbox_config: None,
                },
            )
            .await
            .unwrap();

        let tenant_snapshot =
            match dispatch_scoped(&kernel, Syscall::OperatorSnapshot, Some(&principal_a)).await {
                SyscallReply::OperatorSnapshot { snapshot } => snapshot,
                other => panic!("expected operator snapshot, got {other:?}"),
            };
        assert_eq!(tenant_snapshot.scope, format!("tenant:{tenant_a}"));
        assert_eq!(tenant_snapshot.agents.len(), 1);
        assert_eq!(tenant_snapshot.agents[0].id, own.id.to_string());
        assert!(!tenant_snapshot.agents.iter().any(
            |agent| agent.id == foreign.id.to_string() || agent.name.contains("secret-foreign")
        ));
        assert!(tenant_snapshot.system_metrics.is_none());
        assert!(tenant_snapshot.services.is_none());
        assert!(tenant_snapshot.global_spend_usd.is_none());

        kernel.pause_agent(own.id).await.unwrap();
        let paused =
            match dispatch_scoped(&kernel, Syscall::OperatorSnapshot, Some(&principal_a)).await {
                SyscallReply::OperatorSnapshot { snapshot } => snapshot,
                other => panic!("expected operator snapshot, got {other:?}"),
            };
        assert_eq!(paused.agents[0].state, "Paused");
        assert_eq!(paused.agents[0].scheduler_state, "paused");
        assert!(paused.agents[0].sandbox_active);

        kernel.kill_agent(own.id).await.unwrap();
        let stopped =
            match dispatch_scoped(&kernel, Syscall::OperatorSnapshot, Some(&principal_a)).await {
                SyscallReply::OperatorSnapshot { snapshot } => snapshot,
                other => panic!("expected operator snapshot, got {other:?}"),
            };
        assert_eq!(stopped.agents[0].state, "Stopped");
        assert_eq!(stopped.agents[0].scheduler_state, "stopped");
        assert!(!stopped.agents[0].sandbox_active);

        let system = match dispatch(&kernel, Syscall::OperatorSnapshot).await {
            SyscallReply::OperatorSnapshot { snapshot } => snapshot,
            other => panic!("expected system snapshot, got {other:?}"),
        };
        assert_eq!(system.agents.len(), 2);
        assert!(system.system_metrics.is_some());
        assert!(system.services.is_some());
    }

    #[tokio::test]
    async fn rbac_is_fail_closed_and_package_agents_keep_tenant_ownership() {
        let kernel = AgentKernelImpl::new().expect("kernel new");
        let tenant = kernel.create_tenant("acme").await.unwrap();
        let read_only_id = kernel
            .register_user(&tenant, "reader", "reader@acme.test", Role::ReadOnly)
            .await
            .unwrap();
        let admin_id = kernel
            .register_user(&tenant, "admin", "admin@acme.test", Role::Admin)
            .await
            .unwrap();
        let read_only = Principal {
            user_id: read_only_id,
            tenant_id: tenant.clone(),
            role: Role::ReadOnly,
        };
        let admin = Principal {
            user_id: admin_id,
            tenant_id: tenant.clone(),
            role: Role::Admin,
        };
        let agent = kernel
            .create_agent_for_tenant(
                &tenant,
                AgentConfig {
                    name: "owned".into(),
                    task: "readable".into(),
                    llm_provider: "stub".into(),
                    permission_profile: "standard".into(),
                    priority: Priority::default(),
                    sandbox_config: None,
                },
            )
            .await
            .unwrap();

        assert!(matches!(
            dispatch_scoped(
                &kernel,
                Syscall::AgentInfo {
                    agent_id: agent.id.to_string()
                },
                Some(&read_only)
            )
            .await,
            SyscallReply::AgentInfo { .. }
        ));
        assert_authorization_denied(
            dispatch_scoped(
                &kernel,
                Syscall::StoragePut {
                    agent_id: agent.id.to_string(),
                    key: "k".into(),
                    value: "v".into(),
                },
                Some(&read_only),
            )
            .await,
        );
        assert_authorization_denied(dispatch_scoped(&kernel, Syscall::Metrics, Some(&admin)).await);
        assert_authorization_denied(
            dispatch_scoped(&kernel, Syscall::ListServices, Some(&admin)).await,
        );

        let manifest_toml = r#"
name = "tenant-package"
task = "stay scoped"
provider = "stub"
profile = "standard"
"#;
        let created = dispatch_scoped(
            &kernel,
            Syscall::LoadPackage {
                manifest_toml: manifest_toml.into(),
            },
            Some(&admin),
        )
        .await;
        let id = match created {
            SyscallReply::AgentCreated { id } => uuid::Uuid::parse_str(&id).unwrap(),
            other => panic!("expected tenant package creation, got {other:?}"),
        };
        assert_eq!(
            kernel.context_manager.agent_tenant(id).unwrap(),
            Some(tenant)
        );
    }

    #[tokio::test]
    async fn revoked_tenant_session_loses_authority_without_reconnect() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let tenant = kernel.create_tenant("revocation").await.unwrap();
        let user = kernel
            .register_user(&tenant, "alice", "alice@revocation.test", Role::User)
            .await
            .unwrap();
        let token = kernel.open_session(&user).await.unwrap();
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .expect("bind");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        assert!(matches!(
            client.authenticate(token.clone()).await.unwrap(),
            SyscallReply::Authenticated
        ));
        assert!(matches!(
            client.call(Syscall::ListAgents).await.unwrap(),
            SyscallReply::Agents { .. }
        ));

        kernel.auth.write().await.revoke_session(&token);
        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Error { message } => assert_eq!(message, "authentication required"),
            other => panic!("revoked session retained authority: {other:?}"),
        }
        match client.authenticate(token).await.unwrap() {
            SyscallReply::Error { message } => assert_eq!(message, "authentication failed"),
            other => panic!("revoked token was accepted again: {other:?}"),
        }
    }

    #[test]
    fn syscall_wire_format_is_tagged_json() {
        // The SDK depends on this exact shape.
        let v = serde_json::to_value(Syscall::SendMessage {
            agent_id: "x".into(),
            message: "hi".into(),
        })
        .unwrap();
        assert_eq!(v["op"], "send_message");
        assert_eq!(v["agent_id"], "x");

        // Defaults fill in when the SDK omits optional fields.
        let parsed: Syscall =
            serde_json::from_str(r#"{"op":"create_agent","name":"a","task":"t"}"#).unwrap();
        match parsed {
            Syscall::CreateAgent {
                provider,
                profile,
                priority,
                ..
            } => {
                assert_eq!(provider, "stub");
                assert_eq!(profile, "standard");
                assert_eq!(priority, 3);
            }
            _ => panic!("expected CreateAgent"),
        }
    }
}
