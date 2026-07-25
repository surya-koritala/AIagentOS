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
#[cfg(test)]
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::Semaphore;

use crate::agent::AgentKernel;
use crate::auth::{Principal, Role};
use crate::connector::AgentConnector;
use crate::context::{ContextManager, ContextPressureStats, Fact, FactCategory};
use crate::observability::{AgentAction, ObservabilityEngine};
use crate::resources::ResourceBroker;
use crate::wire_io::{graceful_close_framed, read_bounded_line, write_bounded_json};
use crate::{AgentConfig, AgentKernelImpl, Priority};

/// Default simultaneous syscall connection limit.
pub use crate::wire_io::DEFAULT_MAX_CONNECTIONS as DEFAULT_WIRE_MAX_CONNECTIONS;
/// Maximum duration of the client half-close / peer-EOF handshake.
pub use crate::wire_io::GRACEFUL_CLOSE_TIMEOUT as WIRE_GRACEFUL_CLOSE_TIMEOUT;
/// Maximum time for the first frame and TLS negotiation.
pub use crate::wire_io::HANDSHAKE_TIMEOUT as WIRE_HANDSHAKE_TIMEOUT;
/// Maximum idle time between syscall frames.
pub use crate::wire_io::IDLE_TIMEOUT as WIRE_IDLE_TIMEOUT;
/// Maximum serialized syscall request or reply frame.
pub use crate::wire_io::MAX_JSON_FRAME_BYTES as MAX_WIRE_FRAME_BYTES;
/// Recommended maximum interval between application-level pings.
pub use crate::wire_io::RECOMMENDED_KEEPALIVE_INTERVAL as WIRE_KEEPALIVE_INTERVAL;
/// Maximum wall-clock duration of one dispatched syscall.
pub use crate::wire_io::REQUEST_TIMEOUT as WIRE_REQUEST_TIMEOUT;
/// Maximum queued stream events at each transport boundary.
pub use crate::wire_io::STREAM_EVENT_BUFFER_CAPACITY;

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

/// Maximum duration accepted from an untrusted wire `WaitAgent` request.
///
/// This remains below the production credential-drain bound, leaving time for
/// dispatch to release its credential lease before revocation reports an
/// incomplete drain. In-process callers can still choose their own timeout.
pub const MAX_WIRE_WAIT_AGENT_TIMEOUT_MS: u64 = 25_000;

fn wire_wait_agent_timeout(requested_ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(requested_ms.min(MAX_WIRE_WAIT_AGENT_TIMEOUT_MS))
}

fn default_provider() -> String {
    "stub".to_string()
}
fn default_profile() -> String {
    "standard".to_string()
}
fn default_priority() -> u8 {
    3
}
fn default_tunable_audit_limit() -> usize {
    100
}

fn default_package_requirement() -> String {
    "*".to_string()
}

/// A syscall request from an agent / SDK to the kernel.
#[derive(Clone, Serialize, Deserialize)]
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
    /// Wait until an agent becomes terminal or the timeout expires. The server
    /// caps this caller-controlled value at [`MAX_WIRE_WAIT_AGENT_TIMEOUT_MS`].
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
    /// Drive one turn while emitting ordered request-scoped event frames on
    /// this connection. Cancellation is sent from another authenticated
    /// connection with [`CancelRequest`](Self::CancelRequest).
    SendMessageStream {
        request_id: String,
        agent_id: String,
        message: String,
    },
    /// Cooperatively cancel one exact active streaming request. The agent id
    /// keeps the operation inside the normal tenant ownership check.
    CancelRequest {
        request_id: String,
        agent_id: String,
    },
    /// Invoke a single tool as an agent. Goes through the syscall gate
    /// (namespace / capability / MAC / approval / cgroup membership) before the
    /// resource broker, so a denial is returned as an `Error` — enforcement
    /// applies over the wire.
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
    /// Query an agent's long-term memory using its configured semantic index.
    MemoryQuery {
        agent_id: String,
        query: String,
    },
    /// Replace the content and embedding of an agent-owned fact.
    MemoryUpdate {
        agent_id: String,
        fact_id: String,
        content: String,
    },
    /// Delete an agent-owned fact.
    MemoryDelete {
        agent_id: String,
        fact_id: String,
    },
    /// Rebuild all embeddings owned by an agent with the active embedding model.
    MemoryReindex {
        agent_id: String,
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
    /// Return the versioned, machine-readable request/reply/MCP schemas,
    /// feature identifiers, compatibility behavior, and transport bounds.
    /// Like `Hello`, this is safe before authentication.
    DescribeProtocol,
    /// Prove that a quiet protocol-v2 connection is still responsive and reset
    /// its established idle deadline. Safe before authentication and free of
    /// kernel side effects.
    Ping,
    /// Load an agent package from a TOML manifest (see `crate::agent_package`):
    /// parse + validate, then create the agent through the full admission path
    /// and seed its memory. Replies with the new agent's id (`AgentCreated`).
    /// Running the package's entry prompt is left to the in-process runner.
    LoadPackage {
        manifest_toml: String,
    },
    /// Add or rotate a tenant package publisher's Ed25519 trust root.
    TrustPackageKey {
        publisher: String,
        key_id: String,
        public_key_hex: String,
        valid_from: String,
        #[serde(default)]
        valid_until: Option<String>,
        #[serde(default)]
        supersedes: Option<String>,
    },
    /// Revoke a package trust root. Previously installed artifacts remain
    /// recorded, but fetch, install, and run re-verification fail closed.
    RevokePackageKey {
        key_id: String,
    },
    /// Publish a signed `.agent` archive to the caller's tenant registry.
    PublishPackage {
        archive_hex: String,
    },
    /// Yank a compromised or obsolete package version from resolution.
    YankPackage {
        name: String,
        version: String,
    },
    /// Fetch one non-yanked signed archive.
    FetchPackage {
        name: String,
        version: String,
    },
    /// Search package metadata inside the caller's tenant.
    SearchPackages {
        query: String,
    },
    /// Resolve and transactionally install or upgrade a signed package.
    InstallPackage {
        name: String,
        #[serde(default = "default_package_requirement")]
        requirement: String,
    },
    /// Restore the previous committed version of an installed package.
    RollbackPackage {
        name: String,
    },
    /// Remove an installed package when no installed package depends on it.
    RemovePackage {
        name: String,
    },
    /// List the caller tenant's installed package lock state.
    ListInstalledPackages,
    /// Re-verify and load the installed agent through normal tenant admission.
    RunInstalledPackage {
        name: String,
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
    /// List the small, versioned set of durable settings that drive live
    /// operator/kernel behavior. System-scoped because values are global.
    ListOperatorTunables,
    /// Compare-and-set a durable live tunable.
    SetOperatorTunable {
        name: String,
        value: u64,
        expected_revision: u64,
    },
    /// Restore the effective value from an earlier applied revision while
    /// still advancing the current revision.
    RollbackOperatorTunable {
        name: String,
        target_revision: u64,
        expected_revision: u64,
    },
    /// Read the durable applied/denied mutation history.
    ListOperatorTunableAudit {
        #[serde(default)]
        name: Option<String>,
        #[serde(default = "default_tunable_audit_limit")]
        limit: usize,
    },
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
    /// Re-parse and roll out the explicit configured service directory.
    ReloadServices,
    /// Durable service transition/restart history.
    ListServiceHistory {
        #[serde(default)]
        name: Option<String>,
        #[serde(default = "default_tunable_audit_limit")]
        limit: usize,
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
    #[serde(default)]
    pub circuit_open: bool,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub capabilities: crate::connector::ProviderCapabilities,
    #[serde(default)]
    pub routing_policy: crate::connector::ProviderRoutingPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampled_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_duration_ms: Option<u64>,
    #[serde(default)]
    pub probe_timed_out: bool,
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

/// Ordered events emitted by [`Syscall::SendMessageStream`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum MessageStreamEvent {
    Started,
    Token {
        delta: String,
    },
    ToolCallStarted {
        name: String,
    },
    ToolCallCompleted {
        name: String,
    },
    ContextPressure {
        active_tokens: u32,
        budget_tokens: u32,
        evicted_messages: usize,
        spill_key: String,
    },
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
    #[serde(default)]
    pub namespace_details: Vec<OperatorNamespaceSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<OperatorCgroupSnapshot>,
    #[serde(default)]
    pub gate_decisions: crate::syscall_gate::GateStats,
    pub checkpoint_count: usize,
    pub context_pressure: ContextPressureStats,
    pub latest_usage: Option<crate::context::UsageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorNamespaceSnapshot {
    pub id: u64,
    pub kind: String,
    pub parent: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorCgroupSnapshot {
    pub id: u64,
    pub scope: String,
    pub tokens_per_minute_limit: u64,
    pub concurrent_tool_limit: u32,
    pub context_token_limit: u64,
    pub agent_limit: u32,
    pub active_tool_calls: u32,
    pub context_tokens: u64,
    pub agent_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorPackageSnapshot {
    pub agent_id: String,
    pub tenant_id: String,
    pub name: String,
    pub provider: String,
    pub profile: String,
    pub loaded_at: String,
    pub agent_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorServiceSnapshot {
    pub name: String,
    pub state: String,
    pub agent_id: Option<String>,
    pub restart_count: u32,
    pub last_exit_code: Option<i32>,
    #[serde(default)]
    pub desired_running: bool,
    #[serde(default)]
    pub ready: bool,
    #[serde(default)]
    pub healthy: bool,
    #[serde(default)]
    pub restart_exhausted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_restart_at: Option<String>,
    #[serde(default)]
    pub last_transition_at: String,
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
    #[serde(default)]
    pub total_visible_agents: usize,
    #[serde(default)]
    pub agents_truncated: bool,
    pub providers: Vec<ProviderSummary>,
    #[serde(default)]
    pub packages: Vec<OperatorPackageSnapshot>,
    #[serde(default)]
    pub scoped_gate_decisions: crate::syscall_gate::GateStats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunables: Option<Vec<crate::operator_control::OperatorTunable>>,
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
        } else if message.contains("unavailable") || message.contains("not registered") {
            // Check availability before quota/provider keywords: for example,
            // "durable provider rate-limit accounting is unavailable" is an
            // infrastructure failure, not proof that a quota was exceeded.
            (Self::Unavailable, true)
        } else if message.contains("cancel") {
            // Rate-limit cancellation messages also contain "admission"; keep
            // this ahead of quota classification.
            (Self::Cancelled, false)
        } else if message.contains("concurrency semaphore closed") {
            (Self::Unavailable, true)
        } else if message.contains("cgroup membership changed") {
            (Self::Conflict, true)
        } else if message.contains("rate-limit guard")
            || message.contains("rate-limit reservation cannot")
        {
            // Guard lifecycle violations are local programming/invariant
            // errors, not provider outages or exhausted quota.
            (Self::Internal, false)
        } else if message.contains("request estimate") && message.contains("tpm limit") {
            // Waiting for a new epoch cannot make one request smaller than its
            // configured ceiling. Retrying unchanged is not useful.
            (Self::QuotaExceeded, false)
        } else if message.contains("quota exceeded")
            || message.contains("quota exhausted")
            || message.contains("budget exceeded")
            || message.contains("budget exhausted")
            || message.contains("queue is full")
            || message.contains("rate limit exceeded")
            || message.contains("rate-limit exceeded")
        {
            (Self::QuotaExceeded, true)
        } else if message.contains("timeout") || message.contains("timed out") {
            (Self::Timeout, true)
        } else if message.contains("partial provider stream") {
            // Output is already visible. Retrying would duplicate content even
            // if the underlying provider transport later recovers.
            (Self::Provider, false)
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
        } else {
            (Self::Internal, false)
        }
    }
}

/// The kernel's reply to a [`Syscall`].
#[derive(Clone, Serialize, Deserialize)]
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
    /// One ordered frame in a live message stream.
    StreamEvent {
        request_id: String,
        sequence: u64,
        event: MessageStreamEvent,
    },
    /// Terminal successful frame for a live message stream.
    StreamCompleted {
        request_id: String,
        content: String,
        tool_calls: usize,
        tokens: u32,
    },
    /// Terminal failed/cancelled frame for a live message stream.
    StreamFailed {
        request_id: String,
        code: WireErrorCode,
        message: String,
        retryable: bool,
    },
    /// Whether an exact active request accepted a cancellation signal.
    RequestCancellation {
        request_id: String,
        accepted: bool,
    },
    ToolResult {
        data: serde_json::Value,
    },
    GateStats {
        allowed: u64,
        denied_capability: u64,
        denied_mac: u64,
        denied_approval: u64,
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
    /// Whether an agent-owned fact was updated.
    MemoryUpdated {
        updated: bool,
    },
    /// Whether an agent-owned fact was deleted.
    MemoryDeleted {
        deleted: bool,
    },
    /// Number of agent-owned facts whose embeddings were rebuilt.
    MemoryReindexed {
        count: usize,
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
        /// Fine-grained stable capabilities available on this server.
        #[serde(default)]
        features: Vec<String>,
    },
    /// Prompt response to [`Syscall::Ping`].
    Pong,
    /// The connection is authenticated (reply to [`Syscall::Authenticate`]).
    Authenticated,
    /// Machine-readable public protocol contract.
    ProtocolDescription {
        description: crate::wire_contract::ProtocolDescription,
    },
    /// A trust root was added, rotated, or revoked.
    PackageKeyUpdated,
    /// A signed artifact was published.
    PackagePublished {
        package: crate::package::PackageSummary,
    },
    /// A signed artifact fetched from the tenant registry.
    PackageArchive {
        archive_hex: String,
    },
    /// Tenant-scoped package search results.
    Packages {
        packages: Vec<crate::package::PackageSummary>,
    },
    /// Transactional install, upgrade, or rollback result.
    PackageInstalled {
        package: crate::package::InstalledPackage,
    },
    /// Installed package state.
    InstalledPackages {
        packages: Vec<crate::package::InstalledPackage>,
    },
    /// A package version was yanked or an installation was removed.
    PackageMutationComplete,
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
    OperatorTunables {
        tunables: Vec<crate::operator_control::OperatorTunable>,
    },
    OperatorTunable {
        tunable: crate::operator_control::OperatorTunable,
    },
    OperatorTunableAudit {
        entries: Vec<crate::operator_control::OperatorTunableAudit>,
    },
    Services {
        services: Vec<crate::init_system::ServiceRuntimeInfo>,
    },
    Service {
        service: crate::init_system::ServiceRuntimeInfo,
    },
    ServiceConfigurationReloaded {
        boot_order: Vec<String>,
    },
    ServiceHistory {
        entries: Vec<crate::init_system::ServiceHistoryEntry>,
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

fn redact_debug_fields(value: &mut serde_json::Value, fields: &[&str]) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for field in fields {
        if object.contains_key(*field) {
            object.insert((*field).to_string(), serde_json::json!("[REDACTED]"));
        }
    }
}

impl std::fmt::Debug for Syscall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value =
            serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!("<unserializable>"));
        let fields: &[&str] = match self {
            Self::Authenticate { .. } => &["token"],
            Self::SendMessage { .. } | Self::SendMessageStream { .. } => &["message"],
            Self::CallTool { .. } => &["args"],
            Self::MemoryStore { .. } | Self::MemoryUpdate { .. } => &["content"],
            Self::StoragePut { .. } => &["value"],
            Self::LoadPackage { .. } => &["manifest_toml"],
            Self::PublishPackage { .. } => &["archive_hex"],
            _ => &[],
        };
        redact_debug_fields(&mut value, fields);
        formatter.debug_tuple("Syscall").field(&value).finish()
    }
}

impl std::fmt::Debug for SyscallReply {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value =
            serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!("<unserializable>"));
        let fields: &[&str] = match self {
            Self::Message { .. } | Self::StreamCompleted { .. } => &["content"],
            Self::StreamEvent { .. } => &["event"],
            Self::ToolResult { .. } => &["data"],
            Self::Memory { .. } => &["facts"],
            Self::StorageValue { .. } => &["value"],
            Self::PackageArchive { .. } => &["archive_hex"],
            _ => &[],
        };
        redact_debug_fields(&mut value, fields);
        formatter.debug_tuple("SyscallReply").field(&value).finish()
    }
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
        Syscall::SendMessageStream { agent_id, .. } => (
            AccessLevel::User,
            "agent.send_message_stream",
            Some(agent_id),
        ),
        Syscall::CancelRequest { agent_id, .. } => {
            (AccessLevel::User, "agent.cancel_request", Some(agent_id))
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
        Syscall::MemoryUpdate { agent_id, .. } => {
            (AccessLevel::User, "memory.update", Some(agent_id))
        }
        Syscall::MemoryDelete { agent_id, .. } => {
            (AccessLevel::User, "memory.delete", Some(agent_id))
        }
        Syscall::MemoryReindex { agent_id } => {
            (AccessLevel::User, "memory.reindex", Some(agent_id))
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
        Syscall::DescribeProtocol => (AccessLevel::ReadOnly, "protocol.describe", None),
        Syscall::Ping => (AccessLevel::ReadOnly, "protocol.ping", None),
        Syscall::Authenticate { .. } => (AccessLevel::ReadOnly, "auth.authenticate", None),
        Syscall::LoadPackage { .. } => (AccessLevel::Admin, "package.load", None),
        Syscall::TrustPackageKey { .. } => (AccessLevel::Admin, "package.trust_key", None),
        Syscall::RevokePackageKey { .. } => (AccessLevel::Admin, "package.revoke_key", None),
        Syscall::PublishPackage { .. } => (AccessLevel::Admin, "package.publish", None),
        Syscall::YankPackage { .. } => (AccessLevel::Admin, "package.yank", None),
        Syscall::FetchPackage { .. } => (AccessLevel::ReadOnly, "package.fetch", None),
        Syscall::SearchPackages { .. } => (AccessLevel::ReadOnly, "package.search", None),
        Syscall::InstallPackage { .. } => (AccessLevel::Admin, "package.install", None),
        Syscall::RollbackPackage { .. } => (AccessLevel::Admin, "package.rollback", None),
        Syscall::RemovePackage { .. } => (AccessLevel::Admin, "package.remove", None),
        Syscall::ListInstalledPackages => (AccessLevel::ReadOnly, "package.installed.list", None),
        Syscall::RunInstalledPackage { .. } => (AccessLevel::Admin, "package.run", None),
        Syscall::NodeInfo => (AccessLevel::System, "system.node_info", None),
        Syscall::Metrics => (AccessLevel::System, "system.metrics", None),
        Syscall::OperatorSnapshot => (AccessLevel::ReadOnly, "operator.snapshot", None),
        Syscall::ListOperatorTunables => (AccessLevel::System, "operator.tunable.list", None),
        Syscall::SetOperatorTunable { .. } => (AccessLevel::System, "operator.tunable.set", None),
        Syscall::RollbackOperatorTunable { .. } => {
            (AccessLevel::System, "operator.tunable.rollback", None)
        }
        Syscall::ListOperatorTunableAudit { .. } => {
            (AccessLevel::System, "operator.tunable.audit", None)
        }
        Syscall::ListServices => (AccessLevel::System, "service.list", None),
        Syscall::StartService { .. } => (AccessLevel::System, "service.start", None),
        Syscall::StopService { .. } => (AccessLevel::System, "service.stop", None),
        Syscall::RestartService { .. } => (AccessLevel::System, "service.restart", None),
        Syscall::ReloadServices => (AccessLevel::System, "service.reload", None),
        Syscall::ListServiceHistory { .. } => (AccessLevel::System, "service.history", None),
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
    let credential_kind = principal
        .credential
        .as_ref()
        .map(|credential| match credential.kind {
            crate::auth::CredentialKind::ApiKey => "api_key",
            crate::auth::CredentialKind::Session => "session",
        })
        .unwrap_or("synthetic");
    let credential_id = principal
        .credential
        .as_ref()
        .map(|credential| credential.id.get(..12).unwrap_or(&credential.id))
        .unwrap_or("none");
    tracing::warn!(
        target: "agentos::authorization",
        user_id = %principal.user_id,
        tenant_id = %principal.tenant_id,
        role = principal.role.as_str(),
        credential_kind,
        credential_id,
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
        match call {
            Syscall::SetOperatorTunable { name, value, .. } => {
                kernel.operator_control.record_denial(
                    name,
                    Some(*value),
                    &format!(
                        "tenant:{} user:{} role:{}",
                        principal.tenant_id,
                        principal.user_id,
                        principal.role.as_str()
                    ),
                    "authorization denied: system scope is required",
                );
            }
            Syscall::RollbackOperatorTunable { name, .. } => {
                kernel.operator_control.record_denial(
                    name,
                    None,
                    &format!(
                        "tenant:{} user:{} role:{}",
                        principal.tenant_id,
                        principal.user_id,
                        principal.role.as_str()
                    ),
                    "authorization denied: system scope is required",
                );
            }
            _ => {}
        }
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
/// syscall gate's capability/MAC/approval/cgroup/namespace checks still apply.
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
    let package_scope = tenant.unwrap_or(crate::context::DEFAULT_TENANT);
    let package_actor = principal
        .map(|principal| principal.user_id.as_str())
        .unwrap_or("system");
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
                .wait_agent(id, wire_wait_agent_timeout(timeout_ms))
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
        Syscall::SendMessageStream { .. } => SyscallReply::Error {
            message: "streaming requests require the streaming wire transport".into(),
        },
        Syscall::CancelRequest {
            request_id,
            agent_id,
        } => match uuid::Uuid::parse_str(&agent_id) {
            Ok(id) => SyscallReply::RequestCancellation {
                accepted: kernel.cancel_request(id, &request_id),
                request_id,
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
            // Security preparation is shared with executor/MCP/SDK so action,
            // resource extraction, and accounting cannot drift by entry point.
            let (prepared_tool, _tool_slot) = match kernel
                .tool_registry
                .authorize_and_acquire_call(&kernel.syscall_gate, id, &tool, &args)
                .await
            {
                Ok((prepared, slot)) => (prepared, slot),
                Err(crate::tools::ToolAuthorizationError::InvalidDeclaration(error))
                    if error == crate::tools::TOOL_NOT_FOUND_ERROR =>
                {
                    return SyscallReply::Error { message: error }
                }
                Err(error) => {
                    return SyscallReply::Error {
                        message: format!("tool '{tool}' denied by kernel: {error}"),
                    }
                }
            };

            let reply = match kernel.resource_broker.execute(prepared_tool.request).await {
                Ok(resp) if resp.success => SyscallReply::ToolResult { data: resp.data },
                Ok(resp) => SyscallReply::Error {
                    message: format!("tool '{tool}' failed: {}", resp.error.unwrap_or_default()),
                },
                Err(e) => SyscallReply::Error {
                    message: format!("tool '{tool}' error: {e}"),
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
                denied_approval: s.denied_approval,
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
                    circuit_open: p.circuit_open,
                    consecutive_failures: p.consecutive_failures,
                    capabilities: p.capabilities,
                    routing_policy: p.routing_policy,
                    sampled_at: None,
                    probe_duration_ms: None,
                    probe_timed_out: false,
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
        Syscall::MemoryUpdate {
            agent_id,
            fact_id,
            content,
        } => {
            let agent_id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            let fact_id = match uuid::Uuid::parse_str(&fact_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid fact id: {fact_id}"),
                    }
                }
            };
            match kernel
                .context_manager
                .update_fact(agent_id, fact_id, &content)
            {
                Ok(updated) => SyscallReply::MemoryUpdated { updated },
                Err(e) => SyscallReply::Error {
                    message: format!("memory update failed: {e}"),
                },
            }
        }
        Syscall::MemoryDelete { agent_id, fact_id } => {
            let agent_id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            let fact_id = match uuid::Uuid::parse_str(&fact_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid fact id: {fact_id}"),
                    }
                }
            };
            match kernel.context_manager.delete_fact(agent_id, fact_id) {
                Ok(deleted) => SyscallReply::MemoryDeleted { deleted },
                Err(e) => SyscallReply::Error {
                    message: format!("memory delete failed: {e}"),
                },
            }
        }
        Syscall::MemoryReindex { agent_id } => {
            let agent_id = match uuid::Uuid::parse_str(&agent_id) {
                Ok(id) => id,
                Err(_) => {
                    return SyscallReply::Error {
                        message: format!("invalid agent id: {agent_id}"),
                    }
                }
            };
            match kernel.context_manager.reindex_memory(agent_id) {
                Ok(count) => SyscallReply::MemoryReindexed { count },
                Err(e) => SyscallReply::Error {
                    message: format!("memory reindex failed: {e}"),
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
            match kernel.context_pressure_stats(id) {
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
            features: crate::wire_contract::WIRE_FEATURES
                .iter()
                .map(|feature| (*feature).to_string())
                .collect(),
        },
        Syscall::DescribeProtocol => SyscallReply::ProtocolDescription {
            description: crate::wire_contract::protocol_description(),
        },
        Syscall::Ping => SyscallReply::Pong,
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
        Syscall::TrustPackageKey {
            publisher,
            key_id,
            public_key_hex,
            valid_from,
            valid_until,
            supersedes,
        } => {
            let public_key = match crate::package::archive_from_hex(&public_key_hex) {
                Ok(public_key) => public_key,
                Err(error) => {
                    return SyscallReply::Error {
                        message: error.to_string(),
                    }
                }
            };
            let valid_from = match chrono::DateTime::parse_from_rfc3339(&valid_from) {
                Ok(value) => value.with_timezone(&chrono::Utc),
                Err(_) => {
                    return SyscallReply::Error {
                        message: "invalid package key valid_from timestamp".into(),
                    }
                }
            };
            let valid_until = match valid_until {
                Some(value) => match chrono::DateTime::parse_from_rfc3339(&value) {
                    Ok(value) => Some(value.with_timezone(&chrono::Utc)),
                    Err(_) => {
                        return SyscallReply::Error {
                            message: "invalid package key valid_until timestamp".into(),
                        }
                    }
                },
                None => None,
            };
            match kernel.package_registry.trust_key(
                package_scope,
                package_actor,
                &crate::package::PackageTrustInput {
                    publisher,
                    key_id,
                    public_key,
                    valid_from,
                    valid_until,
                    supersedes,
                },
            ) {
                Ok(()) => SyscallReply::PackageKeyUpdated,
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::RevokePackageKey { key_id } => {
            match kernel
                .package_registry
                .revoke_key(package_scope, package_actor, &key_id)
            {
                Ok(()) => SyscallReply::PackageKeyUpdated,
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::PublishPackage { archive_hex } => {
            let archive = match crate::package::archive_from_hex(&archive_hex) {
                Ok(archive) => archive,
                Err(error) => {
                    return SyscallReply::Error {
                        message: error.to_string(),
                    }
                }
            };
            match kernel
                .package_registry
                .publish(package_scope, package_actor, &archive)
            {
                Ok(package) => SyscallReply::PackagePublished { package },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::YankPackage { name, version } => {
            let version = match semver::Version::parse(&version) {
                Ok(version) => version,
                Err(error) => {
                    return SyscallReply::Error {
                        message: format!("invalid package version: {error}"),
                    }
                }
            };
            match kernel
                .package_registry
                .yank(package_scope, package_actor, &name, &version)
            {
                Ok(()) => SyscallReply::PackageMutationComplete,
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::FetchPackage { name, version } => {
            let version = match semver::Version::parse(&version) {
                Ok(version) => version,
                Err(error) => {
                    return SyscallReply::Error {
                        message: format!("invalid package version: {error}"),
                    }
                }
            };
            match kernel
                .package_registry
                .fetch(package_scope, package_actor, &name, &version)
            {
                Ok(archive) => SyscallReply::PackageArchive {
                    archive_hex: crate::package::archive_to_hex(&archive),
                },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::SearchPackages { query } => {
            match kernel
                .package_registry
                .search(package_scope, package_actor, &query)
            {
                Ok(packages) => SyscallReply::Packages { packages },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::InstallPackage { name, requirement } => {
            let requirement = match semver::VersionReq::parse(&requirement) {
                Ok(requirement) => requirement,
                Err(error) => {
                    return SyscallReply::Error {
                        message: format!("invalid package requirement: {error}"),
                    }
                }
            };
            let policy = if tenant.is_some() {
                crate::package::InstallPolicy::tenant_default()
            } else {
                crate::package::InstallPolicy::system_default()
            };
            match kernel.package_registry.install(
                package_scope,
                package_actor,
                &name,
                &requirement,
                &policy,
            ) {
                Ok(package) => SyscallReply::PackageInstalled { package },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::RollbackPackage { name } => {
            match kernel
                .package_registry
                .rollback(package_scope, package_actor, &name)
            {
                Ok(package) => SyscallReply::PackageInstalled { package },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::RemovePackage { name } => {
            match kernel
                .package_registry
                .remove(package_scope, package_actor, &name)
            {
                Ok(()) => SyscallReply::PackageMutationComplete,
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::ListInstalledPackages => {
            match kernel.package_registry.list_installed(package_scope) {
                Ok(packages) => SyscallReply::InstalledPackages { packages },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::RunInstalledPackage { name } => {
            let manifest = match kernel
                .package_registry
                .installed_agent_manifest(package_scope, &name)
            {
                Ok(manifest) => manifest,
                Err(error) => {
                    return SyscallReply::Error {
                        message: error.to_string(),
                    }
                }
            };
            match crate::agent_package::load_package_for_tenant(kernel, package_scope, &manifest)
                .await
            {
                Ok(handle) => SyscallReply::AgentCreated {
                    id: handle.id.to_string(),
                },
                Err(error) => SyscallReply::Error {
                    message: format!("run installed package failed: {error}"),
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
            let state_guard = kernel.operator_control.snapshot_guard().await;
            let allowed_ids: Option<std::collections::HashSet<uuid::Uuid>> = match tenant {
                Some(tenant) => match kernel.context_manager.list_agents_for_tenant(tenant) {
                    Ok(ids) => Some(ids.into_iter().collect()),
                    Err(error) => {
                        return SyscallReply::Error {
                            message: format!("operator snapshot tenant lookup failed: {error}"),
                        };
                    }
                },
                None => None,
            };
            let mut visible_agents = kernel
                .agent_manager
                .list_agents(None)
                .into_iter()
                .filter(|agent| {
                    allowed_ids
                        .as_ref()
                        .is_none_or(|allowed| allowed.contains(&agent.id))
                })
                .collect::<Vec<_>>();
            visible_agents.sort_by_key(|agent| agent.id);
            let total_visible_agents = visible_agents.len();
            let scoped_ids = visible_agents
                .iter()
                .map(|agent| agent.id)
                .collect::<Vec<_>>();
            let scoped_gate_decisions = if tenant.is_some() {
                kernel
                    .syscall_gate
                    .aggregate_agent_stats(scoped_ids.iter().copied())
            } else {
                kernel.syscall_gate.stats()
            };
            let snapshot_limit = kernel.operator_control.snapshot_max_agents();
            let agents_truncated = visible_agents.len() > snapshot_limit;
            visible_agents.truncate(snapshot_limit);

            let mut agents = Vec::with_capacity(visible_agents.len());
            for agent in visible_agents {
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
                let context_pressure =
                    kernel.context_pressure_stats(agent.id).unwrap_or_else(|_| {
                        ContextPressureStats {
                            agent_id: agent.id,
                            tenant_id: String::new(),
                            active_tokens: 0,
                            budget_tokens: 0,
                            agent_active_tokens: 0,
                            agent_active_limit: 0,
                            tenant_active_tokens: 0,
                            tenant_active_limit: 0,
                            global_active_tokens: 0,
                            global_active_limit: 0,
                            active_rejection_count: 0,
                            spill_count: 0,
                            evicted_messages: 0,
                            stored_spills: 0,
                            stored_spill_bytes: 0,
                            agent_stored_bytes: 0,
                            agent_storage_limit: 0,
                            tenant_stored_bytes: 0,
                            tenant_storage_limit: 0,
                            global_stored_bytes: 0,
                            global_storage_limit: 0,
                            spill_retention_seconds: 0,
                            error_count: 0,
                            last_error: Some("pressure statistics unavailable".into()),
                            updated_at: chrono::Utc::now(),
                        }
                    });
                let namespace_details = gate
                    .as_ref()
                    .map(|info| {
                        info.namespaces
                            .iter()
                            .filter_map(|namespace_id| {
                                kernel.os.namespaces.get(*namespace_id).map(|namespace| {
                                    OperatorNamespaceSnapshot {
                                        id: namespace.id,
                                        kind: format!("{:?}", namespace.ns_type)
                                            .to_ascii_lowercase(),
                                        parent: namespace.parent,
                                    }
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let cgroup = gate
                    .as_ref()
                    .and_then(|info| kernel.cgroups.get(info.cgroup))
                    .map(|group| OperatorCgroupSnapshot {
                        id: group.id,
                        scope: group.quota_scope,
                        tokens_per_minute_limit: group.limits.tokens_per_min,
                        concurrent_tool_limit: group.limits.max_concurrent_tool_calls,
                        context_token_limit: group.limits.max_context_tokens,
                        agent_limit: group.limits.max_agents,
                        active_tool_calls: group.usage.active_tool_calls,
                        context_tokens: group.usage.context_tokens,
                        agent_count: group.usage.agent_count,
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
                    namespace_details,
                    cgroup,
                    gate_decisions: kernel.syscall_gate.agent_stats(agent.id),
                    checkpoint_count,
                    context_pressure,
                    latest_usage: kernel.context_manager.latest_usage(agent.id),
                });
            }
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
                        desired_running: service.desired_running,
                        ready: service.ready,
                        healthy: service.healthy,
                        restart_exhausted: service.restart_exhausted,
                        last_failure: service.last_failure,
                        next_restart_at: service.next_restart_at,
                        last_transition_at: service.last_transition_at,
                    })
                    .collect::<Vec<_>>();
                services.sort_by(|a, b| a.name.cmp(&b.name));
                Some(services)
            } else {
                None
            };
            let package_instances =
                match kernel.context_manager.list_loaded_package_instances(tenant) {
                    Ok(packages) => packages,
                    Err(error) => {
                        return SyscallReply::Error {
                            message: format!("operator package view failed: {error}"),
                        };
                    }
                };
            let packages = package_instances
                .into_iter()
                .map(|package| OperatorPackageSnapshot {
                    agent_state: uuid::Uuid::parse_str(&package.agent_id)
                        .ok()
                        .and_then(|agent_id| kernel.agent_manager.get_agent_state(agent_id))
                        .map(|state| format!("{state:?}"))
                        .unwrap_or_else(|| "Unknown".into()),
                    agent_id: package.agent_id,
                    tenant_id: package.tenant_id,
                    name: package.name,
                    provider: package.provider,
                    profile: package.profile,
                    loaded_at: package.loaded_at,
                })
                .collect();
            let tunables = if trusted_system {
                match kernel.operator_control.list() {
                    Ok(tunables) => Some(tunables),
                    Err(error) => {
                        return SyscallReply::Error {
                            message: format!("operator tunable view failed: {error}"),
                        };
                    }
                }
            } else {
                None
            };
            let system_metrics =
                trusted_system.then(|| crate::metrics::MetricsSnapshot::collect(kernel));
            let global_spend_usd = trusted_system.then(|| kernel.budget_enforcer.current_spend());
            drop(state_guard);

            let probe_started = std::time::Instant::now();
            let sampled_at = chrono::Utc::now().to_rfc3339();
            let provider_probe = tokio::time::timeout(
                kernel.operator_control.provider_probe_timeout(),
                kernel.connector.probe_providers(),
            )
            .await;
            let probe_duration_ms =
                u64::try_from(probe_started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let providers = match provider_probe {
                Ok(providers) => providers
                    .into_iter()
                    .map(|provider| ProviderSummary {
                        id: provider.id,
                        name: provider.name,
                        provider_type: format!("{:?}", provider.provider_type),
                        available: provider.available,
                        circuit_open: provider.circuit_open,
                        consecutive_failures: provider.consecutive_failures,
                        capabilities: provider.capabilities,
                        routing_policy: provider.routing_policy,
                        sampled_at: Some(sampled_at.clone()),
                        probe_duration_ms: Some(probe_duration_ms),
                        probe_timed_out: false,
                    })
                    .collect(),
                Err(_) => kernel
                    .connector
                    .list_providers()
                    .into_iter()
                    .map(|provider| ProviderSummary {
                        id: provider.id,
                        name: provider.name,
                        provider_type: format!("{:?}", provider.provider_type),
                        available: false,
                        circuit_open: provider.circuit_open,
                        consecutive_failures: provider.consecutive_failures,
                        capabilities: provider.capabilities,
                        routing_policy: provider.routing_policy,
                        sampled_at: Some(sampled_at.clone()),
                        probe_duration_ms: Some(probe_duration_ms),
                        probe_timed_out: true,
                    })
                    .collect(),
            };
            SyscallReply::OperatorSnapshot {
                snapshot: Box::new(OperatorSnapshot {
                    captured_at: chrono::Utc::now().to_rfc3339(),
                    consistency:
                        "structural agent/lifecycle/tunable state is barrier-consistent; counters and provider health are sampled and may advance independently"
                            .into(),
                    scope: tenant
                        .map(|tenant| format!("tenant:{tenant}"))
                        .unwrap_or_else(|| "system".into()),
                    kernel_version: env!("CARGO_PKG_VERSION").into(),
                    protocol_version: PROTOCOL_VERSION,
                    agents,
                    total_visible_agents,
                    agents_truncated,
                    providers,
                    packages,
                    scoped_gate_decisions,
                    tunables,
                    services,
                    system_metrics,
                    global_spend_usd,
                }),
            }
        }
        Syscall::ListOperatorTunables => match kernel.operator_control.list() {
            Ok(tunables) => SyscallReply::OperatorTunables { tunables },
            Err(error) => SyscallReply::Error {
                message: error.to_string(),
            },
        },
        Syscall::SetOperatorTunable {
            name,
            value,
            expected_revision,
        } => {
            let actor = principal
                .map(|principal| {
                    format!(
                        "tenant:{} user:{} role:{}",
                        principal.tenant_id,
                        principal.user_id,
                        principal.role.as_str()
                    )
                })
                .unwrap_or_else(|| "trusted-system".into());
            match kernel
                .operator_control
                .set(&name, value, expected_revision, &actor)
                .await
            {
                Ok(tunable) => SyscallReply::OperatorTunable { tunable },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::RollbackOperatorTunable {
            name,
            target_revision,
            expected_revision,
        } => {
            let actor = principal
                .map(|principal| {
                    format!(
                        "tenant:{} user:{} role:{}",
                        principal.tenant_id,
                        principal.user_id,
                        principal.role.as_str()
                    )
                })
                .unwrap_or_else(|| "trusted-system".into());
            match kernel
                .operator_control
                .rollback(&name, target_revision, expected_revision, &actor)
                .await
            {
                Ok(tunable) => SyscallReply::OperatorTunable { tunable },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
        Syscall::ListOperatorTunableAudit { name, limit } => {
            match kernel.operator_control.audit(name.as_deref(), limit) {
                Ok(entries) => SyscallReply::OperatorTunableAudit { entries },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
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
        Syscall::ReloadServices => match kernel.reload_configured_services().await {
            Ok(boot_order) => SyscallReply::ServiceConfigurationReloaded { boot_order },
            Err(error) => SyscallReply::Error {
                message: error.to_string(),
            },
        },
        Syscall::ListServiceHistory { name, limit } => {
            match kernel.list_service_history(name.as_deref(), limit) {
                Ok(entries) => SyscallReply::ServiceHistory { entries },
                Err(error) => SyscallReply::Error {
                    message: error.to_string(),
                },
            }
        }
    }
}

fn public_stream_event(event: crate::execution::StreamEvent) -> Option<MessageStreamEvent> {
    match event {
        crate::execution::StreamEvent::Started { .. } => Some(MessageStreamEvent::Started),
        crate::execution::StreamEvent::Token(delta) => Some(MessageStreamEvent::Token { delta }),
        crate::execution::StreamEvent::ToolCallStarted { name, .. } => {
            Some(MessageStreamEvent::ToolCallStarted { name })
        }
        crate::execution::StreamEvent::ToolCallResult { name, .. } => {
            Some(MessageStreamEvent::ToolCallCompleted { name })
        }
        crate::execution::StreamEvent::ContextPressure {
            active_tokens,
            budget_tokens,
            evicted_messages,
            spill_key,
        } => Some(MessageStreamEvent::ContextPressure {
            active_tokens,
            budget_tokens,
            evicted_messages,
            spill_key,
        }),
        crate::execution::StreamEvent::Done(_)
        | crate::execution::StreamEvent::Cancelled { .. }
        | crate::execution::StreamEvent::Paused { .. }
        | crate::execution::StreamEvent::Error(_) => None,
    }
}

async fn write_public_stream_event<W>(
    write: &mut W,
    request_id: &str,
    sequence: &mut u64,
    event: crate::execution::StreamEvent,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(event) = public_stream_event(event) else {
        return Ok(());
    };
    let reply = SyscallReply::StreamEvent {
        request_id: request_id.to_string(),
        sequence: *sequence,
        event,
    };
    *sequence = sequence.saturating_add(1);
    write_bounded_json(write, &reply, MAX_WIRE_FRAME_BYTES).await
}

/// Authorize and drive one live stream on the current connection. The
/// credential lease acquired by the caller remains held until this returns.
async fn dispatch_message_stream<W>(
    kernel: &AgentKernelImpl,
    request_id: String,
    agent_id: String,
    message: String,
    principal: Option<&Principal>,
    write: &mut W,
    negotiated_version: u32,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if negotiated_version < 2 {
        let reply = SyscallReply::Error {
            message: "incompatible wire-protocol version: message streaming requires v2".into(),
        }
        .into_public_wire(negotiated_version);
        return write_bounded_json(write, &reply, MAX_WIRE_FRAME_BYTES).await;
    }
    let call = Syscall::SendMessageStream {
        request_id: request_id.clone(),
        agent_id: agent_id.clone(),
        message: message.clone(),
    };
    if let Err(reply) = authorize(kernel, principal, &call).await {
        return write_bounded_json(
            write,
            &reply.into_public_wire(negotiated_version),
            MAX_WIRE_FRAME_BYTES,
        )
        .await;
    }
    let parsed_agent = match uuid::Uuid::parse_str(&agent_id) {
        Ok(agent) => agent,
        Err(_) => {
            let reply = SyscallReply::Error {
                message: format!("invalid agent id: {agent_id}"),
            }
            .into_public_wire(negotiated_version);
            return write_bounded_json(write, &reply, MAX_WIRE_FRAME_BYTES).await;
        }
    };
    if request_id.is_empty() || request_id.len() > 128 {
        let reply = SyscallReply::Error {
            message: "invalid request id: expected 1..=128 bytes".into(),
        }
        .into_public_wire(negotiated_version);
        return write_bounded_json(write, &reply, MAX_WIRE_FRAME_BYTES).await;
    }

    // A bounded channel makes the socket writer the backpressure boundary:
    // provider/executor production cannot outrun a slow client without bound.
    let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(STREAM_EVENT_BUFFER_CAPACITY);
    let run = kernel.send_message_stream(parsed_agent, &message, &request_id, events_tx);
    tokio::pin!(run);
    let mut sequence = 0_u64;
    let mut events_open = true;

    enum StreamStep {
        Event(Option<crate::execution::StreamEvent>),
        Finished(Result<crate::execution::AgentOutput, crate::KernelError>),
    }

    loop {
        let step = tokio::time::timeout(WIRE_REQUEST_TIMEOUT, async {
            tokio::select! {
                biased;
                event = events_rx.recv(), if events_open => StreamStep::Event(event),
                result = &mut run => StreamStep::Finished(result),
            }
        })
        .await;

        let step = match step {
            Ok(step) => step,
            Err(_) => {
                kernel.cancel_request(parsed_agent, &request_id);
                // Cancellation-aware providers normally settle immediately.
                // Bound cleanup before the connection is released.
                let _ = tokio::time::timeout(WIRE_HANDSHAKE_TIMEOUT, &mut run).await;
                let reply = SyscallReply::StreamFailed {
                    request_id: request_id.clone(),
                    code: WireErrorCode::Timeout,
                    message: "stream request timed out".into(),
                    retryable: true,
                };
                return write_bounded_json(write, &reply, MAX_WIRE_FRAME_BYTES).await;
            }
        };

        match step {
            StreamStep::Event(Some(event)) => {
                if let Err(error) =
                    write_public_stream_event(write, &request_id, &mut sequence, event).await
                {
                    kernel.cancel_request(parsed_agent, &request_id);
                    return Err(error);
                }
            }
            StreamStep::Event(None) => events_open = false,
            StreamStep::Finished(result) => {
                // A fast provider can finish in the same scheduler poll that
                // enqueues its events. Drain every already-buffered event
                // before the terminal frame to preserve the sequence contract.
                while let Ok(event) = events_rx.try_recv() {
                    if let Err(error) =
                        write_public_stream_event(write, &request_id, &mut sequence, event).await
                    {
                        kernel.cancel_request(parsed_agent, &request_id);
                        return Err(error);
                    }
                }
                let reply = match result {
                    Ok(output) => SyscallReply::StreamCompleted {
                        request_id: request_id.clone(),
                        content: output.content,
                        tool_calls: output.tool_calls_made,
                        tokens: output.tokens_used,
                    },
                    Err(error) => {
                        let message = error.to_string();
                        let (code, retryable) = WireErrorCode::classify(&message);
                        SyscallReply::StreamFailed {
                            request_id: request_id.clone(),
                            code,
                            message,
                            retryable,
                        }
                    }
                };
                return write_bounded_json(write, &reply, MAX_WIRE_FRAME_BYTES).await;
            }
        }
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
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

    // Ensure a process-wide crypto provider is installed (idempotent — a second
    // install returns an error we ignore). Lets callers build a config without
    // naming the rustls crypto provider themselves.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no certificates found in cert_pem",
        ));
    }
    let key = PrivateKeyDer::pem_slice_iter(key_pem)
        .next()
        .transpose()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no private key found in key_pem",
            )
        })?;
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
    connection_limit: Arc<Semaphore>,
    idle_timeout: std::time::Duration,
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
            connection_limit: Arc::new(Semaphore::new(DEFAULT_WIRE_MAX_CONNECTIONS)),
            idle_timeout: WIRE_IDLE_TIMEOUT,
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
            connection_limit: Arc::new(Semaphore::new(DEFAULT_WIRE_MAX_CONNECTIONS)),
            idle_timeout: WIRE_IDLE_TIMEOUT,
        })
    }

    /// Bind a TLS listener to `addr`, terminating rustls on every accepted TCP
    /// connection before handing the encrypted stream to the same generic
    /// request loop used by the plaintext transports.
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
            connection_limit: Arc::new(Semaphore::new(DEFAULT_WIRE_MAX_CONNECTIONS)),
            idle_timeout: WIRE_IDLE_TIMEOUT,
        })
    }

    /// Require connections to authenticate with `token` before any other
    /// syscall. Recommended for any non-loopback TCP bind.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(Arc::new(token.into()));
        self
    }

    /// Override the number of simultaneously admitted client connections.
    ///
    /// Excess accepted sockets are closed immediately instead of allocating an
    /// unbounded task per peer. A zero value is rejected by clamping it to one.
    pub fn with_connection_limit(mut self, max_connections: usize) -> Self {
        self.connection_limit = Arc::new(Semaphore::new(max_connections.max(1)));
        self
    }

    /// Override the established connection idle deadline.
    ///
    /// The public contract reports the 300-second default. Deployments may
    /// tighten it; zero is clamped to one millisecond.
    pub fn with_idle_timeout(mut self, idle_timeout: std::time::Duration) -> Self {
        self.idle_timeout = idle_timeout.max(std::time::Duration::from_millis(1));
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
        let connection_limit = self.connection_limit.clone();
        let idle_timeout = self.idle_timeout;
        match self.listener {
            Listener::Tcp(listener) => loop {
                let (stream, _peer) = listener.accept().await?;
                let Ok(connection_permit) = connection_limit.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let kernel = self.kernel.clone();
                let auth = self.auth_token.clone();
                tokio::spawn(async move {
                    let _connection_permit = connection_permit;
                    let (read, write) = stream.into_split();
                    let _ = Self::handle(kernel, read, write, auth, idle_timeout).await;
                });
            },
            Listener::Tls(listener, acceptor) => loop {
                let (stream, _peer) = listener.accept().await?;
                let Ok(connection_permit) = connection_limit.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let kernel = self.kernel.clone();
                let auth = self.auth_token.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _connection_permit = connection_permit;
                    // Perform the rustls handshake; a failed handshake drops the
                    // connection without affecting the accept loop.
                    let tls =
                        match tokio::time::timeout(WIRE_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                            .await
                        {
                            Ok(Ok(tls)) => tls,
                            Ok(Err(_)) | Err(_) => return,
                        };
                    // The TLS stream is one AsyncRead+AsyncWrite object; split it
                    // into halves so it drops into the existing generic handler.
                    let (read, write) = tokio::io::split(tls);
                    let _ = Self::handle(kernel, read, write, auth, idle_timeout).await;
                });
            },
            #[cfg(unix)]
            Listener::Unix(listener) => loop {
                let (stream, _peer) = listener.accept().await?;
                let Ok(connection_permit) = connection_limit.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let kernel = self.kernel.clone();
                let auth = self.auth_token.clone();
                tokio::spawn(async move {
                    let _connection_permit = connection_permit;
                    let (read, write) = stream.into_split();
                    let _ = Self::handle(kernel, read, write, auth, idle_timeout).await;
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
        idle_timeout: std::time::Duration,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(read);
        // No shared-secret token configured ⇒ authenticated from the start.
        let mut authed = auth.is_none();
        // A client that skips Hello receives the released v1 response shape.
        // Negotiation upgrades only this connection, preserving old clients.
        let mut negotiated_version = MIN_PROTOCOL_VERSION;
        // Connections retain only the credential's SHA-256 identity. The
        // plaintext presented to Authenticate is dropped with that request.
        let mut credential: Option<crate::auth::CredentialIdentity> = None;
        let mut first_frame = true;
        loop {
            let timeout = if first_frame {
                WIRE_HANDSHAKE_TIMEOUT
            } else {
                idle_timeout
            };
            let line = match tokio::time::timeout(
                timeout,
                read_bounded_line(&mut reader, MAX_WIRE_FRAME_BYTES),
            )
            .await
            {
                Ok(Ok(Some(line))) => line,
                Ok(Ok(None)) | Err(_) => break,
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                    let reply = SyscallReply::Error {
                        message: format!("bad request: {error}"),
                    }
                    .into_public_wire(negotiated_version);
                    write_bounded_json(&mut write, &reply, MAX_WIRE_FRAME_BYTES).await?;
                    break;
                }
                Ok(Err(error)) => return Err(error),
            };
            first_frame = false;
            if line.trim().is_empty() {
                continue;
            }
            let parsed = serde_json::from_str::<Syscall>(&line);

            // A streaming turn owns this connection until its terminal frame.
            // Cancellation is intentionally sent from another authenticated
            // connection so event ordering on this socket remains unambiguous.
            if authed
                && matches!(
                    &parsed,
                    Ok(Syscall::SendMessageStream {
                        request_id: _,
                        agent_id: _,
                        message: _
                    })
                )
            {
                let Ok(Syscall::SendMessageStream {
                    request_id,
                    agent_id,
                    message,
                }) = parsed
                else {
                    unreachable!("stream pattern checked above")
                };
                if let Some(identity) = credential.as_ref() {
                    match kernel.acquire_credential_principal(identity).await {
                        Some((resolved, _credential_lease)) => {
                            dispatch_message_stream(
                                &kernel,
                                request_id,
                                agent_id,
                                message,
                                Some(&resolved),
                                &mut write,
                                negotiated_version,
                            )
                            .await?;
                        }
                        None => {
                            authed = false;
                            credential = None;
                            let reply = SyscallReply::Error {
                                message: "authentication required".into(),
                            }
                            .into_public_wire(negotiated_version);
                            write_bounded_json(&mut write, &reply, MAX_WIRE_FRAME_BYTES).await?;
                        }
                    }
                } else {
                    dispatch_message_stream(
                        &kernel,
                        request_id,
                        agent_id,
                        message,
                        None,
                        &mut write,
                        negotiated_version,
                    )
                    .await?;
                }
                continue;
            }

            let reply = match parsed {
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
                            features: crate::wire_contract::WIRE_FEATURES
                                .iter()
                                .map(|feature| (*feature).to_string())
                                .collect(),
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
                Ok(Syscall::DescribeProtocol) => SyscallReply::ProtocolDescription {
                    description: crate::wire_contract::protocol_description(),
                },
                // Authentication accepts two credentials, tried in order:
                //   1. the server's shared secret (unchanged legacy path), and
                //   2. an AuthSystem API key / session token, which additionally
                //      binds this connection to the credential's tenant.
                Ok(Syscall::Authenticate { token }) => {
                    // Authentication is replacement, not an additive operation:
                    // any failed attempt leaves the connection unauthenticated.
                    authed = false;
                    credential = None;
                    // An AuthSystem credential always wins first so that the
                    // connection binds to its tenant — even on an open server.
                    if let Some(principal) = kernel.resolve_principal(&token).await {
                        authed = true;
                        credential = Some(
                            principal
                                .credential
                                .expect("wire-authenticated principals carry credential identity"),
                        );
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
                // Protocol-v2 liveness probe. It is deliberately safe before
                // authentication and has no effect beyond proving application
                // responsiveness and starting the next idle-deadline window.
                Ok(Syscall::Ping) if negotiated_version >= 2 => SyscallReply::Pong,
                Ok(Syscall::Ping) => SyscallReply::Error {
                    message: "incompatible wire-protocol version: v2 is required for ping".into(),
                },
                Ok(_) if !authed => SyscallReply::Error {
                    message: "authentication required".into(),
                },
                Ok(call)
                    if negotiated_version < 2
                        && matches!(
                            &call,
                            Syscall::SendMessageStream { .. } | Syscall::CancelRequest { .. }
                        ) =>
                {
                    SyscallReply::Error {
                        message:
                            "incompatible wire-protocol version: v2 is required for streaming and cancellation"
                                .into(),
                    }
                }
                Ok(call) => {
                    // Re-resolve tenant credentials for every request under a
                    // short auth read lock. A per-credential lease remains alive
                    // through dispatch, so same-credential revocation is
                    // linearizable without blocking unrelated auth writes.
                    if let Some(identity) = credential.as_ref() {
                        match kernel.acquire_credential_principal(identity).await {
                            Some((resolved, _credential_lease)) => {
                                match tokio::time::timeout(
                                    WIRE_REQUEST_TIMEOUT,
                                    dispatch_scoped(&kernel, call, Some(&resolved)),
                                )
                                .await
                                {
                                    Ok(reply) => reply,
                                    Err(_) => SyscallReply::Error {
                                        message: "syscall timed out".into(),
                                    },
                                }
                            }
                            None => {
                                authed = false;
                                credential = None;
                                SyscallReply::Error {
                                    message: "authentication required".into(),
                                }
                            }
                        }
                    } else {
                        match tokio::time::timeout(
                            WIRE_REQUEST_TIMEOUT,
                            dispatch_scoped(&kernel, call, None),
                        )
                        .await
                        {
                            Ok(reply) => reply,
                            Err(_) => SyscallReply::Error {
                                message: "syscall timed out".into(),
                            },
                        }
                    }
                }
                Err(e) => SyscallReply::Error {
                    message: format!("bad request: {e}"),
                },
            };
            let reply = reply.into_public_wire(negotiated_version);
            if let Err(error) = write_bounded_json(&mut write, &reply, MAX_WIRE_FRAME_BYTES).await {
                if error.kind() != std::io::ErrorKind::InvalidData {
                    return Err(error);
                }
                let fallback = SyscallReply::Error {
                    message: "response exceeds the wire frame limit".into(),
                }
                .into_public_wire(negotiated_version);
                write_bounded_json(&mut write, &fallback, MAX_WIRE_FRAME_BYTES).await?;
            }
        }
        write.shutdown().await
    }
}

/// A thin client for the syscall server (used by the Rust SDK and round-trip
/// tests). The wire format is plain JSON, so any client could speak it. The IO
/// halves are boxed so one client type works over both TCP and Unix sockets.
pub struct SyscallClient {
    reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
}

impl SyscallClient {
    /// Connect over TCP.
    pub async fn connect(addr: impl ToSocketAddrs) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(WIRE_HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "wire connect timed out")
            })??;
        let (read, writer) = stream.into_split();
        Ok(Self::from_halves(Box::new(read), Box::new(writer)))
    }

    /// Connect over a Unix-domain socket.
    #[cfg(unix)]
    pub async fn connect_unix(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(
            WIRE_HANDSHAKE_TIMEOUT,
            tokio::net::UnixStream::connect(path),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "wire connect timed out")
        })??;
        let (read, writer) = stream.into_split();
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
        let tcp = tokio::time::timeout(WIRE_HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "wire connect timed out")
            })??;
        let tls = tokio::time::timeout(WIRE_HANDSHAKE_TIMEOUT, connector.connect(dns, tcp))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
            })??;
        let (read, write) = tokio::io::split(tls);
        Ok(Self::from_halves(Box::new(read), Box::new(write)))
    }

    fn from_halves(
        read: Box<dyn AsyncRead + Unpin + Send>,
        writer: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> Self {
        Self {
            reader: BufReader::new(read),
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

    /// Send the protocol-v2 application-level keepalive probe.
    pub async fn ping(&mut self) -> std::io::Result<SyscallReply> {
        self.call(Syscall::Ping).await
    }

    /// Send one syscall frame without reading a reply. Streaming clients use
    /// this once and then call [`read_reply`](Self::read_reply) until a terminal
    /// stream frame arrives.
    pub async fn send(&mut self, call: &Syscall) -> std::io::Result<()> {
        write_bounded_json(&mut self.writer, &call, MAX_WIRE_FRAME_BYTES).await?;
        Ok(())
    }

    /// Read one bounded reply frame. The timeout is per frame, so a live stream
    /// can outlast one ordinary request while still bounding silent peers.
    pub async fn read_reply(&mut self) -> std::io::Result<SyscallReply> {
        let line = match tokio::time::timeout(
            WIRE_REQUEST_TIMEOUT,
            read_bounded_line(&mut self.reader, MAX_WIRE_FRAME_BYTES),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                let _ = self.writer.shutdown().await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "wire request timed out; connection closed",
                ));
            }
        }
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "server closed"))?;
        serde_json::from_str(&line).map_err(std::io::Error::other)
    }

    /// Send one syscall and await its reply.
    pub async fn call(&mut self, call: Syscall) -> std::io::Result<SyscallReply> {
        self.send(&call).await?;
        self.read_reply().await
    }

    /// Gracefully close an idle connection by half-closing client output and
    /// requiring the server to answer with EOF within the public close bound.
    ///
    /// Every ordinary reply or terminal stream frame must be consumed first.
    pub async fn close(mut self) -> std::io::Result<()> {
        graceful_close_framed(
            &mut self.reader,
            &mut self.writer,
            MAX_WIRE_FRAME_BYTES,
            WIRE_GRACEFUL_CLOSE_TIMEOUT,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SlowHealthProvider {
        id: crate::ProviderId,
    }

    #[async_trait::async_trait]
    impl crate::connector::LlmProviderAdapter for SlowHealthProvider {
        fn id(&self) -> &crate::ProviderId {
            &self.id
        }

        fn name(&self) -> &str {
            "slow-health"
        }

        fn provider_type(&self) -> crate::connector::ProviderType {
            crate::connector::ProviderType::Cloud
        }

        async fn is_available(&self) -> bool {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            true
        }

        async fn create_session(
            &self,
        ) -> Result<Box<dyn crate::connector::LlmSession>, crate::ConnectorError> {
            Err(crate::ConnectorError::ProviderUnavailable(self.id.clone()))
        }

        fn translate_to_provider(
            &self,
            message: &crate::connector::StandardMessage,
        ) -> serde_json::Value {
            serde_json::json!({"role": message.role, "content": message.content})
        }

        fn translate_from_provider(
            &self,
            value: &serde_json::Value,
        ) -> Option<crate::connector::StandardMessage> {
            Some(crate::connector::StandardMessage::user(
                value.get("content")?.as_str()?.to_string(),
            ))
        }
    }

    #[test]
    fn wire_wait_agent_timeout_is_bounded() {
        assert_eq!(
            wire_wait_agent_timeout(u64::MAX),
            std::time::Duration::from_millis(MAX_WIRE_WAIT_AGENT_TIMEOUT_MS)
        );
        assert_eq!(
            wire_wait_agent_timeout(17),
            std::time::Duration::from_millis(17)
        );
    }

    #[test]
    fn unavailable_quota_storage_is_not_misclassified_as_quota_exhaustion() {
        assert_eq!(
            WireErrorCode::classify(
                "durable provider rate-limit accounting is unavailable: database is locked"
            ),
            (WireErrorCode::Unavailable, true)
        );
        assert_eq!(
            WireErrorCode::classify("cgroup enforcement unavailable: missing parent"),
            (WireErrorCode::Unavailable, true)
        );
        assert_eq!(
            WireErrorCode::classify("cgroup token quota exceeded"),
            (WireErrorCode::QuotaExceeded, true)
        );
    }

    #[tokio::test]
    async fn raw_syscall_hides_foreign_tool_like_a_missing_tool() {
        let kernel = AgentKernelImpl::new().expect("kernel new");
        let config = |name: &str| AgentConfig {
            name: name.into(),
            task: "tool visibility probe".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        };
        let _owner = kernel
            .create_agent_in_namespace(config("owner"), "private-tools")
            .await
            .unwrap();
        let caller = kernel
            .create_agent_in_namespace(config("caller"), "other-tools")
            .await
            .unwrap();
        kernel
            .register_group_tool(
                "private-tools",
                crate::tools::ToolBinding {
                    name: "private_notes".into(),
                    description: "Read private notes".into(),
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
                },
            )
            .unwrap();

        let foreign = dispatch(
            &kernel,
            Syscall::CallTool {
                agent_id: caller.id.to_string(),
                tool: "private_notes".into(),
                args: serde_json::json!({"path": "/tmp/private"}),
            },
        )
        .await
        .into_public_wire(PROTOCOL_VERSION);
        let missing = dispatch(
            &kernel,
            Syscall::CallTool {
                agent_id: caller.id.to_string(),
                tool: "definitely_missing_tool".into(),
                args: serde_json::json!({}),
            },
        )
        .await
        .into_public_wire(PROTOCOL_VERSION);

        match (foreign, missing) {
            (
                SyscallReply::TypedError {
                    code: foreign_code,
                    message: foreign_message,
                    ..
                },
                SyscallReply::TypedError {
                    code: missing_code,
                    message: missing_message,
                    ..
                },
            ) => {
                assert_eq!(foreign_code, missing_code);
                assert_eq!(foreign_code, WireErrorCode::NotFound);
                assert_eq!(foreign_message, missing_message);
                assert!(
                    !foreign_message.contains("private_notes")
                        && !foreign_message.contains("definitely_missing_tool")
                        && !foreign_message.contains("ns="),
                    "syscall error reflected foreign catalog data: {foreign_message}"
                );
            }
            replies => panic!("expected matching typed tool errors, got {replies:?}"),
        }
    }

    #[test]
    fn every_rate_limit_error_has_a_stable_public_wire_classification() {
        use crate::rate_limit::RateLimitError;

        let cases = [
            (
                RateLimitError::RequestExceedsTpm {
                    requested: 101,
                    limit: 100,
                },
                (WireErrorCode::QuotaExceeded, false),
            ),
            (
                RateLimitError::RequestExceedsCgroupTpm {
                    scope_id: "/tenant/t/profile/p/agent/a".into(),
                    requested: 101,
                    limit: 100,
                },
                (WireErrorCode::QuotaExceeded, false),
            ),
            (
                RateLimitError::QuotaExhausted {
                    scope_kind: "cgroup".into(),
                    scope_id: "/tenant/t/profile/p/agent/a".into(),
                    dimension: "tokens".into(),
                    used: 100,
                    requested: 1,
                    limit: 100,
                    retry_at_unix_ms: 60_000,
                },
                (WireErrorCode::QuotaExceeded, true),
            ),
            (RateLimitError::Cancelled, (WireErrorCode::Cancelled, false)),
            (
                RateLimitError::CgroupMembershipChanged,
                (WireErrorCode::Conflict, true),
            ),
            (
                RateLimitError::ConcurrencyClosed,
                (WireErrorCode::Unavailable, true),
            ),
            (
                RateLimitError::StorageUnavailable("database is locked".into()),
                (WireErrorCode::Unavailable, true),
            ),
            (RateLimitError::NotInvoked, (WireErrorCode::Internal, false)),
            (
                RateLimitError::AlreadyInvoked,
                (WireErrorCode::Internal, false),
            ),
        ];

        for (error, expected) in cases {
            let message = crate::KernelError::RateLimit(error.clone()).to_string();
            assert_eq!(
                WireErrorCode::classify(&message),
                expected,
                "{error:?} produced {message:?}"
            );
        }
    }

    #[test]
    fn partial_provider_stream_is_terminal_on_the_public_wire() {
        let message = crate::KernelError::Connector(crate::ConnectorError::PartialStream(
            "provider failed after publishing output".into(),
        ))
        .to_string();
        assert_eq!(
            WireErrorCode::classify(&message),
            (WireErrorCode::Provider, false)
        );
    }

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
        for call in [
            Syscall::SendMessageStream {
                request_id: "v1-stream".into(),
                agent_id: "not-a-uuid".into(),
                message: "must not start".into(),
            },
            Syscall::CancelRequest {
                request_id: "v1-stream".into(),
                agent_id: "not-a-uuid".into(),
            },
            Syscall::Ping,
        ] {
            match v1.call(call).await.unwrap() {
                SyscallReply::Error { message } => {
                    assert!(
                        message.contains("incompatible wire-protocol") && message.contains("v2"),
                        "{message}"
                    );
                }
                other => panic!("expected v1 feature-version error, got {other:?}"),
            }
        }

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

        // Store a fact, mutate it, rebuild its embedding, query it, then delete
        // it through the public wire surface.
        let fact_id = match client
            .call(Syscall::MemoryStore {
                agent_id: id.clone(),
                content: "the deploy key lives in vault".into(),
                category: Some("instruction".into()),
            })
            .await
            .unwrap()
        {
            SyscallReply::MemoryStored { id } => id,
            other => panic!("expected MemoryStored, got {other:?}"),
        };
        assert!(!fact_id.is_empty());

        assert!(matches!(
            client
                .call(Syscall::MemoryUpdate {
                    agent_id: id.clone(),
                    fact_id: fact_id.clone(),
                    content: "the production deploy key lives in vault".into(),
                })
                .await
                .unwrap(),
            SyscallReply::MemoryUpdated { updated: true }
        ));
        assert!(matches!(
            client
                .call(Syscall::MemoryReindex {
                    agent_id: id.clone(),
                })
                .await
                .unwrap(),
            SyscallReply::MemoryReindexed { count: 1 }
        ));

        match client
            .call(Syscall::MemoryQuery {
                agent_id: id.clone(),
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

        assert!(matches!(
            client
                .call(Syscall::MemoryDelete {
                    agent_id: id.clone(),
                    fact_id,
                })
                .await
                .unwrap(),
            SyscallReply::MemoryDeleted { deleted: true }
        ));
        match client
            .call(Syscall::MemoryQuery {
                agent_id: id,
                query: "deploy key".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::Memory { facts } => assert!(facts.is_empty()),
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
                features,
            } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
                assert_eq!(min_protocol_version, MIN_PROTOCOL_VERSION);
                assert_eq!(server_version, env!("CARGO_PKG_VERSION"));
                assert!(features.contains(&"typed_errors".to_string()));
            }
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ping_resets_idle_deadline_without_granting_auth_and_close_confirms_eof() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .unwrap()
            .with_auth_token("secret")
            .with_idle_timeout(std::time::Duration::from_millis(500));
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        assert!(matches!(
            client
                .call(Syscall::Hello {
                    protocol_version: PROTOCOL_VERSION,
                })
                .await
                .unwrap(),
            SyscallReply::Hello { .. }
        ));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(matches!(client.ping().await.unwrap(), SyscallReply::Pong));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(matches!(client.ping().await.unwrap(), SyscallReply::Pong));

        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::TypedError { message, .. } => {
                assert_eq!(message, "authentication required");
            }
            other => panic!("ping must not authenticate the connection: {other:?}"),
        }
        assert!(matches!(
            client.authenticate("secret").await.unwrap(),
            SyscallReply::Authenticated
        ));
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn idle_deadline_closes_quiet_connection_without_stopping_listener() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .unwrap()
            .with_idle_timeout(std::time::Duration::from_millis(75));
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut stale = SyscallClient::connect(addr).await.unwrap();
        assert!(matches!(
            stale
                .call(Syscall::Hello {
                    protocol_version: PROTOCOL_VERSION,
                })
                .await
                .unwrap(),
            SyscallReply::Hello { .. }
        ));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        stale.ping().await.expect_err("idle connection must close");

        let mut fresh = SyscallClient::connect(addr).await.unwrap();
        assert!(matches!(
            fresh
                .call(Syscall::Hello {
                    protocol_version: PROTOCOL_VERSION,
                })
                .await
                .unwrap(),
            SyscallReply::Hello { .. }
        ));
        fresh.close().await.unwrap();
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
    async fn protocol_description_is_available_before_authentication() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .unwrap()
            .with_auth_token("secret");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut client = SyscallClient::connect(addr).await.unwrap();
        assert!(matches!(
            client
                .call(Syscall::Hello {
                    protocol_version: PROTOCOL_VERSION,
                })
                .await
                .unwrap(),
            SyscallReply::Hello { .. }
        ));
        let description = match client.call(Syscall::DescribeProtocol).await.unwrap() {
            SyscallReply::ProtocolDescription { description } => description,
            other => panic!("expected protocol description, got {other:?}"),
        };
        assert!(description.features.contains(&"typed_errors".to_string()));
        assert_eq!(description.transport.max_frame_bytes, MAX_WIRE_FRAME_BYTES);
        assert!(matches!(
            client.call(Syscall::ListAgents).await.unwrap(),
            SyscallReply::TypedError {
                code: WireErrorCode::AuthenticationRequired,
                ..
            }
        ));
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
        client.close().await.unwrap();
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

    #[test]
    fn pem_server_config_accepts_certificate_and_private_key() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");

        server_config_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .expect("PEM certificate and key should build a server config");
    }

    #[test]
    fn pem_server_config_rejects_missing_certificate_or_key() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let missing_cert = server_config_from_pem(b"", key_pem.as_bytes())
            .expect_err("missing certificate should fail");
        assert_eq!(missing_cert.kind(), std::io::ErrorKind::InvalidInput);
        assert!(missing_cert.to_string().contains("no certificates found"));

        let missing_key = server_config_from_pem(cert_pem.as_bytes(), b"")
            .expect_err("missing private key should fail");
        assert_eq!(missing_key.kind(), std::io::ErrorKind::InvalidInput);
        assert!(missing_key.to_string().contains("no private key found"));
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
        client.close().await.unwrap();
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
        client.close().await.unwrap();
    }

    fn assert_authorization_denied(reply: SyscallReply) {
        match reply {
            SyscallReply::Error { message } => assert_eq!(message, AUTHORIZATION_DENIED),
            other => panic!("expected stable authorization denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authorization_policy_classifies_every_syscall_and_agent_resource() {
        let kernel = AgentKernelImpl::new().expect("kernel new");
        let tenant = kernel.create_tenant("owner").await.unwrap();
        let admin_id = kernel
            .register_user(&tenant, "admin", "admin@owner.test", Role::Admin)
            .await
            .unwrap();
        let reader_id = kernel
            .register_user(&tenant, "reader", "reader@owner.test", Role::ReadOnly)
            .await
            .unwrap();
        let admin = Principal {
            user_id: admin_id,
            tenant_id: tenant.clone(),
            role: Role::Admin,
            credential: None,
        };
        let reader = Principal {
            user_id: reader_id,
            tenant_id: tenant.clone(),
            role: Role::ReadOnly,
            credential: None,
        };
        let agent = kernel
            .create_agent_for_tenant(
                &tenant,
                AgentConfig {
                    name: "owned".into(),
                    task: "classification".into(),
                    llm_provider: "stub".into(),
                    permission_profile: "standard".into(),
                    priority: Priority::default(),
                    sandbox_config: None,
                },
            )
            .await
            .unwrap();
        let id = agent.id.to_string();
        let checkpoint = uuid::Uuid::new_v4().to_string();

        let agent_calls = vec![
            Syscall::PauseAgent {
                agent_id: id.clone(),
            },
            Syscall::ResumeAgent {
                agent_id: id.clone(),
            },
            Syscall::StopAgent {
                agent_id: id.clone(),
            },
            Syscall::KillAgent {
                agent_id: id.clone(),
            },
            Syscall::GetAgentStatus {
                agent_id: id.clone(),
            },
            Syscall::WaitAgent {
                agent_id: id.clone(),
                timeout_ms: 1,
            },
            Syscall::ListGenerationCheckpoints {
                agent_id: id.clone(),
            },
            Syscall::ResumeGenerationCheckpoint {
                agent_id: id.clone(),
                checkpoint_id: checkpoint.clone(),
            },
            Syscall::DeleteGenerationCheckpoint {
                agent_id: id.clone(),
                checkpoint_id: checkpoint,
            },
            Syscall::SendMessage {
                agent_id: id.clone(),
                message: "test".into(),
            },
            Syscall::SendMessageStream {
                request_id: "request-1".into(),
                agent_id: id.clone(),
                message: "test".into(),
            },
            Syscall::CancelRequest {
                request_id: "request-1".into(),
                agent_id: id.clone(),
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
                content: "test".into(),
                category: None,
            },
            Syscall::MemoryQuery {
                agent_id: id.clone(),
                query: "test".into(),
            },
            Syscall::MemoryUpdate {
                agent_id: id.clone(),
                fact_id: uuid::Uuid::new_v4().to_string(),
                content: "updated".into(),
            },
            Syscall::MemoryDelete {
                agent_id: id.clone(),
                fact_id: uuid::Uuid::new_v4().to_string(),
            },
            Syscall::MemoryReindex {
                agent_id: id.clone(),
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
                label: "s".into(),
            },
            Syscall::RestoreSnapshot {
                agent_id: id.clone(),
                label: "s".into(),
            },
            Syscall::ListSnapshots {
                agent_id: id.clone(),
            },
            Syscall::DeleteSnapshot {
                agent_id: id.clone(),
                label: "s".into(),
            },
        ];
        for call in &agent_calls {
            let (required, action, target) = syscall_policy(call);
            assert_eq!(target, Some(id.as_str()), "unscoped operation: {action}");
            assert!(!action.is_empty());
            assert!(authorize(&kernel, Some(&admin), call).await.is_ok());
            assert_eq!(
                authorize(&kernel, Some(&reader), call).await.is_ok(),
                required == AccessLevel::ReadOnly,
                "unexpected reader classification for {action}"
            );
        }

        let unscoped_calls = vec![
            (
                Syscall::CreateAgent {
                    name: "x".into(),
                    task: "x".into(),
                    provider: "stub".into(),
                    profile: "standard".into(),
                    priority: 3,
                },
                AccessLevel::User,
            ),
            (Syscall::ListAgents, AccessLevel::ReadOnly),
            (Syscall::GateStats, AccessLevel::System),
            (Syscall::ListProviders, AccessLevel::ReadOnly),
            (
                Syscall::Hello {
                    protocol_version: 1,
                },
                AccessLevel::ReadOnly,
            ),
            (
                Syscall::Authenticate { token: "x".into() },
                AccessLevel::ReadOnly,
            ),
            (Syscall::DescribeProtocol, AccessLevel::ReadOnly),
            (Syscall::Ping, AccessLevel::ReadOnly),
            (
                Syscall::LoadPackage {
                    manifest_toml: "x".into(),
                },
                AccessLevel::Admin,
            ),
            (
                Syscall::TrustPackageKey {
                    publisher: "publisher".into(),
                    key_id: "key".into(),
                    public_key_hex: "00".into(),
                    valid_from: "2026-01-01T00:00:00Z".into(),
                    valid_until: None,
                    supersedes: None,
                },
                AccessLevel::Admin,
            ),
            (
                Syscall::RevokePackageKey {
                    key_id: "key".into(),
                },
                AccessLevel::Admin,
            ),
            (
                Syscall::PublishPackage {
                    archive_hex: "00".into(),
                },
                AccessLevel::Admin,
            ),
            (
                Syscall::YankPackage {
                    name: "package".into(),
                    version: "1.0.0".into(),
                },
                AccessLevel::Admin,
            ),
            (
                Syscall::FetchPackage {
                    name: "package".into(),
                    version: "1.0.0".into(),
                },
                AccessLevel::ReadOnly,
            ),
            (
                Syscall::SearchPackages {
                    query: "package".into(),
                },
                AccessLevel::ReadOnly,
            ),
            (
                Syscall::InstallPackage {
                    name: "package".into(),
                    requirement: "*".into(),
                },
                AccessLevel::Admin,
            ),
            (
                Syscall::RollbackPackage {
                    name: "package".into(),
                },
                AccessLevel::Admin,
            ),
            (
                Syscall::RemovePackage {
                    name: "package".into(),
                },
                AccessLevel::Admin,
            ),
            (Syscall::ListInstalledPackages, AccessLevel::ReadOnly),
            (
                Syscall::RunInstalledPackage {
                    name: "package".into(),
                },
                AccessLevel::Admin,
            ),
            (Syscall::NodeInfo, AccessLevel::System),
            (Syscall::Metrics, AccessLevel::System),
            (Syscall::OperatorSnapshot, AccessLevel::ReadOnly),
            (Syscall::ListOperatorTunables, AccessLevel::System),
            (
                Syscall::SetOperatorTunable {
                    name: crate::operator_control::MAX_AGENTS.into(),
                    value: 1,
                    expected_revision: 1,
                },
                AccessLevel::System,
            ),
            (
                Syscall::RollbackOperatorTunable {
                    name: crate::operator_control::MAX_AGENTS.into(),
                    target_revision: 1,
                    expected_revision: 2,
                },
                AccessLevel::System,
            ),
            (
                Syscall::ListOperatorTunableAudit {
                    name: None,
                    limit: 10,
                },
                AccessLevel::System,
            ),
            (Syscall::ListServices, AccessLevel::System),
            (
                Syscall::StartService { name: "x".into() },
                AccessLevel::System,
            ),
            (
                Syscall::StopService { name: "x".into() },
                AccessLevel::System,
            ),
            (
                Syscall::RestartService { name: "x".into() },
                AccessLevel::System,
            ),
            (Syscall::ReloadServices, AccessLevel::System),
            (
                Syscall::ListServiceHistory {
                    name: None,
                    limit: 10,
                },
                AccessLevel::System,
            ),
        ];
        for (call, expected) in &unscoped_calls {
            let (required, action, target) = syscall_policy(call);
            assert_eq!(required, *expected, "wrong access level for {action}");
            assert!(target.is_none(), "unexpected agent target for {action}");
            assert_eq!(
                authorize(&kernel, Some(&admin), call).await.is_ok(),
                *expected != AccessLevel::System,
                "unexpected admin classification for {action}"
            );
            assert_eq!(
                authorize(&kernel, Some(&reader), call).await.is_ok(),
                *expected == AccessLevel::ReadOnly,
                "unexpected reader classification for {action}"
            );
            assert!(
                authorize(&kernel, None, call).await.is_ok(),
                "trusted-system path must remain explicit for {action}"
            );
        }

        // syscall_policy is an exhaustive match. This table additionally feeds
        // every concrete operation through serde and proves that the published
        // machine-readable request schema has neither omissions nor extras.
        let calls = agent_calls
            .iter()
            .chain(unscoped_calls.iter().map(|(call, _)| call))
            .collect::<Vec<_>>();
        let fixture_tags = calls
            .iter()
            .map(|call| {
                serde_json::to_value(call)
                    .unwrap()
                    .get("op")
                    .and_then(serde_json::Value::as_str)
                    .unwrap()
                    .to_string()
            })
            .collect::<std::collections::HashSet<_>>();
        let schema = crate::wire_contract::protocol_description();
        let schema_tags = schema.request_schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|variant| {
                variant["properties"]["op"]["const"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(calls.len(), 61);
        assert_eq!(fixture_tags, schema_tags);
    }

    #[tokio::test]
    async fn tenant_authorizer_denies_every_foreign_agent_operation() {
        let kernel = AgentKernelImpl::new().expect("kernel new");
        let tenant_a = kernel.create_tenant("a").await.unwrap();
        let tenant_b = kernel.create_tenant("b").await.unwrap();
        let user_a = kernel
            .register_user(&tenant_a, "alice", "alice@a.test", Role::Admin)
            .await
            .unwrap();
        let principal_a = Principal {
            user_id: user_a,
            tenant_id: tenant_a,
            role: Role::Admin,
            credential: None,
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
            Syscall::PauseAgent {
                agent_id: id.clone(),
            },
            Syscall::ResumeAgent {
                agent_id: id.clone(),
            },
            Syscall::StopAgent {
                agent_id: id.clone(),
            },
            Syscall::KillAgent {
                agent_id: id.clone(),
            },
            Syscall::GetAgentStatus {
                agent_id: id.clone(),
            },
            Syscall::WaitAgent {
                agent_id: id.clone(),
                timeout_ms: 1,
            },
            Syscall::ListGenerationCheckpoints {
                agent_id: id.clone(),
            },
            Syscall::ResumeGenerationCheckpoint {
                agent_id: id.clone(),
                checkpoint_id: uuid::Uuid::new_v4().to_string(),
            },
            Syscall::DeleteGenerationCheckpoint {
                agent_id: id.clone(),
                checkpoint_id: uuid::Uuid::new_v4().to_string(),
            },
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
            Syscall::MemoryUpdate {
                agent_id: id.clone(),
                fact_id: uuid::Uuid::new_v4().to_string(),
                content: "poison".into(),
            },
            Syscall::MemoryDelete {
                agent_id: id.clone(),
                fact_id: uuid::Uuid::new_v4().to_string(),
            },
            Syscall::MemoryReindex {
                agent_id: id.clone(),
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
            credential: None,
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
        assert!(tenant_snapshot.tunables.is_none());
        assert_eq!(tenant_snapshot.total_visible_agents, 1);
        assert!(!tenant_snapshot.agents_truncated);
        assert!(tenant_snapshot.agents[0].cgroup.is_some());
        assert!(!tenant_snapshot.agents[0].namespace_details.is_empty());

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
        let metrics = system.system_metrics.as_ref().unwrap();
        assert_eq!(metrics.agent_count as usize, system.total_visible_agents);
        assert_eq!(metrics.gate, system.scoped_gate_decisions);
        assert!(system.services.is_some());
        assert!(system.tunables.is_some());
    }

    #[tokio::test]
    async fn operator_snapshot_bounds_slow_provider_health_probes() {
        let kernel = AgentKernelImpl::new().expect("kernel new");
        kernel
            .register_provider(Arc::new(SlowHealthProvider {
                id: "slow-health".into(),
            }))
            .unwrap();
        let current = kernel
            .operator_control
            .list()
            .unwrap()
            .into_iter()
            .find(|tunable| tunable.name == crate::operator_control::PROVIDER_PROBE_TIMEOUT_MS)
            .unwrap();
        kernel
            .operator_control
            .set(&current.name, 50, current.revision, "provider-timeout-test")
            .await
            .unwrap();

        let started = std::time::Instant::now();
        let snapshot = match dispatch(&kernel, Syscall::OperatorSnapshot).await {
            SyscallReply::OperatorSnapshot { snapshot } => snapshot,
            other => panic!("expected operator snapshot, got {other:?}"),
        };
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "a provider health probe must not block the operator API"
        );
        let provider = snapshot
            .providers
            .iter()
            .find(|provider| provider.id == "slow-health")
            .expect("registered provider must remain visible after timeout");
        assert!(!provider.available);
        assert!(provider.probe_timed_out);
        assert!(provider
            .probe_duration_ms
            .is_some_and(|duration| duration >= 50));
    }

    #[tokio::test]
    async fn operator_tunables_are_durable_audited_atomic_and_enforced() {
        let db_path = std::env::temp_dir().join(format!(
            "agentos-operator-tunables-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        {
            let kernel = AgentKernelImpl::with_db_path(&db_path).unwrap();
            let initial = match dispatch(&kernel, Syscall::ListOperatorTunables).await {
                SyscallReply::OperatorTunables { tunables } => tunables,
                other => panic!("expected tunables, got {other:?}"),
            };
            let max_agents = initial
                .iter()
                .find(|tunable| tunable.name == crate::operator_control::MAX_AGENTS)
                .unwrap();
            assert_eq!(max_agents.value, 0);
            assert_eq!(max_agents.revision, 1);

            let tenant = kernel.create_tenant("denied-ops").await.unwrap();
            let user = kernel
                .register_user(&tenant, "admin", "admin@denied.test", Role::Admin)
                .await
                .unwrap();
            let tenant_admin = Principal {
                user_id: user,
                tenant_id: tenant,
                role: Role::Admin,
                credential: None,
            };
            assert_authorization_denied(
                dispatch_scoped(
                    &kernel,
                    Syscall::SetOperatorTunable {
                        name: crate::operator_control::MAX_AGENTS.into(),
                        value: 9,
                        expected_revision: 1,
                    },
                    Some(&tenant_admin),
                )
                .await,
            );

            let applied = match dispatch(
                &kernel,
                Syscall::SetOperatorTunable {
                    name: crate::operator_control::MAX_AGENTS.into(),
                    value: 1,
                    expected_revision: 1,
                },
            )
            .await
            {
                SyscallReply::OperatorTunable { tunable } => tunable,
                other => panic!("expected applied tunable, got {other:?}"),
            };
            assert_eq!(applied.value, 1);
            assert_eq!(applied.revision, 2);

            let config = |name: &str| AgentConfig {
                name: name.into(),
                task: "bounded creation".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            };
            let (left, right) = tokio::join!(
                kernel.create_agent_full(config("left")),
                kernel.create_agent_full(config("right"))
            );
            assert_eq!(
                usize::from(left.is_ok()) + usize::from(right.is_ok()),
                1,
                "compare-and-create must enforce max_agents atomically"
            );
            let rejected = left.err().or_else(|| right.err()).unwrap().to_string();
            assert!(rejected.contains("kernel.max_agents"));

            assert!(matches!(
                dispatch(
                    &kernel,
                    Syscall::SetOperatorTunable {
                        name: crate::operator_control::MAX_AGENTS.into(),
                        value: 1_000_001,
                        expected_revision: 2,
                    },
                )
                .await,
                SyscallReply::Error { .. }
            ));
            assert!(matches!(
                dispatch(
                    &kernel,
                    Syscall::SetOperatorTunable {
                        name: crate::operator_control::MAX_AGENTS.into(),
                        value: 2,
                        expected_revision: 1,
                    },
                )
                .await,
                SyscallReply::Error { .. }
            ));

            let restored = match dispatch(
                &kernel,
                Syscall::RollbackOperatorTunable {
                    name: crate::operator_control::MAX_AGENTS.into(),
                    target_revision: 1,
                    expected_revision: 2,
                },
            )
            .await
            {
                SyscallReply::OperatorTunable { tunable } => tunable,
                other => panic!("expected rollback, got {other:?}"),
            };
            assert_eq!(restored.value, 0);
            assert_eq!(restored.revision, 3);
            let persisted_package = crate::agent_package::AgentManifest::from_toml_str(
                "name = \"after-rollback-package\"\ntask = \"durable package view\"",
            )
            .unwrap();
            crate::agent_package::load_package(&kernel, &persisted_package)
                .await
                .expect("rollback must update live admission");

            let audit = match dispatch(
                &kernel,
                Syscall::ListOperatorTunableAudit {
                    name: Some(crate::operator_control::MAX_AGENTS.into()),
                    limit: 100,
                },
            )
            .await
            {
                SyscallReply::OperatorTunableAudit { entries } => entries,
                other => panic!("expected audit, got {other:?}"),
            };
            assert!(audit.iter().any(|entry| {
                entry.outcome == "denied"
                    && entry
                        .reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("authorization denied"))
            }));
            assert!(
                audit
                    .iter()
                    .filter(|entry| entry.outcome == "denied")
                    .count()
                    >= 3
            );
            assert!(audit
                .iter()
                .any(|entry| entry.action == "rollback" && entry.effective_value == Some(0)));
        }

        {
            let restarted = AgentKernelImpl::with_db_path(&db_path).unwrap();
            let persisted = restarted.operator_control.list().unwrap();
            let max_agents = persisted
                .iter()
                .find(|tunable| tunable.name == crate::operator_control::MAX_AGENTS)
                .unwrap();
            assert_eq!(max_agents.value, 0);
            assert_eq!(max_agents.revision, 3);
            assert_eq!(
                restarted.syscall_gate.stats(),
                crate::syscall_gate::GateStats::default(),
                "ephemeral decision counters reset on process restart"
            );
            assert!(restarted
                .operator_control
                .audit(Some(crate::operator_control::MAX_AGENTS), 100)
                .unwrap()
                .iter()
                .any(|entry| entry.action == "rollback"));
            let snapshot = match dispatch(&restarted, Syscall::OperatorSnapshot).await {
                SyscallReply::OperatorSnapshot { snapshot } => snapshot,
                other => panic!("expected restarted snapshot, got {other:?}"),
            };
            assert!(snapshot
                .packages
                .iter()
                .any(|package| package.name == "after-rollback-package"));
        }
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(format!("{}-wal", db_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", db_path.display()));
    }

    #[tokio::test]
    async fn package_and_gate_views_are_tenant_scoped() {
        let kernel = AgentKernelImpl::new().unwrap();
        let tenant_a = kernel.create_tenant("view-a").await.unwrap();
        let tenant_b = kernel.create_tenant("view-b").await.unwrap();
        let user_a = kernel
            .register_user(&tenant_a, "a", "a@view.test", Role::User)
            .await
            .unwrap();
        let user_b = kernel
            .register_user(&tenant_b, "b", "b@view.test", Role::User)
            .await
            .unwrap();
        let principal_a = Principal {
            user_id: user_a,
            tenant_id: tenant_a.clone(),
            role: Role::User,
            credential: None,
        };
        let principal_b = Principal {
            user_id: user_b,
            tenant_id: tenant_b.clone(),
            role: Role::User,
            credential: None,
        };
        let package_a = crate::agent_package::AgentManifest::from_toml_str(
            "name = \"tenant-a-package\"\ntask = \"private-a\"\nprofile = \"read-only\"",
        )
        .unwrap();
        let package_b = crate::agent_package::AgentManifest::from_toml_str(
            "name = \"tenant-b-package\"\ntask = \"private-b\"\nprofile = \"read-only\"",
        )
        .unwrap();
        let agent_a = crate::agent_package::load_package_for_tenant(&kernel, &tenant_a, &package_a)
            .await
            .unwrap();
        let agent_b = crate::agent_package::load_package_for_tenant(&kernel, &tenant_b, &package_b)
            .await
            .unwrap();

        let denied_write = |agent_id: uuid::Uuid| Syscall::CallTool {
            agent_id: agent_id.to_string(),
            tool: "write_file".into(),
            args: serde_json::json!({"path": "blocked.txt", "content": "x"}),
        };
        assert!(matches!(
            dispatch_scoped(&kernel, denied_write(agent_a.id), Some(&principal_a)).await,
            SyscallReply::Error { .. }
        ));
        for _ in 0..2 {
            assert!(matches!(
                dispatch_scoped(&kernel, denied_write(agent_b.id), Some(&principal_b)).await,
                SyscallReply::Error { .. }
            ));
        }

        let snapshot_a =
            match dispatch_scoped(&kernel, Syscall::OperatorSnapshot, Some(&principal_a)).await {
                SyscallReply::OperatorSnapshot { snapshot } => snapshot,
                other => panic!("expected tenant A snapshot, got {other:?}"),
            };
        let snapshot_b =
            match dispatch_scoped(&kernel, Syscall::OperatorSnapshot, Some(&principal_b)).await {
                SyscallReply::OperatorSnapshot { snapshot } => snapshot,
                other => panic!("expected tenant B snapshot, got {other:?}"),
            };
        assert_eq!(snapshot_a.packages.len(), 1);
        assert_eq!(snapshot_a.packages[0].name, "tenant-a-package");
        assert_eq!(snapshot_b.packages.len(), 1);
        assert_eq!(snapshot_b.packages[0].name, "tenant-b-package");
        assert_eq!(snapshot_a.scoped_gate_decisions.denied_capability, 1);
        assert_eq!(snapshot_b.scoped_gate_decisions.denied_capability, 2);
        assert_eq!(snapshot_a.agents[0].gate_decisions.denied_capability, 1);
        assert_eq!(snapshot_b.agents[0].gate_decisions.denied_capability, 2);
        let encoded_a = serde_json::to_string(&snapshot_a).unwrap();
        assert!(!encoded_a.contains("tenant-b-package"));
        assert!(!encoded_a.contains("private-b"));

        let system = match dispatch(&kernel, Syscall::OperatorSnapshot).await {
            SyscallReply::OperatorSnapshot { snapshot } => snapshot,
            other => panic!("expected system snapshot, got {other:?}"),
        };
        assert_eq!(system.packages.len(), 2);
        assert_eq!(
            system.scoped_gate_decisions.denied_capability,
            snapshot_a.scoped_gate_decisions.denied_capability
                + snapshot_b.scoped_gate_decisions.denied_capability
        );
    }

    #[tokio::test]
    async fn concurrent_lifecycle_and_reconfigure_snapshots_are_structurally_valid() {
        let kernel = AgentKernelImpl::new().unwrap();
        let agent = kernel
            .create_agent_full(AgentConfig {
                name: "snapshot-race".into(),
                task: "exercise barrier".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            })
            .await
            .unwrap();

        let mutate_lifecycle = async {
            for _ in 0..20 {
                kernel.pause_agent(agent.id).await.unwrap();
                kernel.resume_agent(agent.id).await.unwrap();
            }
        };
        let reconfigure = async {
            for index in 0..20 {
                let current = kernel
                    .operator_control
                    .list()
                    .unwrap()
                    .into_iter()
                    .find(|tunable| {
                        tunable.name == crate::operator_control::PROVIDER_PROBE_TIMEOUT_MS
                    })
                    .unwrap();
                kernel
                    .operator_control
                    .set(
                        &current.name,
                        if index % 2 == 0 { 100 } else { 200 },
                        current.revision,
                        "concurrency-test",
                    )
                    .await
                    .unwrap();
            }
        };
        let observe = async {
            for _ in 0..80 {
                let snapshot = match dispatch(&kernel, Syscall::OperatorSnapshot).await {
                    SyscallReply::OperatorSnapshot { snapshot } => snapshot,
                    other => panic!("expected snapshot, got {other:?}"),
                };
                let agent = snapshot
                    .agents
                    .iter()
                    .find(|entry| entry.id == agent.id.to_string())
                    .unwrap();
                match agent.state.as_str() {
                    "Running" => {
                        assert!(agent.sandbox_active);
                        assert!(agent.cgroup.is_some());
                        assert!(
                            matches!(agent.scheduler_state.as_str(), "queued" | "running"),
                            "running lifecycle state cannot pair with scheduler state {:?}",
                            agent.scheduler_state
                        );
                    }
                    "Paused" => {
                        assert!(agent.sandbox_active);
                        assert!(agent.cgroup.is_some());
                        assert_eq!(agent.scheduler_state, "paused");
                    }
                    other => panic!("impossible concurrent state {other:?}"),
                }
            }
        };
        tokio::join!(mutate_lifecycle, reconfigure, observe);

        kernel.kill_agent(agent.id).await.unwrap();
        let stopped = match dispatch(&kernel, Syscall::OperatorSnapshot).await {
            SyscallReply::OperatorSnapshot { snapshot } => snapshot,
            other => panic!("expected snapshot, got {other:?}"),
        };
        let stopped = stopped
            .agents
            .iter()
            .find(|entry| entry.id == agent.id.to_string())
            .unwrap();
        assert_eq!(stopped.state, "Stopped");
        assert_eq!(stopped.scheduler_state, "stopped");
        assert!(!stopped.sandbox_active);
        assert!(stopped.cgroup.is_none());
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
            credential: None,
        };
        let admin = Principal {
            user_id: admin_id,
            tenant_id: tenant.clone(),
            role: Role::Admin,
            credential: None,
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
            .expect("bind")
            .with_auth_token("system-secret");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Error { message } => assert_eq!(message, "authentication required"),
            other => panic!("unauthenticated tenant connection was accepted: {other:?}"),
        }
        assert!(matches!(
            client.authenticate(token.clone()).await.unwrap(),
            SyscallReply::Authenticated
        ));
        assert!(matches!(
            client.call(Syscall::ListAgents).await.unwrap(),
            SyscallReply::Agents { .. }
        ));

        assert!(kernel.revoke_session(&token).await.unwrap());
        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Error { message } => assert_eq!(message, "authentication required"),
            other => panic!("revoked session retained authority: {other:?}"),
        }
        match client.authenticate(token).await.unwrap() {
            SyscallReply::Error { message } => assert_eq!(message, "authentication failed"),
            other => panic!("revoked token was accepted again: {other:?}"),
        }
    }

    #[tokio::test]
    async fn failed_reauthentication_clears_the_previous_wire_identity() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let tenant = kernel.create_tenant("reauth").await.unwrap();
        let user = kernel
            .register_user(&tenant, "alice", "alice@reauth.test", Role::User)
            .await
            .unwrap();
        let token = kernel.open_session(&user).await.unwrap();
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .expect("bind")
            .with_auth_token("system-secret");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(addr).await.unwrap();

        assert!(matches!(
            client.authenticate(token).await.unwrap(),
            SyscallReply::Authenticated
        ));
        assert!(matches!(
            client.authenticate("invalid-replacement").await.unwrap(),
            SyscallReply::Error { message } if message == "authentication failed"
        ));
        assert!(matches!(
            client.call(Syscall::ListAgents).await.unwrap(),
            SyscallReply::Error { message } if message == "authentication required"
        ));
    }

    #[tokio::test]
    async fn revocation_waits_only_for_the_same_credential_lease() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let tenant = kernel.create_tenant("linearizable").await.unwrap();
        let user_a = kernel
            .register_user(&tenant, "alice", "alice@linear.test", Role::User)
            .await
            .unwrap();
        let user_b = kernel
            .register_user(&tenant, "bob", "bob@linear.test", Role::User)
            .await
            .unwrap();
        let token_a = kernel.open_session(&user_a).await.unwrap();
        let token_b = kernel.open_session(&user_b).await.unwrap();
        let identity_a = kernel
            .resolve_principal(&token_a)
            .await
            .unwrap()
            .credential
            .unwrap();
        let (_principal, in_flight) = kernel
            .acquire_credential_principal(&identity_a)
            .await
            .expect("first request admitted");

        let revoke_kernel = kernel.clone();
        let revoke_token = token_a.clone();
        let revoke = tokio::spawn(async move { revoke_kernel.revoke_session(&revoke_token).await });

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while kernel.resolve_principal(&token_a).await.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("same-credential revocation did not close admission");
        assert!(
            !revoke.is_finished(),
            "same-credential revocation crossed an in-flight lease"
        );
        assert!(
            kernel
                .acquire_credential_principal(&identity_a)
                .await
                .is_none(),
            "closed credential admitted a post-revocation request"
        );

        // The long-running A request must not retain a global auth read lock.
        // Revoking unrelated B performs both a durable and in-memory auth write.
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(1),
            kernel.revoke_session(&token_b)
        )
        .await
        .expect("unrelated credential revocation blocked behind A")
        .unwrap());

        drop(in_flight);
        assert!(revoke.await.unwrap().unwrap());
        assert!(kernel.resolve_principal(&token_a).await.is_none());
        assert!(
            kernel
                .acquire_credential_principal(&identity_a)
                .await
                .is_none(),
            "same credential executed after revocation returned"
        );
    }

    #[tokio::test]
    async fn tls_tenant_credentials_enforce_owner_role_and_system_boundaries() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server_config, roots) = self_signed_tls();
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let tenant_a = kernel.create_tenant("tls-a").await.unwrap();
        let tenant_b = kernel.create_tenant("tls-b").await.unwrap();
        let reader = kernel
            .register_user(&tenant_a, "reader", "reader@tls.test", Role::ReadOnly)
            .await
            .unwrap();
        let key = kernel.issue_api_key(&reader, "tls-test").await.unwrap();
        let own = kernel
            .create_agent_for_tenant(
                &tenant_a,
                AgentConfig {
                    name: "tls-owned".into(),
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
                    name: "tls-foreign".into(),
                    task: "foreign".into(),
                    llm_provider: "stub".into(),
                    permission_profile: "standard".into(),
                    priority: Priority::default(),
                    sandbox_config: None,
                },
            )
            .await
            .unwrap();

        let server = SyscallServer::bind_tls(kernel.clone(), "127.0.0.1:0", server_config)
            .await
            .expect("bind tls")
            .with_auth_token("system-secret");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = SyscallClient::connect_tls(addr, "localhost", client_config)
            .await
            .expect("connect tls");

        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Error { message } => assert_eq!(message, "authentication required"),
            other => panic!("unauthenticated TLS call was accepted: {other:?}"),
        }
        assert!(matches!(
            client.authenticate(key.clone()).await.unwrap(),
            SyscallReply::Authenticated
        ));
        assert!(matches!(
            client
                .call(Syscall::AgentInfo {
                    agent_id: own.id.to_string(),
                })
                .await
                .unwrap(),
            SyscallReply::AgentInfo { .. }
        ));
        assert_authorization_denied(
            client
                .call(Syscall::AgentInfo {
                    agent_id: foreign.id.to_string(),
                })
                .await
                .unwrap(),
        );
        assert_authorization_denied(
            client
                .call(Syscall::StoragePut {
                    agent_id: own.id.to_string(),
                    key: "forbidden".into(),
                    value: "write".into(),
                })
                .await
                .unwrap(),
        );
        assert_authorization_denied(client.call(Syscall::Metrics).await.unwrap());
        assert!(kernel.revoke_api_key(&key).await.unwrap());
        match client.call(Syscall::ListAgents).await.unwrap() {
            SyscallReply::Error { message } => assert_eq!(message, "authentication required"),
            other => panic!("revoked TLS credential retained authority: {other:?}"),
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

    #[test]
    fn syscall_debug_never_exposes_credentials_or_payload_content() {
        let auth = format!(
            "{:?}",
            Syscall::Authenticate {
                token: "super-secret-token".into(),
            }
        );
        assert!(!auth.contains("super-secret-token"));
        assert!(auth.contains("[REDACTED]"));

        let call = format!(
            "{:?}",
            Syscall::CallTool {
                agent_id: "agent".into(),
                tool: "http".into(),
                args: serde_json::json!({"authorization": "Bearer secret"}),
            }
        );
        assert!(!call.contains("Bearer secret"));

        let stream = format!(
            "{:?}",
            Syscall::SendMessageStream {
                request_id: "request".into(),
                agent_id: "agent".into(),
                message: "private prompt".into(),
            }
        );
        assert!(!stream.contains("private prompt"));

        let stream_event = format!(
            "{:?}",
            SyscallReply::StreamEvent {
                request_id: "request".into(),
                sequence: 0,
                event: MessageStreamEvent::Token {
                    delta: "private completion".into(),
                },
            }
        );
        assert!(!stream_event.contains("private completion"));

        let reply = format!(
            "{:?}",
            SyscallReply::StorageValue {
                value: Some("private-value".into()),
            }
        );
        assert!(!reply.contains("private-value"));
    }
}
