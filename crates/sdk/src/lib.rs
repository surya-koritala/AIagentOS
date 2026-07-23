//! # agent-sdk — embeddable Rust SDK for the AI Agent OS kernel
//!
//! This crate is the ergonomic, **Rust-only** face of the kernel's syscall
//! server ([`kernel::syscall_server`]). A developer building an agent connects
//! to a running [`SyscallServer`](kernel::syscall_server::SyscallServer) over
//! TCP and drives the kernel through typed async methods instead of hand-rolling
//! newline-delimited JSON.
//!
//! The SDK deliberately **reuses the kernel's wire types** ([`Syscall`] /
//! [`SyscallReply`]) and its [`SyscallClient`] transport rather than redefining
//! the protocol — there is exactly one source of truth for the boundary. What
//! this crate adds on top is:
//!
//! * [`KernelClient`] — a typed wrapper that maps each [`Syscall`] variant to an
//!   async method and folds [`SyscallReply::Error`] into a [`Result<_, SdkError>`].
//! * [`Agent`] — a builder (`Agent::builder()`) that creates an agent on the
//!   kernel and hands back a [`AgentHandle`] with `.send(..)` / `.call_tool(..)`.
//!
//! ## Example
//!
//! ```no_run
//! use agent_sdk::Agent;
//!
//! # async fn run() -> Result<(), agent_sdk::SdkError> {
//! let mut agent = Agent::builder()
//!     .name("alpha")
//!     .task("summarize the docs")
//!     .profile("standard")
//!     .connect("127.0.0.1:7777")
//!     .await?;
//!
//! let reply = agent.send("hello").await?;
//! println!("{}", reply.content);
//! # Ok(())
//! # }
//! ```

use kernel::syscall_server::{Syscall, SyscallClient, SyscallReply};
use tokio::net::ToSocketAddrs;

// Re-export the kernel wire types that appear in this crate's public API, so
// SDK consumers can name them without depending on the kernel directly.
pub use kernel::context::ContextPressureStats;
pub use kernel::init_system::ServiceRuntimeInfo;
pub use kernel::syscall_server::{
    AgentSummary, FactSummary, GenerationCheckpointSummary, OperatorAgentSnapshot,
    OperatorServiceSnapshot, OperatorSnapshot, ProviderSummary, WireErrorCode,
};

/// The wire-protocol version this SDK build was compiled against. A client
/// announces it via [`KernelClient::hello`]; a server outside its support
/// window is reported as [`SdkError::IncompatibleProtocol`] rather than failing
/// later with a confusing parse error.
pub use kernel::syscall_server::PROTOCOL_VERSION;

pub mod cluster;
pub mod patterns;

pub use cluster::{ClusterClient, NodeHandle, PlacedAgent, Placement};
pub use patterns::{
    Decision, DirectiveReasoner, FnPlanner, PlanRun, Planner, PlannerExecutor, ReActLoop,
    ReActOutcome, ReActStep, Reasoner, Step, StepResult, ToolInvocation,
};

/// Errors surfaced by the SDK.
///
/// [`SdkError::Kernel`] carries a denial or failure message that the kernel
/// returned as [`SyscallReply::Error`] (e.g. a syscall-gate capability denial).
/// [`SdkError::Transport`] wraps I/O / connection failures, and
/// [`SdkError::UnexpectedReply`] guards the typed methods against a reply
/// variant that doesn't match the syscall that was sent.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    /// The kernel answered with [`SyscallReply::Error`] — e.g. a gate denial,
    /// an unknown tool, or an invalid agent id.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// A transport / connection failure talking to the syscall server.
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),

    /// The kernel replied with a variant that doesn't correspond to the
    /// syscall that was issued. Indicates a protocol mismatch.
    #[error("unexpected reply for {expected}: {got}")]
    UnexpectedReply {
        /// The reply variant the caller expected.
        expected: &'static str,
        /// A debug rendering of the variant actually received.
        got: String,
    },

    /// The server's wire-protocol support window doesn't include the version
    /// this SDK speaks ([`PROTOCOL_VERSION`]). Either the server is too old to
    /// understand the [`Hello`](Syscall::Hello) handshake at all (it predates
    /// protocol versioning), or its `[min, max]` window excludes us. Surfaced by
    /// [`KernelClient::hello`] so a version skew fails clearly up front rather
    /// than as a confusing error on a later syscall.
    #[error("incompatible wire protocol: this client speaks v{client}, server supports {server}")]
    IncompatibleProtocol {
        /// The protocol version this SDK build speaks.
        client: u32,
        /// A human description of the server's support (its window, or that it
        /// predates protocol versioning).
        server: String,
    },
}

/// Result of a [`KernelClient::send_message`] / [`AgentHandle::send`] turn.
#[derive(Debug, Clone)]
pub struct MessageResult {
    /// The agent's textual output for the turn.
    pub content: String,
    /// How many tool calls the agent made during the turn.
    pub tool_calls: usize,
    /// Tokens consumed by the turn.
    pub tokens: u32,
}

/// Result of a durable lifecycle operation. `checkpoint_id` is present when a
/// pause captured resumable work (or a resumed turn paused again).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleResult {
    pub state: String,
    pub checkpoint_id: Option<String>,
    pub resumed_content: Option<String>,
    pub resumed_tool_calls: Option<usize>,
    pub resumed_tokens: Option<u32>,
}

/// Snapshot of the syscall gate's enforcement counters.
#[derive(Debug, Clone, Default)]
pub struct GateStats {
    pub allowed: u64,
    pub denied_capability: u64,
    pub denied_mac: u64,
    pub denied_approval: u64,
    pub denied_cgroup: u64,
    pub denied_namespace: u64,
    pub denied_unknown: u64,
    pub audited: u64,
}

/// A kernel node's load/health snapshot (reply to `node_info`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeLoad {
    /// Total agents the node hosts.
    pub agent_count: usize,
    /// Agents currently executing a turn.
    pub running_agents: usize,
    pub live_agents: usize,
    pub queued_agents: usize,
    pub paused_agents: usize,
    pub stopped_agents: usize,
    pub active_turns: usize,
    pub waiting_turns: usize,
    pub turn_capacity: usize,
    pub llm_requests_in_flight: usize,
    pub llm_requests_waiting: usize,
    pub llm_core_capacity: usize,
}

/// The server's wire-protocol support window (reply to `hello`).
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    /// The newest wire-protocol version the server speaks.
    pub protocol_version: u32,
    /// The oldest wire-protocol version the server still accepts.
    pub min_protocol_version: u32,
    /// The server's crate version (informational).
    pub server_version: String,
}

/// The kernel's operational metrics (reply to `metrics`). Carries the rendered
/// Prometheus text exposition plus a couple of the headline numbers as typed
/// fields.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    /// The full `text/plain; version=0.0.4` Prometheus exposition.
    pub prometheus: String,
    /// Total agents the kernel hosts.
    pub agent_count: usize,
    /// System-wide tokens consumed.
    pub tokens_consumed: u64,
}

/// A typed, async client over the kernel's syscall protocol.
///
/// Wraps [`SyscallClient`]: each method serializes the matching [`Syscall`],
/// awaits the [`SyscallReply`], and maps [`SyscallReply::Error`] into
/// [`SdkError::Kernel`]. One [`KernelClient`] owns one connection; clone the
/// address and [`connect`](Self::connect) again for concurrent callers.
pub struct KernelClient {
    inner: SyscallClient,
}

impl KernelClient {
    /// Connect to a running syscall server at `addr` (e.g. `"127.0.0.1:7777"`).
    pub async fn connect(addr: impl ToSocketAddrs) -> Result<Self, SdkError> {
        let mut client = Self {
            inner: SyscallClient::connect(addr).await?,
        };
        client.hello().await?;
        Ok(client)
    }

    /// Connect to a running syscall server over TLS. Mirrors [`connect`](Self::connect)
    /// but performs a rustls handshake first: the server's certificate is verified
    /// against `config`'s root store and must present `server_name` (e.g.
    /// `"localhost"`). Lets SDK / cluster users dial a TLS-terminated kernel node.
    pub async fn connect_tls(
        addr: impl ToSocketAddrs,
        server_name: impl Into<String>,
        config: rustls::ClientConfig,
    ) -> Result<Self, SdkError> {
        let mut client = Self {
            inner: SyscallClient::connect_tls(addr, server_name, config).await?,
        };
        client.hello().await?;
        Ok(client)
    }

    /// Build a [`KernelClient`] from an already-connected [`SyscallClient`].
    pub fn from_client(inner: SyscallClient) -> Self {
        Self { inner }
    }

    /// Create an agent through the full kernel path (gate registration, cgroup,
    /// namespaces, scheduler admission, procfs). Returns the new agent's id.
    ///
    /// `provider`/`profile` default to `"stub"`/`"standard"` and `priority` to
    /// `3` when passed as [`None`] — matching the kernel's wire defaults.
    pub async fn create_agent(
        &mut self,
        name: impl Into<String>,
        task: impl Into<String>,
        provider: Option<String>,
        profile: Option<String>,
        priority: Option<u8>,
    ) -> Result<String, SdkError> {
        let call = Syscall::CreateAgent {
            name: name.into(),
            task: task.into(),
            provider: provider.unwrap_or_else(|| "stub".to_string()),
            profile: profile.unwrap_or_else(|| "standard".to_string()),
            priority: priority.unwrap_or(3),
        };
        match self.call(call).await? {
            SyscallReply::AgentCreated { id } => Ok(id),
            other => Err(unexpected("AgentCreated", &other)),
        }
    }

    /// List all agents the kernel knows about.
    pub async fn list_agents(&mut self) -> Result<Vec<AgentSummary>, SdkError> {
        match self.call(Syscall::ListAgents).await? {
            SyscallReply::Agents { agents } => Ok(agents),
            other => Err(unexpected("Agents", &other)),
        }
    }

    async fn lifecycle_call(&mut self, call: Syscall) -> Result<LifecycleResult, SdkError> {
        match self.call(call).await? {
            SyscallReply::AgentStatus {
                state,
                checkpoint_id,
                resumed_content,
                resumed_tool_calls,
                resumed_tokens,
            } => Ok(LifecycleResult {
                state,
                checkpoint_id,
                resumed_content,
                resumed_tool_calls,
                resumed_tokens,
            }),
            other => Err(unexpected("AgentStatus", &other)),
        }
    }

    /// Durable pause result, including the checkpoint id when an active turn
    /// reached its cooperative boundary.
    pub async fn pause_agent_durable(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<LifecycleResult, SdkError> {
        self.lifecycle_call(Syscall::PauseAgent {
            agent_id: agent_id.into(),
        })
        .await
    }

    /// Pause admission for an agent and cooperatively cancel an active turn.
    pub async fn pause_agent(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self.pause_agent_durable(agent_id).await?.state)
    }

    /// Durable resume result, including completed continuation output.
    pub async fn resume_agent_durable(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<LifecycleResult, SdkError> {
        self.lifecycle_call(Syscall::ResumeAgent {
            agent_id: agent_id.into(),
        })
        .await
    }

    /// Resume a paused agent.
    pub async fn resume_agent(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self.resume_agent_durable(agent_id).await?.state)
    }

    /// Gracefully stop an agent and clean up its live resources.
    pub async fn stop_agent(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self
            .lifecycle_call(Syscall::StopAgent {
                agent_id: agent_id.into(),
            })
            .await?
            .state)
    }

    /// Force an agent into its terminal state and clean up live resources.
    pub async fn kill_agent(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self
            .lifecycle_call(Syscall::KillAgent {
                agent_id: agent_id.into(),
            })
            .await?
            .state)
    }

    /// Return an agent's current lifecycle state.
    pub async fn agent_status(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self
            .lifecycle_call(Syscall::GetAgentStatus {
                agent_id: agent_id.into(),
            })
            .await?
            .state)
    }

    /// Wait for an agent to become terminal, bounded by `timeout`.
    pub async fn wait_agent(
        &mut self,
        agent_id: impl Into<String>,
        timeout: std::time::Duration,
    ) -> Result<String, SdkError> {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        Ok(self
            .lifecycle_call(Syscall::WaitAgent {
                agent_id: agent_id.into(),
                timeout_ms,
            })
            .await?
            .state)
    }

    pub async fn list_generation_checkpoints(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<Vec<GenerationCheckpointSummary>, SdkError> {
        match self
            .call(Syscall::ListGenerationCheckpoints {
                agent_id: agent_id.into(),
            })
            .await?
        {
            SyscallReply::GenerationCheckpoints { checkpoints } => Ok(checkpoints),
            other => Err(unexpected("GenerationCheckpoints", &other)),
        }
    }

    pub async fn resume_generation_checkpoint(
        &mut self,
        agent_id: impl Into<String>,
        checkpoint_id: impl Into<String>,
    ) -> Result<LifecycleResult, SdkError> {
        self.lifecycle_call(Syscall::ResumeGenerationCheckpoint {
            agent_id: agent_id.into(),
            checkpoint_id: checkpoint_id.into(),
        })
        .await
    }

    pub async fn delete_generation_checkpoint(
        &mut self,
        agent_id: impl Into<String>,
        checkpoint_id: impl Into<String>,
    ) -> Result<bool, SdkError> {
        match self
            .call(Syscall::DeleteGenerationCheckpoint {
                agent_id: agent_id.into(),
                checkpoint_id: checkpoint_id.into(),
            })
            .await?
        {
            SyscallReply::GenerationCheckpointDeleted { existed } => Ok(existed),
            other => Err(unexpected("GenerationCheckpointDeleted", &other)),
        }
    }

    /// Drive one think→act→observe turn for an agent.
    pub async fn send_message(
        &mut self,
        agent_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<MessageResult, SdkError> {
        let call = Syscall::SendMessage {
            agent_id: agent_id.into(),
            message: message.into(),
        };
        match self.call(call).await? {
            SyscallReply::Message {
                content,
                tool_calls,
                tokens,
            } => Ok(MessageResult {
                content,
                tool_calls,
                tokens,
            }),
            other => Err(unexpected("Message", &other)),
        }
    }

    /// Invoke a single tool as an agent. The call goes through the syscall gate
    /// (capability / MAC / cgroup / namespace) on the kernel side, so a denial
    /// comes back as [`SdkError::Kernel`].
    pub async fn call_tool(
        &mut self,
        agent_id: impl Into<String>,
        tool: impl Into<String>,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        let call = Syscall::CallTool {
            agent_id: agent_id.into(),
            tool: tool.into(),
            args,
        };
        match self.call(call).await? {
            SyscallReply::ToolResult { data } => Ok(data),
            other => Err(unexpected("ToolResult", &other)),
        }
    }

    /// Snapshot the syscall gate's enforcement counters.
    pub async fn gate_stats(&mut self) -> Result<GateStats, SdkError> {
        match self.call(Syscall::GateStats).await? {
            SyscallReply::GateStats {
                allowed,
                denied_capability,
                denied_mac,
                denied_approval,
                denied_cgroup,
                denied_namespace,
                denied_unknown,
                audited,
            } => Ok(GateStats {
                allowed,
                denied_capability,
                denied_mac,
                denied_approval,
                denied_cgroup,
                denied_namespace,
                denied_unknown,
                audited,
            }),
            other => Err(unexpected("GateStats", &other)),
        }
    }

    /// Negotiate the wire protocol with the server.
    ///
    /// Sends [`Syscall::Hello`] with this SDK's [`PROTOCOL_VERSION`] and verifies
    /// the version is inside the server's `[min, max]` support window. Returns
    /// the server's [`ProtocolInfo`] on success, or [`SdkError::IncompatibleProtocol`]
    /// when the windows don't overlap — including the case where the server is too
    /// old to understand `Hello` at all (it answers with an error, which predates
    /// protocol versioning). Call this once right after connecting to fail fast on
    /// a version skew instead of hitting a confusing error on a later syscall.
    pub async fn hello(&mut self) -> Result<ProtocolInfo, SdkError> {
        // Use the raw transport, not `self.call`: the latter folds
        // `SyscallReply::Error` into `SdkError::Kernel`, but here an Error reply
        // is itself a meaningful signal (an old server rejecting the handshake).
        match self
            .inner
            .call(Syscall::Hello {
                protocol_version: PROTOCOL_VERSION,
            })
            .await?
        {
            SyscallReply::Hello {
                protocol_version,
                min_protocol_version,
                server_version,
            } => {
                if (min_protocol_version..=protocol_version).contains(&PROTOCOL_VERSION) {
                    Ok(ProtocolInfo {
                        protocol_version,
                        min_protocol_version,
                        server_version,
                    })
                } else {
                    Err(SdkError::IncompatibleProtocol {
                        client: PROTOCOL_VERSION,
                        server: format!(
                            "v{min_protocol_version}..=v{protocol_version} ({server_version})"
                        ),
                    })
                }
            }
            // A server that predates protocol versioning can't parse `hello` and
            // answers with an error — that itself is the incompatibility signal.
            SyscallReply::Error { message } => Err(SdkError::IncompatibleProtocol {
                client: PROTOCOL_VERSION,
                server: format!("rejected handshake: {message}"),
            }),
            SyscallReply::TypedError { message, .. } => Err(SdkError::IncompatibleProtocol {
                client: PROTOCOL_VERSION,
                server: format!("rejected handshake: {message}"),
            }),
            other => Err(unexpected("Hello", &other)),
        }
    }

    /// Read a kernel node's load/health (agent counts) — used by
    /// [`ClusterClient`](crate::cluster::ClusterClient) for placement.
    pub async fn node_info(&mut self) -> Result<NodeLoad, SdkError> {
        match self.call(Syscall::NodeInfo).await? {
            SyscallReply::NodeInfo {
                agent_count,
                running_agents,
                live_agents,
                queued_agents,
                paused_agents,
                stopped_agents,
                active_turns,
                waiting_turns,
                turn_capacity,
                llm_requests_in_flight,
                llm_requests_waiting,
                llm_core_capacity,
            } => Ok(NodeLoad {
                agent_count,
                running_agents,
                live_agents,
                queued_agents,
                paused_agents,
                stopped_agents,
                active_turns,
                waiting_turns,
                turn_capacity,
                llm_requests_in_flight,
                llm_requests_waiting,
                llm_core_capacity,
            }),
            other => Err(unexpected("NodeInfo", &other)),
        }
    }

    /// Pull the kernel's operational metrics as a Prometheus text exposition
    /// (gate enforcement counters, agent counts, token/api totals, uptime). Lets
    /// a client scrape metrics over the syscall protocol without an HTTP port.
    pub async fn metrics(&mut self) -> Result<Metrics, SdkError> {
        match self.call(Syscall::Metrics).await? {
            SyscallReply::Metrics {
                prometheus,
                agent_count,
                tokens_consumed,
            } => Ok(Metrics {
                prometheus,
                agent_count,
                tokens_consumed,
            }),
            other => Err(unexpected("Metrics", &other)),
        }
    }

    /// List the LLM providers registered with the kernel.
    pub async fn list_providers(&mut self) -> Result<Vec<ProviderSummary>, SdkError> {
        match self.call(Syscall::ListProviders).await? {
            SyscallReply::Providers { providers } => Ok(providers),
            other => Err(unexpected("Providers", &other)),
        }
    }

    /// Store a fact in an agent's long-term memory. `category` is one of
    /// `preference` / `learned_pattern` / `fact` / `instruction` (defaults to
    /// `fact` when `None`). Returns the new fact's id.
    pub async fn memory_store(
        &mut self,
        agent_id: impl Into<String>,
        content: impl Into<String>,
        category: Option<String>,
    ) -> Result<String, SdkError> {
        let call = Syscall::MemoryStore {
            agent_id: agent_id.into(),
            content: content.into(),
            category,
        };
        match self.call(call).await? {
            SyscallReply::MemoryStored { id } => Ok(id),
            other => Err(unexpected("MemoryStored", &other)),
        }
    }

    /// Query an agent's long-term memory by substring (newest first).
    pub async fn memory_query(
        &mut self,
        agent_id: impl Into<String>,
        query: impl Into<String>,
    ) -> Result<Vec<FactSummary>, SdkError> {
        let call = Syscall::MemoryQuery {
            agent_id: agent_id.into(),
            query: query.into(),
        };
        match self.call(call).await? {
            SyscallReply::Memory { facts } => Ok(facts),
            other => Err(unexpected("Memory", &other)),
        }
    }

    /// Put (insert-or-overwrite) a value into an agent's durable key/value store
    /// (the per-agent `agent_kv` table, distinct from long-term memory). `value`
    /// is an opaque string — JSON-encode structured data on the caller side.
    pub async fn storage_put(
        &mut self,
        agent_id: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), SdkError> {
        let call = Syscall::StoragePut {
            agent_id: agent_id.into(),
            key: key.into(),
            value: value.into(),
        };
        match self.call(call).await? {
            SyscallReply::StorageOk => Ok(()),
            other => Err(unexpected("StorageOk", &other)),
        }
    }

    /// Get a value from an agent's key/value store. Returns `None` when the key
    /// is absent.
    pub async fn storage_get(
        &mut self,
        agent_id: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<Option<String>, SdkError> {
        let call = Syscall::StorageGet {
            agent_id: agent_id.into(),
            key: key.into(),
        };
        match self.call(call).await? {
            SyscallReply::StorageValue { value } => Ok(value),
            other => Err(unexpected("StorageValue", &other)),
        }
    }

    /// List the keys in an agent's key/value store.
    pub async fn storage_list(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<Vec<String>, SdkError> {
        let call = Syscall::StorageList {
            agent_id: agent_id.into(),
        };
        match self.call(call).await? {
            SyscallReply::StorageKeys { keys } => Ok(keys),
            other => Err(unexpected("StorageKeys", &other)),
        }
    }

    /// Inspect an agent's active context budget, durable spill usage, and
    /// fail-closed pressure errors without returning prompt content.
    pub async fn context_pressure(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<ContextPressureStats, SdkError> {
        let call = Syscall::ContextPressure {
            agent_id: agent_id.into(),
        };
        match self.call(call).await? {
            SyscallReply::ContextPressure { stats } => Ok(stats),
            other => Err(unexpected("ContextPressure", &other)),
        }
    }

    /// Capture the live, timestamped operations view. Tenant-authenticated
    /// connections receive only tenant-owned agents and omit global counters.
    pub async fn operator_snapshot(&mut self) -> Result<OperatorSnapshot, SdkError> {
        match self.call(Syscall::OperatorSnapshot).await? {
            SyscallReply::OperatorSnapshot { snapshot } => Ok(*snapshot),
            other => Err(unexpected("OperatorSnapshot", &other)),
        }
    }

    pub async fn list_services(&mut self) -> Result<Vec<ServiceRuntimeInfo>, SdkError> {
        match self.call(Syscall::ListServices).await? {
            SyscallReply::Services { services } => Ok(services),
            other => Err(unexpected("Services", &other)),
        }
    }

    pub async fn start_service(
        &mut self,
        name: impl Into<String>,
    ) -> Result<ServiceRuntimeInfo, SdkError> {
        match self
            .call(Syscall::StartService { name: name.into() })
            .await?
        {
            SyscallReply::Service { service } => Ok(service),
            other => Err(unexpected("Service", &other)),
        }
    }

    pub async fn stop_service(
        &mut self,
        name: impl Into<String>,
    ) -> Result<ServiceRuntimeInfo, SdkError> {
        match self
            .call(Syscall::StopService { name: name.into() })
            .await?
        {
            SyscallReply::Service { service } => Ok(service),
            other => Err(unexpected("Service", &other)),
        }
    }

    pub async fn restart_service(
        &mut self,
        name: impl Into<String>,
    ) -> Result<ServiceRuntimeInfo, SdkError> {
        match self
            .call(Syscall::RestartService { name: name.into() })
            .await?
        {
            SyscallReply::Service { service } => Ok(service),
            other => Err(unexpected("Service", &other)),
        }
    }

    /// Delete a key from an agent's key/value store. Returns `true` if the key
    /// existed, `false` otherwise.
    pub async fn storage_delete(
        &mut self,
        agent_id: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<bool, SdkError> {
        let call = Syscall::StorageDelete {
            agent_id: agent_id.into(),
            key: key.into(),
        };
        match self.call(call).await? {
            SyscallReply::StorageDeleted { existed } => Ok(existed),
            other => Err(unexpected("StorageDeleted", &other)),
        }
    }

    /// Capture an agent's current working context under `label` (a point-in-time
    /// snapshot). Overwrites an existing snapshot with the same label.
    pub async fn snapshot_context(
        &mut self,
        agent_id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<(), SdkError> {
        let call = Syscall::SnapshotContext {
            agent_id: agent_id.into(),
            label: label.into(),
        };
        match self.call(call).await? {
            SyscallReply::SnapshotSaved => Ok(()),
            other => Err(unexpected("SnapshotSaved", &other)),
        }
    }

    /// Restore a previously captured snapshot, making it the agent's current
    /// context. Returns the restored context's token count.
    pub async fn restore_snapshot(
        &mut self,
        agent_id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<u32, SdkError> {
        let call = Syscall::RestoreSnapshot {
            agent_id: agent_id.into(),
            label: label.into(),
        };
        match self.call(call).await? {
            SyscallReply::SnapshotRestored { tokens } => Ok(tokens),
            other => Err(unexpected("SnapshotRestored", &other)),
        }
    }

    /// List the snapshot labels stored for an agent, newest first.
    pub async fn list_snapshots(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<Vec<String>, SdkError> {
        let call = Syscall::ListSnapshots {
            agent_id: agent_id.into(),
        };
        match self.call(call).await? {
            SyscallReply::Snapshots { labels } => Ok(labels),
            other => Err(unexpected("Snapshots", &other)),
        }
    }

    /// Delete a snapshot by label. Returns `true` if the snapshot existed,
    /// `false` otherwise.
    pub async fn delete_snapshot(
        &mut self,
        agent_id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<bool, SdkError> {
        let call = Syscall::DeleteSnapshot {
            agent_id: agent_id.into(),
            label: label.into(),
        };
        match self.call(call).await? {
            SyscallReply::SnapshotDeleted { existed } => Ok(existed),
            other => Err(unexpected("SnapshotDeleted", &other)),
        }
    }

    /// Load an agent package from a TOML manifest. The kernel parses and
    /// validates it, then creates the agent through the full admission path and
    /// seeds its memory. Returns the new agent's id.
    pub async fn load_package(
        &mut self,
        manifest_toml: impl Into<String>,
    ) -> Result<String, SdkError> {
        let call = Syscall::LoadPackage {
            manifest_toml: manifest_toml.into(),
        };
        match self.call(call).await? {
            SyscallReply::AgentCreated { id } => Ok(id),
            other => Err(unexpected("AgentCreated", &other)),
        }
    }

    /// Authenticate the connection with the server's shared secret. Required
    /// before any other syscall when the server is configured with a token.
    pub async fn authenticate(&mut self, token: impl Into<String>) -> Result<(), SdkError> {
        match self
            .call(Syscall::Authenticate {
                token: token.into(),
            })
            .await?
        {
            SyscallReply::Authenticated => Ok(()),
            other => Err(unexpected("Authenticated", &other)),
        }
    }

    /// Issue a raw syscall and fold [`SyscallReply::Error`] into [`SdkError`].
    /// Lower-level escape hatch behind every typed method above.
    pub async fn call(&mut self, call: Syscall) -> Result<SyscallReply, SdkError> {
        match self.inner.call(call).await? {
            SyscallReply::Error { message } => Err(SdkError::Kernel(message)),
            SyscallReply::TypedError { message, .. } => Err(SdkError::Kernel(message)),
            reply => Ok(reply),
        }
    }
}

fn unexpected(expected: &'static str, got: &SyscallReply) -> SdkError {
    SdkError::UnexpectedReply {
        expected,
        got: format!("{got:?}"),
    }
}

/// Builder for an [`Agent`]. Obtain one with [`Agent::builder`].
///
/// `name` and `task` are required; `provider` / `profile` / `priority` fall back
/// to the kernel wire defaults (`"stub"` / `"standard"` / `3`) when unset.
#[derive(Debug, Default, Clone)]
pub struct AgentBuilder {
    name: Option<String>,
    task: Option<String>,
    provider: Option<String>,
    profile: Option<String>,
    priority: Option<u8>,
}

impl AgentBuilder {
    /// Set the agent's name (required).
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the agent's task / system prompt (required).
    pub fn task(mut self, task: impl Into<String>) -> Self {
        self.task = Some(task.into());
        self
    }

    /// Set the LLM provider (defaults to `"stub"`).
    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Set the permission profile (defaults to `"standard"`). Determines the
    /// agent's capabilities at the syscall gate (e.g. `"read-only"`).
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the scheduling priority 0..=5 (defaults to `3`).
    pub fn priority(mut self, priority: u8) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Connect to the syscall server at `addr`, create the agent, and return a
    /// live [`Agent`] handle.
    ///
    /// # Errors
    /// Returns [`SdkError::Kernel`] with `"name and task are required"` if either
    /// required field is unset, or any transport / kernel error from creation.
    pub async fn connect(self, addr: impl ToSocketAddrs) -> Result<Agent, SdkError> {
        let client = KernelClient::connect(addr).await?;
        self.create_with(client).await
    }

    /// Create the agent over an already-connected [`KernelClient`], returning a
    /// live [`Agent`] handle that owns the client.
    pub async fn create_with(self, mut client: KernelClient) -> Result<Agent, SdkError> {
        let (name, task) = match (self.name, self.task) {
            (Some(name), Some(task)) => (name, task),
            _ => return Err(SdkError::Kernel("name and task are required".to_string())),
        };
        let id = client
            .create_agent(name, task, self.provider, self.profile, self.priority)
            .await?;
        Ok(Agent { id, client })
    }
}

/// A live agent handle bound to a kernel connection.
///
/// Created via [`Agent::builder`]. Owns its [`KernelClient`], so calls are
/// serialized over the single connection; create a second handle for
/// concurrency.
pub struct Agent {
    id: String,
    client: KernelClient,
}

impl Agent {
    /// Start building an agent.
    pub fn builder() -> AgentBuilder {
        AgentBuilder::default()
    }

    /// This agent's kernel id (a UUID string).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrow the underlying typed client for syscalls not specific to this
    /// agent (e.g. [`KernelClient::gate_stats`] / [`KernelClient::list_agents`]).
    pub fn client(&mut self) -> &mut KernelClient {
        &mut self.client
    }

    /// Drive one think→act→observe turn for this agent.
    pub async fn send(&mut self, message: impl Into<String>) -> Result<MessageResult, SdkError> {
        let id = self.id.clone();
        self.client.send_message(id, message).await
    }

    /// Invoke a tool as this agent (subject to the kernel's syscall gate).
    pub async fn call_tool(
        &mut self,
        tool: impl Into<String>,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        let id = self.id.clone();
        self.client.call_tool(id, tool, args).await
    }

    /// Pause this agent and cooperatively cancel an active turn.
    pub async fn pause(&mut self) -> Result<String, SdkError> {
        self.client.pause_agent(self.id.clone()).await
    }

    /// Resume this agent after a pause.
    pub async fn resume(&mut self) -> Result<String, SdkError> {
        self.client.resume_agent(self.id.clone()).await
    }

    /// Gracefully stop this agent.
    pub async fn stop(&mut self) -> Result<String, SdkError> {
        self.client.stop_agent(self.id.clone()).await
    }

    /// Force this agent into the terminal state.
    pub async fn kill(&mut self) -> Result<String, SdkError> {
        self.client.kill_agent(self.id.clone()).await
    }

    /// Return this agent's current lifecycle state.
    pub async fn status(&mut self) -> Result<String, SdkError> {
        self.client.agent_status(self.id.clone()).await
    }

    /// Wait for this agent to become terminal.
    pub async fn wait(&mut self, timeout: std::time::Duration) -> Result<String, SdkError> {
        self.client.wait_agent(self.id.clone(), timeout).await
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    use async_trait::async_trait;
    use kernel::connector::{
        LlmProviderAdapter, LlmResponse, LlmSession, ProviderType, StandardMessage, ToolDefinition,
    };
    use kernel::syscall_server::SyscallServer;
    use kernel::{AgentKernelImpl, ConnectorError};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct PausableAdapter {
        id: String,
        calls: Arc<AtomicUsize>,
        started: Arc<tokio::sync::Notify>,
    }

    struct PausableSession {
        id: String,
        calls: Arc<AtomicUsize>,
        started: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl LlmSession for PausableSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }

        async fn send_with_tools(
            &self,
            _messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.started.notify_waiters();
                std::future::pending::<()>().await;
            }
            Ok(LlmResponse {
                content: "wire resume complete".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 5,
                usage: kernel::connector::LlmUsage::reported(3, 2, 0),
                tool_calls: Vec::new(),
            })
        }

        fn provider_id(&self) -> &String {
            &self.id
        }

        fn model_id(&self) -> &str {
            "wire-checkpoint-model"
        }
    }

    #[async_trait]
    impl LlmProviderAdapter for PausableAdapter {
        fn id(&self) -> &String {
            &self.id
        }
        fn name(&self) -> &str {
            "pausable"
        }
        fn provider_type(&self) -> ProviderType {
            ProviderType::Cloud
        }
        async fn is_available(&self) -> bool {
            true
        }
        async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
            Ok(Box::new(PausableSession {
                id: self.id.clone(),
                calls: Arc::clone(&self.calls),
                started: Arc::clone(&self.started),
            }))
        }
        fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
            serde_json::json!({"role": message.role, "content": message.content})
        }
        fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
            Some(StandardMessage::assistant(value.get("content")?.as_str()?))
        }
    }

    /// `hello()` negotiates against a current server and returns its window.
    #[tokio::test]
    async fn sdk_hello_negotiates_current_server() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut client = KernelClient::connect(addr).await.expect("connect");
        let info = client.hello().await.expect("hello should negotiate");
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        assert!(info.min_protocol_version <= PROTOCOL_VERSION);
        assert!(!info.server_version.is_empty());
    }

    #[tokio::test]
    async fn sdk_lifecycle_roundtrip_is_typed_idempotent_and_terminal() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut client = KernelClient::connect(addr).await.expect("connect");
        let id = client
            .create_agent("lifecycle-sdk", "test lifecycle", None, None, None)
            .await
            .unwrap();

        assert_eq!(client.agent_status(id.clone()).await.unwrap(), "Running");
        assert_eq!(client.pause_agent(id.clone()).await.unwrap(), "Paused");
        assert_eq!(client.pause_agent(id.clone()).await.unwrap(), "Paused");
        assert!(client.send_message(id.clone(), "blocked").await.is_err());
        assert_eq!(client.resume_agent(id.clone()).await.unwrap(), "Running");
        assert_eq!(client.stop_agent(id.clone()).await.unwrap(), "Stopped");
        assert_eq!(client.stop_agent(id.clone()).await.unwrap(), "Stopped");
        assert_eq!(
            client
                .wait_agent(id, std::time::Duration::from_secs(1))
                .await
                .unwrap(),
            "Stopped"
        );
    }

    #[tokio::test]
    async fn sdk_context_pressure_inspection_is_typed_and_content_free() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut client = KernelClient::connect(addr).await.expect("connect");
        let id = client
            .create_agent("pressure-sdk", "inspect pressure", None, None, None)
            .await
            .unwrap();
        let uuid = id.parse::<kernel::AgentId>().unwrap();
        kernel
            .context_manager
            .kv_put(uuid, "context_spill:test:1", "sensitive prompt content")
            .unwrap();
        kernel
            .context_manager
            .record_context_pressure(uuid, 80, 100, 4, None)
            .unwrap();

        let stats = client.context_pressure(id).await.unwrap();
        assert_eq!(stats.active_tokens, 80);
        assert_eq!(stats.budget_tokens, 100);
        assert_eq!(stats.evicted_messages, 4);
        assert_eq!(stats.stored_spills, 1);
        assert_eq!(stats.stored_spill_bytes, 24);
        let encoded = serde_json::to_string(&stats).unwrap();
        assert!(!encoded.contains("sensitive prompt content"));

        let operations = client.operator_snapshot().await.unwrap();
        assert_eq!(operations.scope, "system");
        assert!(operations
            .agents
            .iter()
            .any(|agent| agent.id == uuid.to_string()));
        assert!(operations.system_metrics.is_some());
        assert!(!serde_json::to_string(&operations)
            .unwrap()
            .contains("sensitive prompt content"));
    }

    #[tokio::test]
    async fn sdk_service_supervisor_uses_public_coordinated_lifecycle() {
        use kernel::init_system::{
            DependencyConfig, ExecConfig, ResourceConfig, RestartPolicy, ServiceConfig, ServiceDef,
            ServiceStatus, ServiceType,
        };

        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        kernel
            .os
            .init
            .lock()
            .await
            .replace_definitions(vec![ServiceDef {
                name: "public-service".into(),
                description: Some("public service test".into()),
                exec: ExecConfig {
                    provider: "stub".into(),
                    system_prompt: "run".into(),
                    tools: Vec::new(),
                    model: None,
                },
                service: ServiceConfig {
                    restart: RestartPolicy::OnFailure,
                    restart_delay_ms: 0,
                    max_restarts: 2,
                    service_type: ServiceType::Simple,
                },
                dependencies: DependencyConfig::default(),
                resources: ResourceConfig::default(),
            }])
            .unwrap();
        let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = KernelClient::connect(addr).await.unwrap();

        assert_eq!(client.list_services().await.unwrap().len(), 1);
        let started = client.start_service("public-service").await.unwrap();
        assert_eq!(started.status, ServiceStatus::Running);
        let first_agent = started.agent_id.unwrap();

        let restarted = client.restart_service("public-service").await.unwrap();
        assert_eq!(restarted.status, ServiceStatus::Running);
        assert_ne!(restarted.agent_id, Some(first_agent));
        assert_eq!(
            client.agent_status(first_agent.to_string()).await.unwrap(),
            "Stopped"
        );

        let stopped = client.stop_service("public-service").await.unwrap();
        assert_eq!(stopped.status, ServiceStatus::Inactive);
        assert!(stopped.agent_id.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sdk_public_pause_returns_durable_id_and_resume_returns_output() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        kernel
            .register_provider(Arc::new(PausableAdapter {
                id: "wire-checkpoint".into(),
                calls: Arc::clone(&calls),
                started: Arc::clone(&started),
            }))
            .unwrap();
        let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut control = KernelClient::connect(addr).await.unwrap();
        let id = control
            .create_agent(
                "public-checkpoint",
                "pause me",
                Some("wire-checkpoint".into()),
                None,
                None,
            )
            .await
            .unwrap();
        let mut sender = KernelClient::connect(addr).await.unwrap();
        let started_wait = started.notified();
        let sending_id = id.clone();
        let sending =
            tokio::spawn(
                async move { sender.send_message(sending_id, "long hosted request").await },
            );
        started_wait.await;

        let paused = control.pause_agent_durable(id.clone()).await.unwrap();
        let checkpoint_id = paused.checkpoint_id.expect("public checkpoint id");
        assert_eq!(paused.state, "Paused");
        assert!(sending
            .await
            .unwrap()
            .unwrap()
            .content
            .contains(&checkpoint_id));
        assert_eq!(
            control
                .list_generation_checkpoints(id.clone())
                .await
                .unwrap()
                .len(),
            1
        );

        let resumed = control
            .resume_generation_checkpoint(id.clone(), checkpoint_id.clone())
            .await
            .unwrap();
        assert_eq!(resumed.state, "Running");
        assert_eq!(
            resumed.resumed_content.as_deref(),
            Some("wire resume complete")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(control
            .list_generation_checkpoints(id.clone())
            .await
            .unwrap()
            .is_empty());
        assert!(control
            .delete_generation_checkpoint(id, checkpoint_id)
            .await
            .unwrap());
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use kernel::syscall_server::SyscallServer;
    use kernel::AgentKernelImpl;
    use std::sync::Arc;

    /// The SDK's `connect_tls` dials a TLS-terminated kernel node and drives it
    /// through the typed client over the encrypted transport.
    #[tokio::test]
    async fn sdk_connect_tls_roundtrip() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
            .expect("private key der");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server config");

        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind_tls(kernel, "127.0.0.1:0", server_config)
            .await
            .expect("bind_tls");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("trust cert");
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let mut client = KernelClient::connect_tls(addr, "localhost", client_config)
            .await
            .expect("sdk connect_tls");

        let id = client
            .create_agent("tls-sdk", "demo", None, None, None)
            .await
            .expect("create agent over TLS");
        let agents = client.list_agents().await.expect("list over TLS");
        assert!(
            agents.iter().any(|a| a.id == id && a.name == "tls-sdk"),
            "agent created over the SDK TLS client should be listed: {agents:?}"
        );
    }
}
