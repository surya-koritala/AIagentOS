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

use kernel::syscall_server::{
    AgentSummary, FactSummary, ProviderSummary, Syscall, SyscallClient, SyscallReply,
};
use tokio::net::ToSocketAddrs;

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

/// Snapshot of the syscall gate's enforcement counters.
#[derive(Debug, Clone, Default)]
pub struct GateStats {
    pub allowed: u64,
    pub denied_capability: u64,
    pub denied_mac: u64,
    pub denied_cgroup: u64,
    pub denied_namespace: u64,
    pub denied_unknown: u64,
    pub audited: u64,
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
        Ok(Self {
            inner: SyscallClient::connect(addr).await?,
        })
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
                denied_cgroup,
                denied_namespace,
                denied_unknown,
                audited,
            } => Ok(GateStats {
                allowed,
                denied_capability,
                denied_mac,
                denied_cgroup,
                denied_namespace,
                denied_unknown,
                audited,
            }),
            other => Err(unexpected("GateStats", &other)),
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
}
