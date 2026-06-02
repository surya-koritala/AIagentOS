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
use crate::connector::{AgentConnector, ToolCall};
use crate::context::{ContextManager, Fact, FactCategory};
use crate::resources::ResourceBroker;
use crate::{AgentConfig, AgentKernelImpl, Priority};

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
    /// Drive one think→act→observe turn for an agent (LLM-backed).
    SendMessage { agent_id: String, message: String },
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
    AgentInfo { agent_id: String },
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
    MemoryQuery { agent_id: String, query: String },
    /// Authenticate the connection with the server's shared secret. Required as
    /// the first syscall when the server is configured with a token; a no-op
    /// (always accepted) when it is not.
    Authenticate { token: String },
    /// Load an agent package from a TOML manifest (see `crate::agent_package`):
    /// parse + validate, then create the agent through the full admission path
    /// and seed its memory. Replies with the new agent's id (`AgentCreated`).
    /// Running the package's entry prompt is left to the in-process runner.
    LoadPackage { manifest_toml: String },
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
    /// The connection is authenticated (reply to [`Syscall::Authenticate`]).
    Authenticated,
    /// Any error is surfaced to the caller rather than dropping the connection.
    Error {
        message: String,
    },
}

/// Dispatch a single syscall against the kernel. Pure routing — every call goes
/// through the same `AgentKernelImpl` methods the in-process paths use, so the
/// syscall gate's capability/MAC/cgroup/namespace checks still apply.
pub async fn dispatch(kernel: &AgentKernelImpl, call: Syscall) -> SyscallReply {
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
            match kernel.create_agent_full(config).await {
                Ok(handle) => SyscallReply::AgentCreated {
                    id: handle.id.to_string(),
                },
                Err(e) => SyscallReply::Error {
                    message: e.to_string(),
                },
            }
        }
        Syscall::ListAgents => {
            let agents = kernel
                .agent_manager
                .list_agents(None)
                .into_iter()
                .map(|a| AgentSummary {
                    id: a.id.to_string(),
                    name: a.name,
                    state: format!("{:?}", a.state),
                })
                .collect();
            SyscallReply::Agents { agents }
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
            // Token estimate + representative resource, mirroring the executor's
            // tool path so gate accounting/MAC matching are consistent.
            let est_tokens = (args.to_string().len() as u64 / 4)
                .saturating_add(tool.len() as u64 / 4)
                .saturating_add(10);
            let resource = args
                .get("path")
                .or_else(|| args.get("url"))
                .or_else(|| args.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("*")
                .to_string();

            // Enforcement first — a denial never reaches the broker.
            if let Err(denial) = kernel
                .syscall_gate
                .check_tool_call(id, &tool, &resource, est_tokens)
                .await
            {
                return SyscallReply::Error {
                    message: format!("tool '{tool}' denied by kernel: {}", denial.message()),
                };
            }

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
            kernel.syscall_gate.record_tool_usage(id, est_tokens);
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
        // Authentication is handled at the connection layer (see
        // `SyscallServer::handle`); reaching dispatch means it is accepted.
        Syscall::Authenticate { .. } => SyscallReply::Authenticated,
        Syscall::LoadPackage { manifest_toml } => {
            match crate::agent_package::AgentManifest::from_toml_str(&manifest_toml) {
                Ok(manifest) => match crate::agent_package::load_package(kernel, &manifest).await {
                    Ok(handle) => SyscallReply::AgentCreated {
                        id: handle.id.to_string(),
                    },
                    Err(e) => SyscallReply::Error {
                        message: format!("load package failed: {e}"),
                    },
                },
                Err(e) => SyscallReply::Error {
                    message: format!("invalid package: {e}"),
                },
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

/// The transport a [`SyscallServer`] is bound to.
enum Listener {
    Tcp(TcpListener),
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
        // No token configured ⇒ authenticated from the start.
        let mut authed = auth.is_none();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let reply = match serde_json::from_str::<Syscall>(&line) {
                Ok(Syscall::Authenticate { token }) => match &auth {
                    Some(expected) if token == **expected => {
                        authed = true;
                        SyscallReply::Authenticated
                    }
                    Some(_) => SyscallReply::Error {
                        message: "authentication failed".into(),
                    },
                    None => SyscallReply::Authenticated,
                },
                Ok(_) if !authed => SyscallReply::Error {
                    message: "authentication required".into(),
                },
                Ok(call) => dispatch(&kernel, call).await,
                Err(e) => SyscallReply::Error {
                    message: format!("bad request: {e}"),
                },
            };
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
