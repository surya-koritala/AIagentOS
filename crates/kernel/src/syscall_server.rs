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
//! This first increment covers the agent-lifecycle syscalls (create / list /
//! send / gate stats). LLM, memory, storage and tool syscalls extend the same
//! [`Syscall`] enum and dispatch table next.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

use crate::agent::AgentKernel;
use crate::connector::ToolCall;
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
}

/// A short, serializable view of an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub state: String,
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
    }
}

/// A bound kernel syscall server. Construct with [`bind`](Self::bind), inspect
/// [`local_addr`](Self::local_addr), then run [`serve`](Self::serve).
pub struct SyscallServer {
    kernel: Arc<AgentKernelImpl>,
    listener: TcpListener,
}

impl SyscallServer {
    /// Bind to `addr` (e.g. `"127.0.0.1:0"` for an ephemeral port).
    pub async fn bind(
        kernel: Arc<AgentKernelImpl>,
        addr: impl ToSocketAddrs,
    ) -> std::io::Result<Self> {
        Ok(Self {
            kernel,
            listener: TcpListener::bind(addr).await?,
        })
    }

    /// The actually-bound address (resolves an ephemeral `:0` port).
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, handling each on its own task. Each
    /// connection is a stream of newline-delimited [`Syscall`] requests.
    pub async fn serve(self) -> std::io::Result<()> {
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let kernel = self.kernel.clone();
            tokio::spawn(async move {
                let _ = Self::handle(kernel, stream).await;
            });
        }
    }

    async fn handle(kernel: Arc<AgentKernelImpl>, stream: TcpStream) -> std::io::Result<()> {
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let reply = match serde_json::from_str::<Syscall>(&line) {
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
/// tests). The wire format is plain JSON, so any client could speak it.
pub struct SyscallClient {
    reader: Lines<BufReader<OwnedReadHalf>>,
    writer: OwnedWriteHalf,
}

impl SyscallClient {
    pub async fn connect(addr: impl ToSocketAddrs) -> std::io::Result<Self> {
        let (read, writer) = TcpStream::connect(addr).await?.into_split();
        Ok(Self {
            reader: BufReader::new(read).lines(),
            writer,
        })
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
