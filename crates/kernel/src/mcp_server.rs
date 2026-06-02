//! MCP server — expose the kernel's own tools over the Model Context Protocol.
//!
//! This is the **server** side of MCP, complementing the client in
//! [`crate::mcp`] (which connects *out* to external tool servers). Here the
//! kernel speaks MCP itself, so any MCP client can `initialize`, list the
//! kernel's tools (`tools/list`), and invoke them (`tools/call`).
//!
//! It is modeled on [`crate::syscall_server`]: a server struct holding an
//! `Arc<AgentKernelImpl>` that dispatches each request through the *same* kernel
//! paths the in-process code uses. In particular, `tools/call` runs through the
//! [`SyscallGate`](crate::syscall_gate::SyscallGate) (capability / MAC / cgroup /
//! namespace) **before** the [`ResourceBroker`], exactly like
//! [`crate::syscall_server`]'s `CallTool` — so a gate denial comes back as a
//! JSON-RPC error, not a bypass. Enforcement holds over the wire.
//!
//! Transport is deliberately dependency-light (tokio + serde_json, both already
//! in the workspace): one JSON-RPC request per line, one JSON-RPC response per
//! line, over TCP. The protocol is the MCP spec's JSON-RPC 2.0 envelope
//! (`jsonrpc` / `id` / `method` / `params`, with `result` / `error`).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, Lines};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

use crate::connector::ToolCall;
use crate::resources::ResourceBroker;
use crate::AgentKernelImpl;

/// The MCP protocol version this server implements (the spec revision the
/// in-tree client also negotiates against; see [`crate::mcp`]).
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Standard JSON-RPC 2.0 error codes (plus the spec's reserved range), used in
/// [`JsonRpcError::code`].
pub mod error_codes {
    /// Invalid JSON was received by the server.
    pub const PARSE_ERROR: i64 = -32700;
    /// The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// The method does not exist / is not supported.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Invalid method parameter(s).
    pub const INVALID_PARAMS: i64 = -32602;
    /// Internal JSON-RPC / server error (used for kernel-side failures,
    /// including a gate denial surfaced as an error).
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// A JSON-RPC 2.0 request. `id` is absent for notifications; we accept it as an
/// arbitrary JSON value (number or string per the spec) and echo it back.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC 2.0 response — exactly one of `result` / `error` is set.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Dispatch a single MCP JSON-RPC request against the kernel.
///
/// Pure routing: every method goes through the same `AgentKernelImpl` surfaces
/// the in-process code uses. `tools/call` in particular runs the syscall gate
/// before the resource broker, so capability / MAC / cgroup / namespace checks
/// apply — a denial becomes a JSON-RPC error (never a bypass or a panic).
///
/// Returns `None` for a notification (a request with no `id`), which by the
/// JSON-RPC spec must not produce a response.
pub async fn dispatch(kernel: &AgentKernelImpl, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
    // A request with no `id` is a notification: act on nothing, answer nothing.
    // (`notifications/initialized` from a client lands here.)
    req.id.as_ref()?;
    let id = req.id.clone();

    if req.jsonrpc != "2.0" {
        return Some(JsonRpcResponse::err(
            id,
            error_codes::INVALID_REQUEST,
            format!("unsupported jsonrpc version: {}", req.jsonrpc),
        ));
    }

    let resp = match req.method.as_str() {
        "initialize" => handle_initialize(),
        "tools/list" => handle_tools_list(kernel),
        "tools/call" => handle_tools_call(kernel, req.params).await,
        other => Err((
            error_codes::METHOD_NOT_FOUND,
            format!("method not found: {other}"),
        )),
    };

    Some(match resp {
        Ok(result) => JsonRpcResponse::ok(id, result),
        Err((code, message)) => JsonRpcResponse::err(id, code, message),
    })
}

/// `initialize`: announce the protocol version, our tool capability, and server
/// identity. Mirrors the handshake the in-tree MCP client expects.
fn handle_initialize() -> Result<Value, (i64, String)> {
    Ok(json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "ai-agent-os-kernel", "version": "0.1.0" }
    }))
}

/// `tools/list`: enumerate the kernel's registered tools as MCP tool
/// descriptors (`name` / `description` / `inputSchema`). Sourced from the same
/// `tool_registry` the executor resolves against.
fn handle_tools_list(kernel: &AgentKernelImpl) -> Result<Value, (i64, String)> {
    let tools: Vec<Value> = kernel
        .tool_registry
        .definitions()
        .into_iter()
        .map(|d| {
            json!({
                "name": d.name,
                "description": d.description,
                "inputSchema": d.parameters,
            })
        })
        .collect();
    Ok(json!({ "tools": tools }))
}

/// `tools/call`: invoke a named tool as a given agent, **through the syscall
/// gate then the resource broker** — the exact ordering of
/// [`crate::syscall_server`]'s `CallTool`. Params:
///
/// - `name` (string, required): the tool to call.
/// - `arguments` (object, optional): tool arguments.
/// - `agent_id` (string UUID, required): the calling agent's identity; the gate
///   resolves its capabilities / namespaces from this.
///
/// A gate denial is returned as an `INTERNAL_ERROR` JSON-RPC error. On success
/// the result follows the MCP `content` shape (a single `text` block carrying
/// the tool's JSON output) plus a raw `data` field for structured consumers.
async fn handle_tools_call(
    kernel: &AgentKernelImpl,
    params: Option<Value>,
) -> Result<Value, (i64, String)> {
    let params = params.unwrap_or(Value::Null);

    let tool = match params.get("name").and_then(|v| v.as_str()) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => {
            return Err((
                error_codes::INVALID_PARAMS,
                "missing required 'name' (tool name)".to_string(),
            ))
        }
    };

    let agent_id_str = match params.get("agent_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return Err((
                error_codes::INVALID_PARAMS,
                "missing required 'agent_id' (calling agent identity)".to_string(),
            ))
        }
    };
    let agent_id = match uuid::Uuid::parse_str(agent_id_str) {
        Ok(id) => id,
        Err(_) => {
            return Err((
                error_codes::INVALID_PARAMS,
                format!("invalid agent_id: {agent_id_str}"),
            ))
        }
    };

    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    // Token estimate + representative resource, mirroring the executor's tool
    // path (and syscall_server's CallTool) so gate accounting / MAC matching are
    // consistent across the in-process, syscall, and MCP entry points.
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
        .check_tool_call(agent_id, &tool, &resource, est_tokens)
        .await
    {
        return Err((
            error_codes::INTERNAL_ERROR,
            format!("tool '{tool}' denied by kernel: {}", denial.message()),
        ));
    }

    let call = ToolCall {
        id: "mcp".into(),
        name: tool.clone(),
        arguments: args,
    };

    let result = match kernel.tool_registry.resolve(agent_id, &call) {
        Some(request) => match kernel.resource_broker.execute(request).await {
            Ok(resp) if resp.success => {
                let data = resp.data;
                let text = match &data {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                Ok(json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false,
                    "data": data,
                }))
            }
            Ok(resp) => Err((
                error_codes::INTERNAL_ERROR,
                format!("tool '{tool}' failed: {}", resp.error.unwrap_or_default()),
            )),
            Err(e) => Err((
                error_codes::INTERNAL_ERROR,
                format!("tool '{tool}' error: {e}"),
            )),
        },
        None => Err((
            error_codes::METHOD_NOT_FOUND,
            format!("unknown tool '{tool}'"),
        )),
    };

    // Record usage even on a broker-level failure — the gate already admitted
    // the call (matches syscall_server's CallTool accounting).
    kernel.syscall_gate.record_tool_usage(agent_id, est_tokens);
    result
}

/// A bound MCP server. Construct with [`bind`](Self::bind) (TCP), inspect
/// [`local_addr`](Self::local_addr), then run [`serve`](Self::serve).
pub struct McpServer {
    kernel: Arc<AgentKernelImpl>,
    listener: TcpListener,
}

impl McpServer {
    /// Bind a TCP listener to `addr` (e.g. `"127.0.0.1:0"` for an ephemeral port).
    pub async fn bind(
        kernel: Arc<AgentKernelImpl>,
        addr: impl ToSocketAddrs,
    ) -> std::io::Result<Self> {
        Ok(Self {
            kernel,
            listener: TcpListener::bind(addr).await?,
        })
    }

    /// The actually-bound TCP address (resolves an ephemeral `:0` port).
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, handling each on its own task. Each
    /// connection is a stream of newline-delimited JSON-RPC requests.
    pub async fn serve(self) -> std::io::Result<()> {
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let kernel = self.kernel.clone();
            tokio::spawn(async move {
                let (read, write) = stream.into_split();
                let _ = Self::handle(kernel, read, write).await;
            });
        }
    }

    /// Serve one connection: a stream of newline-delimited JSON-RPC requests
    /// over any async read/write pair. A malformed line yields a JSON-RPC error
    /// response (parse error) rather than dropping the connection; a
    /// notification (no `id`) produces no response.
    async fn handle<R, W>(
        kernel: Arc<AgentKernelImpl>,
        read: R,
        mut write: W,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut lines = BufReader::new(read).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
                Ok(req) => dispatch(&kernel, req).await,
                Err(e) => Some(JsonRpcResponse::err(
                    None,
                    error_codes::PARSE_ERROR,
                    format!("parse error: {e}"),
                )),
            };
            // Notifications (and only notifications) produce no reply.
            if let Some(response) = response {
                let mut buf = serde_json::to_vec(&response).unwrap_or_else(|_| {
                    br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"serialization failed"}}"#.to_vec()
                });
                buf.push(b'\n');
                write.write_all(&buf).await?;
                write.flush().await?;
            }
        }
        Ok(())
    }
}

/// A thin MCP client for the server (used by round-trip tests; the wire format
/// is plain JSON-RPC, so any MCP client could speak it).
pub struct McpClient {
    reader: Lines<BufReader<Box<dyn AsyncRead + Unpin + Send>>>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    next_id: u64,
}

impl McpClient {
    /// Connect over TCP.
    pub async fn connect(addr: impl ToSocketAddrs) -> std::io::Result<Self> {
        let (read, writer) = TcpStream::connect(addr).await?.into_split();
        Ok(Self {
            reader: BufReader::new(Box::new(read) as Box<dyn AsyncRead + Unpin + Send>).lines(),
            writer: Box::new(writer),
            next_id: 1,
        })
    }

    /// Send a JSON-RPC request (auto-assigning an incrementing `id`) and await
    /// its response.
    pub async fn request(
        &mut self,
        method: &str,
        params: Option<Value>,
    ) -> std::io::Result<JsonRpcResponse> {
        let id = self.next_id;
        self.next_id += 1;
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(id)),
            method: method.to_string(),
            params,
        };
        self.send_value(&serde_json::to_value(&req).map_err(std::io::Error::other)?)
            .await?;
        self.read_response().await
    }

    /// Send a raw JSON value as one line (used by tests to exercise malformed /
    /// notification inputs the typed API can't express).
    pub async fn send_value(&mut self, value: &Value) -> std::io::Result<()> {
        let mut buf = serde_json::to_vec(value).map_err(std::io::Error::other)?;
        buf.push(b'\n');
        self.writer.write_all(&buf).await?;
        self.writer.flush().await
    }

    /// Send a raw line verbatim (e.g. invalid JSON), no trailing-newline added
    /// beyond the one provided here.
    pub async fn send_line(&mut self, line: &str) -> std::io::Result<()> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await
    }

    /// Read one JSON-RPC response line.
    pub async fn read_response(&mut self) -> std::io::Result<JsonRpcResponse> {
        let line = self.reader.next_line().await?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "server closed")
        })?;
        serde_json::from_str(&line).map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentConfig, Priority};

    async fn spawn_server() -> (Arc<AgentKernelImpl>, std::net::SocketAddr) {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = McpServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .expect("bind");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        (kernel, addr)
    }

    async fn create_agent(kernel: &AgentKernelImpl, profile: &str) -> uuid::Uuid {
        let config = AgentConfig {
            name: "t".into(),
            task: "t".into(),
            llm_provider: "stub".into(),
            permission_profile: profile.into(),
            priority: Priority::new(3).unwrap(),
            sandbox_config: None,
        };
        kernel.create_agent_full(config).await.expect("create").id
    }

    #[tokio::test]
    async fn initialize_roundtrips() {
        let (_kernel, addr) = spawn_server().await;
        let mut client = McpClient::connect(addr).await.unwrap();

        let resp = client
            .request(
                "initialize",
                Some(json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0.0.0"}
                })),
            )
            .await
            .unwrap();

        assert!(resp.error.is_none(), "initialize errored: {:?}", resp.error);
        let result = resp.result.expect("initialize result");
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], "ai-agent-os-kernel");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn tools_list_returns_nonempty() {
        let (_kernel, addr) = spawn_server().await;
        let mut client = McpClient::connect(addr).await.unwrap();

        let resp = client.request("tools/list", None).await.unwrap();
        assert!(resp.error.is_none(), "tools/list errored: {:?}", resp.error);
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
        assert!(!tools.is_empty(), "expected built-in tools");
        // Built-ins must be present with MCP-shaped descriptors.
        let read = tools
            .iter()
            .find(|t| t["name"] == "read_file")
            .expect("read_file should be listed");
        assert!(read["description"].as_str().unwrap().contains("Read"));
        assert!(read["inputSchema"]["properties"]["path"].is_object());
    }

    #[tokio::test]
    async fn tools_call_denied_for_readonly_agent() {
        let (kernel, addr) = spawn_server().await;
        // A read-only agent lacks CAP_FILE_WRITE.
        let id = create_agent(&kernel, "read-only").await;
        let mut client = McpClient::connect(addr).await.unwrap();

        let resp = client
            .request(
                "tools/call",
                Some(json!({
                    "name": "write_file",
                    "agent_id": id.to_string(),
                    "arguments": {"path": "/tmp/x", "content": "y"}
                })),
            )
            .await
            .unwrap();

        // The gate denial must arrive as a JSON-RPC error, not a result.
        assert!(resp.result.is_none(), "expected no result on denial");
        let err = resp.error.expect("expected a JSON-RPC error");
        assert_eq!(err.code, error_codes::INTERNAL_ERROR);
        assert!(
            err.message.contains("denied by kernel"),
            "expected kernel denial, got: {}",
            err.message
        );

        // And the gate's counters reflect the denial happening on this path.
        assert!(kernel.syscall_gate.stats().denied_capability >= 1);
    }

    #[tokio::test]
    async fn malformed_request_yields_error_not_disconnect() {
        let (_kernel, addr) = spawn_server().await;
        let mut client = McpClient::connect(addr).await.unwrap();

        // Invalid JSON ⇒ a parse-error response, connection stays open.
        client.send_line("{not json}").await.unwrap();
        let resp = client.read_response().await.unwrap();
        let err = resp.error.expect("expected parse error");
        assert_eq!(err.code, error_codes::PARSE_ERROR);

        // The same connection still answers a valid request afterwards.
        let ok = client.request("tools/list", None).await.unwrap();
        assert!(ok.error.is_none());
        assert!(ok.result.unwrap()["tools"].as_array().unwrap().len() >= 5);
    }

    #[tokio::test]
    async fn unknown_method_yields_method_not_found() {
        let (_kernel, addr) = spawn_server().await;
        let mut client = McpClient::connect(addr).await.unwrap();

        let resp = client.request("does/not/exist", None).await.unwrap();
        let err = resp.error.expect("expected method-not-found");
        assert_eq!(err.code, error_codes::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn tools_call_missing_agent_id_is_invalid_params() {
        let (_kernel, addr) = spawn_server().await;
        let mut client = McpClient::connect(addr).await.unwrap();

        let resp = client
            .request(
                "tools/call",
                Some(json!({ "name": "read_file", "arguments": {"path": "/tmp/x"} })),
            )
            .await
            .unwrap();
        let err = resp.error.expect("expected invalid-params");
        assert_eq!(err.code, error_codes::INVALID_PARAMS);
        assert!(err.message.contains("agent_id"));
    }

    #[tokio::test]
    async fn notification_produces_no_response() {
        let (_kernel, addr) = spawn_server().await;
        let mut client = McpClient::connect(addr).await.unwrap();

        // A request with no `id` is a notification — it must not be answered.
        client
            .send_value(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await
            .unwrap();

        // Follow it with a real request; the only line we read back is its
        // response (proving the notification produced nothing).
        let resp = client.request("tools/list", None).await.unwrap();
        assert!(resp.error.is_none());
        assert_eq!(resp.id, Some(json!(1)));
    }

    #[test]
    fn jsonrpc_wire_shape_is_2_0() {
        let resp = JsonRpcResponse::ok(Some(json!(7)), json!({"ok": true}));
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["ok"], true);
        assert!(v.get("error").is_none());
    }
}
