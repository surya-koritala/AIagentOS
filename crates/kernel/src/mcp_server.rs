//! MCP server — expose the kernel's own tools over the Model Context Protocol.
//!
//! This is the **server** side of MCP, complementing the client in
//! [`crate::mcp`] (which connects *out* to external tool servers). Here the
//! kernel speaks MCP itself. Any client can negotiate with `initialize`, but it
//! must bind the connection to an authenticated, tenant-owned agent through
//! `agentos/authenticate` before it can list (`tools/list`) or invoke
//! (`tools/call`) tools.
//!
//! It is modeled on [`crate::syscall_server`]: a server struct holding an
//! `Arc<AgentKernelImpl>` that dispatches each request through the *same* kernel
//! paths the in-process code uses. In particular, `tools/call` runs through the
//! [`SyscallGate`](crate::syscall_gate::SyscallGate) (capability / MAC / approval /
//! cgroup / namespace) **before** the [`ResourceBroker`], exactly like
//! [`crate::syscall_server`]'s `CallTool` — so a gate denial comes back as a
//! JSON-RPC error, not a bypass. Enforcement holds over the wire.
//!
//! Transport is deliberately dependency-light (tokio + serde_json, both already
//! in the workspace): one JSON-RPC request per line, one JSON-RPC response per
//! line, over loopback TCP. Credentials are carried inside the JSON stream, so
//! this plaintext transport deliberately rejects non-loopback binds; remote MCP
//! exposure requires a future TLS transport. The protocol is the MCP spec's
//! JSON-RPC 2.0 envelope (`jsonrpc` / `id` / `method` / `params`, with `result`
//! / `error`).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::Semaphore;

use crate::auth::Role;
use crate::resources::ResourceBroker;
use crate::wire_io::{graceful_close_framed, read_bounded_line, write_bounded_json};
use crate::{AgentId, AgentKernelImpl};

/// Default simultaneous MCP connection limit.
pub use crate::wire_io::DEFAULT_MAX_CONNECTIONS as DEFAULT_MCP_MAX_CONNECTIONS;
/// Maximum duration of the MCP client half-close / peer-EOF handshake.
pub use crate::wire_io::GRACEFUL_CLOSE_TIMEOUT as MCP_GRACEFUL_CLOSE_TIMEOUT;
/// Maximum time for the first MCP frame.
pub use crate::wire_io::HANDSHAKE_TIMEOUT as MCP_HANDSHAKE_TIMEOUT;
/// Maximum idle time between MCP frames.
pub use crate::wire_io::IDLE_TIMEOUT as MCP_IDLE_TIMEOUT;
/// Maximum serialized MCP JSON-RPC request or response frame.
pub use crate::wire_io::MAX_JSON_FRAME_BYTES as MAX_MCP_FRAME_BYTES;
/// Recommended maximum interval between MCP ping requests.
pub use crate::wire_io::RECOMMENDED_KEEPALIVE_INTERVAL as MCP_KEEPALIVE_INTERVAL;
/// Maximum wall-clock duration of one MCP request.
pub use crate::wire_io::REQUEST_TIMEOUT as MCP_REQUEST_TIMEOUT;

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
    /// The connection has no currently valid authenticated identity.
    pub const AUTHENTICATION_REQUIRED: i64 = -32001;
    /// A presented credential was invalid.
    pub const AUTHENTICATION_FAILED: i64 = -32002;
    /// The authenticated principal cannot act as the requested agent.
    pub const AUTHORIZATION_DENIED: i64 = -32003;
}

/// A JSON-RPC 2.0 request. `id` is absent for notifications; we accept it as an
/// arbitrary JSON value (number or string per the spec) and echo it back.
#[derive(Clone, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl std::fmt::Debug for JsonRpcRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut params = self.params.clone();
        if self.method == "agentos/authenticate" {
            if let Some(object) = params.as_mut().and_then(Value::as_object_mut) {
                if object.contains_key("token") {
                    object.insert("token".into(), json!("[REDACTED]"));
                }
            }
        } else if self.method == "tools/call" {
            if let Some(object) = params.as_mut().and_then(Value::as_object_mut) {
                if object.contains_key("arguments") {
                    object.insert("arguments".into(), json!("[REDACTED]"));
                }
            }
        }
        formatter
            .debug_struct("JsonRpcRequest")
            .field("jsonrpc", &self.jsonrpc)
            .field("id", &self.id)
            .field("method", &self.method)
            .field("params", &params)
            .finish()
    }
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

#[derive(Debug, Default)]
enum ConnectionIdentity {
    #[default]
    Unauthenticated,
    Credential {
        credential: crate::auth::CredentialIdentity,
        agent_id: AgentId,
    },
}

/// Dispatch a single MCP JSON-RPC request against the kernel.
///
/// This stateless entry point starts unauthenticated. The TCP server uses the
/// same dispatcher with connection-local identity state so a successful
/// `agentos/authenticate` binds subsequent requests to one agent.
///
/// Returns `None` for a notification (a request with no `id`), which by the
/// JSON-RPC spec must not produce a response.
pub async fn dispatch(kernel: &AgentKernelImpl, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
    let mut identity = ConnectionIdentity::Unauthenticated;
    dispatch_for_connection(kernel, req, &mut identity).await
}

async fn dispatch_for_connection(
    kernel: &AgentKernelImpl,
    req: JsonRpcRequest,
    identity: &mut ConnectionIdentity,
) -> Option<JsonRpcResponse> {
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
        "initialize" => handle_initialize(req.params),
        // MCP 2024-11-05 permits ping before initialization. It has no
        // parameters or side effects and promptly returns an empty result.
        "ping" => Ok(json!({})),
        "agentos/authenticate" => handle_authenticate(kernel, identity, req.params).await,
        "tools/list" | "tools/call" => {
            handle_authenticated_method(kernel, identity, &req.method, req.params).await
        }
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

async fn handle_authenticate(
    kernel: &AgentKernelImpl,
    identity: &mut ConnectionIdentity,
    params: Option<Value>,
) -> Result<Value, (i64, String)> {
    // Every authentication attempt replaces the connection identity. Invalid
    // parameters or credentials must not leave a previous principal active.
    *identity = ConnectionIdentity::Unauthenticated;
    let params = params.unwrap_or(Value::Null);
    let token = params
        .get("token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            (
                error_codes::INVALID_PARAMS,
                "missing required 'token'".to_string(),
            )
        })?;
    let agent_id = params
        .get("agent_id")
        .and_then(Value::as_str)
        .filter(|agent_id| !agent_id.is_empty())
        .ok_or_else(|| {
            (
                error_codes::INVALID_PARAMS,
                "missing required 'agent_id'".to_string(),
            )
        })
        .and_then(|agent_id| {
            uuid::Uuid::parse_str(agent_id).map_err(|_| {
                (
                    error_codes::INVALID_PARAMS,
                    "invalid 'agent_id'".to_string(),
                )
            })
        })?;

    let Some(principal) = kernel.resolve_principal(token).await else {
        return Err((
            error_codes::AUTHENTICATION_FAILED,
            "authentication failed".to_string(),
        ));
    };
    let owns_agent = matches!(
        kernel.context_manager.agent_tenant(agent_id),
        Ok(Some(ref tenant_id)) if tenant_id == &principal.tenant_id
    ) && kernel.syscall_gate.pid_of(agent_id).is_some();
    if !owns_agent {
        tracing::warn!(
            target: "agentos::authorization",
            user_id = %principal.user_id,
            tenant_id = %principal.tenant_id,
            agent_id = %agent_id,
            "MCP authentication denied for absent or foreign agent"
        );
        return Err((
            error_codes::AUTHORIZATION_DENIED,
            "authorization denied".to_string(),
        ));
    }
    let credential = principal
        .credential
        .clone()
        .expect("wire-authenticated principals always carry a credential identity");

    *identity = ConnectionIdentity::Credential {
        credential,
        agent_id,
    };
    Ok(json!({ "authenticated": true, "agent_id": agent_id }))
}

async fn handle_authenticated_method(
    kernel: &AgentKernelImpl,
    identity: &mut ConnectionIdentity,
    method: &str,
    params: Option<Value>,
) -> Result<Value, (i64, String)> {
    let (credential, agent_id) = match identity {
        ConnectionIdentity::Credential {
            credential,
            agent_id,
        } => (credential.clone(), *agent_id),
        ConnectionIdentity::Unauthenticated => {
            return Err((
                error_codes::AUTHENTICATION_REQUIRED,
                "authentication required".to_string(),
            ))
        }
    };

    // Admit this credential and re-resolve its current principal under a short
    // auth read lock. The per-credential lease, not the global auth lock, stays
    // alive through dispatch. Revocation closes this identity and waits only for
    // its admitted calls.
    let Some((principal, _credential_lease)) =
        kernel.acquire_credential_principal(&credential).await
    else {
        *identity = ConnectionIdentity::Unauthenticated;
        return Err((
            error_codes::AUTHENTICATION_REQUIRED,
            "authentication required".to_string(),
        ));
    };
    let owns_agent = matches!(
        kernel.context_manager.agent_tenant(agent_id),
        Ok(Some(ref tenant_id)) if tenant_id == &principal.tenant_id
    ) && kernel.syscall_gate.pid_of(agent_id).is_some();
    if !owns_agent {
        *identity = ConnectionIdentity::Unauthenticated;
        return Err((
            error_codes::AUTHORIZATION_DENIED,
            "authorization denied".to_string(),
        ));
    }

    match method {
        "tools/list" => handle_tools_list(kernel, agent_id),
        "tools/call" if matches!(principal.role, Role::Admin | Role::User) => {
            handle_tools_call(kernel, agent_id, params).await
        }
        "tools/call" => Err((
            error_codes::AUTHORIZATION_DENIED,
            "authorization denied".to_string(),
        )),
        _ => unreachable!("only protected MCP methods are routed here"),
    }
}

/// `initialize`: announce the protocol version, our tool capability, and server
/// identity. Mirrors the handshake the in-tree MCP client expects.
fn handle_initialize(params: Option<Value>) -> Result<Value, (i64, String)> {
    if let Some(requested) = params
        .as_ref()
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str)
    {
        if requested != PROTOCOL_VERSION {
            return Err((
                error_codes::INVALID_PARAMS,
                format!(
                    "unsupported MCP protocol version: client requested {requested}, server supports {PROTOCOL_VERSION}"
                ),
            ));
        }
    }
    Ok(json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "ai-agent-os-kernel", "version": env!("CARGO_PKG_VERSION") }
    }))
}

/// `tools/list`: enumerate the kernel's registered tools as MCP tool
/// descriptors (`name` / `description` / `inputSchema`). Sourced from the same
/// `tool_registry` the executor resolves against and filtered to the bound
/// agent's namespace memberships.
fn handle_tools_list(kernel: &AgentKernelImpl, agent_id: AgentId) -> Result<Value, (i64, String)> {
    let tools: Vec<Value> = kernel
        .tool_registry
        .definitions_for_agent(&kernel.syscall_gate, agent_id)
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

/// `tools/call`: invoke a named tool as the connection-bound agent, **through the syscall
/// gate then the resource broker** — the exact ordering of
/// [`crate::syscall_server`]'s `CallTool`. Params:
///
/// - `name` (string, required): the tool to call.
/// - `arguments` (object, optional): tool arguments.
/// - `agent_id` (string UUID, optional compatibility assertion): when present,
///   it must exactly match the identity already bound to this connection.
///
/// A gate denial is returned as an `AUTHORIZATION_DENIED` JSON-RPC error. On success
/// the result follows the MCP `content` shape (a single `text` block carrying
/// the tool's JSON output) plus a raw `data` field for structured consumers.
async fn handle_tools_call(
    kernel: &AgentKernelImpl,
    agent_id: AgentId,
    params: Option<Value>,
) -> Result<Value, (i64, String)> {
    let params = params.unwrap_or(Value::Null);

    if let Some(asserted_agent) = params.get("agent_id") {
        let matches_bound_agent = asserted_agent
            .as_str()
            .and_then(|agent_id| uuid::Uuid::parse_str(agent_id).ok())
            == Some(agent_id);
        if !matches_bound_agent {
            return Err((
                error_codes::AUTHORIZATION_DENIED,
                "authorization denied".to_string(),
            ));
        }
    }

    let tool = match params.get("name").and_then(|v| v.as_str()) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => {
            return Err((
                error_codes::INVALID_PARAMS,
                "missing required 'name' (tool name)".to_string(),
            ))
        }
    };

    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    // Registry-declared security preparation is shared byte-for-byte with the
    // executor, JSON syscall wire, and SDK-backed client path.
    let (prepared_tool, _tool_slot) = kernel
        .tool_registry
        .authorize_and_acquire_call(&kernel.syscall_gate, agent_id, &tool, &args)
        .await
        .map_err(|error| match error {
            crate::tools::ToolAuthorizationError::InvalidDeclaration(error)
                if error == crate::tools::TOOL_NOT_FOUND_ERROR =>
            {
                (error_codes::INVALID_PARAMS, error)
            }
            crate::tools::ToolAuthorizationError::InvalidDeclaration(error) => (
                error_codes::INVALID_PARAMS,
                format!("tool '{tool}' denied by kernel: {error}"),
            ),
            crate::tools::ToolAuthorizationError::Denied(denial) => (
                error_codes::AUTHORIZATION_DENIED,
                format!("tool '{tool}' denied by kernel: {}", denial.message()),
            ),
        })?;

    let result = match kernel.resource_broker.execute(prepared_tool.request).await {
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
    };

    result
}

/// A bound MCP server. Construct with [`bind`](Self::bind) (TCP), inspect
/// [`local_addr`](Self::local_addr), then run [`serve`](Self::serve).
pub struct McpServer {
    kernel: Arc<AgentKernelImpl>,
    listener: TcpListener,
    connection_limit: Arc<Semaphore>,
    idle_timeout: std::time::Duration,
}

impl McpServer {
    /// Bind a plaintext TCP listener to a loopback address (for example,
    /// `"127.0.0.1:0"` for an ephemeral port).
    ///
    /// API keys/session tokens are presented inside this protocol, so
    /// unspecified or externally reachable addresses fail closed. Remote MCP
    /// service must wait for a transport that provides TLS.
    pub async fn bind(
        kernel: Arc<AgentKernelImpl>,
        addr: impl ToSocketAddrs,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        if !local_addr.ip().is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "plaintext MCP may bind only to loopback addresses, not {}",
                    local_addr.ip()
                ),
            ));
        }
        Ok(Self {
            kernel,
            listener,
            connection_limit: Arc::new(Semaphore::new(DEFAULT_MCP_MAX_CONNECTIONS)),
            idle_timeout: MCP_IDLE_TIMEOUT,
        })
    }

    /// Override the number of simultaneously admitted MCP connections.
    pub fn with_connection_limit(mut self, max_connections: usize) -> Self {
        self.connection_limit = Arc::new(Semaphore::new(max_connections.max(1)));
        self
    }

    /// Override the established MCP connection idle deadline.
    ///
    /// The public contract reports the 300-second default. Zero is clamped to
    /// one millisecond.
    pub fn with_idle_timeout(mut self, idle_timeout: std::time::Duration) -> Self {
        self.idle_timeout = idle_timeout.max(std::time::Duration::from_millis(1));
        self
    }

    /// The actually-bound TCP address (resolves an ephemeral `:0` port).
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, handling each on its own task. Each
    /// connection is a stream of newline-delimited JSON-RPC requests.
    pub async fn serve(self) -> std::io::Result<()> {
        let idle_timeout = self.idle_timeout;
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let Ok(connection_permit) = self.connection_limit.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let kernel = self.kernel.clone();
            tokio::spawn(async move {
                let _connection_permit = connection_permit;
                let (read, write) = stream.into_split();
                let _ = Self::handle(kernel, read, write, idle_timeout).await;
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
        idle_timeout: std::time::Duration,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(read);
        let mut identity = ConnectionIdentity::Unauthenticated;
        let mut first_frame = true;
        loop {
            let timeout = if first_frame {
                MCP_HANDSHAKE_TIMEOUT
            } else {
                idle_timeout
            };
            let line = match tokio::time::timeout(
                timeout,
                read_bounded_line(&mut reader, MAX_MCP_FRAME_BYTES),
            )
            .await
            {
                Ok(Ok(Some(line))) => line,
                Ok(Ok(None)) | Err(_) => break,
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                    let response = JsonRpcResponse::err(
                        None,
                        error_codes::PARSE_ERROR,
                        format!("parse error: {error}"),
                    );
                    write_bounded_json(&mut write, &response, MAX_MCP_FRAME_BYTES).await?;
                    break;
                }
                Ok(Err(error)) => return Err(error),
            };
            first_frame = false;
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
                Ok(req) => {
                    let request_id = req.id.clone();
                    match tokio::time::timeout(
                        MCP_REQUEST_TIMEOUT,
                        dispatch_for_connection(&kernel, req, &mut identity),
                    )
                    .await
                    {
                        Ok(response) => response,
                        Err(_) => Some(JsonRpcResponse::err(
                            request_id,
                            error_codes::INTERNAL_ERROR,
                            "request timed out",
                        )),
                    }
                }
                Err(e) => Some(JsonRpcResponse::err(
                    None,
                    error_codes::PARSE_ERROR,
                    format!("parse error: {e}"),
                )),
            };
            // Notifications (and only notifications) produce no reply.
            if let Some(response) = response {
                if let Err(error) =
                    write_bounded_json(&mut write, &response, MAX_MCP_FRAME_BYTES).await
                {
                    if error.kind() != std::io::ErrorKind::InvalidData {
                        return Err(error);
                    }
                    let fallback = JsonRpcResponse::err(
                        response.id,
                        error_codes::INTERNAL_ERROR,
                        "response exceeds the MCP frame limit",
                    );
                    write_bounded_json(&mut write, &fallback, MAX_MCP_FRAME_BYTES).await?;
                }
            }
        }
        write.shutdown().await
    }
}

/// A thin MCP client for the server (used by round-trip tests; the wire format
/// is plain JSON-RPC, so any MCP client could speak it).
pub struct McpClient {
    reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    next_id: u64,
}

impl McpClient {
    /// Connect over TCP.
    pub async fn connect(addr: impl ToSocketAddrs) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(MCP_HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "MCP connect timed out")
            })??;
        let (read, writer) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(Box::new(read) as Box<dyn AsyncRead + Unpin + Send>),
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

    /// Bind this connection to `agent_id` using an AuthSystem API key or
    /// session token. The server revalidates the credential and ownership on
    /// every subsequent protected request.
    pub async fn authenticate(
        &mut self,
        token: impl Into<String>,
        agent_id: AgentId,
    ) -> std::io::Result<JsonRpcResponse> {
        self.request(
            "agentos/authenticate",
            Some(json!({
                "token": token.into(),
                "agent_id": agent_id,
            })),
        )
        .await
    }

    /// Send the standard MCP application-level liveness probe.
    pub async fn ping(&mut self) -> std::io::Result<JsonRpcResponse> {
        self.request("ping", None).await
    }

    /// Send a raw JSON value as one line (used by tests to exercise malformed /
    /// notification inputs the typed API can't express).
    pub async fn send_value(&mut self, value: &Value) -> std::io::Result<()> {
        write_bounded_json(&mut self.writer, value, MAX_MCP_FRAME_BYTES).await
    }

    /// Send a raw line verbatim (e.g. invalid JSON), no trailing-newline added
    /// beyond the one provided here.
    pub async fn send_line(&mut self, line: &str) -> std::io::Result<()> {
        if line.len() > MAX_MCP_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("JSON frame exceeds {MAX_MCP_FRAME_BYTES} bytes"),
            ));
        }
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await
    }

    /// Read one JSON-RPC response line.
    pub async fn read_response(&mut self) -> std::io::Result<JsonRpcResponse> {
        let line = match tokio::time::timeout(
            MCP_REQUEST_TIMEOUT,
            read_bounded_line(&mut self.reader, MAX_MCP_FRAME_BYTES),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                let _ = self.writer.shutdown().await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "MCP request timed out; connection closed",
                ));
            }
        }
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "server closed"))?;
        serde_json::from_str(&line).map_err(std::io::Error::other)
    }

    /// Gracefully close an idle MCP connection using the 2024-11-05 lifecycle:
    /// half-close client output, then require bounded peer EOF.
    pub async fn close(mut self) -> std::io::Result<()> {
        graceful_close_framed(
            &mut self.reader,
            &mut self.writer,
            MAX_MCP_FRAME_BYTES,
            MCP_GRACEFUL_CLOSE_TIMEOUT,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;
    use crate::resources::ResourceType;
    use crate::tools::{SecurityAction, ToolBinding, ToolSecurity};
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

    fn agent_config(name: &str, profile: &str) -> AgentConfig {
        AgentConfig {
            name: name.into(),
            task: "t".into(),
            llm_provider: "stub".into(),
            permission_profile: profile.into(),
            priority: Priority::new(3).unwrap(),
            sandbox_config: None,
        }
    }

    async fn create_identity(
        kernel: &AgentKernelImpl,
        tenant_name: &str,
        profile: &str,
        role: Role,
    ) -> (String, String, AgentId) {
        let tenant = kernel.create_tenant(tenant_name).await.expect("tenant");
        let user = kernel
            .register_user(
                &tenant,
                &format!("{tenant_name}-user"),
                &format!("{tenant_name}@example.test"),
                role,
            )
            .await
            .expect("user");
        let token = kernel.open_session(&user).await.expect("session");
        let agent = kernel
            .create_agent_for_tenant(&tenant, agent_config(tenant_name, profile))
            .await
            .expect("create tenant agent");
        (tenant, token, agent.id)
    }

    async fn authenticate(client: &mut McpClient, token: &str, agent_id: AgentId) {
        let response = client
            .authenticate(token.to_string(), agent_id)
            .await
            .expect("authenticate request");
        assert!(
            response.error.is_none(),
            "authentication failed: {:?}",
            response.error
        );
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
    async fn ping_is_preinitialize_keepalive_and_close_confirms_peer_eof() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = McpServer::bind(kernel, "127.0.0.1:0")
            .await
            .unwrap()
            .with_idle_timeout(std::time::Duration::from_millis(500));
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = McpClient::connect(addr).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let first = client.ping().await.unwrap();
        assert_eq!(first.result, Some(json!({})));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let second = client.ping().await.unwrap();
        assert_eq!(second.result, Some(json!({})));

        let initialized = client
            .request(
                "initialize",
                Some(json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "keepalive-test", "version": "1.0.0"}
                })),
            )
            .await
            .unwrap();
        assert!(initialized.error.is_none());
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn idle_deadline_closes_quiet_mcp_connection_without_stopping_listener() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = McpServer::bind(kernel, "127.0.0.1:0")
            .await
            .unwrap()
            .with_idle_timeout(std::time::Duration::from_millis(75));
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut stale = McpClient::connect(addr).await.unwrap();
        assert!(stale.ping().await.unwrap().error.is_none());
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        stale
            .ping()
            .await
            .expect_err("idle MCP connection must close");

        let mut fresh = McpClient::connect(addr).await.unwrap();
        assert!(fresh.ping().await.unwrap().error.is_none());
        fresh.close().await.unwrap();
    }

    #[tokio::test]
    async fn initialize_rejects_an_incompatible_mcp_version() {
        let (_kernel, addr) = spawn_server().await;
        let mut client = McpClient::connect(addr).await.unwrap();
        let response = client
            .request("initialize", Some(json!({"protocolVersion": "2099-01-01"})))
            .await
            .unwrap();
        let error = response.error.expect("version mismatch");
        assert_eq!(error.code, error_codes::INVALID_PARAMS);
        assert!(error.message.contains("unsupported MCP protocol version"));

        // A rejected initialize does not poison framing or grant authority.
        let response = client
            .request(
                "initialize",
                Some(json!({"protocolVersion": PROTOCOL_VERSION})),
            )
            .await
            .unwrap();
        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn plaintext_server_rejects_non_loopback_bind() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let error = match McpServer::bind(kernel, "0.0.0.0:0").await {
            Ok(_) => panic!("plaintext MCP must not bind beyond loopback"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("loopback"));
    }

    #[tokio::test]
    async fn tools_list_returns_nonempty() {
        let (kernel, addr) = spawn_server().await;
        let (_tenant, token, agent_id) =
            create_identity(&kernel, "list-owner", "standard", Role::User).await;
        let mut client = McpClient::connect(addr).await.unwrap();
        authenticate(&mut client, &token, agent_id).await;

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
        let (_tenant, token, id) =
            create_identity(&kernel, "readonly-profile", "read-only", Role::User).await;
        let mut client = McpClient::connect(addr).await.unwrap();
        authenticate(&mut client, &token, id).await;

        let resp = client
            .request(
                "tools/call",
                Some(json!({
                    "name": "write_file",
                    "arguments": {"path": "/tmp/x", "content": "y"}
                })),
            )
            .await
            .unwrap();

        // The gate denial must arrive as a JSON-RPC error, not a result.
        assert!(resp.result.is_none(), "expected no result on denial");
        let err = resp.error.expect("expected a JSON-RPC error");
        assert_eq!(err.code, error_codes::AUTHORIZATION_DENIED);
        assert!(
            err.message.contains("denied by kernel"),
            "expected kernel denial, got: {}",
            err.message
        );

        // And the gate's counters reflect the denial happening on this path.
        assert!(kernel.syscall_gate.stats().denied_capability >= 1);
    }

    #[tokio::test]
    async fn readonly_principal_can_list_but_cannot_execute_tools() {
        let (kernel, addr) = spawn_server().await;
        let (_tenant, token, agent_id) =
            create_identity(&kernel, "readonly-principal", "standard", Role::ReadOnly).await;
        let mut client = McpClient::connect(addr).await.unwrap();
        authenticate(&mut client, &token, agent_id).await;

        let list = client.request("tools/list", None).await.unwrap();
        assert!(list.error.is_none());
        let call = client
            .request(
                "tools/call",
                Some(json!({
                    "name": "read_file",
                    "arguments": {"path": "/tmp/x"}
                })),
            )
            .await
            .unwrap();
        assert_eq!(
            call.error
                .expect("read-only principal must not execute")
                .code,
            error_codes::AUTHORIZATION_DENIED
        );
        assert_eq!(kernel.syscall_gate.stats().allowed, 0);
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

        // The same connection still answers a valid public request afterwards.
        let ok = client.request("initialize", None).await.unwrap();
        assert!(ok.error.is_none());
        assert_eq!(ok.result.unwrap()["protocolVersion"], PROTOCOL_VERSION);
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
    async fn unauthenticated_clients_cannot_list_or_call_tools() {
        let (_kernel, addr) = spawn_server().await;
        let mut client = McpClient::connect(addr).await.unwrap();

        let list = client.request("tools/list", None).await.unwrap();
        assert_eq!(
            list.error.expect("tools/list must require auth").code,
            error_codes::AUTHENTICATION_REQUIRED
        );

        let call = client
            .request(
                "tools/call",
                Some(json!({ "name": "read_file", "arguments": {"path": "/tmp/x"} })),
            )
            .await
            .unwrap();
        assert_eq!(
            call.error.expect("tools/call must require auth").code,
            error_codes::AUTHENTICATION_REQUIRED
        );
    }

    #[tokio::test]
    async fn caller_supplied_agent_id_cannot_override_bound_identity() {
        let (kernel, addr) = spawn_server().await;
        let (tenant, token, bound_agent) =
            create_identity(&kernel, "agent-binding", "standard", Role::User).await;
        let foreign_agent = kernel
            .create_agent_for_tenant(&tenant, agent_config("foreign-agent", "standard"))
            .await
            .expect("second agent")
            .id;
        let mut client = McpClient::connect(addr).await.unwrap();
        authenticate(&mut client, &token, bound_agent).await;

        let response = client
            .request(
                "tools/call",
                Some(json!({
                    "name": "read_file",
                    "agent_id": foreign_agent,
                    "arguments": {"path": "/tmp/x"}
                })),
            )
            .await
            .unwrap();
        assert_eq!(
            response.error.expect("forged agent id must be denied").code,
            error_codes::AUTHORIZATION_DENIED
        );
    }

    #[tokio::test]
    async fn credential_cannot_bind_to_cross_tenant_agent() {
        let (kernel, addr) = spawn_server().await;
        let (_tenant_a, token_a, _agent_a) =
            create_identity(&kernel, "tenant-a", "standard", Role::User).await;
        let (_tenant_b, _token_b, agent_b) =
            create_identity(&kernel, "tenant-b", "standard", Role::User).await;
        let mut client = McpClient::connect(addr).await.unwrap();

        let response = client.authenticate(token_a, agent_b).await.unwrap();
        assert_eq!(
            response
                .error
                .expect("cross-tenant bind must be denied")
                .code,
            error_codes::AUTHORIZATION_DENIED
        );
        let list = client.request("tools/list", None).await.unwrap();
        assert_eq!(
            list.error
                .expect("failed bind must remain unauthenticated")
                .code,
            error_codes::AUTHENTICATION_REQUIRED
        );
    }

    #[tokio::test]
    async fn failed_reauthentication_clears_the_previous_mcp_identity() {
        let (kernel, addr) = spawn_server().await;
        let (_tenant, token, agent_id) =
            create_identity(&kernel, "mcp-reauth", "standard", Role::User).await;
        let mut client = McpClient::connect(addr).await.unwrap();
        authenticate(&mut client, &token, agent_id).await;

        let failed = client
            .authenticate("invalid-replacement", agent_id)
            .await
            .unwrap();
        assert_eq!(
            failed
                .error
                .expect("replacement authentication must fail")
                .code,
            error_codes::AUTHENTICATION_FAILED
        );
        let list = client.request("tools/list", None).await.unwrap();
        assert_eq!(
            list.error
                .expect("failed reauthentication must clear identity")
                .code,
            error_codes::AUTHENTICATION_REQUIRED
        );
    }

    #[tokio::test]
    async fn revoked_credential_invalidates_an_existing_connection() {
        let (kernel, addr) = spawn_server().await;
        let (_tenant, token, agent_id) =
            create_identity(&kernel, "revoked-mcp", "standard", Role::User).await;
        let mut client = McpClient::connect(addr).await.unwrap();
        authenticate(&mut client, &token, agent_id).await;
        assert!(kernel.revoke_session(&token).await.expect("revoke session"));

        let response = client.request("tools/list", None).await.unwrap();
        assert_eq!(
            response.error.expect("revoked session must be denied").code,
            error_codes::AUTHENTICATION_REQUIRED
        );
    }

    #[tokio::test]
    async fn tools_list_hides_foreign_namespace_tools() {
        let (kernel, addr) = spawn_server().await;
        let (tenant_a, token_a, agent_a) =
            create_identity(&kernel, "visibility-a", "standard", Role::User).await;
        let (_tenant_b, token_b, agent_b) =
            create_identity(&kernel, "visibility-b", "standard", Role::User).await;
        kernel
            .register_group_tool(
                &tenant_a,
                ToolBinding {
                    name: "tenant_a_notes".into(),
                    description: "Read tenant A notes".into(),
                    parameters_schema: json!({
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"]
                    }),
                    resource_type: ResourceType::Filesystem,
                    operation: "read".into(),
                    security: ToolSecurity::argument(SecurityAction::Read, "path"),
                },
            )
            .expect("register scoped tool");

        let mut client_a = McpClient::connect(addr).await.unwrap();
        authenticate(&mut client_a, &token_a, agent_a).await;
        let list_a = client_a.request("tools/list", None).await.unwrap();
        let tools_a = list_a.result.unwrap()["tools"].as_array().unwrap().clone();
        assert!(tools_a.iter().any(|tool| tool["name"] == "tenant_a_notes"));

        let mut client_b = McpClient::connect(addr).await.unwrap();
        authenticate(&mut client_b, &token_b, agent_b).await;
        let list_b = client_b.request("tools/list", None).await.unwrap();
        let tools_b = list_b.result.unwrap()["tools"].as_array().unwrap().clone();
        assert!(!tools_b.iter().any(|tool| tool["name"] == "tenant_a_notes"));

        let foreign = client_b
            .request(
                "tools/call",
                Some(json!({
                    "name": "tenant_a_notes",
                    "arguments": {"path": "/tmp/foreign"}
                })),
            )
            .await
            .unwrap()
            .error
            .expect("foreign-scoped tool probe must fail");
        let missing = client_b
            .request(
                "tools/call",
                Some(json!({
                    "name": "definitely_missing_tool",
                    "arguments": {}
                })),
            )
            .await
            .unwrap()
            .error
            .expect("missing tool probe must fail");
        assert_eq!(foreign.code, missing.code);
        assert_eq!(foreign.message, missing.message);
        assert_eq!(foreign.code, error_codes::INVALID_PARAMS);
        assert!(
            !foreign.message.contains("tenant_a_notes")
                && !foreign.message.contains("definitely_missing_tool")
                && !foreign.message.contains("ns="),
            "MCP tool lookup must not reflect foreign catalog data: {}",
            foreign.message
        );
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
        let resp = client.request("initialize", None).await.unwrap();
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

    #[test]
    fn jsonrpc_debug_redacts_auth_and_tool_arguments() {
        let auth = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "agentos/authenticate".into(),
            params: Some(json!({"token": "secret-token", "agent_id": "agent"})),
        };
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("secret-token"));
        assert!(rendered.contains("[REDACTED]"));

        let tool = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(2)),
            method: "tools/call".into(),
            params: Some(json!({"name": "http", "arguments": {"token": "secret"}})),
        };
        assert!(!format!("{tool:?}").contains("\"secret\""));
    }
}
