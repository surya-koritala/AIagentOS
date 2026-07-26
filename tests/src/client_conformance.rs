//! One authorization and behavior contract exercised by every public client.
//!
//! Each adapter below is deliberately thin and calls the production surface
//! used by its binary/UI. The scenario runner is shared: a new public client is
//! not qualified until it can pass the same fail-closed sequence.

use std::sync::Arc;

use agent_cli::OperatorClient;
use agent_sdk::{KernelClient, SdkError, WireErrorCode};
use agent_tui::{app::App, TuiClient};
use async_trait::async_trait;
use kernel::auth::Role;
use kernel::mcp_server::{error_codes, McpClient, McpServer};
use kernel::resources::ResourceType;
use kernel::syscall_server::{
    Syscall, SyscallClient, SyscallReply, SyscallServer, PROTOCOL_VERSION,
};
use kernel::tools::{SecurityAction, ToolBinding, ToolSecurity};
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use serde_json::json;
use tauri_app::DesktopClient;

const OWNER_TOOL: &str = "conformance_owner_catalog";
const FOREIGN_TOOL: &str = "conformance_foreign_catalog";
const INVALID_TOKEN: &str = "invalid-conformance-credential";

#[derive(Debug)]
struct SurfaceFailure {
    code: WireErrorCode,
    message: String,
}

impl SurfaceFailure {
    fn from_sdk(error: SdkError) -> Self {
        let code = error
            .wire_code()
            .unwrap_or_else(|| panic!("surface returned an untyped SDK error: {error}"));
        let message = error
            .kernel_message()
            .unwrap_or_else(|| panic!("wire error omitted its safe message: {error}"))
            .to_string();
        Self { code, message }
    }

    fn from_raw(reply: SyscallReply) -> Result<SyscallReply, Self> {
        match reply {
            SyscallReply::TypedError { code, message, .. } => Err(Self { code, message }),
            SyscallReply::Error { message } => {
                panic!("protocol-v2 raw client received legacy error: {message}")
            }
            reply => Ok(reply),
        }
    }

    fn from_mcp(error: kernel::mcp_server::JsonRpcError) -> Self {
        let code = match error.code {
            error_codes::AUTHENTICATION_REQUIRED => WireErrorCode::AuthenticationRequired,
            error_codes::AUTHENTICATION_FAILED => WireErrorCode::AuthenticationFailed,
            error_codes::AUTHORIZATION_DENIED => WireErrorCode::AuthorizationDenied,
            error_codes::INVALID_PARAMS => WireErrorCode::InvalidArgument,
            _ => WireErrorCode::Internal,
        };
        Self {
            code,
            message: error.message,
        }
    }
}

type SurfaceResult<T> = Result<T, SurfaceFailure>;

#[derive(Debug, Clone, Copy)]
struct ReadVisibility {
    owner_visible: bool,
    foreign_hidden: bool,
}

#[async_trait]
trait ClientSurface {
    fn name(&self) -> &'static str;
    async fn ping(&mut self) -> SurfaceResult<()>;
    async fn authenticate(&mut self, token: &str, owner_agent: &str) -> SurfaceResult<()>;
    async fn protected_read(
        &mut self,
        owner_agent: &str,
        foreign_agent: &str,
    ) -> SurfaceResult<ReadVisibility>;
    async fn protected_write(&mut self, owner_agent: &str) -> SurfaceResult<()>;
    async fn foreign_read(&mut self, agent_id: &str) -> SurfaceResult<()>;
}

struct SdkSurface(KernelClient);

#[async_trait]
impl ClientSurface for SdkSurface {
    fn name(&self) -> &'static str {
        "Rust SDK"
    }

    async fn ping(&mut self) -> SurfaceResult<()> {
        self.0.ping().await.map_err(SurfaceFailure::from_sdk)
    }

    async fn authenticate(&mut self, token: &str, _owner_agent: &str) -> SurfaceResult<()> {
        self.0
            .authenticate(token)
            .await
            .map_err(SurfaceFailure::from_sdk)
    }

    async fn protected_read(
        &mut self,
        owner_agent: &str,
        foreign_agent: &str,
    ) -> SurfaceResult<ReadVisibility> {
        let agents = self
            .0
            .list_agents()
            .await
            .map_err(SurfaceFailure::from_sdk)?;
        Ok(ReadVisibility {
            owner_visible: agents.iter().any(|agent| agent.id == owner_agent),
            foreign_hidden: !agents.iter().any(|agent| agent.id == foreign_agent),
        })
    }

    async fn protected_write(&mut self, owner_agent: &str) -> SurfaceResult<()> {
        self.0
            .call_tool(owner_agent, "check_inbox", json!({}))
            .await
            .map(|_| ())
            .map_err(SurfaceFailure::from_sdk)
    }

    async fn foreign_read(&mut self, agent_id: &str) -> SurfaceResult<()> {
        self.0
            .agent_info(agent_id)
            .await
            .map(|_| ())
            .map_err(SurfaceFailure::from_sdk)
    }
}

struct CliSurface(OperatorClient);

#[async_trait]
impl ClientSurface for CliSurface {
    fn name(&self) -> &'static str {
        "CLI (agentctl)"
    }

    async fn ping(&mut self) -> SurfaceResult<()> {
        self.0.ping().await.map_err(SurfaceFailure::from_sdk)
    }

    async fn authenticate(&mut self, token: &str, _owner_agent: &str) -> SurfaceResult<()> {
        self.0
            .authenticate(token)
            .await
            .map_err(SurfaceFailure::from_sdk)
    }

    async fn protected_read(
        &mut self,
        owner_agent: &str,
        foreign_agent: &str,
    ) -> SurfaceResult<ReadVisibility> {
        let agents = self
            .0
            .list_agents()
            .await
            .map_err(SurfaceFailure::from_sdk)?;
        Ok(ReadVisibility {
            owner_visible: agents.iter().any(|agent| agent.id == owner_agent),
            foreign_hidden: !agents.iter().any(|agent| agent.id == foreign_agent),
        })
    }

    async fn protected_write(&mut self, owner_agent: &str) -> SurfaceResult<()> {
        self.0
            .call_tool(owner_agent, "check_inbox", json!({}))
            .await
            .map(|_| ())
            .map_err(SurfaceFailure::from_sdk)
    }

    async fn foreign_read(&mut self, agent_id: &str) -> SurfaceResult<()> {
        self.0
            .agent_info(agent_id)
            .await
            .map(|_| ())
            .map_err(SurfaceFailure::from_sdk)
    }
}

struct TuiSurface {
    client: TuiClient,
    app: App,
}

#[async_trait]
impl ClientSurface for TuiSurface {
    fn name(&self) -> &'static str {
        "TUI"
    }

    async fn ping(&mut self) -> SurfaceResult<()> {
        self.client.ping().await.map_err(SurfaceFailure::from_sdk)
    }

    async fn authenticate(&mut self, token: &str, _owner_agent: &str) -> SurfaceResult<()> {
        self.client
            .authenticate(token)
            .await
            .map_err(SurfaceFailure::from_sdk)
    }

    async fn protected_read(
        &mut self,
        owner_agent: &str,
        foreign_agent: &str,
    ) -> SurfaceResult<ReadVisibility> {
        self.app
            .refresh(&mut self.client)
            .await
            .map_err(SurfaceFailure::from_sdk)?;
        Ok(ReadVisibility {
            owner_visible: self.app.agents.iter().any(|agent| agent.id == owner_agent),
            foreign_hidden: !self
                .app
                .agents
                .iter()
                .any(|agent| agent.id == foreign_agent),
        })
    }

    async fn protected_write(&mut self, owner_agent: &str) -> SurfaceResult<()> {
        self.client
            .call_tool(owner_agent, "check_inbox", json!({}))
            .await
            .map(|_| ())
            .map_err(SurfaceFailure::from_sdk)
    }

    async fn foreign_read(&mut self, agent_id: &str) -> SurfaceResult<()> {
        self.client
            .agent_info(agent_id)
            .await
            .map(|_| ())
            .map_err(SurfaceFailure::from_sdk)
    }
}

struct DesktopSurface(DesktopClient);

#[async_trait]
impl ClientSurface for DesktopSurface {
    fn name(&self) -> &'static str {
        "Desktop"
    }

    async fn ping(&mut self) -> SurfaceResult<()> {
        self.0.ping().await.map_err(SurfaceFailure::from_sdk)
    }

    async fn authenticate(&mut self, token: &str, _owner_agent: &str) -> SurfaceResult<()> {
        self.0
            .authenticate(token)
            .await
            .map_err(SurfaceFailure::from_sdk)
    }

    async fn protected_read(
        &mut self,
        owner_agent: &str,
        foreign_agent: &str,
    ) -> SurfaceResult<ReadVisibility> {
        let agents = self
            .0
            .list_agents()
            .await
            .map_err(SurfaceFailure::from_sdk)?;
        Ok(ReadVisibility {
            owner_visible: agents.iter().any(|agent| agent.id == owner_agent),
            foreign_hidden: !agents.iter().any(|agent| agent.id == foreign_agent),
        })
    }

    async fn protected_write(&mut self, owner_agent: &str) -> SurfaceResult<()> {
        self.0
            .call_tool(owner_agent, "check_inbox", json!({}))
            .await
            .map(|_| ())
            .map_err(SurfaceFailure::from_sdk)
    }

    async fn foreign_read(&mut self, agent_id: &str) -> SurfaceResult<()> {
        self.0
            .agent_info(agent_id)
            .await
            .map(|_| ())
            .map_err(SurfaceFailure::from_sdk)
    }
}

struct RawSurface(SyscallClient);

impl RawSurface {
    async fn connect(addr: &str) -> Self {
        let mut client = SyscallClient::connect(addr).await.expect("raw connect");
        let hello = client
            .call(Syscall::Hello {
                protocol_version: PROTOCOL_VERSION,
            })
            .await
            .expect("raw hello");
        assert!(
            matches!(hello, SyscallReply::Hello { .. }),
            "raw protocol negotiation failed: {hello:?}"
        );
        Self(client)
    }

    async fn call(&mut self, syscall: Syscall) -> SurfaceResult<SyscallReply> {
        let reply = self.0.call(syscall).await.expect("raw request");
        SurfaceFailure::from_raw(reply)
    }
}

#[async_trait]
impl ClientSurface for RawSurface {
    fn name(&self) -> &'static str {
        "raw protocol"
    }

    async fn ping(&mut self) -> SurfaceResult<()> {
        match self.call(Syscall::Ping).await? {
            SyscallReply::Pong => Ok(()),
            other => panic!("raw ping returned {other:?}"),
        }
    }

    async fn authenticate(&mut self, token: &str, _owner_agent: &str) -> SurfaceResult<()> {
        match self
            .call(Syscall::Authenticate {
                token: token.to_string(),
            })
            .await?
        {
            SyscallReply::Authenticated => Ok(()),
            other => panic!("raw authentication returned {other:?}"),
        }
    }

    async fn protected_read(
        &mut self,
        owner_agent: &str,
        foreign_agent: &str,
    ) -> SurfaceResult<ReadVisibility> {
        match self.call(Syscall::ListAgents).await? {
            SyscallReply::Agents { agents } => Ok(ReadVisibility {
                owner_visible: agents.iter().any(|agent| agent.id == owner_agent),
                foreign_hidden: !agents.iter().any(|agent| agent.id == foreign_agent),
            }),
            other => panic!("raw list returned {other:?}"),
        }
    }

    async fn protected_write(&mut self, owner_agent: &str) -> SurfaceResult<()> {
        match self
            .call(Syscall::CallTool {
                agent_id: owner_agent.to_string(),
                tool: "check_inbox".to_string(),
                args: json!({}),
            })
            .await?
        {
            SyscallReply::ToolResult { .. } => Ok(()),
            other => panic!("raw tool call returned {other:?}"),
        }
    }

    async fn foreign_read(&mut self, agent_id: &str) -> SurfaceResult<()> {
        match self
            .call(Syscall::AgentInfo {
                agent_id: agent_id.to_string(),
            })
            .await?
        {
            SyscallReply::AgentInfo { .. } => Ok(()),
            other => panic!("raw agent info returned {other:?}"),
        }
    }
}

struct McpSurface(McpClient);

impl McpSurface {
    async fn response(
        response: std::io::Result<kernel::mcp_server::JsonRpcResponse>,
    ) -> SurfaceResult<serde_json::Value> {
        let response = response.expect("MCP request");
        match response.error {
            Some(error) => Err(SurfaceFailure::from_mcp(error)),
            None => Ok(response
                .result
                .unwrap_or_else(|| panic!("successful MCP response omitted result"))),
        }
    }
}

#[async_trait]
impl ClientSurface for McpSurface {
    fn name(&self) -> &'static str {
        "MCP"
    }

    async fn ping(&mut self) -> SurfaceResult<()> {
        Self::response(self.0.ping().await).await.map(|_| ())
    }

    async fn authenticate(&mut self, token: &str, owner_agent: &str) -> SurfaceResult<()> {
        let owner_agent = uuid::Uuid::parse_str(owner_agent).expect("owner UUID");
        Self::response(self.0.authenticate(token, owner_agent).await)
            .await
            .map(|_| ())
    }

    async fn protected_read(
        &mut self,
        _owner_agent: &str,
        _foreign_agent: &str,
    ) -> SurfaceResult<ReadVisibility> {
        let result = Self::response(self.0.request("tools/list", None).await).await?;
        let tools = result["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("MCP tools/list omitted tools array"));
        Ok(ReadVisibility {
            owner_visible: tools.iter().any(|tool| tool["name"] == OWNER_TOOL),
            foreign_hidden: !tools.iter().any(|tool| tool["name"] == FOREIGN_TOOL),
        })
    }

    async fn protected_write(&mut self, owner_agent: &str) -> SurfaceResult<()> {
        Self::response(
            self.0
                .request(
                    "tools/call",
                    Some(json!({
                        "name": "check_inbox",
                        "agent_id": owner_agent,
                        "arguments": {}
                    })),
                )
                .await,
        )
        .await
        .map(|_| ())
    }

    async fn foreign_read(&mut self, agent_id: &str) -> SurfaceResult<()> {
        Self::response(
            self.0
                .request(
                    "tools/call",
                    Some(json!({
                        "name": "check_inbox",
                        "agent_id": agent_id,
                        "arguments": {}
                    })),
                )
                .await,
        )
        .await
        .map(|_| ())
    }
}

#[derive(Debug, Clone, Copy)]
enum SurfaceKind {
    Sdk,
    Cli,
    Tui,
    Desktop,
    Raw,
    Mcp,
}

struct Harness {
    wire_addr: String,
    mcp_addr: String,
    owner_token: String,
    readonly_token: String,
    owner_agent: String,
    foreign_agent: String,
    absent_agent: String,
}

impl Harness {
    async fn new() -> Self {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
        let owner_tenant = kernel.create_tenant("conformance-owner").await.unwrap();
        let owner_user = kernel
            .register_user(
                &owner_tenant,
                "conformance-user",
                "user@conformance.test",
                Role::User,
            )
            .await
            .unwrap();
        let readonly_user = kernel
            .register_user(
                &owner_tenant,
                "conformance-reader",
                "reader@conformance.test",
                Role::ReadOnly,
            )
            .await
            .unwrap();
        let owner_token = kernel
            .issue_api_key(&owner_user, "conformance-user")
            .await
            .unwrap();
        let readonly_token = kernel
            .issue_api_key(&readonly_user, "conformance-reader")
            .await
            .unwrap();

        let foreign_tenant = kernel.create_tenant("conformance-foreign").await.unwrap();
        let foreign_user = kernel
            .register_user(
                &foreign_tenant,
                "foreign-user",
                "foreign@conformance.test",
                Role::User,
            )
            .await
            .unwrap();
        let _foreign_token = kernel
            .issue_api_key(&foreign_user, "conformance-foreign")
            .await
            .unwrap();

        let owner_agent = kernel
            .create_agent_for_tenant(&owner_tenant, agent_config("owner-agent"))
            .await
            .unwrap()
            .id;
        let foreign_agent = kernel
            .create_agent_for_tenant(&foreign_tenant, agent_config("foreign-agent"))
            .await
            .unwrap()
            .id;

        kernel
            .register_group_tool(&owner_tenant, catalog_tool(OWNER_TOOL))
            .unwrap();
        kernel
            .register_group_tool(&foreign_tenant, catalog_tool(FOREIGN_TOOL))
            .unwrap();

        let wire_server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
            .await
            .unwrap()
            .with_auth_token("conformance-system-secret");
        let wire_addr = wire_server.local_addr().unwrap().to_string();
        tokio::spawn(wire_server.serve());

        let mcp_server = McpServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let mcp_addr = mcp_server.local_addr().unwrap().to_string();
        tokio::spawn(mcp_server.serve());

        Self {
            wire_addr,
            mcp_addr,
            owner_token,
            readonly_token,
            owner_agent: owner_agent.to_string(),
            foreign_agent: foreign_agent.to_string(),
            absent_agent: uuid::Uuid::new_v4().to_string(),
        }
    }

    async fn connect(&self, kind: SurfaceKind) -> Box<dyn ClientSurface> {
        match kind {
            SurfaceKind::Sdk => Box::new(SdkSurface(
                KernelClient::connect(&self.wire_addr).await.unwrap(),
            )),
            SurfaceKind::Cli => Box::new(CliSurface(
                OperatorClient::connect(&self.wire_addr, None)
                    .await
                    .unwrap(),
            )),
            SurfaceKind::Tui => Box::new(TuiSurface {
                client: TuiClient::connect(&self.wire_addr, None).await.unwrap(),
                app: App::new(self.wire_addr.clone()),
            }),
            SurfaceKind::Desktop => Box::new(DesktopSurface(
                DesktopClient::connect(&self.wire_addr, None).await.unwrap(),
            )),
            SurfaceKind::Raw => Box::new(RawSurface::connect(&self.wire_addr).await),
            SurfaceKind::Mcp => Box::new(McpSurface(
                McpClient::connect(&self.mcp_addr).await.unwrap(),
            )),
        }
    }
}

fn agent_config(name: &str) -> AgentConfig {
    AgentConfig {
        name: name.to_string(),
        task: "shared client conformance".to_string(),
        llm_provider: "stub".to_string(),
        permission_profile: "standard".to_string(),
        priority: Priority::new(3).unwrap(),
        sandbox_config: None,
    }
}

fn catalog_tool(name: &str) -> ToolBinding {
    ToolBinding {
        name: name.to_string(),
        description: "Namespace-scoped conformance catalog marker".to_string(),
        parameters_schema: json!({"type": "object", "properties": {}}),
        resource_type: ResourceType::Ipc,
        operation: "receive".to_string(),
        security: ToolSecurity::constant(SecurityAction::Ipc, "ipc:self").caller_namespace(),
    }
}

fn expect_code(
    surface: &str,
    result: SurfaceResult<impl std::fmt::Debug>,
    expected: WireErrorCode,
) -> SurfaceFailure {
    let error = result.unwrap_err();
    assert_eq!(
        error.code, expected,
        "{surface} returned the wrong stable error: {error:?}"
    );
    assert!(
        !error.message.contains(INVALID_TOKEN),
        "{surface} reflected a credential in its public error: {error:?}"
    );
    error
}

async fn run_shared_suite(kind: SurfaceKind, harness: &Harness) {
    let mut client = harness.connect(kind).await;
    let surface = client.name();

    client
        .ping()
        .await
        .unwrap_or_else(|error| panic!("{surface} pre-auth ping failed: {error:?}"));
    expect_code(
        surface,
        client
            .protected_read(&harness.owner_agent, &harness.foreign_agent)
            .await,
        WireErrorCode::AuthenticationRequired,
    );
    expect_code(
        surface,
        client
            .authenticate(INVALID_TOKEN, &harness.owner_agent)
            .await,
        WireErrorCode::AuthenticationFailed,
    );
    expect_code(
        surface,
        client
            .protected_read(&harness.owner_agent, &harness.foreign_agent)
            .await,
        WireErrorCode::AuthenticationRequired,
    );

    let mut client = harness.connect(kind).await;
    let surface = client.name();
    client
        .authenticate(&harness.owner_token, &harness.owner_agent)
        .await
        .unwrap_or_else(|error| panic!("{surface} owner authentication failed: {error:?}"));
    let visibility = client
        .protected_read(&harness.owner_agent, &harness.foreign_agent)
        .await
        .unwrap_or_else(|error| panic!("{surface} owner read failed: {error:?}"));
    assert!(
        visibility.owner_visible,
        "{surface} hid its owner's resource/catalog"
    );
    assert!(
        visibility.foreign_hidden,
        "{surface} exposed a foreign tenant's resource/catalog"
    );
    client
        .protected_write(&harness.owner_agent)
        .await
        .unwrap_or_else(|error| panic!("{surface} owner write failed: {error:?}"));

    let foreign = expect_code(
        surface,
        client.foreign_read(&harness.foreign_agent).await,
        WireErrorCode::AuthorizationDenied,
    );
    let absent = expect_code(
        surface,
        client.foreign_read(&harness.absent_agent).await,
        WireErrorCode::AuthorizationDenied,
    );
    assert_eq!(
        foreign.message, absent.message,
        "{surface} exposes a foreign-versus-absent resource oracle"
    );

    expect_code(
        surface,
        client
            .authenticate(INVALID_TOKEN, &harness.owner_agent)
            .await,
        WireErrorCode::AuthenticationFailed,
    );
    expect_code(
        surface,
        client
            .protected_read(&harness.owner_agent, &harness.foreign_agent)
            .await,
        WireErrorCode::AuthenticationRequired,
    );

    let mut reader = harness.connect(kind).await;
    let surface = reader.name();
    reader
        .authenticate(&harness.readonly_token, &harness.owner_agent)
        .await
        .unwrap_or_else(|error| panic!("{surface} reader authentication failed: {error:?}"));
    reader
        .protected_read(&harness.owner_agent, &harness.foreign_agent)
        .await
        .unwrap_or_else(|error| panic!("{surface} reader read failed: {error:?}"));
    expect_code(
        surface,
        reader.protected_write(&harness.owner_agent).await,
        WireErrorCode::AuthorizationDenied,
    );
}

#[tokio::test]
async fn every_public_client_passes_one_authorization_and_behavior_suite() {
    let harness = Harness::new().await;
    for kind in [
        SurfaceKind::Sdk,
        SurfaceKind::Cli,
        SurfaceKind::Tui,
        SurfaceKind::Desktop,
        SurfaceKind::Raw,
        SurfaceKind::Mcp,
    ] {
        run_shared_suite(kind, &harness).await;
    }
}
