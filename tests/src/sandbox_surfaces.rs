//! End-to-end proof that every public tool-call surface retains the same
//! kernel-owned sandbox identity and cannot launch a host process.

use std::sync::Arc;

use adapters::azure_openai::AzureOpenAiAdapter;
use agent_sdk::KernelClient;
use kernel::auth::Role;
use kernel::mcp_server::{McpClient, McpServer};
use kernel::sandbox::SandboxManager;
use kernel::syscall_server::{Syscall, SyscallClient, SyscallReply, SyscallServer};
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn assert_sandbox_denial(message: &str, surface: &str) {
    let normalized = message.to_ascii_lowercase();
    assert!(
        normalized.contains("sandbox")
            || normalized.contains("host process")
            || normalized.contains("isolated process"),
        "{surface} did not retain the sandbox denial: {message}"
    );
}

fn raw_error(reply: SyscallReply) -> String {
    match reply {
        SyscallReply::Error { message } | SyscallReply::TypedError { message, .. } => message,
        other => panic!("expected tool denial, got {other:?}"),
    }
}

fn custom_tool_config() -> String {
    r#"
[[tool]]
name = "sandbox_surface_custom"
description = "Qualification-only fixed process tool"
command = "echo"
args_template = ["{input}"]

[tool.security]
action = "execute"
required_capabilities = [64]
namespace_visibility = "global"
approval_policy = "none"
sandbox_requirement = "required"
[tool.security.resource_extractor]
kind = "constant"
value = "echo"

[tool.parameters]
input = { type = "string", required = true }
"#
    .to_string()
}

#[tokio::test]
async fn llm_executor_tool_calls_share_the_fail_closed_sandbox() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/openai/deployments/.*/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "sandbox-executor-call",
                        "type": "function",
                        "function": {
                            "name": "git_status",
                            "arguments": "{\"directory\":\".\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex("/openai/deployments/.*/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "The kernel refused the host-process request."
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25}
        })))
        .mount(&mock_server)
        .await;

    let kernel = AgentKernelImpl::new().expect("kernel");
    kernel
        .register_provider(Arc::new(AzureOpenAiAdapter::new(
            mock_server.uri(),
            "gpt-4o".into(),
            "qualification-key".into(),
        )))
        .expect("register provider");
    let agent = kernel
        .create_agent_full(AgentConfig {
            name: "surface-llm-executor".into(),
            task: "prove executor sandbox propagation".into(),
            llm_provider: "azure-openai".into(),
            permission_profile: "full-access".into(),
            priority: Priority::default(),
            sandbox_config: None,
        })
        .await
        .expect("create executor agent");
    assert!(
        kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent.id)
            .is_some(),
        "LLM-driven agents must receive the managed sandbox default"
    );

    let output = kernel
        .send_message(agent.id, "Run git status on the host")
        .await
        .expect("executor should recover from a denied tool call");
    assert_eq!(
        output.content,
        "The kernel refused the host-process request."
    );
    assert_eq!(output.tool_calls_made, 1);

    let requests = mock_server
        .received_requests()
        .await
        .expect("request recording enabled");
    assert_eq!(requests.len(), 2, "one tool round and one recovery round");
    let recovery_body: serde_json::Value =
        serde_json::from_slice(&requests[1].body).expect("recovery request JSON");
    let tool_result = recovery_body["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .find(|message| message["role"] == "tool")
        .and_then(|message| message["content"].as_str())
        .expect("kernel denial returned to the LLM");
    assert_sandbox_denial(tool_result, "LLM executor");
}

#[tokio::test]
async fn wire_sdk_package_custom_and_mcp_calls_share_the_fail_closed_sandbox() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    let custom_path = std::env::temp_dir().join(format!(
        "aiagentos-sandbox-surfaces-{}.toml",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&custom_path, custom_tool_config()).unwrap();
    kernel::custom_tools::load_custom_tools(&kernel.tool_registry, &custom_path);
    assert!(kernel.tool_registry.has_tool("sandbox_surface_custom"));

    let syscall_server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .expect("bind syscall server");
    let syscall_addr = syscall_server.local_addr().unwrap();
    let syscall_task = tokio::spawn(syscall_server.serve());

    let mut sdk = KernelClient::connect(syscall_addr)
        .await
        .expect("SDK connect");
    let agent_id = sdk
        .create_agent(
            "surface-sdk",
            "prove sandbox propagation",
            Some("stub".into()),
            Some("full-access".into()),
            Some(3),
        )
        .await
        .expect("SDK create");
    let agent_uuid = uuid::Uuid::parse_str(&agent_id).unwrap();
    assert!(
        kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent_uuid)
            .is_some(),
        "wire-created agents must receive the managed sandbox default"
    );

    let sdk_denial = sdk
        .call_tool(
            agent_id.clone(),
            "git_status",
            serde_json::json!({"directory": "."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_sandbox_denial(&sdk_denial, "SDK");

    let custom_denial = sdk
        .call_tool(
            agent_id.clone(),
            "sandbox_surface_custom",
            serde_json::json!({"input": "must-not-run"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_sandbox_denial(&custom_denial, "custom tool");

    let package_id = sdk
        .load_package(
            r#"
name = "sandbox-package"
task = "prove package sandbox propagation"
provider = "stub"
profile = "standard"
tools = ["git_status"]
"#,
        )
        .await
        .expect("load package");
    let package_uuid = uuid::Uuid::parse_str(&package_id).unwrap();
    assert!(
        kernel
            .sandbox_manager
            .get_sandbox_for_agent(package_uuid)
            .is_some(),
        "package agents must receive the managed sandbox default"
    );
    let package_denial = sdk
        .call_tool(
            package_id,
            "git_status",
            serde_json::json!({"directory": "."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_sandbox_denial(&package_denial, "package via SDK");

    let mut raw = SyscallClient::connect(syscall_addr)
        .await
        .expect("raw wire connect");
    let raw_denial = raw_error(
        raw.call(Syscall::CallTool {
            agent_id: agent_id.clone(),
            tool: "git_status".into(),
            args: serde_json::json!({"directory": "."}),
        })
        .await
        .expect("raw wire reply"),
    );
    assert_sandbox_denial(&raw_denial, "raw wire");

    let tenant = kernel.create_tenant("sandbox-mcp").await.unwrap();
    let user = kernel
        .register_user(
            &tenant,
            "sandbox-mcp-user",
            "sandbox-mcp@example.test",
            Role::User,
        )
        .await
        .unwrap();
    let token = kernel.open_session(&user).await.unwrap();
    let mcp_agent = kernel
        .create_agent_for_tenant(
            &tenant,
            AgentConfig {
                name: "surface-mcp".into(),
                task: "prove MCP sandbox propagation".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            },
        )
        .await
        .unwrap();
    let mcp_server = McpServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .expect("bind MCP server");
    let mcp_addr = mcp_server.local_addr().unwrap();
    let mcp_task = tokio::spawn(mcp_server.serve());
    let mut mcp = McpClient::connect(mcp_addr).await.expect("MCP connect");
    let authenticated = mcp
        .authenticate(token, mcp_agent.id)
        .await
        .expect("MCP authentication");
    assert!(authenticated.error.is_none());
    let mcp_denial = mcp
        .request(
            "tools/call",
            Some(serde_json::json!({
                "name": "git_status",
                "arguments": {"directory": "."}
            })),
        )
        .await
        .expect("MCP tool reply")
        .error
        .expect("MCP process launch must be denied")
        .message;
    assert_sandbox_denial(&mcp_denial, "MCP");

    mcp_task.abort();
    syscall_task.abort();
    std::fs::remove_file(custom_path).unwrap();
}
