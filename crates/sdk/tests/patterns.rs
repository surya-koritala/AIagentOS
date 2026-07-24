//! Integration tests for the SDK agent **patterns** ([`agent_sdk::patterns`]).
//!
//! These stand up a *real* in-memory kernel behind a `SyscallServer`, register a
//! **wiremock-backed** `AzureOpenAiAdapter` (no real API calls) and a filesystem
//! resource provider, then drive the patterns end-to-end through the SDK over
//! loopback TCP. The ReAct test proves the loop (a) executed a tool through the
//! kernel and (b) reached the final answer within the iteration bound; the
//! planner test proves the plan→execute control flow runs a mix of turns and
//! direct tool calls in order.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agent_sdk::patterns::{
    DirectiveReasoner, FnPlanner, PlannerExecutor, ReActLoop, Step, StepResult,
};
use agent_sdk::{Agent, KernelClient};

use adapters::azure_openai::AzureOpenAiAdapter;
use kernel::agent_package::{load_package_for_tenant, AgentManifest};
use kernel::auth::Role;
use kernel::connector::{
    LlmResponse, LlmSession, LlmUsage, StandardMessage, ToolCall, ToolDefinition,
};
use kernel::execution::AgentExecutor;
use kernel::mcp_server::{McpClient, McpServer};
use kernel::resources::ResourceType;
use kernel::syscall_server::{Syscall, SyscallClient, SyscallReply, SyscallServer};
use kernel::tool_registry_share::{SharedToolDef, SharedToolRegistry};
use kernel::tools::{SecurityAction, ToolSecurity};
use kernel::{AgentId, AgentKernelImpl, ConnectorError, ProviderId};

use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Deterministic two-response LLM session: request one declared tool, then stop.
///
/// The executor intentionally surfaces an authorization denial as a tool
/// result so the model can recover. Inspecting that tool result lets the parity
/// regression compare the executor verdict with the wire/MCP/SDK verdicts.
struct OneToolSession {
    calls: AtomicUsize,
    provider: ProviderId,
    tool: String,
    args: serde_json::Value,
}

impl OneToolSession {
    fn new(tool: &str, args: serde_json::Value) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            provider: "parity-fixture".into(),
            tool: tool.to_string(),
            args,
        }
    }

    fn next_response(&self) -> LlmResponse {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            LlmResponse {
                content: String::new(),
                finish_reason: Some("tool_calls".into()),
                tokens_used: 1,
                usage: LlmUsage::reported(0, 1, 0),
                tool_calls: vec![ToolCall {
                    id: "parity-call".into(),
                    name: self.tool.clone(),
                    arguments: self.args.clone(),
                }],
            }
        } else {
            LlmResponse {
                content: "done".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 1,
                usage: LlmUsage::reported(0, 1, 0),
                tool_calls: Vec::new(),
            }
        }
    }
}

#[async_trait::async_trait]
impl LlmSession for OneToolSession {
    async fn send(&self, _messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        Ok(self.next_response())
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        Ok(self.next_response())
    }

    fn provider_id(&self) -> &ProviderId {
        &self.provider
    }
}

/// Boot an in-memory kernel with a wiremock Azure adapter, wrap it in a
/// `SyscallServer`, and return the bound address.
async fn spawn_kernel_with_mock(mock_server: &MockServer) -> std::net::SocketAddr {
    let kernel = AgentKernelImpl::new().expect("kernel new");

    let adapter = AzureOpenAiAdapter::new(
        mock_server.uri(),
        "gpt-4o".to_string(),
        "fake-key".to_string(),
    );
    kernel
        .register_provider(Arc::new(adapter))
        .expect("register adapter");
    let kernel = Arc::new(kernel);
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.serve());
    addr
}

/// Seed a fixture through the public tool path so the test exercises the same
/// private, capability-mediated workspace used by the subsequent read.
async fn seed_agent_file(agent: &mut Agent, path: &str, content: &str) {
    agent
        .call_tool(
            "write_file",
            serde_json::json!({"path": path, "content": content}),
        )
        .await
        .expect("seed sandbox fixture through write_file");
}

/// End-to-end ReAct loop: the mock LLM first emits a `TOOL:` directive, the SDK
/// loop executes `read_file` through the kernel, feeds the observation back, and
/// the second turn emits a `FINAL:` answer — all over real syscalls.
#[tokio::test]
async fn react_loop_executes_tool_then_finalizes_e2e() {
    let mock_server = MockServer::start().await;

    // Turn 1: the agent asks to read a file (directive convention in content).
    Mock::given(method("POST"))
        .and(path_regex("/openai/deployments/.*/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "TOOL: read_file {\"path\":\"sdk_react.txt\"}"
                },
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 20}
        })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Turn 2 (after the observation is fed back): the agent finalizes.
    Mock::given(method("POST"))
        .and(path_regex("/openai/deployments/.*/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "FINAL: the file says hello from the sdk react test"
                },
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 18}
        })))
        .mount(&mock_server)
        .await;

    let addr = spawn_kernel_with_mock(&mock_server).await;

    // full-access so the read_file tool clears the gate's capability check.
    let mut agent = Agent::builder()
        .name("react")
        .task("answer using tools")
        .provider("azure-openai")
        .profile("full-access")
        .connect(addr)
        .await
        .expect("builder connect");
    seed_agent_file(&mut agent, "sdk_react.txt", "hello from the sdk react test").await;

    let outcome = ReActLoop::new(DirectiveReasoner::new())
        .max_iterations(5)
        .run(&mut agent, "What does sdk_react.txt contain?")
        .await
        .expect("react run");

    // (a) it reached a final answer within the bound...
    assert!(outcome.reached_final(), "loop should finalize: {outcome:?}");
    assert_eq!(outcome.iterations, 2, "one tool turn + one final turn");
    assert!(
        outcome
            .final_answer
            .as_deref()
            .unwrap_or_default()
            .contains("hello from the sdk react test"),
        "final answer should carry the observed content: {:?}",
        outcome.final_answer
    );

    // (b) ...and it actually executed the tool through the kernel.
    let tools: Vec<_> = outcome.tool_calls().collect();
    assert_eq!(tools.len(), 1, "exactly one tool call");
    assert_eq!(tools[0].tool, "read_file");
    assert_eq!(
        tools[0].observation["content"],
        serde_json::json!("hello from the sdk react test"),
        "observation should be the kernel's tool result"
    );
}

/// The loop honors its iteration bound: a reasoner that always asks for a tool
/// (the mock never finalizes) stops at `max_iterations` with no final answer.
#[tokio::test]
async fn react_loop_respects_max_iterations_e2e() {
    let mock_server = MockServer::start().await;

    // Every turn asks for the tool again — the loop must stop on the bound.
    Mock::given(method("POST"))
        .and(path_regex("/openai/deployments/.*/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "TOOL: read_file {\"path\":\"loop.txt\"}"
                },
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 5}
        })))
        .mount(&mock_server)
        .await;

    let addr = spawn_kernel_with_mock(&mock_server).await;

    let mut agent = Agent::builder()
        .name("looper")
        .task("loop")
        .provider("azure-openai")
        .profile("full-access")
        .connect(addr)
        .await
        .expect("builder connect");
    seed_agent_file(&mut agent, "loop.txt", "never satisfied").await;

    let outcome = ReActLoop::new(DirectiveReasoner::new())
        .max_iterations(3)
        .run(&mut agent, "go")
        .await
        .expect("react run");

    assert!(
        !outcome.reached_final(),
        "should hit the bound, not finalize"
    );
    assert_eq!(outcome.iterations, 3);
    assert_eq!(
        outcome.tool_calls().count(),
        3,
        "one tool call per iteration"
    );
}

/// End-to-end planner/executor: a fixed plan runs a direct tool call then an LLM
/// turn, in order, against the real kernel; the aggregated `PlanRun` reflects
/// both step kinds.
#[tokio::test]
async fn planner_executor_runs_mixed_plan_e2e() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/openai/deployments/.*/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "summary: done"},
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 12}
        })))
        .mount(&mock_server)
        .await;

    let addr = spawn_kernel_with_mock(&mock_server).await;

    let mut agent = Agent::builder()
        .name("planner")
        .task("plan and execute")
        .provider("azure-openai")
        .profile("full-access")
        .connect(addr)
        .await
        .expect("builder connect");
    seed_agent_file(&mut agent, "planned.txt", "planned payload").await;

    // Fixed recipe: read a file, then ask the agent to summarize.
    let planner = FnPlanner(|goal: &str| {
        vec![
            Step::Tool {
                tool: "read_file".into(),
                args: serde_json::json!({ "path": "planned.txt" }),
            },
            Step::Prompt(format!("summarize for goal: {goal}")),
        ]
    });

    let run = PlannerExecutor::new(planner)
        .run(&mut agent, "report on the file")
        .await
        .expect("plan run");

    assert_eq!(run.step_count(), 2, "both steps executed");

    // Step 0 was a direct tool call through the kernel.
    match &run.results[0] {
        StepResult::Tool { tool, observation } => {
            assert_eq!(tool, "read_file");
            assert_eq!(observation["content"], serde_json::json!("planned payload"));
        }
        other => panic!("expected a tool step first, got {other:?}"),
    }

    // Step 1 was an LLM turn; final_content surfaces its output.
    assert_eq!(run.final_content(), Some("summary: done"));
}

/// A read-only agent's tool step in a plan surfaces the kernel's gate denial as
/// an error from the executor — enforcement still applies through the pattern.
#[tokio::test]
async fn planner_executor_propagates_gate_denial_e2e() {
    let mock_server = MockServer::start().await;
    // No LLM turns are reached before the denial, but bind a default mock anyway.
    Mock::given(method("POST"))
        .and(path_regex("/openai/deployments/.*/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"total_tokens": 1}
        })))
        .mount(&mock_server)
        .await;

    let addr = spawn_kernel_with_mock(&mock_server).await;

    // read-only lacks CAP_FILE_WRITE.
    let mut agent = Agent::builder()
        .name("ro-plan")
        .task("t")
        .provider("azure-openai")
        .profile("read-only")
        .connect(addr)
        .await
        .expect("builder connect");

    let planner = FnPlanner(|_: &str| {
        vec![Step::Tool {
            tool: "write_file".into(),
            args: serde_json::json!({ "path": "/tmp/x", "content": "y" }),
        }]
    });

    let err = PlannerExecutor::new(planner)
        .run(&mut agent, "try to write")
        .await
        .expect_err("write step should be denied by the gate");
    match err {
        agent_sdk::SdkError::Kernel(msg) => {
            assert!(
                msg.contains("denied by kernel"),
                "expected gate denial: {msg}"
            )
        }
        other => panic!("expected Kernel denial, got {other:?}"),
    }
}

async fn executor_path_allows(
    kernel: &AgentKernelImpl,
    agent_id: AgentId,
    tool: &str,
    args: &serde_json::Value,
) -> bool {
    let mut executor = AgentExecutor::new(
        agent_id,
        Box::new(OneToolSession::new(tool, args.clone())),
        kernel.resource_broker.clone(),
        kernel.tool_registry.clone(),
        kernel.context_manager.clone(),
        kernel.syscall_gate.clone(),
        "exercise the declared package tool once".into(),
    );
    executor
        .run("run parity fixture")
        .await
        .expect("executor run");
    let result = executor
        .messages()
        .iter()
        .find(|message| message.role == "tool")
        .expect("executor must record a tool result")
        .content
        .as_str();
    if result.contains("denied by kernel") {
        return false;
    }
    assert!(
        !result.contains("Unknown tool")
            && !result.contains(" failed:")
            && !result.contains(" error:"),
        "authorization passed but the fixture tool did not execute: {result}"
    );
    true
}

async fn syscall_wire_path_allows(
    client: &mut SyscallClient,
    agent_id: AgentId,
    tool: &str,
    args: &serde_json::Value,
) -> bool {
    match client
        .call(Syscall::CallTool {
            agent_id: agent_id.to_string(),
            tool: tool.to_string(),
            args: args.clone(),
        })
        .await
        .expect("wire call")
    {
        SyscallReply::ToolResult { .. } => true,
        SyscallReply::Error { message } if message.contains("denied by kernel") => false,
        other => panic!("unexpected raw CallTool verdict: {other:?}"),
    }
}

async fn mcp_path_allows(client: &mut McpClient, tool: &str, args: &serde_json::Value) -> bool {
    let response = client
        .request(
            "tools/call",
            Some(serde_json::json!({
                "name": tool,
                "arguments": args,
            })),
        )
        .await
        .expect("MCP call");
    match (response.result, response.error) {
        (Some(_), None) => true,
        (None, Some(error)) if error.message.contains("denied by kernel") => false,
        other => panic!("unexpected MCP tools/call verdict: {other:?}"),
    }
}

async fn sdk_pattern_path_allows(
    addr: std::net::SocketAddr,
    profile: &str,
    tool: &str,
    args: &serde_json::Value,
) -> bool {
    let mut agent = Agent::builder()
        .name(format!("sdk-parity-{profile}"))
        .task("exercise the declared package tool once")
        .profile(profile)
        .connect(addr)
        .await
        .expect("SDK agent");
    let tool = tool.to_string();
    let args = args.clone();
    let planner = FnPlanner(move |_: &str| {
        vec![Step::Tool {
            tool: tool.clone(),
            args: args.clone(),
        }]
    });
    match PlannerExecutor::new(planner)
        .run(&mut agent, "run parity fixture")
        .await
    {
        Ok(run) => {
            assert!(
                matches!(run.results.as_slice(), [StepResult::Tool { .. }]),
                "SDK planner must execute exactly one tool step"
            );
            true
        }
        Err(agent_sdk::SdkError::Kernel(message)) if message.contains("denied by kernel") => false,
        Err(other) => panic!("unexpected SDK planner verdict: {other:?}"),
    }
}

/// One declaration must produce the same allow/deny decision through every
/// public execution surface. The binding is published as shared package data,
/// resolved from each package manifest, installed into the live registry, and
/// then exercised by package-loaded agents through executor, raw CallTool, MCP,
/// and the SDK planner pattern.
#[tokio::test]
async fn package_tool_security_decisions_are_identical_across_public_paths() {
    const TOOL: &str = "package_write_note";
    let args = serde_json::json!({"path": "parity.txt", "content": "same contract"});

    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
    let mut shared = SharedToolRegistry::new();
    shared
        .publish(
            SharedToolDef::new(
                TOOL,
                "Write a note supplied by an installed agent package",
                ResourceType::Filesystem,
                "write",
                ToolSecurity::argument(SecurityAction::Write, "path").sandboxed(),
            )
            .with_parameters(serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["path", "content"]
            })),
        )
        .expect("publish complete package tool declaration");

    let package_source = |name: &str, profile: &str| {
        AgentManifest::from_toml_str(&format!(
            "name = \"{name}\"\ntask = \"parity\"\nprofile = \"{profile}\"\ntools = [\"{TOOL}\"]\n"
        ))
        .expect("package manifest")
    };
    let denied_manifest = package_source("package-parity-denied", "read-only");
    let allowed_manifest = package_source("package-parity-allowed", "standard");

    let resolved = denied_manifest
        .resolve_tools(&shared)
        .expect("package tool resolution");
    assert_eq!(resolved.len(), 1);
    kernel
        .tool_registry
        .register(resolved[0].to_binding())
        .expect("install package-resolved binding");
    assert_eq!(
        allowed_manifest.resolve_tools(&shared).expect("resolution"),
        resolved,
        "both packages must resolve the exact same security declaration"
    );

    let tenant = kernel
        .create_tenant("parity-owner")
        .await
        .expect("create parity tenant");
    let user = kernel
        .register_user(&tenant, "parity-user", "parity@example.test", Role::User)
        .await
        .expect("create parity user");
    let token = kernel.open_session(&user).await.expect("open MCP session");
    let denied_agent = load_package_for_tenant(&kernel, &tenant, &denied_manifest)
        .await
        .expect("load denied package");
    let allowed_agent = load_package_for_tenant(&kernel, &tenant, &allowed_manifest)
        .await
        .expect("load allowed package");

    let syscall_server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .expect("bind syscall server");
    let syscall_addr = syscall_server.local_addr().expect("syscall address");
    tokio::spawn(syscall_server.serve());
    let mut syscall_client = SyscallClient::connect(syscall_addr)
        .await
        .expect("raw syscall client");

    let mcp_server = McpServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .expect("bind MCP server");
    let mcp_addr = mcp_server.local_addr().expect("MCP address");
    tokio::spawn(mcp_server.serve());
    let mut denied_mcp_client = McpClient::connect(mcp_addr)
        .await
        .expect("denied MCP client");
    let denied_auth = denied_mcp_client
        .authenticate(token.clone(), denied_agent.id)
        .await
        .expect("authenticate denied-profile MCP client");
    assert!(
        denied_auth.error.is_none(),
        "MCP authentication failed: {:?}",
        denied_auth.error
    );
    let mut allowed_mcp_client = McpClient::connect(mcp_addr)
        .await
        .expect("allowed MCP client");
    let allowed_auth = allowed_mcp_client
        .authenticate(token, allowed_agent.id)
        .await
        .expect("authenticate standard-profile MCP client");
    assert!(
        allowed_auth.error.is_none(),
        "MCP authentication failed: {:?}",
        allowed_auth.error
    );

    let denied = [
        executor_path_allows(&kernel, denied_agent.id, TOOL, &args).await,
        syscall_wire_path_allows(&mut syscall_client, denied_agent.id, TOOL, &args).await,
        mcp_path_allows(&mut denied_mcp_client, TOOL, &args).await,
        sdk_pattern_path_allows(syscall_addr, "read-only", TOOL, &args).await,
    ];
    assert_eq!(
        denied, [false; 4],
        "read-only must receive the same declaration-backed denial everywhere"
    );

    let allowed = [
        executor_path_allows(&kernel, allowed_agent.id, TOOL, &args).await,
        syscall_wire_path_allows(&mut syscall_client, allowed_agent.id, TOOL, &args).await,
        mcp_path_allows(&mut allowed_mcp_client, TOOL, &args).await,
        sdk_pattern_path_allows(syscall_addr, "standard", TOOL, &args).await,
    ];
    assert_eq!(
        allowed, [true; 4],
        "standard must receive the same declaration-backed allow everywhere"
    );

    let stats = kernel.syscall_gate.stats();
    assert_eq!(
        stats.denied_capability, 4,
        "each denied public path must record the same missing-capability verdict"
    );
    assert_eq!(
        stats.allowed, 4,
        "each allowed public path must record one admitted execution"
    );
}

/// Sanity: the low-level client the patterns build on still connects (keeps the
/// test file self-contained if the patterns API changes).
#[tokio::test]
async fn kernel_client_connects_for_patterns() {
    let mock_server = MockServer::start().await;
    let addr = spawn_kernel_with_mock(&mock_server).await;
    let mut client = KernelClient::connect(addr).await.expect("connect");
    assert!(client.list_agents().await.expect("list").is_empty());
}
