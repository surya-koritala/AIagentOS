//! Integration tests for the SDK agent **patterns** ([`agent_sdk::patterns`]).
//!
//! These stand up a *real* in-memory kernel behind a `SyscallServer`, register a
//! **wiremock-backed** `AzureOpenAiAdapter` (no real API calls) and a filesystem
//! resource provider, then drive the patterns end-to-end through the SDK over
//! loopback TCP. The ReAct test proves the loop (a) executed a tool through the
//! kernel and (b) reached the final answer within the iteration bound; the
//! planner test proves the plan→execute control flow runs a mix of turns and
//! direct tool calls in order.

use std::sync::Arc;

use agent_sdk::patterns::{
    DirectiveReasoner, FnPlanner, PlannerExecutor, ReActLoop, Step, StepResult,
};
use agent_sdk::{Agent, KernelClient};

use adapters::azure_openai::AzureOpenAiAdapter;
use kernel::resources::{ResourceBroker, ResourceProvider, ResourceType};
use kernel::syscall_server::SyscallServer;
use kernel::{AgentKernelImpl, ResourceError};

use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A tiny in-memory filesystem provider so `read_file` returns a known payload
/// without touching the real disk.
struct FakeFs {
    content: String,
}

#[async_trait::async_trait]
impl ResourceProvider for FakeFs {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Filesystem
    }
    fn supported_operations(&self) -> Vec<String> {
        vec!["read".into(), "write".into(), "list".into()]
    }
    async fn execute(
        &self,
        operation: &str,
        _params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError> {
        match operation {
            "read" => Ok(serde_json::json!({ "content": self.content })),
            _ => Ok(serde_json::json!({})),
        }
    }
}

/// Boot an in-memory kernel with a wiremock Azure adapter + a fake-fs provider,
/// wrap it in a `SyscallServer`, and return the bound addr. `mock_content` is
/// what `read_file` will return.
async fn spawn_kernel_with_mock(
    mock_server: &MockServer,
    mock_content: &str,
) -> std::net::SocketAddr {
    let kernel = AgentKernelImpl::new().expect("kernel new");

    let adapter = AzureOpenAiAdapter::new(
        mock_server.uri(),
        "gpt-4o".to_string(),
        "fake-key".to_string(),
    );
    kernel
        .register_provider(Arc::new(adapter))
        .expect("register adapter");
    kernel.resource_broker.register_provider(Box::new(FakeFs {
        content: mock_content.to_string(),
    }));

    let kernel = Arc::new(kernel);
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.serve());
    addr
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
                    "content": "TOOL: read_file {\"path\":\"/tmp/sdk_react.txt\"}"
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

    let addr = spawn_kernel_with_mock(&mock_server, "hello from the sdk react test").await;

    // full-access so the read_file tool clears the gate's capability check.
    let mut agent = Agent::builder()
        .name("react")
        .task("answer using tools")
        .provider("azure-openai")
        .profile("full-access")
        .connect(addr)
        .await
        .expect("builder connect");

    let outcome = ReActLoop::new(DirectiveReasoner::new())
        .max_iterations(5)
        .run(&mut agent, "What does /tmp/sdk_react.txt contain?")
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
                    "content": "TOOL: read_file {\"path\":\"/tmp/loop.txt\"}"
                },
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 5}
        })))
        .mount(&mock_server)
        .await;

    let addr = spawn_kernel_with_mock(&mock_server, "never satisfied").await;

    let mut agent = Agent::builder()
        .name("looper")
        .task("loop")
        .provider("azure-openai")
        .profile("full-access")
        .connect(addr)
        .await
        .expect("builder connect");

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

    let addr = spawn_kernel_with_mock(&mock_server, "planned payload").await;

    let mut agent = Agent::builder()
        .name("planner")
        .task("plan and execute")
        .provider("azure-openai")
        .profile("full-access")
        .connect(addr)
        .await
        .expect("builder connect");

    // Fixed recipe: read a file, then ask the agent to summarize.
    let planner = FnPlanner(|goal: &str| {
        vec![
            Step::Tool {
                tool: "read_file".into(),
                args: serde_json::json!({ "path": "/tmp/planned.txt" }),
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

    let addr = spawn_kernel_with_mock(&mock_server, "x").await;

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

/// Sanity: the low-level client the patterns build on still connects (keeps the
/// test file self-contained if the patterns API changes).
#[tokio::test]
async fn kernel_client_connects_for_patterns() {
    let mock_server = MockServer::start().await;
    let addr = spawn_kernel_with_mock(&mock_server, "x").await;
    let mut client = KernelClient::connect(addr).await.expect("connect");
    assert!(client.list_agents().await.expect("list").is_empty());
}
