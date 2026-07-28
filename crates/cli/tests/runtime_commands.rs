use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kernel::auth::Role;
use kernel::connector::{
    LlmProviderAdapter, LlmResponse, LlmSession, LlmUsage, ProviderCapabilities, ProviderType,
    StandardMessage, ToolDefinition,
};
use kernel::{AgentConfig, AgentKernelImpl, ConnectorError, Priority, ProviderId};

struct CliTestAdapter {
    id: ProviderId,
    delayed_calls: Arc<AtomicUsize>,
    delayed_calls_per_provider: usize,
}

struct CliTestSession {
    id: ProviderId,
    delayed_calls: Arc<AtomicUsize>,
    delayed_calls_per_provider: usize,
}

impl CliTestSession {
    async fn response(&self) -> Result<LlmResponse, ConnectorError> {
        if self.delayed_calls.fetch_add(1, Ordering::SeqCst) < self.delayed_calls_per_provider {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        Ok(LlmResponse {
            content: format!("response from {}", self.id),
            finish_reason: Some("stop".into()),
            tokens_used: 7,
            usage: LlmUsage::reported(4, 3, 0),
            tool_calls: Vec::new(),
        })
    }
}

#[async_trait]
impl LlmSession for CliTestSession {
    async fn send(&self, _messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.response().await
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.response().await
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "cli-regression-model"
    }
}

#[async_trait]
impl LlmProviderAdapter for CliTestAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        &self.id
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(CliTestSession {
            id: self.id.clone(),
            delayed_calls: Arc::clone(&self.delayed_calls),
            delayed_calls_per_provider: self.delayed_calls_per_provider,
        }))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            native_streaming: true,
            prompt_cancellation: true,
            ..ProviderCapabilities::default()
        }
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({ "role": message.role, "content": message.content })
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value["content"].as_str()?))
    }
}

fn agentctl(addr: &str, token: Option<&str>, arguments: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentctl"));
    command.arg("--addr").arg(addr);
    if let Some(token) = token {
        command.arg("--token").arg(token);
    }
    command
        .args(arguments)
        .output()
        .expect("run agentctl command")
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn parse_json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON output ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn pause_stream_and_get_checkpoint(
    address: &str,
    token: &str,
    agent_id: &str,
    request_id: &str,
) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--addr")
        .arg(address)
        .arg("--token")
        .arg(token)
        .args(["stream", request_id, agent_id, "pause at provider boundary"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn checkpoint stream");
    let mut stdout = BufReader::new(child.stdout.take().expect("checkpoint stdout"));
    let mut started = String::new();
    stdout.read_line(&mut started).expect("read started frame");
    let started: serde_json::Value =
        serde_json::from_str(&started).expect("checkpoint started frame JSON");
    assert_eq!(started["event"]["event"], "started");

    let paused = agentctl(address, Some(token), &["pause", agent_id]);
    assert_success(&paused, "pause active stream");
    assert_eq!(String::from_utf8_lossy(&paused.stdout).trim(), "Paused");

    let mut remaining_stdout = String::new();
    stdout
        .read_to_string(&mut remaining_stdout)
        .expect("read paused stream output");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("checkpoint stderr")
        .read_to_string(&mut stderr)
        .expect("read checkpoint stderr");
    let status = child.wait().expect("wait for paused stream");
    assert!(
        status.success(),
        "durably paused stream failed:\nstdout={started}{remaining_stdout}\nstderr={stderr}"
    );
    let terminal: serde_json::Value =
        serde_json::from_str(remaining_stdout.trim()).expect("paused terminal frame JSON");
    assert_eq!(terminal["type"], "completed");
    assert!(terminal["result"]["content"]
        .as_str()
        .is_some_and(|content| content.starts_with("Paused at durable checkpoint ")));

    let checkpoints = agentctl(address, Some(token), &["checkpoints", agent_id]);
    assert_success(&checkpoints, "list durable checkpoint");
    let checkpoints = parse_json(&checkpoints);
    let checkpoints = checkpoints.as_array().expect("checkpoint array");
    assert_eq!(checkpoints.len(), 1);
    checkpoints[0]["id"]
        .as_str()
        .expect("checkpoint id")
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_agentctl_covers_tenant_runtime_streams_and_operations_views() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    for (id, delayed_calls_per_provider) in [
        ("cli-fast", 0),
        ("cli-slow", usize::MAX),
        ("cli-checkpoint-resume", 1),
        ("cli-checkpoint-delete", 1),
    ] {
        kernel
            .register_provider(Arc::new(CliTestAdapter {
                id: id.into(),
                delayed_calls: Arc::new(AtomicUsize::new(0)),
                delayed_calls_per_provider,
            }))
            .expect("register test provider");
    }

    let tenant = kernel
        .create_tenant("agentctl-runtime")
        .await
        .expect("tenant");
    let user = kernel
        .register_user(
            &tenant,
            "operator",
            "operator@agentctl-runtime.test",
            Role::User,
        )
        .await
        .expect("user");
    let token = kernel
        .issue_api_key(&user, "agentctl-runtime")
        .await
        .expect("API key");
    let foreign = kernel
        .create_agent_full(AgentConfig {
            name: "foreign-system-agent".into(),
            task: "must remain outside tenant output".into(),
            llm_provider: "cli-fast".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        })
        .await
        .expect("foreign agent");

    let server = kernel::syscall_server::SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind");
    let address = server.local_addr().expect("server address").to_string();
    let server_task = tokio::spawn(server.serve());

    let created = agentctl(
        &address,
        Some(&token),
        &[
            "create",
            "tenant-agent",
            "exercise canonical operator",
            "cli-fast",
            "standard",
            "4",
        ],
    );
    assert_success(&created, "create");
    let agent_id = parse_json(&created)["id"]
        .as_str()
        .expect("created agent id")
        .to_string();
    assert_eq!(
        kernel
            .context_manager
            .agent_tenant(agent_id.parse().expect("agent UUID"))
            .expect("tenant lookup"),
        Some(tenant.clone()),
    );

    let list = agentctl(&address, Some(&token), &["list"]);
    assert_success(&list, "list");
    let list_text = String::from_utf8_lossy(&list.stdout);
    assert!(list_text.contains(&agent_id));
    assert!(!list_text.contains(&foreign.id.to_string()));

    let inspect = agentctl(&address, Some(&token), &["inspect"]);
    assert_success(&inspect, "inspect");
    let inspect_json = parse_json(&inspect);
    assert_eq!(inspect_json["scope"], format!("tenant:{tenant}"));
    assert_eq!(inspect_json["agents"][0]["id"], agent_id);
    assert!(inspect_json["agents"][0]["cgroup"].is_object());
    assert!(inspect_json["agents"][0]["context_pressure"].is_object());
    assert!(inspect_json["services"].is_null());
    assert!(inspect_json["system_metrics"].is_null());

    let capabilities = agentctl(&address, Some(&token), &["capabilities", &agent_id]);
    assert_success(&capabilities, "capabilities");
    let capabilities = parse_json(&capabilities);
    assert!(capabilities["pid"].as_u64().is_some());
    assert!(capabilities["capabilities"].is_array());
    assert!(capabilities["namespaces"].is_array());

    let providers = agentctl(&address, Some(&token), &["providers"]);
    assert_success(&providers, "providers");
    let providers = parse_json(&providers);
    assert!(providers
        .as_array()
        .expect("provider array")
        .iter()
        .any(|provider| provider["id"] == "cli-fast"
            && provider["available"] == true
            && provider["capabilities"]["native_streaming"] == true));

    let message = agentctl(
        &address,
        Some(&token),
        &["message", &agent_id, "hello from agentctl"],
    );
    assert_success(&message, "message");
    let message = parse_json(&message);
    assert_eq!(message["content"], "response from cli-fast");
    assert_eq!(message["tokens"], 7);

    let stream = agentctl(
        &address,
        Some(&token),
        &["stream", "runtime-stream-1", &agent_id, "stream this"],
    );
    assert_success(&stream, "stream");
    let stream_lines = String::from_utf8(stream.stdout)
        .expect("UTF-8 stream")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("NDJSON frame"))
        .collect::<Vec<_>>();
    assert_eq!(stream_lines[0]["event"]["event"], "started");
    assert!(stream_lines.iter().any(|line| {
        line["type"] == "event"
            && line["event"]["event"] == "token"
            && line["event"]["delta"] == "response from cli-fast"
    }));
    assert_eq!(
        stream_lines.last().expect("terminal frame")["type"],
        "completed"
    );

    let checkpoints = agentctl(&address, Some(&token), &["checkpoints", &agent_id]);
    assert_success(&checkpoints, "checkpoints");
    assert_eq!(parse_json(&checkpoints), serde_json::json!([]));

    let protocol = agentctl(&address, Some(&token), &["protocol"]);
    assert_success(&protocol, "protocol");
    let protocol = parse_json(&protocol);
    assert_eq!(
        protocol["protocol_version"],
        kernel::syscall_server::PROTOCOL_VERSION
    );
    assert!(protocol["features"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));

    let metrics = agentctl(&address, None, &["metrics"]);
    assert_success(&metrics, "metrics");
    let metrics = String::from_utf8_lossy(&metrics.stdout);
    assert!(metrics.contains("# TYPE agentos_agents gauge"));
    assert!(metrics.contains("# TYPE agentos_syscall_gate_total counter"));
    let denied_metrics = agentctl(&address, Some(&token), &["metrics"]);
    assert!(!denied_metrics.status.success());
    assert!(denied_metrics.stdout.is_empty());
    assert!(String::from_utf8_lossy(&denied_metrics.stderr).contains("AuthorizationDenied"));

    let checkpoint_created = agentctl(
        &address,
        Some(&token),
        &[
            "create",
            "checkpoint-resume-agent",
            "exercise durable resume",
            "cli-checkpoint-resume",
            "standard",
            "3",
        ],
    );
    assert_success(&checkpoint_created, "create checkpoint resume agent");
    let checkpoint_agent_id = parse_json(&checkpoint_created)["id"]
        .as_str()
        .expect("checkpoint agent id")
        .to_string();
    let checkpoint_address = address.clone();
    let checkpoint_token = token.clone();
    let checkpoint_agent = checkpoint_agent_id.clone();
    let checkpoint_id = tokio::task::spawn_blocking(move || {
        pause_stream_and_get_checkpoint(
            &checkpoint_address,
            &checkpoint_token,
            &checkpoint_agent,
            "runtime-checkpoint-resume",
        )
    })
    .await
    .expect("checkpoint pause task");
    let resumed = agentctl(
        &address,
        Some(&token),
        &["checkpoint-resume", &checkpoint_agent_id, &checkpoint_id],
    );
    assert_success(&resumed, "checkpoint-resume");
    let resumed = parse_json(&resumed);
    assert_eq!(resumed["state"], "Running");
    assert!(resumed["checkpoint_id"].is_null());
    assert_eq!(
        resumed["resumed_content"],
        "response from cli-checkpoint-resume"
    );

    let delete_created = agentctl(
        &address,
        Some(&token),
        &[
            "create",
            "checkpoint-delete-agent",
            "exercise durable deletion",
            "cli-checkpoint-delete",
            "standard",
            "3",
        ],
    );
    assert_success(&delete_created, "create checkpoint delete agent");
    let delete_agent_id = parse_json(&delete_created)["id"]
        .as_str()
        .expect("delete agent id")
        .to_string();
    let delete_address = address.clone();
    let delete_token = token.clone();
    let delete_agent = delete_agent_id.clone();
    let delete_checkpoint_id = tokio::task::spawn_blocking(move || {
        pause_stream_and_get_checkpoint(
            &delete_address,
            &delete_token,
            &delete_agent,
            "runtime-checkpoint-delete",
        )
    })
    .await
    .expect("checkpoint delete pause task");
    let deleted = agentctl(
        &address,
        Some(&token),
        &["checkpoint-delete", &delete_agent_id, &delete_checkpoint_id],
    );
    assert_success(&deleted, "checkpoint-delete");
    assert_eq!(parse_json(&deleted)["deleted"], true);
    let after_delete = agentctl(&address, Some(&token), &["checkpoints", &delete_agent_id]);
    assert_success(&after_delete, "checkpoints after delete");
    assert_eq!(parse_json(&after_delete), serde_json::json!([]));

    let slow_created = agentctl(
        &address,
        Some(&token),
        &[
            "create",
            "slow-agent",
            "prove cancellation",
            "cli-slow",
            "standard",
            "3",
        ],
    );
    assert_success(&slow_created, "create slow agent");
    let slow_agent_id = parse_json(&slow_created)["id"]
        .as_str()
        .expect("slow agent id")
        .to_string();

    let cancellation_address = address.clone();
    let cancellation_token = token.clone();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_agentctl"))
            .arg("--addr")
            .arg(&cancellation_address)
            .arg("--token")
            .arg(&cancellation_token)
            .args([
                "stream",
                "runtime-cancel-1",
                &slow_agent_id,
                "wait until cancelled",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cancellable stream");
        let mut stdout = BufReader::new(child.stdout.take().expect("stream stdout"));
        let mut started = String::new();
        stdout.read_line(&mut started).expect("read started frame");
        let started: serde_json::Value =
            serde_json::from_str(&started).expect("started frame JSON");
        assert_eq!(started["event"]["event"], "started");

        let cancelled = agentctl(
            &cancellation_address,
            Some(&cancellation_token),
            &["cancel", "runtime-cancel-1", &slow_agent_id],
        );
        assert_success(&cancelled, "cancel");
        assert_eq!(parse_json(&cancelled)["accepted"], true);

        let mut remaining_stdout = String::new();
        stdout
            .read_to_string(&mut remaining_stdout)
            .expect("read remaining stream output");
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("stream stderr")
            .read_to_string(&mut stderr)
            .expect("read stream stderr");
        let status = child.wait().expect("wait for cancelled stream");
        assert!(!status.success(), "cancelled stream unexpectedly succeeded");
        assert!(
            stderr.contains("Cancelled") || stderr.contains("cancelled"),
            "cancelled stream omitted typed diagnostic: {stderr}"
        );
    })
    .await
    .expect("cancellation task");

    server_task.abort();
    let _ = server_task.await;
}
