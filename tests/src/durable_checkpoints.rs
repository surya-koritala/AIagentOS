//! Public-runtime regressions for durable generation checkpoints (#113).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, ProviderType, StandardMessage,
    ToolCall, ToolDefinition,
};
use kernel::context::{SqliteContextManager, DEFAULT_TENANT};
use kernel::execution::{GenerationCheckpoint, UsageTelemetry};
use kernel::sandbox::SandboxManager;
use kernel::syscall_server::{dispatch_scoped, Syscall, SyscallReply};
use kernel::{auth::Principal, auth::Role};
use kernel::{AgentConfig, AgentKernelImpl, AgentState, ConnectorError, Priority};

struct BoundaryAdapter {
    id: String,
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    block_first: bool,
}

struct BoundarySession {
    id: String,
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    block_first: bool,
}

#[async_trait]
impl LlmSession for BoundarySession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.block_first && call == 0 {
            self.started.notify_waiters();
            std::future::pending::<()>().await;
        }
        Ok(LlmResponse {
            content: "resumed exactly once".into(),
            finish_reason: Some("stop".into()),
            tokens_used: 7,
            usage: kernel::connector::LlmUsage::reported(4, 3, 0),
            tool_calls: Vec::new(),
        })
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        assert!(options.max_output_tokens.is_none_or(|limit| limit >= 3));
        self.send_with_tools(messages, tools).await
    }

    fn provider_id(&self) -> &String {
        &self.id
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }

    fn model_id(&self) -> &str {
        "checkpoint-model-v1"
    }
}

#[async_trait]
impl LlmProviderAdapter for BoundaryAdapter {
    fn id(&self) -> &String {
        &self.id
    }

    fn name(&self) -> &str {
        "checkpoint-boundary"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(BoundarySession {
            id: self.id.clone(),
            calls: Arc::clone(&self.calls),
            started: Arc::clone(&self.started),
            block_first: self.block_first,
        }))
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

struct CyclingAdapter {
    id: String,
    block_requests: Arc<AtomicBool>,
    blocked_requests: Arc<AtomicUsize>,
}

struct CyclingSession {
    id: String,
    block_requests: Arc<AtomicBool>,
    blocked_requests: Arc<AtomicUsize>,
}

#[async_trait]
impl LlmSession for CyclingSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        if self.block_requests.load(Ordering::SeqCst) {
            self.blocked_requests.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        Ok(LlmResponse {
            content: "resumed cycle".into(),
            finish_reason: Some("stop".into()),
            tokens_used: 4,
            usage: kernel::connector::LlmUsage::reported(2, 2, 0),
            tool_calls: Vec::new(),
        })
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        _options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, tools).await
    }

    fn provider_id(&self) -> &String {
        &self.id
    }

    fn model_id(&self) -> &str {
        "cycling-model-v1"
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait]
impl LlmProviderAdapter for CyclingAdapter {
    fn id(&self) -> &String {
        &self.id
    }

    fn name(&self) -> &str {
        "checkpoint-cycling"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(CyclingSession {
            id: self.id.clone(),
            block_requests: Arc::clone(&self.block_requests),
            blocked_requests: Arc::clone(&self.blocked_requests),
        }))
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

struct RestartToolAdapter {
    id: String,
    calls: Arc<AtomicUsize>,
    second_request_started: Arc<tokio::sync::Notify>,
    path: String,
}

struct RestartToolSession {
    id: String,
    calls: Arc<AtomicUsize>,
    second_request_started: Arc<tokio::sync::Notify>,
    path: String,
}

#[async_trait]
impl LlmSession for RestartToolSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        match self.calls.fetch_add(1, Ordering::SeqCst) {
            0 => Ok(LlmResponse {
                content: String::new(),
                finish_reason: Some("tool_calls".into()),
                tokens_used: 4,
                usage: kernel::connector::LlmUsage::reported(2, 2, 0),
                tool_calls: vec![ToolCall {
                    id: "stable-write-call".into(),
                    name: "write_file".into(),
                    arguments: serde_json::json!({
                        "path": self.path,
                        "content": "written exactly once"
                    }),
                }],
            }),
            1 => {
                self.second_request_started.notify_waiters();
                std::future::pending::<Result<LlmResponse, ConnectorError>>().await
            }
            _ => Ok(LlmResponse {
                content: "continued after restart".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 4,
                usage: kernel::connector::LlmUsage::reported(2, 2, 0),
                tool_calls: Vec::new(),
            }),
        }
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        _options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, tools).await
    }

    fn provider_id(&self) -> &String {
        &self.id
    }

    fn model_id(&self) -> &str {
        "restart-tool-model-v1"
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait]
impl LlmProviderAdapter for RestartToolAdapter {
    fn id(&self) -> &String {
        &self.id
    }

    fn name(&self) -> &str {
        "checkpoint-restart-tool"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(RestartToolSession {
            id: self.id.clone(),
            calls: Arc::clone(&self.calls),
            second_request_started: Arc::clone(&self.second_request_started),
            path: self.path.clone(),
        }))
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

struct CompletionRaceAdapter {
    id: String,
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

struct CompletionRaceSession {
    id: String,
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl LlmSession for CompletionRaceSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.started.notify_waiters();
            self.release.notified().await;
        }
        Ok(LlmResponse {
            content: "completion race resolved".into(),
            finish_reason: Some("stop".into()),
            tokens_used: 4,
            usage: kernel::connector::LlmUsage::reported(2, 2, 0),
            tool_calls: Vec::new(),
        })
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        _options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, tools).await
    }

    fn provider_id(&self) -> &String {
        &self.id
    }

    fn model_id(&self) -> &str {
        "completion-race-model-v1"
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait]
impl LlmProviderAdapter for CompletionRaceAdapter {
    fn id(&self) -> &String {
        &self.id
    }

    fn name(&self) -> &str {
        "checkpoint-completion-race"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(CompletionRaceSession {
            id: self.id.clone(),
            calls: Arc::clone(&self.calls),
            started: Arc::clone(&self.started),
            release: Arc::clone(&self.release),
        }))
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

fn config(provider: &str) -> AgentConfig {
    AgentConfig {
        name: "checkpoint-agent".into(),
        task: "pause and continue".into(),
        llm_provider: provider.into(),
        permission_profile: "standard".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_request_pause_persists_and_resume_consumes_once() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(tokio::sync::Notify::new());
    let adapter = Arc::new(BoundaryAdapter {
        id: "checkpoint-provider".into(),
        calls: Arc::clone(&calls),
        started: Arc::clone(&started),
        block_first: true,
    });
    kernel.register_provider(adapter).unwrap();
    let id = kernel
        .create_agent_full(config("checkpoint-provider"))
        .await
        .unwrap()
        .id;

    let started_wait = started.notified();
    let sending = {
        let kernel = Arc::clone(&kernel);
        tokio::spawn(async move { kernel.send_message(id, "begin long request").await })
    };
    started_wait.await;
    assert_eq!(kernel.pause_agent(id).await.unwrap(), AgentState::Paused);
    let paused = sending.await.unwrap().unwrap();
    assert!(paused.content.contains("durable checkpoint"));

    let checkpoint = kernel
        .latest_generation_checkpoint(id)
        .unwrap()
        .expect("checkpoint identity");
    assert_eq!(checkpoint.provider_id, "checkpoint-provider");
    assert_eq!(checkpoint.model_id, "checkpoint-model-v1");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let (state, output, next) = kernel
        .resume_agent_from_checkpoint(id, Some(checkpoint.id))
        .await
        .unwrap();
    assert_eq!(state, AgentState::Running);
    assert_eq!(output.unwrap().content, "resumed exactly once");
    assert!(next.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(kernel.latest_generation_checkpoint(id).unwrap().is_none());

    let duplicate = kernel
        .resume_agent_from_checkpoint(id, Some(checkpoint.id))
        .await
        .unwrap_err();
    assert!(duplicate.to_string().contains("Invalid state transition"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn public_pause_completion_race_never_leaves_an_orphan_checkpoint() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    kernel
        .register_provider(Arc::new(CompletionRaceAdapter {
            id: "completion-race-provider".into(),
            calls: Arc::clone(&calls),
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        }))
        .unwrap();
    let agent_id = kernel
        .create_agent_full(config("completion-race-provider"))
        .await
        .unwrap()
        .id;

    let started_wait = started.notified();
    let send_kernel = Arc::clone(&kernel);
    let sending = tokio::spawn(async move {
        send_kernel
            .send_message(agent_id, "race pause against completion")
            .await
    });
    started_wait.await;

    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let pause_kernel = Arc::clone(&kernel);
    let pause_barrier = Arc::clone(&barrier);
    let pausing = tokio::spawn(async move {
        pause_barrier.wait().await;
        pause_kernel.pause_agent(agent_id).await
    });
    let release_barrier = Arc::clone(&barrier);
    let releasing = tokio::spawn(async move {
        release_barrier.wait().await;
        release.notify_waiters();
    });
    barrier.wait().await;

    assert_eq!(pausing.await.unwrap().unwrap(), AgentState::Paused);
    releasing.await.unwrap();
    let send_output = sending.await.unwrap().unwrap();
    if send_output.content.contains("durable checkpoint") {
        let checkpoint_id = kernel
            .latest_generation_checkpoint(agent_id)
            .unwrap()
            .expect("a paused race outcome must publish its checkpoint")
            .id;
        let (state, output, next) = kernel
            .resume_agent_from_checkpoint(agent_id, Some(checkpoint_id))
            .await
            .unwrap();
        assert_eq!(state, AgentState::Running);
        assert_eq!(output.unwrap().content, "completion race resolved");
        assert!(next.is_none());
    } else {
        assert_eq!(send_output.content, "completion race resolved");
        assert!(kernel
            .latest_generation_checkpoint(agent_id)
            .unwrap()
            .is_none());
        assert_eq!(
            kernel.resume_agent(agent_id).await.unwrap(),
            AgentState::Running
        );
    }

    assert!(kernel
        .latest_generation_checkpoint(agent_id)
        .unwrap()
        .is_none());
    let metrics = kernel::metrics::MetricsSnapshot::collect(&kernel);
    assert_eq!(metrics.active_turns, 0);
    assert_eq!(metrics.waiting_turns, 0);
    assert_eq!(metrics.llm_requests_in_flight, 0);
    assert_eq!(metrics.llm_requests_waiting, 0);
    assert!(calls.load(Ordering::SeqCst) <= 2);
}

#[test]
fn paused_checkpoint_survives_server_restart_and_resumes() {
    let root = std::env::temp_dir().join(format!("aiagentos-checkpoint-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("kernel.sqlite");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let (agent_id, checkpoint_id) = {
        let kernel = Arc::new(AgentKernelImpl::with_db_path(&db).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        kernel
            .register_provider(Arc::new(BoundaryAdapter {
                id: "restart-provider".into(),
                calls,
                started: Arc::clone(&started),
                block_first: true,
            }))
            .unwrap();
        runtime.block_on(async {
            let id = kernel
                .create_agent_full(config("restart-provider"))
                .await
                .unwrap()
                .id;
            let wait = started.notified();
            let sending = {
                let kernel = Arc::clone(&kernel);
                tokio::spawn(async move { kernel.send_message(id, "restart me").await })
            };
            wait.await;
            kernel.pause_agent(id).await.unwrap();
            sending.await.unwrap().unwrap();
            let checkpoint = kernel.latest_generation_checkpoint(id).unwrap().unwrap();
            (id, checkpoint.id)
        })
    };

    let kernel = AgentKernelImpl::with_db_path(&db).unwrap();
    assert_eq!(
        kernel.get_agent_status(agent_id).unwrap(),
        AgentState::Paused
    );
    let calls = Arc::new(AtomicUsize::new(1));
    kernel
        .register_provider(Arc::new(BoundaryAdapter {
            id: "restart-provider".into(),
            calls: Arc::clone(&calls),
            started: Arc::new(tokio::sync::Notify::new()),
            block_first: true,
        }))
        .unwrap();
    let (_, output, _) = runtime
        .block_on(kernel.resume_agent_from_checkpoint(agent_id, Some(checkpoint_id)))
        .unwrap();
    assert_eq!(output.unwrap().content, "resumed exactly once");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    drop(kernel);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn restart_resume_does_not_repeat_a_completed_tool_side_effect() {
    let root = std::env::temp_dir().join(format!(
        "aiagentos-checkpoint-tool-restart-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("kernel.sqlite");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let second_request_started = Arc::new(tokio::sync::Notify::new());

    let (agent_id, checkpoint_id, side_effect_path) = {
        let kernel = Arc::new(AgentKernelImpl::with_db_path(&db).unwrap());
        runtime.block_on(async {
            let agent = kernel
                .create_agent_full(config("restart-tool-provider"))
                .await
                .unwrap();
            let workspace = kernel
                .agent_manager
                .get_agent_config(agent.id)
                .and_then(|config| config.sandbox_config)
                .unwrap()
                .workspace_dir;
            let side_effect_path = workspace.join("side-effect.txt");
            kernel
                .register_provider(Arc::new(RestartToolAdapter {
                    id: "restart-tool-provider".into(),
                    calls: Arc::clone(&calls),
                    second_request_started: Arc::clone(&second_request_started),
                    path: side_effect_path.to_string_lossy().into_owned(),
                }))
                .unwrap();

            let second_request_wait = second_request_started.notified();
            let sending = {
                let send_kernel = Arc::clone(&kernel);
                tokio::spawn(async move {
                    send_kernel
                        .send_message(agent.id, "perform one durable side effect")
                        .await
                })
            };
            second_request_wait.await;
            assert_eq!(
                std::fs::read_to_string(&side_effect_path).unwrap(),
                "written exactly once"
            );
            kernel.pause_agent(agent.id).await.unwrap();
            assert!(sending
                .await
                .unwrap()
                .unwrap()
                .content
                .contains("durable checkpoint"));
            let checkpoint_id = kernel
                .latest_generation_checkpoint(agent.id)
                .unwrap()
                .unwrap()
                .id;
            (agent.id, checkpoint_id, side_effect_path)
        })
    };

    let kernel = AgentKernelImpl::with_db_path(&db).unwrap();
    kernel
        .register_provider(Arc::new(RestartToolAdapter {
            id: "restart-tool-provider".into(),
            calls: Arc::clone(&calls),
            second_request_started,
            path: side_effect_path.to_string_lossy().into_owned(),
        }))
        .unwrap();
    let (_, output, next) = runtime
        .block_on(kernel.resume_agent_from_checkpoint(agent_id, Some(checkpoint_id)))
        .unwrap();
    let output = output.unwrap();
    assert_eq!(output.content, "continued after restart");
    assert_eq!(
        output.tool_calls_made, 1,
        "the checkpointed tool result must suppress replay"
    );
    assert!(next.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        std::fs::read_to_string(&side_effect_path).unwrap(),
        "written exactly once"
    );

    runtime.block_on(kernel.kill_agent(agent_id)).unwrap();
    drop(kernel);
    std::fs::remove_dir_all(root).unwrap();
}

fn sample_checkpoint(agent_id: uuid::Uuid) -> GenerationCheckpoint {
    GenerationCheckpoint {
        agent_id,
        conversation_id: "conversation".into(),
        user_message: "sensitive prompt".into(),
        messages: vec![StandardMessage::user("sensitive prompt")],
        partial_content: String::new(),
        tool_calls_made: 0,
        tokens_used: 0,
        usage: UsageTelemetry::default(),
    }
}

#[test]
fn checkpoint_metadata_is_tenant_scoped_claimed_once_and_expires() {
    let manager = SqliteContextManager::in_memory().unwrap();
    let agent_id = uuid::Uuid::new_v4();
    let checkpoint = sample_checkpoint(agent_id);
    let id = manager
        .save_generation_checkpoint(
            "tenant-a",
            "provider",
            "model",
            &checkpoint,
            Duration::from_secs(60),
        )
        .unwrap();

    assert_eq!(
        manager
            .list_generation_checkpoints("tenant-a", Some(agent_id))
            .unwrap()
            .len(),
        1
    );
    assert!(manager
        .list_generation_checkpoints("tenant-b", Some(agent_id))
        .unwrap()
        .is_empty());
    assert!(manager
        .claim_generation_checkpoint(id, agent_id, "tenant-b")
        .is_err());
    let claimed = manager
        .claim_generation_checkpoint(id, agent_id, "tenant-a")
        .unwrap();
    assert_eq!(claimed.checkpoint.user_message, "sensitive prompt");
    assert!(manager
        .claim_generation_checkpoint(id, agent_id, "tenant-a")
        .is_err());
    manager.release_generation_checkpoint(id).unwrap();

    let expired = manager
        .save_generation_checkpoint(
            DEFAULT_TENANT,
            "provider",
            "model",
            &checkpoint,
            Duration::ZERO,
        )
        .unwrap();
    assert!(manager
        .list_generation_checkpoints(DEFAULT_TENANT, Some(agent_id))
        .unwrap()
        .iter()
        .all(|checkpoint| checkpoint.id != expired));
    assert!(manager
        .claim_generation_checkpoint(expired, agent_id, DEFAULT_TENANT)
        .is_err());
}

#[tokio::test]
async fn provider_or_model_change_leaves_checkpoint_recoverable() {
    let kernel = AgentKernelImpl::new().unwrap();
    kernel
        .register_provider(Arc::new(BoundaryAdapter {
            id: "current-provider".into(),
            calls: Arc::new(AtomicUsize::new(0)),
            started: Arc::new(tokio::sync::Notify::new()),
            block_first: false,
        }))
        .unwrap();
    let agent_id = kernel
        .create_agent_full(config("current-provider"))
        .await
        .unwrap()
        .id;
    kernel.pause_agent(agent_id).await.unwrap();
    let checkpoint_id = kernel
        .context_manager
        .save_generation_checkpoint(
            DEFAULT_TENANT,
            "current-provider",
            "different-model",
            &sample_checkpoint(agent_id),
            Duration::from_secs(60),
        )
        .unwrap();

    let mismatch = kernel
        .resume_agent_from_checkpoint(agent_id, Some(checkpoint_id))
        .await
        .unwrap_err();
    assert!(mismatch.to_string().contains("provider/model mismatch"));
    assert!(mismatch.to_string().contains("different-model"));
    assert_eq!(
        kernel.get_agent_status(agent_id).unwrap(),
        AgentState::Paused
    );
    assert_eq!(
        kernel
            .latest_generation_checkpoint(agent_id)
            .unwrap()
            .unwrap()
            .id,
        checkpoint_id,
        "an incompatible checkpoint must be released for recovery or deletion"
    );

    assert!(kernel
        .context_manager
        .delete_generation_checkpoint(checkpoint_id, DEFAULT_TENANT)
        .unwrap());

    let unavailable = kernel
        .create_agent_full(config("provider-not-installed"))
        .await
        .unwrap()
        .id;
    kernel.pause_agent(unavailable).await.unwrap();
    let unavailable_checkpoint = kernel
        .context_manager
        .save_generation_checkpoint(
            DEFAULT_TENANT,
            "provider-not-installed",
            "unknown-model",
            &sample_checkpoint(unavailable),
            Duration::from_secs(60),
        )
        .unwrap();
    let unavailable_error = kernel
        .resume_agent_from_checkpoint(unavailable, Some(unavailable_checkpoint))
        .await
        .unwrap_err();
    assert!(
        unavailable_error
            .to_string()
            .contains("Provider unavailable"),
        "unexpected provider failure: {unavailable_error}"
    );
    assert_eq!(
        kernel
            .latest_generation_checkpoint(unavailable)
            .unwrap()
            .unwrap()
            .id,
        unavailable_checkpoint
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_multi_agent_pause_resume_releases_permits_and_checkpoints() {
    const AGENTS: usize = 12;
    const CYCLES: usize = 3;

    let security = kernel::config::Config::default();
    let budgets = kernel::config::BudgetConfig {
        agent_tokens_per_min: 0,
        tenant_tokens_per_min: 0,
        rpm: 0,
        tpm: 0,
        max_concurrent: 0,
        ..kernel::config::BudgetConfig::default()
    };
    let kernel = Arc::new(
        AgentKernelImpl::with_context_manager(
            Arc::new(SqliteContextManager::in_memory().unwrap()),
            &budgets,
            security.mac_enforcing,
            &security.mac_rules,
        )
        .unwrap(),
    );
    let expected_agents = u64::try_from(AGENTS).unwrap();
    let block_requests = Arc::new(AtomicBool::new(true));
    let blocked_requests = Arc::new(AtomicUsize::new(0));
    kernel
        .register_provider(Arc::new(CyclingAdapter {
            id: "cycling-provider".into(),
            block_requests: Arc::clone(&block_requests),
            blocked_requests: Arc::clone(&blocked_requests),
        }))
        .unwrap();

    let mut agents = Vec::with_capacity(AGENTS);
    for index in 0..AGENTS {
        let mut agent_config = config("cycling-provider");
        agent_config.name = format!("cycling-agent-{index}");
        agents.push(kernel.create_agent_full(agent_config).await.unwrap().id);
    }

    for cycle in 0..CYCLES {
        block_requests.store(true, Ordering::SeqCst);
        let blocked_before = blocked_requests.load(Ordering::SeqCst);
        let mut sends = Vec::with_capacity(AGENTS);
        let llm_cores = kernel::llm_sched::DEFAULT_LLM_CORES.min(AGENTS);

        // Occupy every LLM core with a known first cohort before enqueueing the
        // remaining agents. This makes the cancellation coverage deterministic:
        // the second cohort is definitely waiting for a core rather than racing
        // the pause tasks on fast or instrumented CI runners.
        for agent_id in agents.iter().take(llm_cores) {
            let turn_kernel = Arc::clone(&kernel);
            let agent_id = *agent_id;
            sends.push(tokio::spawn(async move {
                turn_kernel
                    .send_message(agent_id, &format!("cycle {cycle}"))
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let metrics = kernel::metrics::MetricsSnapshot::collect(&kernel);
                if blocked_requests.load(Ordering::SeqCst) - blocked_before == llm_cores
                    && metrics.llm_requests_in_flight == llm_cores as u64
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the first cohort should occupy every LLM core");

        for agent_id in agents.iter().skip(llm_cores) {
            let turn_kernel = Arc::clone(&kernel);
            let agent_id = *agent_id;
            sends.push(tokio::spawn(async move {
                turn_kernel
                    .send_message(agent_id, &format!("cycle {cycle}"))
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let metrics = kernel::metrics::MetricsSnapshot::collect(&kernel);
                if metrics.active_turns + metrics.waiting_turns == expected_agents
                    && metrics.llm_requests_waiting == (AGENTS - llm_cores) as u64
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the second cohort should wait behind the occupied LLM cores");

        let mut pauses = Vec::with_capacity(AGENTS);
        for agent_id in agents.iter().skip(llm_cores) {
            let pause_kernel = Arc::clone(&kernel);
            let agent_id = *agent_id;
            pauses.push(tokio::spawn(async move {
                pause_kernel.pause_agent(agent_id).await
            }));
        }
        for pause in pauses {
            assert_eq!(pause.await.unwrap().unwrap(), AgentState::Paused);
        }
        assert_eq!(
            blocked_requests.load(Ordering::SeqCst) - blocked_before,
            llm_cores,
            "waiting turns must pause before provider invocation"
        );

        let mut active_pauses = Vec::with_capacity(llm_cores);
        for agent_id in agents.iter().take(llm_cores) {
            let pause_kernel = Arc::clone(&kernel);
            let agent_id = *agent_id;
            active_pauses.push(tokio::spawn(async move {
                pause_kernel.pause_agent(agent_id).await
            }));
        }
        for pause in active_pauses {
            assert_eq!(pause.await.unwrap().unwrap(), AgentState::Paused);
        }
        for send in sends {
            assert!(send
                .await
                .unwrap()
                .unwrap()
                .content
                .contains("durable checkpoint"));
        }
        let provider_requests_started = blocked_requests.load(Ordering::SeqCst) - blocked_before;
        assert_eq!(provider_requests_started, llm_cores);

        let paused_metrics = kernel::metrics::MetricsSnapshot::collect(&kernel);
        assert_eq!(paused_metrics.active_turns, 0);
        assert_eq!(paused_metrics.waiting_turns, 0);
        assert_eq!(paused_metrics.llm_requests_in_flight, 0);
        assert_eq!(paused_metrics.llm_requests_waiting, 0);

        let mut checkpoints = Vec::with_capacity(AGENTS);
        for agent_id in &agents {
            let checkpoint = kernel
                .latest_generation_checkpoint(*agent_id)
                .unwrap()
                .expect("each paused turn must have one durable checkpoint");
            checkpoints.push((*agent_id, checkpoint.id));
        }
        block_requests.store(false, Ordering::SeqCst);
        let mut resumes = Vec::with_capacity(AGENTS);
        for (agent_id, checkpoint_id) in checkpoints {
            let resume_kernel = Arc::clone(&kernel);
            resumes.push(tokio::spawn(async move {
                resume_kernel
                    .resume_agent_from_checkpoint(agent_id, Some(checkpoint_id))
                    .await
            }));
        }
        for resume in resumes {
            let (state, output, next) = resume.await.unwrap().unwrap();
            assert_eq!(state, AgentState::Running);
            assert!(output.unwrap().content.contains("resumed cycle"));
            assert!(next.is_none());
        }
        for agent_id in &agents {
            assert!(kernel
                .latest_generation_checkpoint(*agent_id)
                .unwrap()
                .is_none());
        }

        let resumed_metrics = kernel::metrics::MetricsSnapshot::collect(&kernel);
        assert_eq!(resumed_metrics.active_turns, 0);
        assert_eq!(resumed_metrics.waiting_turns, 0);
        assert_eq!(resumed_metrics.llm_requests_in_flight, 0);
        assert_eq!(resumed_metrics.llm_requests_waiting, 0);
    }

    for agent_id in agents {
        kernel.kill_agent(agent_id).await.unwrap();
        assert!(kernel.syscall_gate.agent_info(agent_id).is_none());
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(agent_id)
            .is_none());
    }
    assert_eq!(
        kernel
            .cgroups
            .get(kernel.cgroups.root())
            .unwrap()
            .usage
            .agent_count,
        0
    );
}

#[tokio::test]
async fn foreign_tenant_cannot_list_resume_or_delete_public_checkpoint() {
    let kernel = AgentKernelImpl::new().unwrap();
    let agent_id = kernel
        .create_agent_for_tenant("tenant-a", config("unavailable"))
        .await
        .unwrap()
        .id;
    kernel.pause_agent(agent_id).await.unwrap();
    let checkpoint_id = kernel
        .context_manager
        .save_generation_checkpoint(
            "tenant-a",
            "provider",
            "model",
            &sample_checkpoint(agent_id),
            Duration::from_secs(60),
        )
        .unwrap();
    let foreign = Principal {
        user_id: "user-b".into(),
        tenant_id: "tenant-b".into(),
        role: Role::Admin,
        credential: None,
    };

    for syscall in [
        Syscall::ListGenerationCheckpoints {
            agent_id: agent_id.to_string(),
        },
        Syscall::ResumeGenerationCheckpoint {
            agent_id: agent_id.to_string(),
            checkpoint_id: checkpoint_id.to_string(),
        },
        Syscall::DeleteGenerationCheckpoint {
            agent_id: agent_id.to_string(),
            checkpoint_id: checkpoint_id.to_string(),
        },
    ] {
        match dispatch_scoped(&kernel, syscall, Some(&foreign)).await {
            SyscallReply::Error { message } => {
                assert_eq!(message, "resource not found or access denied")
            }
            reply => panic!("foreign checkpoint operation leaked access: {reply:?}"),
        }
    }
}
