//! Live public-wire regression for the TUI checkpoint projection and its
//! exact-target resume/delete controls.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_sdk::KernelClient;
use agent_tui::app::{App, Key, UiAction};
use agent_tui::TuiClient;
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, ProviderCapabilities,
    ProviderType, StandardMessage, ToolDefinition,
};
use kernel::syscall_server::SyscallServer;
use kernel::{AgentKernelImpl, ConnectorError, ProviderId};

struct PausableAdapter {
    id: ProviderId,
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
}

struct PausableSession {
    id: ProviderId,
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl LlmSession for PausableSession {
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
            std::future::pending::<()>().await;
        }
        Ok(LlmResponse {
            content: "TUI checkpoint resume complete".into(),
            finish_reason: Some("stop".into()),
            tokens_used: 5,
            usage: kernel::connector::LlmUsage::reported(3, 2, 0),
            tool_calls: Vec::new(),
        })
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        assert!(
            options.max_output_tokens.is_some_and(|limit| limit > 0),
            "production execution must forward a positive output bound"
        );
        self.send_with_tools(messages, tools).await
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "tui-checkpoint-test"
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for PausableAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "TUI checkpoint test"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(PausableSession {
            id: self.id.clone(),
            calls: Arc::clone(&self.calls),
            started: Arc::clone(&self.started),
        }))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            tool_calls: true,
            prompt_cancellation: true,
            ..ProviderCapabilities::default()
        }
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

async fn create_checkpoint(
    control: &mut TuiClient,
    address: std::net::SocketAddr,
    token: &str,
    started: &tokio::sync::Notify,
    name: &str,
    provider: &str,
) -> (String, String) {
    let agent_id = control
        .create_agent(
            name,
            "pause at a public provider boundary",
            Some(provider.into()),
            None,
            None,
        )
        .await
        .expect("create checkpoint agent");
    let mut sender = KernelClient::connect(address)
        .await
        .expect("sender connect");
    sender
        .authenticate(token)
        .await
        .expect("sender authentication");
    let started_wait = started.notified();
    let sending_agent = agent_id.clone();
    let sending =
        tokio::spawn(async move { sender.send_message(sending_agent, "pause this turn").await });

    tokio::time::timeout(Duration::from_secs(2), started_wait)
        .await
        .expect("provider start timeout");
    assert_eq!(
        control
            .pause_agent(agent_id.clone())
            .await
            .expect("pause through public TUI client"),
        "Paused"
    );
    let paused = tokio::time::timeout(Duration::from_secs(2), sending)
        .await
        .expect("paused sender timeout")
        .expect("sender task")
        .expect("paused turn result");
    let checkpoints = control
        .list_generation_checkpoints(agent_id.clone())
        .await
        .expect("list checkpoint through public TUI client");
    assert_eq!(checkpoints.len(), 1);
    let checkpoint_id = checkpoints[0].id.clone();
    assert!(paused.content.contains(&checkpoint_id));
    (agent_id, checkpoint_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tui_checkpoint_list_resume_and_exact_delete_use_the_authenticated_public_client() {
    let resume_started = Arc::new(tokio::sync::Notify::new());
    let delete_started = Arc::new(tokio::sync::Notify::new());
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    kernel
        .register_provider(Arc::new(PausableAdapter {
            id: "tui-checkpoint-resume".into(),
            calls: Arc::new(AtomicUsize::new(0)),
            started: Arc::clone(&resume_started),
        }))
        .expect("register checkpoint resume provider");
    kernel
        .register_provider(Arc::new(PausableAdapter {
            id: "tui-checkpoint-delete".into(),
            calls: Arc::new(AtomicUsize::new(0)),
            started: Arc::clone(&delete_started),
        }))
        .expect("register checkpoint delete provider");
    let token = "tui-checkpoint-auth";
    let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind")
        .with_auth_token(token);
    let address = server.local_addr().expect("address");
    let server_task = tokio::spawn(server.serve());
    let mut control = TuiClient::connect(&address.to_string(), Some(token))
        .await
        .expect("authenticated TUI client");
    let mut app = App::new(address.to_string());

    let (resume_agent, resume_checkpoint) = create_checkpoint(
        &mut control,
        address,
        token,
        &resume_started,
        "resume-agent",
        "tui-checkpoint-resume",
    )
    .await;
    app.refresh(&mut control)
        .await
        .expect("refresh resume agent");
    let checkpoints = control
        .list_generation_checkpoints(resume_agent.clone())
        .await
        .expect("list resumable checkpoint");
    app.set_generation_checkpoints(resume_agent.clone(), checkpoints);
    assert_eq!(
        app.on_key(Key::Char('e')),
        Some(UiAction::ResumeGenerationCheckpoint {
            agent_id: resume_agent.clone(),
            checkpoint_id: resume_checkpoint.clone(),
        })
    );
    let resumed = control
        .resume_generation_checkpoint(resume_agent.clone(), resume_checkpoint.clone())
        .await
        .expect("explicit public checkpoint resume");
    app.checkpoint_resumed(&resume_agent, &resume_checkpoint, resumed);
    assert_eq!(
        app.last_output.as_deref(),
        Some("TUI checkpoint resume complete")
    );
    assert!(control
        .list_generation_checkpoints(resume_agent)
        .await
        .expect("checkpoint consumed")
        .is_empty());

    let (delete_agent, delete_checkpoint) = create_checkpoint(
        &mut control,
        address,
        token,
        &delete_started,
        "delete-agent",
        "tui-checkpoint-delete",
    )
    .await;
    app.refresh(&mut control)
        .await
        .expect("refresh delete agent");
    while app.selected_agent().map(|agent| agent.id.as_str()) != Some(delete_agent.as_str()) {
        app.on_key(Key::Char('j'));
    }
    assert_eq!(
        app.on_key(Key::Char('g')),
        Some(UiAction::LoadGenerationCheckpoints {
            agent_id: delete_agent.clone(),
        })
    );
    let checkpoints = control
        .list_generation_checkpoints(delete_agent.clone())
        .await
        .expect("list deletable checkpoint");
    app.set_generation_checkpoints(delete_agent.clone(), checkpoints);
    assert_eq!(app.on_key(Key::Char('K')), None);
    assert!(app.status.contains("permanent checkpoint deletion"));
    for character in delete_checkpoint.chars() {
        app.on_key(Key::Char(character));
    }
    assert_eq!(
        app.on_key(Key::Enter),
        Some(UiAction::DeleteGenerationCheckpoint {
            agent_id: delete_agent.clone(),
            checkpoint_id: delete_checkpoint.clone(),
        })
    );
    let existed = control
        .delete_generation_checkpoint(delete_agent.clone(), delete_checkpoint.clone())
        .await
        .expect("exact public checkpoint delete");
    app.checkpoint_deleted(&delete_agent, &delete_checkpoint, existed);
    assert!(existed);
    assert!(app.checkpoints.is_empty());
    assert!(control
        .list_generation_checkpoints(delete_agent)
        .await
        .expect("checkpoint deleted")
        .is_empty());
    server_task.abort();
}
