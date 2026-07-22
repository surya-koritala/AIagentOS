//! Public-runtime regressions for durable generation checkpoints (#113).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kernel::connector::{
    LlmProviderAdapter, LlmResponse, LlmSession, ProviderType, StandardMessage, ToolDefinition,
};
use kernel::context::{SqliteContextManager, DEFAULT_TENANT};
use kernel::execution::{GenerationCheckpoint, UsageTelemetry};
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

    fn provider_id(&self) -> &String {
        &self.id
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
