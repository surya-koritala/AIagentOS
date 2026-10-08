use agent_sdk::KernelClient;
use async_trait::async_trait;
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, LlmUsage, ProviderCapabilities,
    ProviderType, StandardMessage, ToolDefinition,
};
use kernel::syscall_server::SyscallServer;
use kernel::{AgentConfig, AgentKernelImpl, ConnectorError, Priority};
use std::sync::{Arc, Mutex};

type CapturedRequests = Arc<Mutex<Vec<Vec<StandardMessage>>>>;

struct CaptureProvider {
    id: String,
    requests: CapturedRequests,
}
struct CaptureSession {
    id: String,
    requests: CapturedRequests,
}
#[async_trait]
impl LlmSession for CaptureSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.requests.lock().unwrap().push(messages);
        Ok(LlmResponse {
            content: "fixture reply".into(),
            finish_reason: Some("stop".into()),
            tokens_used: 104,
            usage: LlmUsage::reported(100, 4, 0),
            tool_calls: vec![],
        })
    }
    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send(messages).await
    }
    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        assert!(options.max_output_tokens.is_some_and(|bound| bound > 0));
        self.send_with_tools(messages, tools).await
    }
    fn provider_id(&self) -> &String {
        &self.id
    }
    fn model_id(&self) -> &str {
        "context-fixture"
    }
    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}
#[async_trait]
impl LlmProviderAdapter for CaptureProvider {
    fn id(&self) -> &String {
        &self.id
    }
    fn name(&self) -> &str {
        "captured fixture"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(CaptureSession {
            id: self.id.clone(),
            requests: self.requests.clone(),
        }))
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            tool_calls: true,
            ..Default::default()
        }
    }
    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::to_value(message).unwrap()
    }
    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        serde_json::from_value(value.clone()).ok()
    }
}
fn config(name: &str) -> AgentConfig {
    AgentConfig {
        name: name.into(),
        task: "durable execution history".into(),
        llm_provider: "capture".into(),
        permission_profile: "standard".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }
}
fn register(kernel: &AgentKernelImpl) -> CapturedRequests {
    let requests = Arc::new(Mutex::new(Vec::new()));
    kernel
        .register_provider(Arc::new(CaptureProvider {
            id: "capture".into(),
            requests: requests.clone(),
        }))
        .unwrap();
    requests
}

#[tokio::test]
async fn branched_conversation_is_consumed_by_normal_public_wire_execution() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let requests = register(&kernel);
    let parent = kernel.create_agent_full(config("parent")).await.unwrap().id;
    let child = kernel.create_agent_full(config("child")).await.unwrap().id;
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(address).await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.send_message(parent.to_string(), "shared original task"),
    )
    .await
    .expect("first provider request did not complete in 10 seconds")
    .unwrap();
    let (source, prefix) = kernel
        .context_manager
        .latest_execution_history(parent)
        .unwrap()
        .unwrap();
    kernel
        .context_manager
        .fork_conversation(parent, &source, child, "child-history")
        .unwrap();
    assert_eq!(
        requests.lock().unwrap().len(),
        1,
        "branch creation performs no provider work"
    );
    let child_result = client
        .send_message(child.to_string(), "child continuation")
        .await
        .unwrap();
    assert_eq!(
        child_result.tokens, 104,
        "only the actual child request is billed in its result"
    );
    client
        .send_message(parent.to_string(), "parent continuation")
        .await
        .unwrap();
    {
        let observed = requests.lock().unwrap();
        assert_eq!(observed.len(), 3);
        assert!(observed[1].starts_with(&prefix));
        assert_eq!(observed[1].last().unwrap().content, "child continuation");
        assert!(observed[2].starts_with(&prefix));
        assert!(!observed[2]
            .iter()
            .any(|message| message.content == "child continuation"));
    }
    let (_, child_history) = kernel
        .context_manager
        .latest_execution_history(child)
        .unwrap()
        .unwrap();
    assert!(child_history.starts_with(&prefix));
    assert!(!child_history
        .iter()
        .any(|message| message.content == "parent continuation"));
    client.close().await.unwrap();
    task.abort();
    let _ = task.await;
    kernel.stop_agent(parent).await.unwrap();
    kernel.stop_agent(child).await.unwrap();
}

#[tokio::test]
async fn parent_and_child_restore_their_private_history_after_a_kernel_restart() {
    let root =
        std::env::temp_dir().join(format!("agentos-execution-branch-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("store.db");
    let (parent, child, parent_prefix, child_prefix);
    {
        let kernel = Arc::new(AgentKernelImpl::with_db_path(&path).unwrap());
        register(&kernel);
        parent = kernel.create_agent_full(config("parent")).await.unwrap().id;
        child = kernel.create_agent_full(config("child")).await.unwrap().id;
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(server.serve());
        let mut client = KernelClient::connect(address).await.unwrap();
        client
            .send_message(parent.to_string(), "shared before restart")
            .await
            .unwrap();
        let (source, _) = kernel
            .context_manager
            .latest_execution_history(parent)
            .unwrap()
            .unwrap();
        kernel
            .context_manager
            .fork_conversation(parent, &source, child, "child-history")
            .unwrap();
        client
            .send_message(child.to_string(), "private child before restart")
            .await
            .unwrap();
        client
            .send_message(parent.to_string(), "private parent before restart")
            .await
            .unwrap();
        parent_prefix = kernel
            .context_manager
            .latest_execution_history(parent)
            .unwrap()
            .unwrap()
            .1;
        child_prefix = kernel
            .context_manager
            .latest_execution_history(child)
            .unwrap()
            .unwrap()
            .1;
        client.close().await.unwrap();
        task.abort();
        let _ = task.await;
        kernel.context_manager.checkpoint().unwrap();
    }
    {
        let kernel = Arc::new(AgentKernelImpl::with_db_path(&path).unwrap());
        let requests = register(&kernel);
        let restored = kernel.rehydrate_agents().await.unwrap();
        assert!(restored.contains(&parent) && restored.contains(&child));
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(server.serve());
        let mut client = KernelClient::connect(address).await.unwrap();
        client
            .send_message(child.to_string(), "after restart child")
            .await
            .unwrap();
        client
            .send_message(parent.to_string(), "after restart parent")
            .await
            .unwrap();
        {
            let observed = requests.lock().unwrap();
            assert_eq!(observed.len(), 2);
            assert!(observed[0].starts_with(&child_prefix));
            assert!(observed[1].starts_with(&parent_prefix));
            assert!(!observed[0]
                .iter()
                .any(|message| message.content == "private parent before restart"));
        }
        client.close().await.unwrap();
        task.abort();
        let _ = task.await;
        kernel.stop_agent(parent).await.unwrap();
        kernel.stop_agent(child).await.unwrap();
    }
    std::fs::remove_dir_all(root).unwrap();
}
