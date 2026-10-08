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
    boundary: Option<Arc<ProviderBoundary>>,
}
struct CaptureSession {
    id: String,
    requests: CapturedRequests,
    boundary: Option<Arc<ProviderBoundary>>,
}
#[derive(Default)]
struct ProviderBoundary {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait]
impl LlmSession for CaptureSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.requests.lock().unwrap().push(messages);
        if let Some(boundary) = &self.boundary {
            boundary.entered.notify_one();
            boundary.release.notified().await;
        }
        Ok(LlmResponse {
            provider_metadata: None,
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
            boundary: self.boundary.clone(),
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
            boundary: None,
        }))
        .unwrap();
    requests
}

#[tokio::test]
async fn branched_conversation_is_consumed_by_normal_public_wire_execution() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let requests = register(&kernel);
    let parent = kernel.create_agent_full(config("parent")).await.unwrap().id;
    let child = uuid::Uuid::new_v4();
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
    let (_source, prefix) = kernel
        .context_manager
        .latest_execution_history(parent)
        .unwrap()
        .unwrap();
    let cloned = client
        .clone_agent(
            parent.to_string(),
            child,
            "child",
            vec!["CAP_NET_ACCESS".into()],
        )
        .await
        .unwrap();
    assert_eq!(cloned.child_id, child);
    assert_eq!(cloned.inherited_handles, 0);
    assert!(!kernel
        .syscall_gate
        .agent_info(child)
        .unwrap()
        .capabilities
        .iter()
        .any(|cap| cap == "CAP_NET_ACCESS"));
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
        child = uuid::Uuid::new_v4();
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
        let (_source, _) = kernel
            .context_manager
            .latest_execution_history(parent)
            .unwrap()
            .unwrap();
        client
            .clone_agent(parent.to_string(), child, "child", vec!["CAP_EXEC".into()])
            .await
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
        assert!(!kernel
            .syscall_gate
            .agent_info(child)
            .unwrap()
            .capabilities
            .iter()
            .any(|cap| cap == "CAP_EXEC"));
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(server.serve());
        let mut client = KernelClient::connect(address).await.unwrap();
        let kv = client
            .vfs_open_kv(
                child.to_string(),
                "/kv",
                "restored-policy",
                vec![
                    agent_sdk::WorkspaceRight::Read,
                    agent_sdk::WorkspaceRight::Write,
                ],
            )
            .await
            .unwrap();
        client
            .vfs_write_data(
                child.to_string(),
                &kv.id,
                serde_json::json!({"value":"still governed after restart"}),
            )
            .await
            .unwrap();
        assert_eq!(
            client
                .vfs_read_data(child.to_string(), &kv.id, serde_json::json!({}))
                .await
                .unwrap()["value"],
            "still governed after restart"
        );
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

#[tokio::test]
async fn wire_page_in_and_named_namespace_isolation_survive_restart_and_parent_erasure() {
    let root = std::env::temp_dir().join(format!("agentos-spill-wire-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("store.db");
    let (parent, child, foreign);
    let value =
        serde_json::to_string(&vec![StandardMessage::user("durable omitted detail")]).unwrap();
    let digest = ring::digest::digest(&ring::digest::SHA256, value.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    {
        let kernel = Arc::new(AgentKernelImpl::with_db_path(&path).unwrap());
        parent = kernel
            .create_agent_in_namespace(config("parent"), "private-work")
            .await
            .unwrap()
            .id;
        child = uuid::Uuid::new_v4();
        foreign = kernel
            .create_agent_in_namespace(config("foreign"), "unrelated-work")
            .await
            .unwrap()
            .id;
        kernel
            .context_manager
            .store_context_spill(parent, "context_spill:wire", &value, &digest)
            .unwrap();
        let reference = StandardMessage::system(format!(
            "[Context spill: key=context_spill:wire; sha256-prefix={}; n=1]",
            &digest[..16]
        ));
        kernel
            .context_manager
            .save_conversation(
                "parent-history",
                parent,
                &[StandardMessage::system("base"), reference],
            )
            .unwrap();
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(server.serve());
        let mut client = KernelClient::connect(address).await.unwrap();
        client
            .clone_agent(parent.to_string(), child, "spill child", vec![])
            .await
            .unwrap();
        client.close().await.unwrap();
        task.abort();
        let _ = task.await;
        kernel.context_manager.checkpoint().unwrap();
    }
    {
        let kernel = Arc::new(AgentKernelImpl::with_db_path(&path).unwrap());
        kernel.rehydrate_agents().await.unwrap();
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(server.serve());
        let mut client = KernelClient::connect(address).await.unwrap();
        let parent_mounts = client
            .vfs_namespace_mounts(parent.to_string())
            .await
            .unwrap();
        let child_mounts = client
            .vfs_namespace_mounts(child.to_string())
            .await
            .unwrap();
        let foreign_mounts = client
            .vfs_namespace_mounts(foreign.to_string())
            .await
            .unwrap();
        assert_eq!(parent_mounts.namespace, child_mounts.namespace);
        assert_ne!(parent_mounts.namespace, foreign_mounts.namespace);
        assert_eq!(
            client
                .storage_get(child.to_string(), "context_spill:wire")
                .await
                .unwrap(),
            Some(value.clone())
        );
        assert_eq!(
            client
                .storage_get(foreign.to_string(), "context_spill:wire")
                .await
                .unwrap(),
            None
        );
        client
            .erase_agent_data(parent, agent_sdk::CONFIRM_DATA_ERASURE)
            .await
            .unwrap();
        assert_eq!(
            client
                .storage_get(child.to_string(), "context_spill:wire")
                .await
                .unwrap(),
            Some(value)
        );
        client.close().await.unwrap();
        task.abort();
        let _ = task.await;
        kernel.stop_agent(child).await.unwrap();
        kernel.stop_agent(foreign).await.unwrap();
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn clone_wire_enforces_tenants_roles_identity_and_fresh_vfs_handles() {
    use agent_sdk::{WireErrorCode, WorkspaceKind, WorkspaceOpenRequest, WorkspaceRight};
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let tenant = kernel.create_tenant("clone-owner").await.unwrap();
    let other_tenant = kernel.create_tenant("clone-foreign").await.unwrap();
    let parent = kernel
        .create_agent_for_tenant(&tenant, config("owned parent"))
        .await
        .unwrap()
        .id;
    let other = kernel
        .create_agent_for_tenant(&other_tenant, config("foreign parent"))
        .await
        .unwrap()
        .id;
    let user = kernel
        .register_user(
            &tenant,
            "writer",
            "writer@clone.test",
            kernel::auth::Role::User,
        )
        .await
        .unwrap();
    let reader = kernel
        .register_user(
            &tenant,
            "reader",
            "reader@clone.test",
            kernel::auth::Role::ReadOnly,
        )
        .await
        .unwrap();
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(address).await.unwrap();
    client
        .authenticate(kernel.issue_api_key(&user, "clone-writer").await.unwrap())
        .await
        .unwrap();
    let denied_child = uuid::Uuid::new_v4();
    assert_eq!(
        client
            .clone_agent(other.to_string(), denied_child, "foreign clone", vec![])
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::AuthorizationDenied)
    );
    assert_eq!(
        client
            .clone_agent(parent.to_string(), other, "identity collision", vec![])
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::AuthorizationDenied)
    );
    let handle = client
        .vfs_open_kv(
            parent.to_string(),
            "/kv",
            "parent-only",
            vec![WorkspaceRight::Read, WorkspaceRight::Write],
        )
        .await
        .unwrap();
    let kv_read = client
        .vfs_dup_data(parent.to_string(), &handle.id, vec![WorkspaceRight::Read])
        .await
        .unwrap();
    let tool = client
        .vfs_open(parent.to_string(), "/tools/read_file")
        .await
        .unwrap();
    let workspace = client
        .vfs_open_workspace(
            parent.to_string(),
            WorkspaceOpenRequest {
                path: "/workspace".into(),
                kind: WorkspaceKind::Directory,
                rights: vec![
                    WorkspaceRight::Read,
                    WorkspaceRight::Write,
                    WorkspaceRight::List,
                    WorkspaceRight::Stat,
                ],
                allow_missing: false,
            },
        )
        .await
        .unwrap();
    let workspace_list = client
        .vfs_dup_workspace(
            parent.to_string(),
            &workspace.id,
            vec![WorkspaceRight::List],
        )
        .await
        .unwrap();
    let workspace_file = client
        .vfs_open_workspace(
            parent.to_string(),
            WorkspaceOpenRequest {
                path: "/workspace/parent-only.bin".into(),
                kind: WorkspaceKind::File,
                rights: vec![WorkspaceRight::Read, WorkspaceRight::Write],
                allow_missing: true,
            },
        )
        .await
        .unwrap();
    client
        .vfs_write_bytes(
            parent.to_string(),
            &workspace_file.id,
            b"private parent bytes",
        )
        .await
        .unwrap();
    let memory = client
        .vfs_open_data(
            parent.to_string(),
            "/memory",
            vec![
                WorkspaceRight::Read,
                WorkspaceRight::Write,
                WorkspaceRight::Stat,
            ],
        )
        .await
        .unwrap();
    let memory_read = client
        .vfs_dup_data(parent.to_string(), &memory.id, vec![WorkspaceRight::Read])
        .await
        .unwrap();
    client
        .vfs_write_data(
            parent.to_string(),
            &memory.id,
            serde_json::json!({"content":"private parent semantic fact", "category":"Fact"}),
        )
        .await
        .unwrap();
    let ipc = client
        .vfs_open_data(
            parent.to_string(),
            "/ipc",
            vec![
                WorkspaceRight::Read,
                WorkspaceRight::Write,
                WorkspaceRight::Stat,
            ],
        )
        .await
        .unwrap();
    let ipc_read = client
        .vfs_dup_data(parent.to_string(), &ipc.id, vec![WorkspaceRight::Read])
        .await
        .unwrap();
    client
        .vfs_write_data(
            parent.to_string(),
            &ipc.id,
            serde_json::json!({"to":parent, "payload":{"private":"parent mailbox"}}),
        )
        .await
        .unwrap();
    client
        .vfs_write_data(
            parent.to_string(),
            &handle.id,
            serde_json::json!({"value":"private parent KV"}),
        )
        .await
        .unwrap();
    let child = uuid::Uuid::new_v4();
    client
        .clone_agent(parent.to_string(), child, "owned child", vec![])
        .await
        .unwrap();
    assert_eq!(
        kernel.context_manager.agent_tenant(child).unwrap(),
        Some(tenant)
    );
    assert!(
        client
            .vfs_read_data(child.to_string(), &handle.id, serde_json::json!({}))
            .await
            .is_err(),
        "parent descriptor is not inherited"
    );
    let gates = kernel.syscall_gate.stats();
    for id in [
        &handle.id,
        &kv_read.id,
        &memory.id,
        &memory_read.id,
        &ipc.id,
        &ipc_read.id,
    ] {
        assert_eq!(
            client
                .vfs_read_data(child.to_string(), id, serde_json::json!({}))
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::NotFound)
        );
        assert_eq!(
            client
                .vfs_close(child.to_string(), id)
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::NotFound)
        );
    }
    assert_eq!(
        client
            .vfs_invoke(
                child.to_string(),
                &tool.id,
                serde_json::json!({"path":"parent-only.txt"})
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    for id in [&workspace.id, &workspace_list.id] {
        assert_eq!(
            client
                .vfs_list_workspace(child.to_string(), id)
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::NotFound)
        );
        assert_eq!(
            client
                .vfs_close(child.to_string(), id)
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::NotFound)
        );
    }
    assert_eq!(
        client
            .vfs_read_bytes(child.to_string(), &workspace_file.id, 0, 64)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    assert_eq!(
        client
            .vfs_close(child.to_string(), &workspace_file.id)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    assert_eq!(
        kernel.syscall_gate.stats().allowed,
        gates.allowed,
        "foreign descriptors never enter backing authorization"
    );
    assert_eq!(
        client
            .vfs_mounts(child.to_string())
            .await
            .unwrap()
            .open_handles,
        0
    );
    // Child denial did not close or alter the parent's attenuated references.
    assert_eq!(
        client
            .vfs_read_data(parent.to_string(), &kv_read.id, serde_json::json!({}))
            .await
            .unwrap()["value"],
        "private parent KV"
    );
    assert_eq!(
        client
            .vfs_read_data(
                parent.to_string(),
                &memory_read.id,
                serde_json::json!({"query":"private parent semantic fact"})
            )
            .await
            .unwrap()["facts"][0]["content"],
        "private parent semantic fact"
    );
    assert_eq!(
        client
            .vfs_read_data(parent.to_string(), &ipc_read.id, serde_json::json!({}))
            .await
            .unwrap()["payload"]["private"],
        "parent mailbox"
    );
    assert!(client
        .vfs_list_workspace(parent.to_string(), &workspace_list.id)
        .await
        .unwrap()["entries"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("parent-only.bin")));
    assert_eq!(
        client
            .vfs_read_bytes(parent.to_string(), &workspace_file.id, 0, 64)
            .await
            .unwrap()
            .bytes,
        b"private parent bytes"
    );
    let fresh = client
        .vfs_open_kv(
            child.to_string(),
            "/kv",
            "parent-only",
            vec![WorkspaceRight::Read],
        )
        .await
        .unwrap();
    assert!(
        client
            .vfs_read_data(child.to_string(), &fresh.id, serde_json::json!({}))
            .await
            .unwrap()["value"]
            .is_null(),
        "agent-private KV does not transfer"
    );
    let fresh_memory = client
        .vfs_open_data(
            child.to_string(),
            "/memory",
            vec![WorkspaceRight::Read, WorkspaceRight::Stat],
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_stat_data(child.to_string(), &fresh_memory.id)
            .await
            .unwrap()["facts"],
        0
    );
    assert!(client
        .vfs_read_data(
            child.to_string(),
            &fresh_memory.id,
            serde_json::json!({"query":"private parent semantic fact"})
        )
        .await
        .unwrap()["facts"]
        .as_array()
        .unwrap()
        .is_empty());
    let fresh_ipc = client
        .vfs_open_data(
            child.to_string(),
            "/ipc",
            vec![WorkspaceRight::Read, WorkspaceRight::Stat],
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_stat_data(child.to_string(), &fresh_ipc.id)
            .await
            .unwrap()["pending"],
        0
    );
    assert_eq!(
        client
            .vfs_read_data(child.to_string(), &fresh_ipc.id, serde_json::json!({}))
            .await
            .unwrap()["empty"],
        true
    );
    let fresh_workspace = client
        .vfs_open_workspace(
            child.to_string(),
            WorkspaceOpenRequest {
                path: "/workspace".into(),
                kind: WorkspaceKind::Directory,
                rights: vec![WorkspaceRight::List],
                allow_missing: false,
            },
        )
        .await
        .unwrap();
    assert!(!client
        .vfs_list_workspace(child.to_string(), &fresh_workspace.id)
        .await
        .unwrap()["entries"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("parent-only.bin")));
    let fresh_tool = client
        .vfs_open(child.to_string(), "/tools/read_file")
        .await
        .unwrap();
    assert_ne!(fresh_tool.id, tool.id);
    for id in [
        &handle.id,
        &kv_read.id,
        &tool.id,
        &workspace.id,
        &workspace_list.id,
        &workspace_file.id,
        &memory.id,
        &memory_read.id,
        &ipc.id,
        &ipc_read.id,
    ] {
        client.vfs_close(parent.to_string(), id).await.unwrap();
    }
    for id in [
        &fresh.id,
        &fresh_memory.id,
        &fresh_ipc.id,
        &fresh_workspace.id,
        &fresh_tool.id,
    ] {
        client.vfs_close(child.to_string(), id).await.unwrap();
    }
    assert_eq!(
        client
            .vfs_mounts(parent.to_string())
            .await
            .unwrap()
            .open_handles,
        0
    );
    assert_eq!(
        client
            .vfs_mounts(child.to_string())
            .await
            .unwrap()
            .open_handles,
        0
    );
    client
        .authenticate(kernel.issue_api_key(&reader, "clone-reader").await.unwrap())
        .await
        .unwrap();
    let denied_child = uuid::Uuid::new_v4();
    assert_eq!(
        client
            .clone_agent(parent.to_string(), denied_child, "reader clone", vec![])
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::AuthorizationDenied)
    );
    assert!(kernel
        .context_manager
        .agent_tenant(denied_child)
        .unwrap()
        .is_none());
    client.close().await.unwrap();
    task.abort();
    let _ = task.await;
    kernel.stop_agent(parent).await.unwrap();
    kernel.stop_agent(child).await.unwrap();
    kernel.stop_agent(other).await.unwrap();
}

#[tokio::test]
async fn concurrent_public_branch_writes_and_parent_erasure_preserve_child_history() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let requests = register(&kernel);
    let parent = kernel
        .create_agent_full(config("concurrent parent"))
        .await
        .unwrap()
        .id;
    let prefix = vec![StandardMessage::user("shared durable starting task")];
    kernel
        .context_manager
        .save_conversation("concurrent-source", parent, &prefix)
        .unwrap();
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut parent_client = KernelClient::connect(address).await.unwrap();
    let mut child_client = KernelClient::connect(address).await.unwrap();
    let child = uuid::Uuid::new_v4();
    parent_client
        .clone_agent(parent.to_string(), child, "concurrent child", vec![])
        .await
        .unwrap();
    let (parent_result, child_result) = tokio::join!(
        parent_client.send_message(parent.to_string(), "parent private turn"),
        child_client.send_message(child.to_string(), "child private turn")
    );
    parent_result.unwrap();
    child_result.unwrap();
    for (owner, forbidden) in [
        (parent, "child private turn"),
        (child, "parent private turn"),
    ] {
        let (_, history) = kernel
            .context_manager
            .latest_execution_history(owner)
            .unwrap()
            .unwrap();
        assert!(history.starts_with(&prefix));
        assert!(!history.iter().any(|message| message.content == forbidden));
    }
    assert_eq!(requests.lock().unwrap().len(), 2);
    parent_client
        .erase_agent_data(parent, agent_sdk::CONFIRM_DATA_ERASURE)
        .await
        .unwrap();
    child_client
        .send_message(child.to_string(), "after parent erasure")
        .await
        .unwrap();
    {
        let observed = requests.lock().unwrap();
        assert!(observed.last().unwrap().starts_with(&prefix));
        assert!(!observed
            .last()
            .unwrap()
            .iter()
            .any(|message| message.content == "parent private turn"));
    }
    parent_client.close().await.unwrap();
    child_client.close().await.unwrap();
    task.abort();
    let _ = task.await;
    kernel.stop_agent(child).await.unwrap();
}

#[tokio::test]
async fn fenced_clone_requires_both_exact_destination_proofs() {
    use agent_sdk::{AgentMutationFenceProof, ReservedAgentIdentity, WireErrorCode};
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let parent = kernel
        .create_agent_full(config("fenced parent"))
        .await
        .unwrap()
        .id;
    let child = uuid::Uuid::new_v4();
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(address).await.unwrap();
    let proof = AgentMutationFenceProof {
        cluster_id: uuid::Uuid::new_v4().to_string(),
        owner_node_id: kernel.cluster_control.identity().node_id.clone(),
        authority_term: 1,
        authority_generation: 1,
        fencing_token: 1,
        proof_expires_at: chrono::Utc::now() + chrono::Duration::seconds(30),
    };
    for id in [parent, child] {
        client
            .install_agent_mutation_fence(
                id.to_string(),
                &proof.cluster_id,
                &proof.owner_node_id,
                proof.authority_term,
                proof.authority_generation,
                proof.fencing_token,
                proof.proof_expires_at,
                "clone fixture",
            )
            .await
            .unwrap();
    }
    assert_eq!(
        client
            .clone_agent(parent.to_string(), child, "child", vec![])
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::Conflict)
    );
    let mut wrong_child_proof = proof.clone();
    wrong_child_proof.fencing_token += 1;
    let wrong_child = ReservedAgentIdentity {
        agent_id: child.to_string(),
        ownership_proof: wrong_child_proof,
    };
    assert_eq!(
        client
            .clone_agent_fenced(
                parent.to_string(),
                proof.clone(),
                wrong_child,
                "child",
                vec![]
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::Conflict)
    );
    assert!(kernel
        .context_manager
        .agent_tenant(child)
        .unwrap()
        .is_none());
    let reservation = ReservedAgentIdentity {
        agent_id: child.to_string(),
        ownership_proof: proof.clone(),
    };
    let cloned = client
        .clone_agent_fenced(parent.to_string(), proof, reservation, "child", vec![])
        .await
        .unwrap();
    assert_eq!(cloned.child_id, child);
    client.close().await.unwrap();
    task.abort();
    let _ = task.await;
    kernel.stop_agent(parent).await.unwrap();
    kernel.stop_agent(child).await.unwrap();
}

#[tokio::test]
async fn public_clone_rejects_an_active_provider_turn_without_admitting_a_child() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let boundary = Arc::new(ProviderBoundary::default());
    let requests = Arc::new(Mutex::new(Vec::new()));
    kernel
        .register_provider(Arc::new(CaptureProvider {
            id: "capture".into(),
            requests: requests.clone(),
            boundary: Some(boundary.clone()),
        }))
        .unwrap();
    let parent = kernel
        .create_agent_full(config("active parent"))
        .await
        .unwrap()
        .id;
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut sending = KernelClient::connect(address).await.unwrap();
    let mut cloning = KernelClient::connect(address).await.unwrap();
    let send = tokio::spawn(async move {
        let result = sending
            .send_message(parent.to_string(), "in progress")
            .await;
        sending.close().await.unwrap();
        result
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        boundary.entered.notified(),
    )
    .await
    .unwrap();
    let child = uuid::Uuid::new_v4();
    let error = cloning
        .clone_agent(parent.to_string(), child, "active child", vec![])
        .await
        .unwrap_err();
    assert!(error
        .kernel_message()
        .unwrap()
        .contains("active or queued turn"));
    assert_eq!(error.wire_code(), Some(agent_sdk::WireErrorCode::Lifecycle));
    assert!(kernel
        .context_manager
        .agent_tenant(child)
        .unwrap()
        .is_none());
    assert!(kernel.syscall_gate.agent_info(child).is_none());
    assert_eq!(requests.lock().unwrap().len(), 1);
    boundary.release.notify_one();
    send.await.unwrap().unwrap();
    cloning.close().await.unwrap();
    task.abort();
    let _ = task.await;
    kernel.stop_agent(parent).await.unwrap();
}

#[tokio::test]
async fn public_clone_and_parent_erasure_have_one_consistent_lifecycle_order() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let parent = kernel
        .create_agent_full(config("erasure race parent"))
        .await
        .unwrap()
        .id;
    let prefix = vec![StandardMessage::user("child-owned shared history")];
    kernel
        .context_manager
        .save_conversation("race-source", parent, &prefix)
        .unwrap();
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut cloning = KernelClient::connect(address).await.unwrap();
    let mut erasing = KernelClient::connect(address).await.unwrap();
    let child = uuid::Uuid::new_v4();
    let (cloned, erased) = tokio::join!(
        cloning.clone_agent(parent.to_string(), child, "race child", vec![]),
        erasing.erase_agent_data(parent, agent_sdk::CONFIRM_DATA_ERASURE)
    );
    assert!(erased.unwrap().is_some());
    assert!(kernel
        .context_manager
        .agent_tenant(parent)
        .unwrap()
        .is_none());
    if cloned.is_ok() {
        assert_eq!(
            kernel
                .context_manager
                .latest_execution_history(child)
                .unwrap()
                .unwrap()
                .1,
            prefix
        );
        assert!(erasing
            .erase_agent_data(child, agent_sdk::CONFIRM_DATA_ERASURE)
            .await
            .unwrap()
            .is_some());
    } else {
        assert!(kernel
            .context_manager
            .agent_tenant(child)
            .unwrap()
            .is_none());
        assert!(kernel.syscall_gate.agent_info(child).is_none());
    }
    assert!(kernel.context_manager.load_all_agents().unwrap().is_empty());
    assert!(kernel.context_manager.list_conversations().is_empty());
    cloning.close().await.unwrap();
    erasing.close().await.unwrap();
    task.abort();
    let _ = task.await;
}
