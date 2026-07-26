//! Integration tests: drive a real in-memory kernel through the SDK over a
//! `SyscallServer`. No external services — the kernel is `AgentKernelImpl::new()`
//! (in-memory SQLite) and the transport is loopback TCP on an ephemeral port.

use std::sync::Arc;

use agent_sdk::{Agent, KernelClient, MessageStreamEvent, SdkError, WireErrorCode};
use kernel::agent::AgentKernel;
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, LlmUsage, ProviderCapabilities,
    ProviderEventSink, ProviderStreamEvent, ProviderType, StandardMessage, ToolDefinition,
};
use kernel::syscall_server::SyscallServer;
use kernel::{AgentKernelImpl, ConnectorError, ProviderId};

struct StreamTestAdapter {
    id: ProviderId,
    blocked: bool,
    event_count: usize,
}

struct StreamTestSession {
    id: ProviderId,
    blocked: bool,
    event_count: usize,
}

#[async_trait::async_trait]
impl LlmSession for StreamTestSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        if self.blocked {
            std::future::pending::<()>().await;
        }
        Ok(LlmResponse {
            content: "streamed reply".into(),
            finish_reason: Some("stop".into()),
            tokens_used: 3,
            usage: LlmUsage::reported(1, 2, 0),
            tool_calls: vec![],
        })
    }

    async fn send_streaming_events_controlled(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        _options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: ProviderEventSink,
    ) -> Result<LlmResponse, ConnectorError> {
        if self.blocked {
            events
                .emit(ProviderStreamEvent::TextDelta("before-cancel".into()))
                .await;
            cancellation.cancelled().await;
            return Err(ConnectorError::cancelled(self.id.clone(), None));
        }
        let event_count = self.event_count.max(1);
        for _ in 0..event_count {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    return Err(ConnectorError::cancelled(self.id.clone(), None));
                }
                _ = events.emit(ProviderStreamEvent::TextDelta(
                    if self.event_count == 0 {
                        "streamed reply".into()
                    } else {
                        "x".into()
                    }
                )) => {}
            }
        }
        Ok(LlmResponse {
            content: if self.event_count == 0 {
                "streamed reply".into()
            } else {
                "x".repeat(self.event_count)
            },
            finish_reason: Some("stop".into()),
            tokens_used: event_count.try_into().unwrap_or(u32::MAX),
            usage: LlmUsage::reported(1, event_count.try_into().unwrap_or(u32::MAX), 0),
            tool_calls: vec![],
        })
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "stream-test-model"
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for StreamTestAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "stream test"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(StreamTestSession {
            id: self.id.clone(),
            blocked: self.blocked,
            event_count: self.event_count,
        }))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
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

/// Boot an in-memory kernel + syscall server on 127.0.0.1:0 and return its addr.
async fn spawn_server() -> std::net::SocketAddr {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.serve());
    addr
}

async fn remove_test_tree_after_handle_release(path: &std::path::Path) {
    let mut last_error = None;
    for _ in 0..40 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    panic!(
        "remove test root after bounded handle-release wait: {}",
        last_error.expect("cleanup attempted")
    );
}

async fn spawn_stream_server(
    provider_id: &str,
    blocked: bool,
    event_count: usize,
) -> (std::net::SocketAddr, Arc<AgentKernelImpl>) {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
    kernel
        .register_provider(Arc::new(StreamTestAdapter {
            id: provider_id.into(),
            blocked,
            event_count,
        }))
        .expect("register stream provider");
    let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.serve());
    (addr, kernel)
}

#[tokio::test]
async fn create_lists_and_gate_stats_via_kernel_client() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    // create_agent → typed id back.
    let id = client
        .create_agent("alpha", "demo task", None, None, None)
        .await
        .expect("create_agent");

    // list_agents reflects the new agent.
    let agents = client.list_agents().await.expect("list_agents");
    assert!(
        agents.iter().any(|a| a.id == id && a.name == "alpha"),
        "created agent should appear in list: {agents:?}"
    );

    // gate_stats round-trips through the typed mapping.
    let stats = client.gate_stats().await.expect("gate_stats");
    // The create path admits the agent without a tool denial.
    assert_eq!(stats.denied_capability, 0);

    let enforcement = client.agent_info(&id).await.expect("agent_info");
    assert!(enforcement.pid > 0);
    assert!(!enforcement.capabilities.is_empty());
    assert!(!enforcement.namespaces.is_empty());

    let protocol = client.describe_protocol().await.expect("describe_protocol");
    assert!(protocol.features.contains(&"typed_errors".to_string()));
    assert!(protocol
        .features
        .contains(&"bounded_json_frames".to_string()));
    assert!(protocol
        .features
        .contains(&"connection_keepalive".to_string()));
    assert!(protocol
        .features
        .contains(&"graceful_connection_close".to_string()));
    assert!(protocol.request_schema["oneOf"].is_array());
}

#[tokio::test]
async fn sdk_ping_and_graceful_close_roundtrip() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");
    client.ping().await.expect("ping");
    client.close().await.expect("graceful close");
}

#[tokio::test]
async fn message_stream_is_ordered_and_returns_the_terminal_result() {
    let (addr, _kernel) = spawn_stream_server("stream-success", false, 0).await;
    let mut client = KernelClient::connect(addr).await.expect("connect");
    let id = client
        .create_agent(
            "streaming",
            "stream one turn",
            Some("stream-success".into()),
            None,
            None,
        )
        .await
        .expect("create agent");
    let mut events = Vec::new();
    let result = client
        .send_message_stream("request-success", &id, "hello", |event| {
            events.push(event.clone())
        })
        .await
        .expect("stream turn");

    assert_eq!(result.content, "streamed reply");
    assert_eq!(result.tokens, 2);
    assert_eq!(events.first(), Some(&MessageStreamEvent::Started));
    assert!(events.iter().any(|event| matches!(
        event,
        MessageStreamEvent::Token { delta } if delta == "streamed reply"
    )));
    assert!(client
        .list_agents()
        .await
        .expect("connection remains usable")
        .iter()
        .any(|agent| agent.id == id));
}

#[tokio::test]
async fn sustained_stream_crosses_bounded_buffers_without_loss_or_reordering() {
    const EVENT_COUNT: usize = 10_000;
    let (addr, _kernel) = spawn_stream_server("stream-soak", false, EVENT_COUNT).await;
    let mut client = KernelClient::connect(addr).await.expect("connect");
    let id = client
        .create_agent(
            "stream-soak",
            "exercise bounded backpressure",
            Some("stream-soak".into()),
            None,
            None,
        )
        .await
        .expect("create agent");
    let mut started = 0_usize;
    let mut deltas = 0_usize;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.send_message_stream("request-soak", &id, "start", |event| match event {
            MessageStreamEvent::Started => started += 1,
            MessageStreamEvent::Token { delta } => {
                assert_eq!(delta, "x");
                deltas += 1;
            }
            _ => {}
        }),
    )
    .await
    .expect("bounded stream timed out")
    .expect("bounded stream");

    assert_eq!(started, 1);
    assert_eq!(deltas, EVENT_COUNT);
    assert_eq!(result.content.len(), EVENT_COUNT);
    assert_eq!(result.tokens, EVENT_COUNT as u32 + 1);
}

#[tokio::test]
async fn second_authenticated_connection_cancels_one_exact_stream_request() {
    let (addr, kernel) = spawn_stream_server("stream-blocked", true, 0).await;
    let mut stream_client = KernelClient::connect(addr).await.expect("stream connect");
    let mut control_client = KernelClient::connect(addr).await.expect("control connect");
    let id = stream_client
        .create_agent(
            "cancel-stream",
            "wait for cancellation",
            Some("stream-blocked".into()),
            None,
            None,
        )
        .await
        .expect("create agent");

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let stream_agent = id.clone();
    let stream = tokio::spawn(async move {
        stream_client
            .send_message_stream(
                "request-cancel",
                stream_agent,
                "block until cancelled",
                |event| {
                    if matches!(event, MessageStreamEvent::Started) {
                        let _ = started_tx.send(());
                    }
                },
            )
            .await
    });

    tokio::time::timeout(std::time::Duration::from_secs(2), started_rx.recv())
        .await
        .expect("started event timeout")
        .expect("started event channel");
    assert!(control_client
        .cancel_request("request-cancel", &id)
        .await
        .expect("cancel request"));

    let error = tokio::time::timeout(std::time::Duration::from_secs(2), stream)
        .await
        .expect("stream cancellation timeout")
        .expect("stream task")
        .expect_err("cancelled stream must fail");
    assert_eq!(error.wire_code(), Some(WireErrorCode::Cancelled));
    assert!(!control_client
        .cancel_request("request-cancel", &id)
        .await
        .expect("completed request is no longer active"));
    assert_eq!(
        kernel
            .get_agent_status(id.parse().expect("agent id"))
            .expect("agent state"),
        kernel::AgentState::Running
    );
}

#[tokio::test]
async fn agent_builder_creates_and_lists() {
    let addr = spawn_server().await;

    let mut agent = Agent::builder()
        .name("beta")
        .task("builder task")
        .profile("standard")
        .priority(2)
        .connect(addr)
        .await
        .expect("builder connect");

    let id = agent.id().to_string();
    assert!(!id.is_empty());

    // The same connection can issue non-agent-specific syscalls.
    let agents = agent.client().list_agents().await.expect("list_agents");
    assert!(agents.iter().any(|a| a.id == id && a.name == "beta"));
}

#[tokio::test]
async fn builder_requires_name_and_task() {
    let addr = spawn_server().await;
    let client = KernelClient::connect(addr).await.expect("connect");

    let result = Agent::builder()
        .name("missing-task")
        .create_with(client)
        .await;
    match result {
        Ok(_) => panic!("should require task"),
        Err(SdkError::Kernel(msg)) => {
            assert!(msg.contains("name and task are required"), "{msg}")
        }
        Err(other) => panic!("expected Kernel error, got {other:?}"),
    }
}

#[tokio::test]
async fn memory_store_query_and_list_providers_via_sdk() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    let id = client
        .create_agent("mem", "t", None, None, None)
        .await
        .expect("create_agent");

    // Store a fact, then retrieve it by substring.
    let fact_id = client
        .memory_store(&id, "api token rotates monthly", Some("instruction".into()))
        .await
        .expect("memory_store");
    assert!(!fact_id.is_empty());

    let facts = client
        .memory_query(&id, "token rotates")
        .await
        .expect("memory_query");
    assert!(
        facts.iter().any(|f| f.content.contains("api token")),
        "stored fact should be retrievable: {facts:?}"
    );

    // No providers registered in the bare test kernel, but the call round-trips.
    let providers = client.list_providers().await.expect("list_providers");
    assert!(providers.is_empty());
}

#[tokio::test]
async fn storage_put_get_list_delete_via_sdk() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    let id = client
        .create_agent("kv", "t", None, None, None)
        .await
        .expect("create_agent");

    // Missing key → None.
    assert_eq!(
        client.storage_get(&id, "color").await.expect("storage_get"),
        None
    );

    // Put then get.
    client
        .storage_put(&id, "color", "blue")
        .await
        .expect("storage_put");
    assert_eq!(
        client
            .storage_get(&id, "color")
            .await
            .expect("storage_get")
            .as_deref(),
        Some("blue")
    );

    // Overwrite, then list.
    client
        .storage_put(&id, "color", "green")
        .await
        .expect("storage_put overwrite");
    assert_eq!(
        client.storage_list(&id).await.expect("storage_list"),
        vec!["color".to_string()]
    );

    // Delete returns true; deleting again returns false.
    assert!(client
        .storage_delete(&id, "color")
        .await
        .expect("storage_delete"));
    assert!(!client
        .storage_delete(&id, "color")
        .await
        .expect("storage_delete again"));
    assert_eq!(
        client.storage_get(&id, "color").await.expect("storage_get"),
        None
    );
}

#[tokio::test]
async fn snapshot_context_via_sdk() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    // create_agent seeds an initial (default) context, snapshottable immediately.
    let id = client
        .create_agent("snap", "t", None, None, None)
        .await
        .expect("create_agent");

    // Capture, list, restore, delete round-trip through the typed methods.
    client
        .snapshot_context(&id, "start")
        .await
        .expect("snapshot_context");

    let labels = client.list_snapshots(&id).await.expect("list_snapshots");
    assert_eq!(labels, vec!["start".to_string()]);

    let tokens = client
        .restore_snapshot(&id, "start")
        .await
        .expect("restore_snapshot");
    assert_eq!(tokens, 0, "fresh context has zero tokens");

    assert!(client
        .delete_snapshot(&id, "start")
        .await
        .expect("delete_snapshot"));
    assert!(!client
        .delete_snapshot(&id, "start")
        .await
        .expect("delete_snapshot again"));
    assert!(client
        .list_snapshots(&id)
        .await
        .expect("list_snapshots")
        .is_empty());

    // Restoring a missing snapshot is a kernel error, not a panic.
    let err = client
        .restore_snapshot(&id, "missing")
        .await
        .expect_err("missing snapshot should fail");
    let message = err
        .kernel_message()
        .unwrap_or_else(|| panic!("expected kernel error, got {err:?}"));
    assert!(message.contains("restore snapshot failed"), "{message}");
}

#[tokio::test]
async fn load_package_via_sdk() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    let id = client
        .load_package(
            r#"
name = "sdk-pkg"
task = "packaged via sdk"
profile = "read-only"
priority = 3
memory = ["seeded by package"]
"#,
        )
        .await
        .expect("load_package");

    // The packaged agent is live and queryable for its seeded memory.
    let agents = client.list_agents().await.expect("list_agents");
    assert!(agents.iter().any(|a| a.id == id && a.name == "sdk-pkg"));

    let facts = client
        .memory_query(&id, "seeded")
        .await
        .expect("memory_query");
    assert!(facts
        .iter()
        .any(|f| f.content.contains("seeded by package")));

    // A malformed manifest comes back as a kernel error, not a panic.
    let err = client
        .load_package("name = \"x\"")
        .await
        .expect_err("missing task should fail");
    let message = err
        .kernel_message()
        .unwrap_or_else(|| panic!("expected kernel error, got {err:?}"));
    assert!(message.contains("invalid package"), "{message}");
}

#[tokio::test]
async fn operator_snapshot_and_tunable_control_via_sdk() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    let initial = client
        .list_operator_tunables()
        .await
        .expect("list_operator_tunables");
    let max_agents = initial
        .iter()
        .find(|tunable| tunable.name == kernel::operator_control::MAX_AGENTS)
        .unwrap();
    let changed = client
        .set_operator_tunable(&max_agents.name, 2, max_agents.revision)
        .await
        .expect("set_operator_tunable");
    assert_eq!(changed.value, 2);

    let package_id = client
        .load_package("name = \"ops-sdk\"\ntask = \"operator view\"")
        .await
        .expect("load package");
    let snapshot = client.operator_snapshot().await.expect("operator_snapshot");
    assert_eq!(snapshot.total_visible_agents, 1);
    assert!(!snapshot.agents_truncated);
    assert_eq!(snapshot.packages.len(), 1);
    assert_eq!(snapshot.packages[0].agent_id, package_id);
    assert!(snapshot.tunables.is_some());
    assert_eq!(
        snapshot
            .system_metrics
            .as_ref()
            .expect("system metrics")
            .gate,
        snapshot.scoped_gate_decisions
    );

    let rolled_back = client
        .rollback_operator_tunable(&changed.name, 1, changed.revision)
        .await
        .expect("rollback_operator_tunable");
    assert_eq!(rolled_back.value, 0);
    let audit = client
        .operator_tunable_audit(Some(changed.name), 10)
        .await
        .expect("operator_tunable_audit");
    assert!(audit.iter().any(|entry| entry.action == "rollback"));
}

#[tokio::test]
async fn system_operator_can_create_and_verify_online_backup_via_sdk() {
    let root = std::env::temp_dir().join(format!("agentos-sdk-backup-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("create test root");
    let database = root.join("agent_os.db");
    let backup_root = root.join("backups");
    let kernel = Arc::new(AgentKernelImpl::with_db_path(&database).expect("persistent kernel"));
    let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("local_addr");
    let server_task = tokio::spawn(server.serve());

    let mut client = KernelClient::connect(addr).await.expect("connect");
    let manifest = client
        .create_storage_backup(backup_root.to_string_lossy(), "operator_001")
        .await
        .expect("create_storage_backup");
    assert_eq!(
        kernel::storage::verify_backup(&backup_root.join("operator_001")).unwrap(),
        manifest
    );

    drop(client);
    server_task.abort();
    let _ = server_task.await;
    drop(kernel);
    remove_test_tree_after_handle_release(&root).await;
}

#[tokio::test]
async fn system_operator_can_erase_live_agent_user_and_tenant_via_typed_sdk() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("local_addr");
    let server_task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(addr).await.expect("connect");
    let agent_id = client
        .create_agent("erase-sdk", "private task", None, None, None)
        .await
        .expect("create agent")
        .parse::<uuid::Uuid>()
        .expect("agent uuid");

    let receipt = client
        .erase_agent_data(agent_id, agent_sdk::CONFIRM_DATA_ERASURE)
        .await
        .expect("erase through SDK")
        .expect("agent data existed");
    assert_eq!(
        receipt.subject_kind,
        kernel::context::DeletionSubjectKind::Agent
    );
    assert!(kernel
        .context_manager
        .agent_tenant(agent_id)
        .unwrap()
        .is_none());
    assert!(kernel.agent_manager.get_agent_state(agent_id).is_none());
    assert!(!client
        .list_agents()
        .await
        .expect("list after erasure")
        .iter()
        .any(|agent| agent.id == agent_id.to_string()));

    let user_tenant = kernel.create_tenant("sdk-user-erasure").await.unwrap();
    let user_id = kernel
        .register_user(
            &user_tenant,
            "sdk-user",
            "sdk-user@erasure.test",
            kernel::auth::Role::User,
        )
        .await
        .unwrap();
    let user_receipt = client
        .erase_user_data(user_id.clone(), agent_sdk::CONFIRM_DATA_ERASURE)
        .await
        .expect("erase user through SDK")
        .expect("user data existed");
    assert_eq!(
        user_receipt.subject_kind,
        kernel::context::DeletionSubjectKind::User
    );
    assert!(kernel.auth.read().await.get_user(&user_id).is_none());

    let tenant_id = kernel.create_tenant("sdk-tenant-erasure").await.unwrap();
    let tenant_agent = kernel
        .create_agent_for_tenant(
            &tenant_id,
            kernel::AgentConfig {
                name: "sdk-tenant-agent".into(),
                task: "private tenant task".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: kernel::Priority::default(),
                sandbox_config: None,
            },
        )
        .await
        .unwrap()
        .id;
    let tenant_receipt = client
        .erase_tenant_data(tenant_id.clone(), agent_sdk::CONFIRM_DATA_ERASURE)
        .await
        .expect("erase tenant through SDK")
        .expect("tenant data existed");
    assert_eq!(
        tenant_receipt.subject_kind,
        kernel::context::DeletionSubjectKind::Tenant
    );
    assert!(kernel.auth.read().await.get_tenant(&tenant_id).is_none());
    assert!(kernel.agent_manager.get_agent_state(tenant_agent).is_none());

    drop(client);
    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn read_only_agent_tool_call_is_denied() {
    let addr = spawn_server().await;

    // A read-only agent lacks CAP_FILE_WRITE, so write_file is gate-denied.
    let mut agent = Agent::builder()
        .name("ro")
        .task("t")
        .profile("read-only")
        .connect(addr)
        .await
        .expect("builder connect");

    let err = agent
        .call_tool(
            "write_file",
            serde_json::json!({"path": "/tmp/x", "content": "y"}),
        )
        .await
        .expect_err("write should be denied for a read-only agent");
    assert_eq!(err.wire_code(), Some(WireErrorCode::PermissionDenied));
    assert!(!err.is_retryable());
    let message = err
        .kernel_message()
        .unwrap_or_else(|| panic!("expected kernel denial, got {err:?}"));
    assert!(
        message.contains("denied by kernel"),
        "expected a kernel denial, got: {message}"
    );

    // The denial is reflected in the gate counters over the same connection.
    let stats = agent.client().gate_stats().await.expect("gate_stats");
    assert!(
        stats.denied_capability >= 1,
        "gate should record the capability denial: {stats:?}"
    );
}
