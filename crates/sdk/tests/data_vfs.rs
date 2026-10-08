use agent_sdk::{KernelClient, WireErrorCode, WorkspaceRight as Right};
use kernel::permissions::PermissionSystem;
use kernel::syscall_server::SyscallServer;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use std::sync::Arc;

struct Fixture {
    kernel: Arc<AgentKernelImpl>,
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Fixture {
    async fn new() -> Self {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        Self {
            kernel,
            addr,
            task: tokio::spawn(server.serve()),
        }
    }
    fn config(name: &str) -> AgentConfig {
        AgentConfig {
            name: name.into(),
            task: "data VFS proof".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        }
    }
    async fn agent(&self, name: &str, group: &str) -> String {
        self.kernel
            .create_agent_in_namespace(Self::config(name), group)
            .await
            .unwrap()
            .id
            .to_string()
    }
    async fn client(&self) -> KernelClient {
        KernelClient::connect(self.addr).await.unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn data_mounts_use_real_kv_memory_and_ipc_with_one_gate_per_backing_call() {
    let f = Fixture::new().await;
    let a = f.agent("sender", "team").await;
    let b = f.agent("receiver", "team").await;
    let mut client = f.client().await;
    let kv = client
        .vfs_open_kv(
            &a,
            "/kv",
            "notes/🦀",
            vec![Right::Read, Right::Write, Right::Stat],
        )
        .await
        .unwrap();
    let memory = client
        .vfs_open_data(&a, "/memory", vec![Right::Read, Right::Write, Right::Stat])
        .await
        .unwrap();
    let outbox = client
        .vfs_open_data(&a, "/ipc", vec![Right::Write, Right::List, Right::Stat])
        .await
        .unwrap();
    let inbox = client
        .vfs_open_data(&b, "/ipc", vec![Right::Read, Right::Stat])
        .await
        .unwrap();
    let before = f.kernel.syscall_gate.stats().allowed;
    client
        .vfs_write_data(&a, &kv.id, serde_json::json!({"value":"persistent 🦀"}))
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_read_data(&a, &kv.id, serde_json::json!({}))
            .await
            .unwrap()["value"],
        "persistent 🦀"
    );
    assert_eq!(client.vfs_stat_data(&a, &kv.id).await.unwrap()["bytes"], 15);
    let fact = client
        .vfs_write_data(
            &a,
            &memory.id,
            serde_json::json!({"content":"Rust memory safety", "category":"Fact"}),
        )
        .await
        .unwrap();
    assert!(fact["id"].as_str().is_some());
    let found = client
        .vfs_read_data(&a, &memory.id, serde_json::json!({"query":"Rust memory"}))
        .await
        .unwrap();
    assert_eq!(found["facts"][0]["content"], "Rust memory safety");
    assert_eq!(
        client.vfs_stat_data(&a, &memory.id).await.unwrap()["facts"],
        1
    );
    client
        .vfs_write_data(
            &a,
            &outbox.id,
            serde_json::json!({"to":b,"payload":{"sequence":1}}),
        )
        .await
        .unwrap();
    assert_eq!(
        client.vfs_stat_data(&b, &inbox.id).await.unwrap()["pending"],
        1
    );
    assert_eq!(
        client
            .vfs_read_data(&b, &inbox.id, serde_json::json!({}))
            .await
            .unwrap()["payload"]["sequence"],
        1
    );
    assert_eq!(
        client
            .vfs_read_data(&b, &inbox.id, serde_json::json!({}))
            .await
            .unwrap()["empty"],
        true
    );
    assert_eq!(f.kernel.syscall_gate.stats().allowed, before + 10);
}

#[tokio::test]
async fn data_rights_duplicate_close_and_key_binding_cannot_broaden_or_redirect() {
    let f = Fixture::new().await;
    let a = f.agent("owner", "team").await;
    let b = f.agent("peer", "team").await;
    let mut client = f.client().await;
    let kv = client
        .vfs_open_kv(
            &a,
            "/kv",
            "fixed",
            vec![Right::Read, Right::Write, Right::Stat],
        )
        .await
        .unwrap();
    client
        .vfs_write_data(&a, &kv.id, serde_json::json!({"value":"original"}))
        .await
        .unwrap();
    let read = client
        .vfs_dup_data(&a, &kv.id, vec![Right::Read])
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_dup_data(&a, &read.id, vec![Right::Write])
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
    assert_eq!(
        client
            .vfs_write_data(&a, &read.id, serde_json::json!({"value":"denied"}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
    assert_eq!(
        client
            .vfs_read_data(&b, &kv.id, serde_json::json!({}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    assert_eq!(
        client
            .vfs_write_data(
                &a,
                &kv.id,
                serde_json::json!({"key":"another","value":"redirect"})
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::InvalidArgument)
    );
    client.vfs_close(&a, &kv.id).await.unwrap();
    assert_eq!(
        client
            .vfs_read_data(&a, &read.id, serde_json::json!({}))
            .await
            .unwrap()["value"],
        "original"
    );
    client.vfs_close(&a, &read.id).await.unwrap();
}

#[tokio::test]
async fn data_quota_failures_preserve_existing_rows_and_shared_handle_capacity() {
    let f = Fixture::new().await;
    let a = f.agent("quota", "team").await;
    let mut client = f.client().await;
    let kv = client
        .vfs_open_kv(&a, "/kv", "fixed", vec![Right::Read, Right::Write])
        .await
        .unwrap();
    client
        .vfs_write_data(&a, &kv.id, serde_json::json!({"value":"keep"}))
        .await
        .unwrap();
    let id = uuid::Uuid::parse_str(&a).unwrap();
    let usage = f
        .kernel
        .context_manager
        .context_pressure_stats(id)
        .unwrap()
        .agent_stored_bytes;
    f.kernel
        .context_manager
        .set_context_storage_limits(kernel::context::ContextStorageLimits {
            per_agent_bytes: usage + 8,
            per_tenant_bytes: 0,
            global_bytes: 0,
            spill_retention_seconds: 60,
        })
        .unwrap();
    assert_eq!(
        client
            .vfs_write_data(
                &a,
                &kv.id,
                serde_json::json!({"value":"too large".repeat(100)})
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::QuotaExceeded)
    );
    assert_eq!(
        client
            .vfs_read_data(&a, &kv.id, serde_json::json!({}))
            .await
            .unwrap()["value"],
        "keep"
    );
    for _ in 1..kernel::vfs::MAX_HANDLES_PER_AGENT {
        client
            .vfs_open_data(&a, "/memory", vec![Right::Read])
            .await
            .unwrap();
    }
    assert_eq!(
        client
            .vfs_open(&a, "/tools/read_file")
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::QuotaExceeded)
    );
    client.vfs_close(&a, &kv.id).await.unwrap();
    client.vfs_open(&a, "/tools/read_file").await.unwrap();
}

#[tokio::test]
async fn data_unmount_and_policy_or_exact_binding_changes_revoke_current_operations() {
    let f = Fixture::new().await;
    let a = f.agent("revocation", "team").await;
    let mut client = f.client().await;
    let kv = client
        .vfs_open_kv(&a, "/kv", "key", vec![Right::Read, Right::Write])
        .await
        .unwrap();
    client
        .vfs_write_data(&a, &kv.id, serde_json::json!({"value":"data"}))
        .await
        .unwrap();
    let binding = f.kernel.tool_registry.binding_catalog()["kv_get"].clone();
    f.kernel.tool_registry.unregister("kv_get");
    f.kernel.tool_registry.register(binding).unwrap();
    assert_eq!(
        client
            .vfs_read_data(&a, &kv.id, serde_json::json!({}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    let fresh = client
        .vfs_open_kv(&a, "/kv", "key", vec![Right::Read])
        .await
        .unwrap();
    f.kernel.syscall_gate.set_mac_enforcing(true).await;
    f.kernel
        .syscall_gate
        .load_mac_policy(vec![kernel::mac::PolicyRule {
            subject: "*".into(),
            action: "read".into(),
            object: "*".into(),
            decision: "deny".into(),
        }])
        .await;
    assert_eq!(
        client
            .vfs_read_data(&a, &fresh.id, serde_json::json!({}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
    f.kernel.syscall_gate.set_mac_enforcing(false).await;
    let view = client.vfs_namespace_mounts(&a).await.unwrap();
    let mount = view
        .mounts
        .iter()
        .find(|mount| mount.path == "/kv")
        .unwrap();
    client
        .vfs_unmount(&a, &view.table_id, view.generation, &mount.path, &mount.id)
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_read_data(&a, &fresh.id, serde_json::json!({}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
}

#[tokio::test]
async fn data_ipc_preserves_fifo_and_denies_foreign_namespaces() {
    let f = Fixture::new().await;
    let a = f.agent("from", "team").await;
    let b = f.agent("to", "team").await;
    let foreign = f.agent("foreign", "elsewhere").await;
    let mut client = f.client().await;
    let out = client
        .vfs_open_data(&a, "/ipc", vec![Right::Write])
        .await
        .unwrap();
    let inbox = client
        .vfs_open_data(&b, "/ipc", vec![Right::Read])
        .await
        .unwrap();
    let error = client
        .vfs_write_data(
            &a,
            &out.id,
            serde_json::json!({"to":foreign,"payload":"private"}),
        )
        .await
        .unwrap_err();
    assert!(error.kernel_message().unwrap().contains("agent not found"));
    for sequence in 0..3 {
        client
            .vfs_write_data(
                &a,
                &out.id,
                serde_json::json!({"to":b,"payload":{"sequence":sequence}}),
            )
            .await
            .unwrap();
    }
    for sequence in 0..3 {
        assert_eq!(
            client
                .vfs_read_data(&b, &inbox.id, serde_json::json!({}))
                .await
                .unwrap()["payload"]["sequence"],
            sequence
        );
    }
}

#[tokio::test]
async fn data_reserved_keys_and_noncanonical_paths_fail_and_directory_stat_hides_keys() {
    let f = Fixture::new().await;
    let a = f.agent("paths", "team").await;
    let mut client = f.client().await;
    for path in [
        "/kv/../escape",
        "/kv/0",
        "/kv/FF",
        "/kv/ff",
        "/memory/child",
    ] {
        assert!(
            client
                .vfs_open_data(&a, path, vec![Right::Read])
                .await
                .is_err(),
            "{path}"
        );
    }
    assert!(client
        .vfs_open_kv(&a, "/kv", "context_spill:internal", vec![Right::Write])
        .await
        .is_err());
    let kv = client
        .vfs_open_kv(&a, "/kv", "hidden-key", vec![Right::Write])
        .await
        .unwrap();
    client
        .vfs_write_data(&a, &kv.id, serde_json::json!({"value":"value"}))
        .await
        .unwrap();
    let dir = client
        .vfs_open_data(&a, "/kv", vec![Right::Stat])
        .await
        .unwrap();
    assert_eq!(client.vfs_stat_data(&a, &dir.id).await.unwrap()["keys"], 1);
    assert_eq!(
        client
            .vfs_list_data(&a, &dir.id)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
}

#[tokio::test]
async fn data_wire_tenants_reader_roles_and_profile_revocation_are_authoritative() {
    let f = Fixture::new().await;
    let tenant = f.kernel.create_tenant("data-owner").await.unwrap();
    let foreign = f.kernel.create_tenant("data-foreign").await.unwrap();
    let actor = f
        .kernel
        .create_agent_for_tenant(&tenant, Fixture::config("owned"))
        .await
        .unwrap()
        .id
        .to_string();
    let other = f
        .kernel
        .create_agent_for_tenant(&foreign, Fixture::config("other"))
        .await
        .unwrap()
        .id
        .to_string();
    let user = f
        .kernel
        .register_user(&tenant, "user", "user@data.test", kernel::auth::Role::User)
        .await
        .unwrap();
    let reader = f
        .kernel
        .register_user(
            &tenant,
            "reader",
            "reader@data.test",
            kernel::auth::Role::ReadOnly,
        )
        .await
        .unwrap();
    let mut client = f.client().await;
    client
        .authenticate(f.kernel.issue_api_key(&user, "data-user").await.unwrap())
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_open_data(&other, "/memory", vec![Right::Read])
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::AuthorizationDenied)
    );
    let handle = client
        .vfs_open_kv(&actor, "/kv", "key", vec![Right::Read, Right::Write])
        .await
        .unwrap();
    client
        .vfs_write_data(&actor, &handle.id, serde_json::json!({"value":"value"}))
        .await
        .unwrap();
    f.kernel
        .permission_manager
        .assign_profile(uuid::Uuid::parse_str(&actor).unwrap(), &"read-only".into());
    assert_eq!(
        client
            .vfs_write_data(&actor, &handle.id, serde_json::json!({"value":"changed"}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
    client
        .authenticate(
            f.kernel
                .issue_api_key(&reader, "data-reader")
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_read_data(&actor, &handle.id, serde_json::json!({}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::AuthorizationDenied)
    );
}

#[tokio::test]
async fn stopped_agents_cannot_use_or_reopen_data_descriptors() {
    let f = Fixture::new().await;
    let actor = f.agent("stop", "team").await;
    let mut client = f.client().await;
    let handle = client
        .vfs_open_kv(&actor, "/kv", "durable", vec![Right::Read, Right::Write])
        .await
        .unwrap();
    client
        .vfs_write_data(&actor, &handle.id, serde_json::json!({"value":"retained"}))
        .await
        .unwrap();
    client.stop_agent(&actor).await.unwrap();
    assert_eq!(
        client
            .vfs_read_data(&actor, &handle.id, serde_json::json!({}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    assert_eq!(
        client
            .vfs_open_data(&actor, "/memory", vec![Right::Read])
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    assert_eq!(
        f.kernel
            .context_manager
            .kv_get(uuid::Uuid::parse_str(&actor).unwrap(), "durable")
            .unwrap()
            .as_deref(),
        Some("retained")
    );
}

#[tokio::test]
async fn data_ipc_payload_bound_rejects_delivery_and_keeps_the_inbox_empty() {
    let f = Fixture::new().await;
    let a = f.agent("payload", "team").await;
    let b = f.agent("empty", "team").await;
    let mut client = f.client().await;
    let out = client
        .vfs_open_data(&a, "/ipc", vec![Right::Write])
        .await
        .unwrap();
    let inbox = client
        .vfs_open_data(&b, "/ipc", vec![Right::Read])
        .await
        .unwrap();
    assert!(client
        .vfs_write_data(
            &a,
            &out.id,
            serde_json::json!({"to":b,"payload":"x".repeat(kernel::ipc::MAX_IPC_PAYLOAD_BYTES)})
        )
        .await
        .is_err());
    assert_eq!(
        client
            .vfs_read_data(&b, &inbox.id, serde_json::json!({}))
            .await
            .unwrap()["empty"],
        true
    );
}

#[tokio::test]
async fn data_mutations_keep_exact_destination_fences_and_node_drain() {
    use kernel::syscall_server::{Syscall, SyscallReply};
    let f = Fixture::new().await;
    let actor = f.agent("fenced", "team").await;
    let mut client = f.client().await;
    let proof = agent_sdk::AgentMutationFenceProof {
        cluster_id: uuid::Uuid::new_v4().to_string(),
        owner_node_id: f.kernel.cluster_control.status().unwrap().identity.node_id,
        authority_term: 1,
        authority_generation: 1,
        fencing_token: 1,
        proof_expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
    };
    client
        .install_agent_mutation_fence(
            &actor,
            &proof.cluster_id,
            &proof.owner_node_id,
            1,
            1,
            1,
            proof.proof_expires_at,
            "data fence proof",
        )
        .await
        .unwrap();
    assert!(client
        .vfs_open_data(&actor, "/memory", vec![Right::Read])
        .await
        .unwrap_err()
        .kernel_message()
        .unwrap()
        .contains("fence"));
    let wrap = |mutation| Syscall::FencedAgentMutation {
        agent_id: actor.clone(),
        proof: proof.clone(),
        mutation: Box::new(mutation),
    };
    let handle = match client
        .call(wrap(Syscall::VfsOpenData {
            agent_id: actor.clone(),
            path: "/memory".into(),
            rights: vec![Right::Read, Right::Stat],
        }))
        .await
        .unwrap()
    {
        SyscallReply::VfsDataOpened { handle } => handle,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        client
            .call(wrap(Syscall::VfsStatData {
                agent_id: actor.clone(),
                handle: handle.id.clone()
            }))
            .await
            .unwrap(),
        SyscallReply::ToolResult { .. }
    ));
    let node = f.kernel.cluster_control.status().unwrap();
    client
        .set_node_availability(
            agent_sdk::NodeAvailability::Draining,
            node.generation,
            "data drain proof",
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .call(wrap(Syscall::VfsReadData {
                agent_id: actor.clone(),
                handle: handle.id.clone(),
                args: serde_json::json!({})
            }))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::Unavailable)
    );
    assert!(matches!(
        client
            .call(wrap(Syscall::VfsClose {
                agent_id: actor.clone(),
                handle: handle.id
            }))
            .await
            .unwrap(),
        SyscallReply::VfsClosed
    ));
}

#[tokio::test]
async fn persistent_data_survives_restart_and_old_descriptors_do_not() {
    let root = std::env::temp_dir().join(format!("agentos-data-restart-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("state.db");
    let actor;
    let old;
    {
        let kernel = Arc::new(AgentKernelImpl::with_db_path(&path).unwrap());
        actor = kernel
            .create_agent_full(Fixture::config("durable"))
            .await
            .unwrap()
            .id
            .to_string();
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(server.serve());
        let mut client = KernelClient::connect(addr).await.unwrap();
        let handle = client
            .vfs_open_kv(&actor, "/kv", "key", vec![Right::Read, Right::Write])
            .await
            .unwrap();
        old = handle.id;
        client
            .vfs_write_data(&actor, &old, serde_json::json!({"value":"survived"}))
            .await
            .unwrap();
        client.close().await.unwrap();
        task.abort();
        let _ = task.await;
    }
    let kernel = Arc::new(AgentKernelImpl::with_db_path(&path).unwrap());
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(addr).await.unwrap();
    assert_eq!(
        client
            .vfs_read_data(&actor, &old, serde_json::json!({}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    // The same runnable owner is restored, with private durable data retained.
    assert_eq!(
        kernel
            .context_manager
            .kv_get(uuid::Uuid::parse_str(&actor).unwrap(), "key")
            .unwrap()
            .as_deref(),
        Some("survived")
    );
    assert_eq!(client.agent_status(&actor).await.unwrap(), "Running");
    let fresh = client.vfs_open_kv(&actor, "/kv", "key", vec![Right::Read]).await.unwrap();
    assert_ne!(fresh.id, old);
    assert_eq!(client.vfs_read_data(&actor, &fresh.id, serde_json::json!({})).await.unwrap()["value"], "survived");
    client.vfs_close(&actor, fresh.id).await.unwrap();
    client.close().await.unwrap();
    task.abort();
    let _ = task.await;
    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}
