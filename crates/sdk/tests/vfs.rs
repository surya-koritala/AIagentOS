use agent_sdk::{KernelClient, WireErrorCode};
use kernel::syscall_server::{Syscall, SyscallServer};
use kernel::{AgentConfig, AgentKernelImpl, IsolationLevel, Priority, SandboxConfig};
use serde_json::json;
use std::{path::PathBuf, sync::Arc};

struct Fixture {
    kernel: Arc<AgentKernelImpl>,
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    root: PathBuf,
}

impl Fixture {
    async fn new() -> Self {
        let root = std::env::temp_dir().join(format!("agentos-vfs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("proof.txt"), "governed file contents").unwrap();
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let server = tokio::spawn(server.serve());
        Self {
            kernel,
            addr,
            server,
            root,
        }
    }

    fn config(&self, name: &str) -> AgentConfig {
        AgentConfig {
            name: name.into(),
            task: "VFS regression".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: Some(SandboxConfig {
                workspace_dir: self.root.clone(),
                isolation_level: IsolationLevel::Filesystem,
                allowed_network_hosts: Some(Vec::new()),
                max_disk_usage_bytes: Some(1024 * 1024),
                max_memory_bytes: None,
                container_image: None,
            }),
        }
    }

    async fn agent(&self, name: &str) -> uuid::Uuid {
        self.kernel
            .create_agent_full(self.config(name))
            .await
            .unwrap()
            .id
    }

    async fn client(&self) -> KernelClient {
        KernelClient::connect(self.addr).await.unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn vfs_errors_retain_legacy_v1_and_typed_v2_envelopes() {
    let f = Fixture::new().await;
    let agent = f.agent("versions").await.to_string();
    let mut client = kernel::syscall_server::SyscallClient::connect(f.addr)
        .await
        .unwrap();
    client
        .call(Syscall::Hello {
            protocol_version: 1,
        })
        .await
        .unwrap();
    let request = Syscall::VfsOpen {
        agent_id: agent,
        path: "/tools/../read_file".into(),
    };
    assert!(matches!(
        client.call(request.clone()).await.unwrap(),
        kernel::syscall_server::SyscallReply::Error { .. }
    ));
    client
        .call(Syscall::Hello {
            protocol_version: 2,
        })
        .await
        .unwrap();
    assert!(matches!(
        client.call(request).await.unwrap(),
        kernel::syscall_server::SyscallReply::TypedError {
            code: WireErrorCode::InvalidArgument,
            ..
        }
    ));
}

#[tokio::test]
async fn vfs_restart_never_restores_an_old_handle() {
    let f = Fixture::new().await;
    let database = f.root.join("restart.db");
    let kernel = Arc::new(AgentKernelImpl::with_db_path(&database).unwrap());
    let agent = kernel
        .create_agent_full(f.config("persistent"))
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
    let handle = client.vfs_open(&agent, "/tools/read_file").await.unwrap();
    client.close().await.unwrap();
    task.abort();
    let _ = task.await;
    drop(kernel);

    let kernel = Arc::new(AgentKernelImpl::with_db_path(&database).unwrap());
    let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(addr).await.unwrap();
    assert_eq!(
        client
            .vfs_invoke(&agent, &handle.id, json!({"path":"proof.txt"}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    assert_eq!(client.agent_status(&agent).await.unwrap(), "Running");
    let fresh = client.vfs_open(&agent, "/tools/read_file").await.unwrap();
    assert_ne!(fresh.id, handle.id);
    assert_eq!(client.vfs_invoke(&agent, &fresh.id, json!({"path":"proof.txt"})).await.unwrap()["content"], "governed file contents");
    client.vfs_close(&agent, fresh.id).await.unwrap();
    client.close().await.unwrap();
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn vfs_drain_denies_new_work_but_permits_handle_reclamation() {
    let f = Fixture::new().await;
    let agent = f.agent("drained").await.to_string();
    let mut client = f.client().await;
    let handle = client.vfs_open(&agent, "/tools/read_file").await.unwrap();
    let control = f.kernel.cluster_control.status().unwrap();
    client
        .set_node_availability(
            agent_sdk::NodeAvailability::Draining,
            control.generation,
            "VFS drain regression",
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_open(&agent, "/tools/read_file")
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::Unavailable)
    );
    assert_eq!(
        client
            .vfs_invoke(&agent, &handle.id, json!({"path":"proof.txt"}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::Unavailable)
    );
    client.vfs_close(&agent, handle.id).await.unwrap();
    assert_eq!(client.vfs_mounts(agent).await.unwrap().open_handles, 0);
}

#[tokio::test]
async fn vfs_mutations_require_the_exact_destination_ownership_fence() {
    let f = Fixture::new().await;
    let agent = f.agent("fenced").await.to_string();
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
            &agent,
            &proof.cluster_id,
            &proof.owner_node_id,
            proof.authority_term,
            proof.authority_generation,
            proof.fencing_token,
            proof.proof_expires_at,
            "VFS fence regression",
        )
        .await
        .unwrap();
    assert!(client
        .vfs_open(&agent, "/tools/read_file")
        .await
        .unwrap_err()
        .kernel_message()
        .unwrap()
        .contains("fence"));
    let wrap = |mutation| Syscall::FencedAgentMutation {
        agent_id: agent.clone(),
        proof: proof.clone(),
        mutation: Box::new(mutation),
    };
    let handle = match client
        .call(wrap(Syscall::VfsOpen {
            agent_id: agent.clone(),
            path: "/tools/read_file".into(),
        }))
        .await
        .unwrap()
    {
        kernel::syscall_server::SyscallReply::VfsOpened { handle } => handle,
        other => panic!("unexpected fenced open: {other:?}"),
    };
    assert!(client
        .vfs_invoke(&agent, &handle.id, json!({"path":"proof.txt"}))
        .await
        .unwrap_err()
        .kernel_message()
        .unwrap()
        .contains("fence"));
    let response = client
        .call(wrap(Syscall::VfsInvoke {
            agent_id: agent.clone(),
            handle: handle.id.clone(),
            args: json!({"path":"proof.txt"}),
        }))
        .await
        .unwrap();
    assert!(matches!(
        response,
        kernel::syscall_server::SyscallReply::ToolResult { .. }
    ));
    assert!(client
        .vfs_close(&agent, &handle.id)
        .await
        .unwrap_err()
        .kernel_message()
        .unwrap()
        .contains("fence"));
    client
        .call(wrap(Syscall::VfsClose {
            agent_id: agent.clone(),
            handle: handle.id,
        }))
        .await
        .unwrap();
}

#[tokio::test]
async fn vfs_sdk_reads_real_workspace_and_accounts_once() {
    let f = Fixture::new().await;
    let agent = f.agent("reader").await.to_string();
    let mut client = f.client().await;
    assert!(client
        .describe_protocol()
        .await
        .unwrap()
        .features
        .contains(&"tool_vfs".into()));
    let view = client.vfs_mounts(&agent).await.unwrap();
    assert_eq!(view.mount, "/tools");
    assert!(view.entries.contains(&"/tools/read_file".into()));
    let before = f.kernel.syscall_gate.stats();
    let handle = client.vfs_open(&agent, "/tools/read_file").await.unwrap();
    assert_eq!(f.kernel.syscall_gate.stats().allowed, before.allowed);
    let result = client
        .vfs_invoke(&agent, &handle.id, json!({"path":"proof.txt"}))
        .await
        .unwrap();
    assert_eq!(result["content"], "governed file contents");
    assert_eq!(f.kernel.syscall_gate.stats().allowed, before.allowed + 1);
    client.vfs_close(&agent, &handle.id).await.unwrap();
    assert_eq!(client.vfs_mounts(&agent).await.unwrap().open_handles, 0);
    let error = client
        .vfs_invoke(&agent, &handle.id, json!({"path":"proof.txt"}))
        .await
        .unwrap_err();
    assert_eq!(error.wire_code(), Some(WireErrorCode::NotFound));
}

#[tokio::test]
async fn vfs_handles_never_cache_capabilities_mac_or_approvals() {
    let f = Fixture::new().await;
    let agent = f.agent("policy").await;
    let mut client = f.client().await;
    let read = client
        .vfs_open(agent.to_string(), "/tools/read_file")
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
    let error = client
        .vfs_invoke(agent.to_string(), &read.id, json!({"path":"proof.txt"}))
        .await
        .unwrap_err();
    assert_eq!(error.wire_code(), Some(WireErrorCode::PermissionDenied));
    f.kernel.syscall_gate.set_mac_enforcing(false).await;
    let delete = client
        .vfs_open(agent.to_string(), "/tools/delete_file")
        .await
        .unwrap();
    let error = client
        .vfs_invoke(agent.to_string(), &delete.id, json!({"path":"proof.txt"}))
        .await
        .unwrap_err();
    assert_eq!(error.wire_code(), Some(WireErrorCode::PermissionDenied));
    let mut config = f.config("approval");
    config.permission_profile = "full-access".into();
    let full = f
        .kernel
        .create_agent_full(config)
        .await
        .unwrap()
        .id
        .to_string();
    let handle = client.vfs_open(&full, "/tools/delete_file").await.unwrap();
    let error = client
        .vfs_invoke(&full, &handle.id, json!({"path":"proof.txt"}))
        .await
        .unwrap_err();
    assert_eq!(error.wire_code(), Some(WireErrorCode::PermissionDenied));
    assert!(f.root.join("proof.txt").exists());
}

#[tokio::test]
async fn vfs_binding_replacement_revokes_even_identical_registrations() {
    let f = Fixture::new().await;
    let agent = f.agent("bindings").await.to_string();
    let mut client = f.client().await;
    let old = client.vfs_open(&agent, "/tools/read_file").await.unwrap();
    let binding = f.kernel.tool_registry.binding_catalog()["read_file"].clone();
    f.kernel.tool_registry.unregister("read_file");
    f.kernel.tool_registry.register(binding).unwrap();
    let error = client
        .vfs_invoke(&agent, &old.id, json!({"path":"proof.txt"}))
        .await
        .unwrap_err();
    assert_eq!(error.wire_code(), Some(WireErrorCode::NotFound));
    let fresh = client.vfs_open(&agent, "/tools/read_file").await.unwrap();
    assert_eq!(
        client
            .vfs_invoke(&agent, &fresh.id, json!({"path":"proof.txt"}))
            .await
            .unwrap()["content"],
        "governed file contents"
    );
    client.vfs_close(&agent, old.id).await.unwrap();
}

#[tokio::test]
async fn vfs_agent_ownership_capacity_and_stop_revoke_handles() {
    let f = Fixture::new().await;
    let owner = f.agent("owner").await.to_string();
    let other = f.agent("other").await.to_string();
    let mut client = f.client().await;
    let first = client.vfs_open(&owner, "/tools/read_file").await.unwrap();
    assert_eq!(
        client
            .vfs_invoke(&other, &first.id, json!({"path":"proof.txt"}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    assert_eq!(
        client
            .vfs_close(&other, &first.id)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    for _ in 1..kernel::vfs::MAX_HANDLES_PER_AGENT {
        client.vfs_open(&owner, "/tools/read_file").await.unwrap();
    }
    assert_eq!(
        client
            .vfs_open(&owner, "/tools/read_file")
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::QuotaExceeded)
    );
    client.vfs_close(&owner, &first.id).await.unwrap();
    let last = client.vfs_open(&owner, "/tools/read_file").await.unwrap();
    client.stop_agent(&owner).await.unwrap();
    assert_eq!(
        client
            .vfs_invoke(&owner, last.id, json!({"path":"proof.txt"}))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
}

#[tokio::test]
async fn vfs_mount_and_open_hide_foreign_namespaces_and_recheck_revocation() {
    let f = Fixture::new().await;
    let mut binding = f.kernel.tool_registry.binding_catalog()["read_file"].clone();
    binding.name = "private_vfs".into();
    f.kernel
        .register_group_tool("private-vfs", binding)
        .unwrap();
    let owner = f
        .kernel
        .create_agent_in_namespace(f.config("private"), "private-vfs")
        .await
        .unwrap()
        .id;
    let other = f.agent("outside").await;
    let mut client = f.client().await;
    assert!(!client
        .vfs_mounts(other.to_string())
        .await
        .unwrap()
        .entries
        .contains(&"/tools/private_vfs".into()));
    assert_eq!(
        client
            .vfs_open(other.to_string(), "/tools/private_vfs")
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    let handle = client
        .vfs_open(owner.to_string(), "/tools/private_vfs")
        .await
        .unwrap();
    f.kernel
        .syscall_gate
        .set_agent_namespaces(owner, Vec::new());
    let error = client
        .vfs_invoke(owner.to_string(), handle.id, json!({"path":"proof.txt"}))
        .await
        .unwrap_err();
    assert!(matches!(
        error.wire_code(),
        Some(WireErrorCode::NotFound | WireErrorCode::PermissionDenied)
    ));
}

#[tokio::test]
async fn vfs_authenticated_tenants_and_readonly_roles_are_enforced() {
    let f = Fixture::new().await;
    let tenant = f.kernel.create_tenant("vfs-tenant").await.unwrap();
    let foreign = f.kernel.create_tenant("vfs-foreign").await.unwrap();
    let user = f
        .kernel
        .register_user(&tenant, "user", "user@vfs.test", kernel::auth::Role::User)
        .await
        .unwrap();
    let reader = f
        .kernel
        .register_user(
            &tenant,
            "reader",
            "reader@vfs.test",
            kernel::auth::Role::ReadOnly,
        )
        .await
        .unwrap();
    let own = f
        .kernel
        .create_agent_for_tenant(&tenant, f.config("tenant-agent"))
        .await
        .unwrap()
        .id
        .to_string();
    let other = f
        .kernel
        .create_agent_for_tenant(&foreign, f.config("foreign-agent"))
        .await
        .unwrap()
        .id
        .to_string();
    let key = f.kernel.issue_api_key(&user, "vfs-user").await.unwrap();
    let mut client = f.client().await;
    client.authenticate(key).await.unwrap();
    let handle = client.vfs_open(&own, "/tools/read_file").await.unwrap();
    for request in [
        Syscall::VfsMounts {
            agent_id: other.clone(),
        },
        Syscall::VfsOpen {
            agent_id: other.clone(),
            path: "/tools/read_file".into(),
        },
        Syscall::VfsInvoke {
            agent_id: other.clone(),
            handle: handle.id.clone(),
            args: json!({}),
        },
        Syscall::VfsClose {
            agent_id: other,
            handle: handle.id.clone(),
        },
    ] {
        assert_eq!(
            client.call(request).await.unwrap_err().wire_code(),
            Some(WireErrorCode::AuthorizationDenied)
        );
    }
    client
        .authenticate(f.kernel.issue_api_key(&reader, "vfs-reader").await.unwrap())
        .await
        .unwrap();
    client.vfs_mounts(&own).await.unwrap();
    assert_eq!(
        client
            .vfs_open(&own, "/tools/read_file")
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::AuthorizationDenied)
    );
}

#[tokio::test]
async fn vfs_close_racing_invoke_reclaims_capacity_and_never_reopens_handle() {
    let f = Fixture::new().await;
    let agent = f.agent("race").await.to_string();
    let mut invoking = f.client().await;
    let mut closing = f.client().await;
    for _ in 0..24 {
        let handle = closing.vfs_open(&agent, "/tools/read_file").await.unwrap();
        let (result, closed) = tokio::join!(
            invoking.vfs_invoke(&agent, &handle.id, json!({"path":"proof.txt"})),
            closing.vfs_close(&agent, &handle.id)
        );
        closed.unwrap();
        match result {
            Ok(data) => assert_eq!(data["content"], "governed file contents"),
            Err(error) => assert_eq!(error.wire_code(), Some(WireErrorCode::NotFound)),
        }
        assert_eq!(closing.vfs_mounts(&agent).await.unwrap().open_handles, 0);
        assert_eq!(
            invoking
                .vfs_invoke(&agent, handle.id, json!({"path":"proof.txt"}))
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::NotFound)
        );
    }
}
