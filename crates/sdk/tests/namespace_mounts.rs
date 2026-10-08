use agent_sdk::{
    KernelClient, MountKind, WireErrorCode, WorkspaceKind, WorkspaceOpenRequest, WorkspaceRight,
};
use kernel::syscall_server::SyscallServer;
use kernel::{AgentConfig, AgentKernelImpl, IsolationLevel, Priority, SandboxConfig};
use std::{path::PathBuf, sync::Arc};

struct Fixture {
    kernel: Arc<AgentKernelImpl>,
    root: PathBuf,
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Fixture {
    async fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("agentos-mount-wire-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("project")).unwrap();
        std::fs::write(root.join("project/file.bin"), b"mounted bytes").unwrap();
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        Self {
            kernel,
            root,
            addr,
            server: tokio::spawn(server.serve()),
        }
    }
    fn config(&self, name: &str) -> AgentConfig {
        AgentConfig {
            name: name.into(),
            task: "namespace mount proof".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: Some(SandboxConfig {
                workspace_dir: self.root.clone(),
                isolation_level: IsolationLevel::Filesystem,
                allowed_network_hosts: Some(Vec::new()),
                max_disk_usage_bytes: Some(100000),
                max_memory_bytes: None,
                container_image: None,
            }),
        }
    }
    async fn agent(&self, name: &str, group: &str) -> String {
        self.kernel
            .create_agent_in_namespace(self.config(name), group)
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
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn file(path: &str) -> WorkspaceOpenRequest {
    WorkspaceOpenRequest {
        path: path.into(),
        kind: WorkspaceKind::File,
        rights: vec![WorkspaceRight::Read, WorkspaceRight::Write],
        allow_missing: false,
    }
}

#[tokio::test]
async fn mount_aliases_use_real_governed_backends_with_one_gate_per_operation() {
    let f = Fixture::new().await;
    let agent = f.agent("aliases", "project").await;
    let mut client = f.client().await;
    assert!(client
        .describe_protocol()
        .await
        .unwrap()
        .features
        .contains(&"namespace_mounts".into()));
    let initial = client.vfs_namespace_mounts(&agent).await.unwrap();
    assert_eq!(
        initial
            .mounts
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["/ipc", "/kv", "/memory", "/tools", "/workspace"]
    );
    let tools = client
        .vfs_mount(
            &agent,
            &initial.table_id,
            initial.generation,
            "/commands",
            MountKind::Tools,
        )
        .await
        .unwrap();
    let workspace = client
        .vfs_mount(
            &agent,
            &tools.table_id,
            tools.generation,
            "/project",
            MountKind::Workspace,
        )
        .await
        .unwrap();
    assert_eq!(workspace.mounts.len(), 7);
    assert!(client
        .vfs_mount_entries(&agent, "/commands")
        .await
        .unwrap()
        .entries
        .contains(&"/commands/read_file".into()));
    let before = f.kernel.syscall_gate.stats().allowed;
    let tool = client
        .vfs_open(&agent, "/commands/read_file")
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_invoke(
                &agent,
                &tool.id,
                serde_json::json!({"path":"project/file.bin"})
            )
            .await
            .unwrap()["content"],
        "mounted bytes"
    );
    let entry = client
        .vfs_open_workspace(&agent, file("/project/project/file.bin"))
        .await
        .unwrap();
    assert_eq!(entry.path, "/project/project/file.bin");
    let duplicate = client
        .vfs_dup_workspace(&agent, &entry.id, vec![WorkspaceRight::Read])
        .await
        .unwrap();
    assert_eq!(duplicate.path, entry.path);
    assert_eq!(
        client
            .vfs_read_bytes(&agent, &duplicate.id, 0, 64)
            .await
            .unwrap()
            .bytes,
        b"mounted bytes"
    );
    assert_eq!(
        client
            .vfs_write_bytes(&agent, &entry.id, &[0, 255, 42])
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        std::fs::read(f.root.join("project/file.bin")).unwrap(),
        [0, 255, 42]
    );
    assert_eq!(f.kernel.syscall_gate.stats().allowed, before + 4);
}

#[tokio::test]
async fn unmount_revokes_peer_descriptors_and_pending_capacity_without_cross_namespace_effects() {
    let f = Fixture::new().await;
    let first = f.agent("first", "team").await;
    let peer = f.agent("peer", "team").await;
    let other = f.agent("other", "separate").await;
    let mut client = f.client().await;
    let view = client.vfs_namespace_mounts(&first).await.unwrap();
    assert_eq!(view, client.vfs_namespace_mounts(&peer).await.unwrap());
    assert_ne!(
        view.namespace,
        client.vfs_namespace_mounts(&other).await.unwrap().namespace
    );
    let first_handle = client
        .vfs_open_workspace(&first, file("/workspace/project/file.bin"))
        .await
        .unwrap();
    let peer_handle = client
        .vfs_open_workspace(&peer, file("/workspace/project/file.bin"))
        .await
        .unwrap();
    let other_handle = client
        .vfs_open_workspace(&other, file("/workspace/project/file.bin"))
        .await
        .unwrap();
    let mount = view
        .mounts
        .iter()
        .find(|entry| entry.kind == MountKind::Workspace)
        .unwrap();
    let removed = client
        .vfs_unmount(
            &first,
            &view.table_id,
            view.generation,
            &mount.path,
            &mount.id,
        )
        .await
        .unwrap();
    for (agent, handle) in [(&first, &first_handle), (&peer, &peer_handle)] {
        assert_eq!(
            client
                .vfs_read_bytes(agent, &handle.id, 0, 64)
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::NotFound)
        );
        assert_eq!(client.vfs_mounts(agent).await.unwrap().open_handles, 0);
    }
    assert_eq!(
        client
            .vfs_read_bytes(&other, &other_handle.id, 0, 64)
            .await
            .unwrap()
            .bytes,
        b"mounted bytes"
    );
    let recreated = client
        .vfs_mount(
            &first,
            &removed.table_id,
            removed.generation,
            "/workspace",
            MountKind::Workspace,
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_read_bytes(&first, &first_handle.id, 0, 64)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    assert_eq!(
        client
            .vfs_unmount(
                &peer,
                &recreated.table_id,
                recreated.generation,
                "/workspace",
                &mount.id
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    client
        .vfs_open_workspace(&peer, file("/workspace/project/file.bin"))
        .await
        .unwrap();
}

#[tokio::test]
async fn mount_administration_requires_tenant_admin_and_exact_owned_agent() {
    let f = Fixture::new().await;
    let tenant = f.kernel.create_tenant("mount-owner").await.unwrap();
    let foreign = f.kernel.create_tenant("mount-foreign").await.unwrap();
    let agent = f
        .kernel
        .create_agent_for_tenant(&tenant, f.config("owned"))
        .await
        .unwrap()
        .id
        .to_string();
    let other = f
        .kernel
        .create_agent_for_tenant(&foreign, f.config("foreign"))
        .await
        .unwrap()
        .id
        .to_string();
    let mut client = f.client().await;
    let view = client.vfs_namespace_mounts(&agent).await.unwrap();
    for role in [kernel::auth::Role::User, kernel::auth::Role::ReadOnly] {
        let user = f
            .kernel
            .register_user(&tenant, role.as_str(), "user@mount.test", role)
            .await
            .unwrap();
        client
            .authenticate(f.kernel.issue_api_key(&user, "mount-test").await.unwrap())
            .await
            .unwrap();
        assert_eq!(client.vfs_namespace_mounts(&agent).await.unwrap(), view);
        assert_eq!(
            client
                .vfs_namespace_mounts(&other)
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::AuthorizationDenied)
        );
        assert_eq!(
            client
                .vfs_mount(
                    &agent,
                    &view.table_id,
                    view.generation,
                    "/alias",
                    MountKind::Tools
                )
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::AuthorizationDenied)
        );
        let mount = &view.mounts[0];
        assert_eq!(
            client
                .vfs_unmount(
                    &agent,
                    &view.table_id,
                    view.generation,
                    &mount.path,
                    &mount.id
                )
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::AuthorizationDenied)
        );
    }
    let admin = f
        .kernel
        .register_user(
            &tenant,
            "admin",
            "admin@mount.test",
            kernel::auth::Role::Admin,
        )
        .await
        .unwrap();
    client
        .authenticate(f.kernel.issue_api_key(&admin, "mount-admin").await.unwrap())
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_mount(
                &other,
                &view.table_id,
                view.generation,
                "/alias",
                MountKind::Tools
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::AuthorizationDenied)
    );
    client
        .vfs_mount(
            &agent,
            &view.table_id,
            view.generation,
            "/alias",
            MountKind::Tools,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn stale_mount_updates_and_path_collisions_do_not_mutate_the_table() {
    let f = Fixture::new().await;
    let agent = f.agent("collisions", "paths").await;
    let mut client = f.client().await;
    let view = client.vfs_namespace_mounts(&agent).await.unwrap();
    for path in ["/tools", "/tools/subtree", "/workspace/subtree"] {
        assert_eq!(
            client
                .vfs_mount(
                    &agent,
                    &view.table_id,
                    view.generation,
                    path,
                    MountKind::Tools
                )
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::Conflict)
        );
    }
    for path in ["/", "/a//b", "/a/../b", "/CON", "/a/", "relative"] {
        assert_eq!(
            client
                .vfs_mount(
                    &agent,
                    &view.table_id,
                    view.generation,
                    path,
                    MountKind::Tools
                )
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::InvalidArgument)
        );
    }
    assert_eq!(client.vfs_namespace_mounts(&agent).await.unwrap(), view);
    client
        .vfs_mount(
            &agent,
            &view.table_id,
            view.generation,
            "/alias",
            MountKind::Tools,
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_mount(
                &agent,
                &view.table_id,
                view.generation,
                "/different",
                MountKind::Tools
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::Conflict)
    );
}

#[tokio::test]
async fn namespace_leave_and_rejoin_never_resurrect_a_descriptor() {
    let f = Fixture::new().await;
    let agent = f.agent("membership", "team").await;
    let id = uuid::Uuid::parse_str(&agent).unwrap();
    let mut client = f.client().await;
    let descriptor = client.vfs_open(&agent, "/tools/read_file").await.unwrap();
    let original = f.kernel.syscall_gate.agent_info(id).unwrap().namespaces;
    f.kernel.syscall_gate.set_agent_namespaces(id, Vec::new());
    assert_eq!(
        client
            .vfs_invoke(
                &agent,
                &descriptor.id,
                serde_json::json!({"path":"project/file.bin"})
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    f.kernel.syscall_gate.set_agent_namespaces(id, original);
    assert_eq!(
        client
            .vfs_invoke(
                &agent,
                &descriptor.id,
                serde_json::json!({"path":"project/file.bin"})
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    client.vfs_close(&agent, &descriptor.id).await.unwrap();
    let fresh = client.vfs_open(&agent, "/tools/read_file").await.unwrap();
    client
        .vfs_invoke(
            &agent,
            &fresh.id,
            serde_json::json!({"path":"project/file.bin"}),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn mount_mutations_obey_exact_destination_fences_and_drain_allows_unmount() {
    use kernel::syscall_server::{Syscall, SyscallReply};
    let f = Fixture::new().await;
    let agent = f.agent("fenced-mount", "team").await;
    let mut client = f.client().await;
    let view = client.vfs_namespace_mounts(&agent).await.unwrap();
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
            "mount fence regression",
        )
        .await
        .unwrap();
    assert!(client
        .vfs_mount(
            &agent,
            &view.table_id,
            view.generation,
            "/commands",
            MountKind::Tools
        )
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
    let updated = match client
        .call(wrap(Syscall::VfsMount {
            agent_id: agent.clone(),
            expected_table_id: view.table_id.clone(),
            expected_generation: view.generation,
            path: "/commands".into(),
            kind: MountKind::Tools,
        }))
        .await
        .unwrap()
    {
        SyscallReply::VfsNamespaceMounts { view } => view,
        other => panic!("unexpected mount reply: {other:?}"),
    };
    let node = f.kernel.cluster_control.status().unwrap();
    client
        .set_node_availability(
            agent_sdk::NodeAvailability::Draining,
            node.generation,
            "mount drain regression",
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .call(wrap(Syscall::VfsMount {
                agent_id: agent.clone(),
                expected_table_id: updated.table_id.clone(),
                expected_generation: updated.generation,
                path: "/new".into(),
                kind: MountKind::Tools,
            }))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::Unavailable)
    );
    let mount = updated
        .mounts
        .iter()
        .find(|entry| entry.path == "/commands")
        .unwrap();
    assert!(matches!(
        client
            .call(wrap(Syscall::VfsUnmount {
                agent_id: agent.clone(),
                expected_table_id: updated.table_id,
                expected_generation: updated.generation,
                path: mount.path.clone(),
                mount_id: mount.id.clone(),
            }))
            .await
            .unwrap(),
        SyscallReply::VfsNamespaceMounts { .. }
    ));
}

#[tokio::test]
async fn unknown_actor_and_unmounted_root_errors_preserve_the_live_table() {
    let f = Fixture::new().await;
    let agent = f.agent("error-contract", "team").await;
    let mut client = f.client().await;
    let view = client.vfs_namespace_mounts(&agent).await.unwrap();
    let before = f.kernel.syscall_gate.stats().allowed;
    for target in ["malformed-id".to_string(), uuid::Uuid::new_v4().to_string()] {
        let mutation_error = if target == "malformed-id" {
            WireErrorCode::InvalidArgument
        } else {
            WireErrorCode::NotFound
        };
        assert_eq!(
            client
                .vfs_namespace_mounts(&target)
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::NotFound)
        );
        assert_eq!(
            client
                .vfs_mount_entries(&target, "/tools")
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::NotFound)
        );
        assert_eq!(
            client
                .vfs_mount(
                    &target,
                    &view.table_id,
                    view.generation,
                    "/alias",
                    MountKind::Tools
                )
                .await
                .unwrap_err()
                .wire_code(),
            Some(mutation_error)
        );
        assert_eq!(
            client
                .vfs_unmount(
                    &target,
                    &view.table_id,
                    view.generation,
                    "/tools",
                    &view.mounts[0].id
                )
                .await
                .unwrap_err()
                .wire_code(),
            Some(mutation_error)
        );
    }
    assert_eq!(
        client
            .vfs_mount_entries(&agent, "/not-mounted")
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    assert_eq!(client.vfs_namespace_mounts(&agent).await.unwrap(), view);
    assert_eq!(f.kernel.syscall_gate.stats().allowed, before);
}
