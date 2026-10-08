use agent_sdk::{
    KernelClient, WireErrorCode, WorkspaceHandle, WorkspaceKind, WorkspaceOpenRequest,
    WorkspaceRight,
};
use kernel::syscall_server::{Syscall, SyscallServer};
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
            std::env::temp_dir().join(format!("agentos-workspace-vfs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("project")).unwrap();
        std::fs::write(root.join("project/file.bin"), [0u8, 255, 1, 2, 3, 128]).unwrap();
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let server = tokio::spawn(server.serve());
        Self {
            kernel,
            root,
            addr,
            server,
        }
    }
    fn config(&self, name: &str, limit: u64) -> AgentConfig {
        AgentConfig {
            name: name.into(),
            task: "workspace wire regression".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: Some(SandboxConfig {
                workspace_dir: self.root.clone(),
                allowed_network_hosts: Some(Vec::new()),
                max_disk_usage_bytes: Some(limit),
                max_memory_bytes: None,
                isolation_level: IsolationLevel::Filesystem,
                container_image: None,
            }),
        }
    }
    async fn agent(&self, name: &str) -> String {
        self.kernel
            .create_agent_full(self.config(name, 16 * 1024 * 1024))
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

fn request(path: &str, kind: WorkspaceKind, rights: &[WorkspaceRight]) -> WorkspaceOpenRequest {
    WorkspaceOpenRequest {
        path: path.into(),
        kind,
        rights: rights.to_vec(),
        allow_missing: false,
    }
}
async fn directory(
    client: &mut KernelClient,
    agent: &str,
    rights: &[WorkspaceRight],
) -> WorkspaceHandle {
    client
        .vfs_open_workspace(
            agent,
            request("/workspace/project", WorkspaceKind::Directory, rights),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn workspace_real_binary_read_write_list_and_stat_pass_one_gate_each() {
    let f = Fixture::new().await;
    let agent = f.agent("bytes").await;
    let mut client = f.client().await;
    assert!(client
        .describe_protocol()
        .await
        .unwrap()
        .features
        .contains(&"workspace_vfs".into()));
    assert_eq!(
        client.vfs_workspace_mounts(&agent).await.unwrap().mount,
        "/workspace"
    );
    let before = f.kernel.syscall_gate.stats().allowed;
    let dir = directory(
        &mut client,
        &agent,
        &[
            WorkspaceRight::Read,
            WorkspaceRight::Write,
            WorkspaceRight::List,
            WorkspaceRight::Stat,
        ],
    )
    .await;
    assert_eq!(f.kernel.syscall_gate.stats().allowed, before + 1);
    let file = client
        .vfs_open_at(
            &agent,
            &dir.id,
            request(
                "file.bin",
                WorkspaceKind::File,
                &[
                    WorkspaceRight::Read,
                    WorkspaceRight::Write,
                    WorkspaceRight::Stat,
                ],
            ),
        )
        .await
        .unwrap();
    let chunk = client.vfs_read_bytes(&agent, &file.id, 1, 3).await.unwrap();
    assert_eq!(chunk.bytes, vec![255, 1, 2]);
    assert!(!chunk.eof);
    assert_eq!(
        client
            .vfs_read_bytes(&agent, &file.id, 4, 32)
            .await
            .unwrap()
            .bytes,
        vec![3, 128]
    );
    assert_eq!(
        client
            .vfs_stat_workspace(&agent, &file.id)
            .await
            .unwrap()
            .size,
        6
    );
    let listing = client.vfs_list_workspace(&agent, &dir.id).await.unwrap();
    assert_eq!(listing["entries"], serde_json::json!(["file.bin"]));
    let replacement = [128, 0, 255, 42];
    assert_eq!(
        client
            .vfs_write_bytes(&agent, &file.id, &replacement)
            .await
            .unwrap(),
        4
    );
    assert_eq!(
        std::fs::read(f.root.join("project/file.bin")).unwrap(),
        replacement
    );
    assert_eq!(f.kernel.syscall_gate.stats().allowed, before + 7);
}

#[tokio::test]
async fn workspace_dup_and_open_at_can_only_attenuate_rights() {
    let f = Fixture::new().await;
    let agent = f.agent("attenuation").await;
    let mut client = f.client().await;
    let parent = directory(
        &mut client,
        &agent,
        &[
            WorkspaceRight::Read,
            WorkspaceRight::List,
            WorkspaceRight::Stat,
        ],
    )
    .await;
    let error = client
        .vfs_open_at(
            &agent,
            &parent.id,
            request("file.bin", WorkspaceKind::File, &[WorkspaceRight::Write]),
        )
        .await
        .unwrap_err();
    assert_eq!(error.wire_code(), Some(WireErrorCode::PermissionDenied));
    let file = client
        .vfs_open_at(
            &agent,
            &parent.id,
            request(
                "file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read, WorkspaceRight::Stat],
            ),
        )
        .await
        .unwrap();
    let duplicate = client
        .vfs_dup_workspace(&agent, &file.id, vec![WorkspaceRight::Read])
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_dup_workspace(&agent, &duplicate.id, vec![WorkspaceRight::Write])
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
    client.vfs_close(&agent, &file.id).await.unwrap();
    assert_eq!(
        client
            .vfs_read_bytes(&agent, &duplicate.id, 0, 64)
            .await
            .unwrap()
            .bytes,
        [0u8, 255, 1, 2, 3, 128]
    );
    assert_eq!(
        client
            .vfs_stat_workspace(&agent, &duplicate.id)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
    assert_eq!(
        client
            .vfs_write_bytes(&agent, &duplicate.id, b"forbidden")
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
    assert_eq!(
        client
            .vfs_workspace_mounts(&agent)
            .await
            .unwrap()
            .open_handles,
        2
    );
}

#[tokio::test]
async fn workspace_disk_quota_covers_the_whole_workspace_not_only_the_opened_directory() {
    let f = Fixture::new().await;
    std::fs::write(f.root.join("outside-open-directory.bin"), vec![1u8; 9000]).unwrap();
    let agent = f
        .kernel
        .create_agent_full(f.config("quota", 10000))
        .await
        .unwrap()
        .id
        .to_string();
    let mut client = f.client().await;
    let dir = directory(
        &mut client,
        &agent,
        &[WorkspaceRight::Write, WorkspaceRight::Stat],
    )
    .await;
    let file = client
        .vfs_open_at(
            &agent,
            &dir.id,
            request("file.bin", WorkspaceKind::File, &[WorkspaceRight::Write]),
        )
        .await
        .unwrap();
    let error = client
        .vfs_write_bytes(&agent, &file.id, &vec![2u8; 2000])
        .await
        .unwrap_err();
    assert_eq!(error.wire_code(), Some(WireErrorCode::QuotaExceeded));
    assert_eq!(
        std::fs::read(f.root.join("project/file.bin")).unwrap(),
        [0u8, 255, 1, 2, 3, 128]
    );
    assert!(std::fs::read_dir(f.root.join("project"))
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".aiagentos-write-")));
}

#[tokio::test]
async fn workspace_capabilities_never_follow_a_replaced_directory_binding() {
    let f = Fixture::new().await;
    let agent = f.agent("rebind").await;
    let mut client = f.client().await;
    let dir = directory(
        &mut client,
        &agent,
        &[WorkspaceRight::Read, WorkspaceRight::List],
    )
    .await;
    let file = client
        .vfs_open_at(
            &agent,
            &dir.id,
            request("file.bin", WorkspaceKind::File, &[WorkspaceRight::Read]),
        )
        .await
        .unwrap();
    let renamed = std::fs::rename(f.root.join("project"), f.root.join("original"));
    #[cfg(not(windows))]
    renamed.unwrap();
    #[cfg(windows)]
    if let Err(error) = renamed {
        // cap-primitives deliberately omits FILE_SHARE_DELETE for directories.
        assert_eq!(error.raw_os_error(), Some(32));
        assert_eq!(
            client
                .vfs_read_bytes(&agent, &file.id, 0, 64)
                .await
                .unwrap()
                .bytes,
            [0u8, 255, 1, 2, 3, 128]
        );
        client.vfs_close(&agent, &file.id).await.unwrap();
        client.vfs_close(&agent, &dir.id).await.unwrap();
        std::fs::rename(f.root.join("project"), f.root.join("original")).unwrap();
        std::fs::create_dir(f.root.join("project")).unwrap();
        std::fs::write(f.root.join("project/file.bin"), b"different binding").unwrap();
        assert!(client
            .vfs_read_bytes(&agent, &file.id, 0, 64)
            .await
            .is_err());
        assert!(client.vfs_list_workspace(&agent, &dir.id).await.is_err());
        let fresh = client
            .vfs_open_workspace(
                &agent,
                request(
                    "/workspace/project/file.bin",
                    WorkspaceKind::File,
                    &[WorkspaceRight::Read],
                ),
            )
            .await
            .unwrap();
        assert_eq!(
            client
                .vfs_read_bytes(&agent, &fresh.id, 0, 64)
                .await
                .unwrap()
                .bytes,
            b"different binding"
        );
        return;
    }
    std::fs::create_dir(f.root.join("project")).unwrap();
    std::fs::write(f.root.join("project/file.bin"), b"different binding").unwrap();
    assert!(client
        .vfs_read_bytes(&agent, &file.id, 0, 64)
        .await
        .is_err());
    assert!(client.vfs_list_workspace(&agent, &dir.id).await.is_err());
}

#[tokio::test]
async fn workspace_path_aliases_reject_ambient_paths_and_parent_traversal() {
    let f = Fixture::new().await;
    let agent = f.agent("paths").await;
    let mut client = f.client().await;
    for path in [
        "/etc/passwd",
        "/workspace/../outside",
        "/workspace//project",
        "/workspace/project/./file.bin",
        "/workspace/project\\file.bin",
        "/workspace/C:/secret",
        "/workspace/project/",
    ] {
        let error = client
            .vfs_open_workspace(
                &agent,
                request(path, WorkspaceKind::File, &[WorkspaceRight::Read]),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.wire_code(),
            Some(WireErrorCode::InvalidArgument),
            "{path}"
        );
    }
    let dir = directory(&mut client, &agent, &[WorkspaceRight::Read]).await;
    for path in ["../file.bin", "/file.bin", "x/../file.bin", "./file.bin"] {
        assert!(client
            .vfs_open_at(
                &agent,
                &dir.id,
                request(path, WorkspaceKind::File, &[WorkspaceRight::Read])
            )
            .await
            .is_err());
    }
    assert_eq!(
        client
            .vfs_workspace_mounts(&agent)
            .await
            .unwrap()
            .open_handles,
        1
    );
}

#[tokio::test]
async fn workspace_handles_preserve_agent_isolation_current_policy_and_binding_identity() {
    let f = Fixture::new().await;
    let agent = f.agent("owner").await;
    let other = f.agent("other").await;
    let mut client = f.client().await;
    let file = client
        .vfs_open_workspace(
            &agent,
            request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read, WorkspaceRight::Write],
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_read_bytes(&other, &file.id, 0, 64)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    f.kernel.syscall_gate.set_capabilities(
        uuid::Uuid::parse_str(&agent).unwrap(),
        kernel::agent_struct::CapabilitySet::none(),
    );
    assert_eq!(
        client
            .vfs_write_bytes(&agent, &file.id, b"denied")
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
    let binding = f.kernel.tool_registry.binding_catalog()["read_file_bytes"].clone();
    f.kernel.tool_registry.unregister("read_file_bytes");
    f.kernel.tool_registry.register(binding).unwrap();
    assert_eq!(
        client
            .vfs_read_bytes(&agent, &file.id, 0, 64)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
}

#[tokio::test]
async fn workspace_virtual_new_entry_writes_atomically_and_exhaustion_reclaims_slots() {
    let f = Fixture::new().await;
    let agent = f.agent("new-entry").await;
    let mut client = f.client().await;
    let mut open = request(
        "/workspace/project/new.bin",
        WorkspaceKind::File,
        &[WorkspaceRight::Write, WorkspaceRight::Read],
    );
    open.allow_missing = true;
    let file = client.vfs_open_workspace(&agent, open).await.unwrap();
    assert!(!f.root.join("project/new.bin").exists());
    client
        .vfs_write_bytes(&agent, &file.id, b"new contents")
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(f.root.join("project/new.bin")).unwrap(),
        b"new contents"
    );
    for _ in 1..kernel::vfs::MAX_HANDLES_PER_AGENT {
        client.vfs_open(&agent, "/tools/read_file").await.unwrap();
    }
    assert_eq!(
        client
            .vfs_open_workspace(
                &agent,
                request(
                    "/workspace/project/file.bin",
                    WorkspaceKind::File,
                    &[WorkspaceRight::Read]
                )
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::QuotaExceeded)
    );
    client.vfs_close(&agent, &file.id).await.unwrap();
    client
        .vfs_open_workspace(
            &agent,
            request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read],
            ),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn workspace_bounds_foreign_tenants_and_readonly_roles_fail_before_io() {
    let f = Fixture::new().await;
    let tenant = f.kernel.create_tenant("workspace-owner").await.unwrap();
    let foreign = f.kernel.create_tenant("workspace-foreign").await.unwrap();
    let user = f
        .kernel
        .register_user(
            &tenant,
            "user",
            "user@workspace.test",
            kernel::auth::Role::User,
        )
        .await
        .unwrap();
    let reader = f
        .kernel
        .register_user(
            &tenant,
            "reader",
            "reader@workspace.test",
            kernel::auth::Role::ReadOnly,
        )
        .await
        .unwrap();
    let owned = f
        .kernel
        .create_agent_for_tenant(&tenant, f.config("owned", 100000))
        .await
        .unwrap()
        .id
        .to_string();
    let other = f
        .kernel
        .create_agent_for_tenant(&foreign, f.config("foreign", 100000))
        .await
        .unwrap()
        .id
        .to_string();
    let mut client = f.client().await;
    client
        .authenticate(
            f.kernel
                .issue_api_key(&user, "workspace-user")
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_open_workspace(
                &other,
                request(
                    "/workspace/project/file.bin",
                    WorkspaceKind::File,
                    &[WorkspaceRight::Read]
                )
            )
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::AuthorizationDenied)
    );
    let file = client
        .vfs_open_workspace(
            &owned,
            request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read],
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .vfs_read_bytes(&owned, &file.id, 0, 0)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::InvalidArgument)
    );
    client
        .authenticate(
            f.kernel
                .issue_api_key(&reader, "workspace-reader")
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    client.vfs_workspace_mounts(&owned).await.unwrap();
    assert_eq!(
        client
            .vfs_read_bytes(&owned, &file.id, 0, 64)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::AuthorizationDenied)
    );
}

#[tokio::test]
async fn workspace_policy_and_namespace_revocation_apply_to_existing_handles() {
    let f = Fixture::new().await;
    let binding = f.kernel.tool_registry.binding_catalog()["read_file_bytes"].clone();
    f.kernel.tool_registry.unregister("read_file_bytes");
    f.kernel
        .register_group_tool("workspace-private", binding)
        .unwrap();
    let agent = f
        .kernel
        .create_agent_in_namespace(f.config("namespace", 100000), "workspace-private")
        .await
        .unwrap()
        .id;
    let mut client = f.client().await;
    let file = client
        .vfs_open_workspace(
            agent.to_string(),
            request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read],
            ),
        )
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
            .vfs_read_bytes(agent.to_string(), &file.id, 0, 64)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::PermissionDenied)
    );
    f.kernel.syscall_gate.set_mac_enforcing(false).await;
    f.kernel
        .syscall_gate
        .set_agent_namespaces(agent, Vec::new());
    assert_eq!(
        client
            .vfs_read_bytes(agent.to_string(), &file.id, 0, 64)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
}

#[tokio::test]
async fn workspace_drain_and_exact_destination_fences_remain_authoritative() {
    let f = Fixture::new().await;
    let agent = f.agent("fenced").await;
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
            "workspace fence regression",
        )
        .await
        .unwrap();
    assert!(client
        .vfs_open_workspace(
            &agent,
            request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read]
            )
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
    let file = match client
        .call(wrap(Syscall::VfsOpenWorkspace {
            agent_id: agent.clone(),
            request: request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read],
            ),
        }))
        .await
        .unwrap()
    {
        kernel::syscall_server::SyscallReply::WorkspaceOpened { handle } => handle,
        other => panic!("unexpected workspace open: {other:?}"),
    };
    assert!(client
        .vfs_read_bytes(&agent, &file.id, 0, 64)
        .await
        .unwrap_err()
        .kernel_message()
        .unwrap()
        .contains("fence"));
    assert!(matches!(
        client
            .call(wrap(Syscall::VfsReadWorkspace {
                agent_id: agent.clone(),
                handle: file.id.clone(),
                offset: 0,
                max_bytes: 64
            }))
            .await
            .unwrap(),
        kernel::syscall_server::SyscallReply::WorkspaceRead { .. }
    ));
    let control = f.kernel.cluster_control.status().unwrap();
    client
        .set_node_availability(
            agent_sdk::NodeAvailability::Draining,
            control.generation,
            "workspace drain regression",
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .call(wrap(Syscall::VfsReadWorkspace {
                agent_id: agent.clone(),
                handle: file.id.clone(),
                offset: 0,
                max_bytes: 64
            }))
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::Unavailable)
    );
    client
        .call(wrap(Syscall::VfsClose {
            agent_id: agent.clone(),
            handle: file.id,
        }))
        .await
        .unwrap();
}

#[tokio::test]
async fn workspace_close_and_stop_races_leave_no_live_handles() {
    let f = Fixture::new().await;
    let agent = f.agent("close-race").await;
    let mut reading = f.client().await;
    let mut closing = f.client().await;
    for _ in 0..16 {
        let file = closing
            .vfs_open_workspace(
                &agent,
                request(
                    "/workspace/project/file.bin",
                    WorkspaceKind::File,
                    &[WorkspaceRight::Read],
                ),
            )
            .await
            .unwrap();
        let (read, close) = tokio::join!(
            reading.vfs_read_bytes(&agent, &file.id, 0, 64),
            closing.vfs_close(&agent, &file.id)
        );
        close.unwrap();
        match read {
            Ok(bytes) => assert_eq!(bytes.bytes, [0u8, 255, 1, 2, 3, 128]),
            Err(error) => assert_eq!(error.wire_code(), Some(WireErrorCode::NotFound)),
        }
        assert_eq!(
            closing
                .vfs_workspace_mounts(&agent)
                .await
                .unwrap()
                .open_handles,
            0
        );
    }
    let opening = f.client().await;
    let mut opening = opening;
    let (open, stopped) = tokio::join!(
        opening.vfs_open_workspace(
            &agent,
            request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read]
            )
        ),
        closing.stop_agent(&agent)
    );
    stopped.unwrap();
    if let Ok(handle) = open {
        assert_eq!(
            reading
                .vfs_read_bytes(&agent, handle.id, 0, 64)
                .await
                .unwrap_err()
                .wire_code(),
            Some(WireErrorCode::NotFound)
        );
    }
    assert_eq!(
        f.kernel
            .vfs_workspace_mounts(uuid::Uuid::parse_str(&agent).unwrap())
            .unwrap_err()
            .to_string(),
        "VFS object not found"
    );
}

#[tokio::test]
async fn workspace_wrong_kind_and_malformed_transfers_never_mutate_files() {
    let f = Fixture::new().await;
    let agent = f.agent("malformed").await;
    let mut client = f.client().await;
    let dir = directory(
        &mut client,
        &agent,
        &[
            WorkspaceRight::Read,
            WorkspaceRight::Write,
            WorkspaceRight::List,
        ],
    )
    .await;
    assert!(client.vfs_read_bytes(&agent, &dir.id, 0, 64).await.is_err());
    let file = client
        .vfs_open_at(
            &agent,
            &dir.id,
            request(
                "file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read, WorkspaceRight::Write],
            ),
        )
        .await
        .unwrap();
    assert!(client
        .vfs_invoke(&agent, &file.id, serde_json::json!({}))
        .await
        .is_err());
    assert!(client
        .vfs_write_workspace(&agent, &file.id, "not-base64")
        .await
        .is_err());
    assert_eq!(
        std::fs::read(f.root.join("project/file.bin")).unwrap(),
        [0u8, 255, 1, 2, 3, 128]
    );
    assert_eq!(
        client
            .vfs_read_bytes(&agent, &file.id, 0, 2_000_000)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::InvalidArgument)
    );
}

#[tokio::test]
async fn workspace_sandbox_replacement_never_redirects_an_existing_descriptor() {
    use kernel::sandbox::SandboxManager;
    let f = Fixture::new().await;
    let agent = f.agent("sandbox-generation").await;
    let id = uuid::Uuid::parse_str(&agent).unwrap();
    let mut client = f.client().await;
    let file = client
        .vfs_open_workspace(
            &agent,
            request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read],
            ),
        )
        .await
        .unwrap();
    let old = f.kernel.sandbox_manager.get_sandbox_for_agent(id).unwrap();
    f.kernel.sandbox_manager.destroy_sandbox(old).unwrap();
    let new_root = f.root.join("replacement");
    std::fs::create_dir_all(new_root.join("project")).unwrap();
    std::fs::write(new_root.join("project/file.bin"), b"different sandbox").unwrap();
    let mut config = f.config("replacement", 100000).sandbox_config.unwrap();
    config.workspace_dir = new_root;
    f.kernel
        .sandbox_manager
        .create_sandbox(id, &config)
        .unwrap();
    assert_eq!(
        client
            .vfs_read_bytes(&agent, &file.id, 0, 64)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
}

#[tokio::test]
async fn workspace_handles_are_not_resurrected_after_durable_agent_restart() {
    let f = Fixture::new().await;
    let database = f.root.join("restart.db");
    let kernel = Arc::new(AgentKernelImpl::with_db_path(&database).unwrap());
    let agent = kernel
        .create_agent_full(f.config("restart", 16 * 1024 * 1024))
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
    let file = client
        .vfs_open_workspace(
            &agent,
            request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read],
            ),
        )
        .await
        .unwrap();
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
            .vfs_read_bytes(&agent, file.id, 0, 64)
            .await
            .unwrap_err()
            .wire_code(),
        Some(WireErrorCode::NotFound)
    );
    client.close().await.unwrap();
    task.abort();
    let _ = task.await;
}

#[cfg(unix)]
#[tokio::test]
async fn workspace_symlinks_never_escape_or_redirect_a_capability() {
    let f = Fixture::new().await;
    let agent = f.agent("symlinks").await;
    let outside = f.root.with_extension("outside");
    std::fs::write(&outside, b"must not be read or overwritten").unwrap();
    std::os::unix::fs::symlink(&outside, f.root.join("project/link")).unwrap();
    std::os::unix::fs::symlink(f.root.join("project"), f.root.join("alias")).unwrap();
    let mut client = f.client().await;
    assert!(client
        .vfs_open_workspace(
            &agent,
            request(
                "/workspace/project/link",
                WorkspaceKind::File,
                &[WorkspaceRight::Read]
            )
        )
        .await
        .is_err());
    assert!(client
        .vfs_open_workspace(
            &agent,
            request(
                "/workspace/alias/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read]
            )
        )
        .await
        .is_err());
    let file = client
        .vfs_open_workspace(
            &agent,
            request(
                "/workspace/project/file.bin",
                WorkspaceKind::File,
                &[WorkspaceRight::Read, WorkspaceRight::Write],
            ),
        )
        .await
        .unwrap();
    std::fs::remove_file(f.root.join("project/file.bin")).unwrap();
    std::os::unix::fs::symlink(&outside, f.root.join("project/file.bin")).unwrap();
    assert!(client
        .vfs_read_bytes(&agent, &file.id, 0, 64)
        .await
        .is_err());
    assert!(client
        .vfs_write_bytes(&agent, &file.id, b"must not write")
        .await
        .is_err());
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"must not be read or overwritten"
    );
    std::fs::remove_file(outside).unwrap();
}
