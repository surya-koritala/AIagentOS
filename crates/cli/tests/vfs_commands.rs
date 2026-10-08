use kernel::syscall_server::SyscallServer;
use kernel::{AgentConfig, AgentKernelImpl, IsolationLevel, Priority, SandboxConfig};
use serde_json::{json, Value};
use std::{process::Command, sync::Arc};

async fn command(addr: std::net::SocketAddr, args: Vec<String>) -> Value {
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_agentctl"))
            .arg("--addr")
            .arg(addr.to_string())
            .args(args)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test]
async fn agentctl_vfs_open_invoke_and_close_use_the_public_server() {
    let root = std::env::temp_dir().join(format!("agentos-cli-vfs-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("proof.txt"), "CLI governed proof").unwrap();
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let agent = kernel
        .create_agent_full(AgentConfig {
            name: "cli-vfs".into(),
            task: "VFS CLI proof".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: Some(SandboxConfig {
                workspace_dir: root.clone(),
                isolation_level: IsolationLevel::Filesystem,
                allowed_network_hosts: Some(Vec::new()),
                max_disk_usage_bytes: Some(1024 * 1024),
                max_memory_bytes: None,
                container_image: None,
            }),
        })
        .await
        .unwrap()
        .id
        .to_string();
    let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mounts = command(addr, vec!["vfs-mounts".into(), agent.clone()]).await;
    assert_eq!(mounts["mount"], "/tools");
    let handle = command(
        addr,
        vec!["vfs-open".into(), agent.clone(), "/tools/read_file".into()],
    )
    .await;
    let id = handle["id"].as_str().unwrap().to_string();
    let result = command(
        addr,
        vec![
            "vfs-invoke".into(),
            agent.clone(),
            id.clone(),
            json!({"path":"proof.txt"}).to_string(),
        ],
    )
    .await;
    assert_eq!(result["content"], "CLI governed proof");
    let closed = command(addr, vec!["vfs-close".into(), agent.clone(), id]).await;
    assert_eq!(closed, json!({"closed":true}));
    assert_eq!(
        command(addr, vec!["vfs-mounts".into(), agent.clone()]).await["open_handles"],
        0
    );
    let view = command(addr, vec!["vfs-namespace-mounts".into(), agent.clone()]).await;
    let updated = command(
        addr,
        vec![
            "vfs-mount".into(),
            agent.clone(),
            view["table_id"].as_str().unwrap().into(),
            view["generation"].as_u64().unwrap().to_string(),
            "/commands".into(),
            "tools".into(),
        ],
    )
    .await;
    let entries = command(
        addr,
        vec![
            "vfs-mount-entries".into(),
            agent.clone(),
            "/commands".into(),
        ],
    )
    .await;
    assert!(entries["entries"]
        .as_array()
        .unwrap()
        .contains(&json!("/commands/read_file")));
    let mount = updated["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|mount| mount["path"] == "/commands")
        .unwrap();
    let removed = command(
        addr,
        vec![
            "vfs-unmount".into(),
            agent,
            updated["table_id"].as_str().unwrap().into(),
            updated["generation"].as_u64().unwrap().to_string(),
            "/commands".into(),
            mount["id"].as_str().unwrap().into(),
        ],
    )
    .await;
    assert_eq!(removed["mounts"].as_array().unwrap().len(), 2);
    task.abort();
    let _ = task.await;
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn agentctl_workspace_handles_drive_real_binary_io_and_rights() {
    let root = std::env::temp_dir().join(format!("agentos-cli-workspace-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(root.join("project")).unwrap();
    std::fs::write(root.join("project/file.bin"), b"old").unwrap();
    std::fs::write(root.join("source.bin"), [0u8, 255, 42]).unwrap();
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let agent = kernel
        .create_agent_full(AgentConfig {
            name: "cli-workspace".into(),
            task: "workspace CLI proof".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: Some(SandboxConfig {
                workspace_dir: root.clone(),
                isolation_level: IsolationLevel::Filesystem,
                allowed_network_hosts: Some(Vec::new()),
                max_disk_usage_bytes: Some(100000),
                max_memory_bytes: None,
                container_image: None,
            }),
        })
        .await
        .unwrap()
        .id
        .to_string();
    let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    assert_eq!(
        command(addr, vec!["vfs-workspace-mounts".into(), agent.clone()]).await["mount"],
        "/workspace"
    );
    let parent = command(
        addr,
        vec![
            "vfs-workspace-open".into(),
            agent.clone(),
            "/workspace/project".into(),
            "directory".into(),
            "read,write,list,stat".into(),
        ],
    )
    .await;
    let parent = parent["id"].as_str().unwrap().to_string();
    let file = command(
        addr,
        vec![
            "vfs-open-at".into(),
            agent.clone(),
            parent.clone(),
            "file.bin".into(),
            "file".into(),
            "read,write,stat".into(),
        ],
    )
    .await;
    let file = file["id"].as_str().unwrap().to_string();
    assert_eq!(
        command(
            addr,
            vec![
                "vfs-write".into(),
                agent.clone(),
                file.clone(),
                root.join("source.bin").to_string_lossy().into_owned()
            ]
        )
        .await["written_bytes"],
        3
    );
    assert_eq!(
        command(addr, vec!["vfs-read".into(), agent.clone(), file.clone()]).await["data_base64"],
        "AP8q"
    );
    assert_eq!(
        command(addr, vec!["vfs-stat".into(), agent.clone(), file.clone()]).await["size"],
        3
    );
    assert_eq!(
        command(addr, vec!["vfs-list".into(), agent.clone(), parent.clone()]).await["entries"],
        json!(["file.bin"])
    );
    let duplicate = command(
        addr,
        vec!["vfs-dup".into(), agent.clone(), file.clone(), "read".into()],
    )
    .await;
    assert_eq!(duplicate["rights"], json!(["read"]));
    assert_eq!(
        std::fs::read(root.join("project/file.bin")).unwrap(),
        [0u8, 255, 42]
    );
    for handle in [file, parent, duplicate["id"].as_str().unwrap().to_string()] {
        command(addr, vec!["vfs-close".into(), agent.clone(), handle]).await;
    }
    task.abort();
    let _ = task.await;
    std::fs::remove_dir_all(root).unwrap();
}
