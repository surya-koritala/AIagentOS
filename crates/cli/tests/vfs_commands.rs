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
        command(addr, vec!["vfs-mounts".into(), agent]).await["open_handles"],
        0
    );
    task.abort();
    let _ = task.await;
    std::fs::remove_dir_all(root).unwrap();
}
