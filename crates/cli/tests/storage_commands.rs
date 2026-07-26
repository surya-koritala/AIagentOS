use std::process::Command;
use std::sync::Arc;

struct TestRoot(std::path::PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("agentctl-storage-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_create_command_uses_the_live_system_operator_api() {
    let root = TestRoot::new();
    let database = root.0.join("agent_os.db");
    let backup_root = root.0.join("backups");
    let kernel = Arc::new(kernel::AgentKernelImpl::with_db_path(&database).expect("kernel"));
    let server = kernel::syscall_server::SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("server address");
    let server_task = tokio::spawn(server.serve());

    let command_backup_root = backup_root.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_agentctl"))
            .arg("--addr")
            .arg(addr.to_string())
            .arg("backup-create")
            .arg(command_backup_root)
            .arg("operator_001")
            .output()
            .expect("run backup-create")
    })
    .await
    .expect("join backup-create");
    assert!(
        output.status.success(),
        "backup-create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: kernel::storage::BackupManifest =
        serde_json::from_slice(&output.stdout).expect("manifest JSON");
    assert_eq!(
        kernel::storage::verify_backup(&backup_root.join("operator_001")).unwrap(),
        manifest
    );

    server_task.abort();
    let _ = server_task.await;
}

#[test]
fn verify_and_offline_restore_commands_complete_a_fresh_host_roundtrip() {
    let root = TestRoot::new();
    let source = root.0.join("source.db");
    let backup_root = root.0.join("backups");
    let backup_dir = backup_root.join("release_001");
    let destination = root.0.join("fresh-host/agent_os.db");

    {
        let kernel = kernel::AgentKernelImpl::with_db_path(&source).expect("source kernel");
        kernel
            .context_manager
            .create_backup(&backup_root, "release_001")
            .expect("source backup");

        let online_restore = Command::new(env!("CARGO_BIN_EXE_agentctl"))
            .arg("backup-restore")
            .arg(&backup_dir)
            .arg(&source)
            .arg("--confirm-offline")
            .output()
            .expect("run restore against live database");
        assert!(!online_restore.status.success());
        assert!(
            String::from_utf8_lossy(&online_restore.stderr).contains("already owned"),
            "unexpected live-owner error: {}",
            String::from_utf8_lossy(&online_restore.stderr)
        );
    }

    let verify = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-verify")
        .arg(&backup_dir)
        .output()
        .expect("run backup-verify");
    assert!(
        verify.status.success(),
        "backup-verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let manifest: kernel::storage::BackupManifest =
        serde_json::from_slice(&verify.stdout).expect("manifest JSON");
    assert_eq!(manifest.database_file, "agent_os.db");

    let unconfirmed = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-restore")
        .arg(&backup_dir)
        .arg(&destination)
        .output()
        .expect("run unconfirmed backup-restore");
    assert_eq!(unconfirmed.status.code(), Some(2));
    assert!(!destination.exists());

    let restore = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-restore")
        .arg(&backup_dir)
        .arg(&destination)
        .arg("--confirm-offline")
        .output()
        .expect("run backup-restore");
    assert!(
        restore.status.success(),
        "backup-restore failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );
    let report: kernel::storage::RestoreReport =
        serde_json::from_slice(&restore.stdout).expect("restore report JSON");
    assert!(!report.replaced_existing);
    assert_eq!(report.manifest, manifest);

    let restored =
        kernel::AgentKernelImpl::with_db_path(&destination).expect("boot restored database");
    let restored_manifest = restored
        .context_manager
        .create_backup(&root.0.join("restored-backups"), "proof")
        .expect("backup restored database");
    assert_eq!(restored_manifest.installation_id, manifest.installation_id);
}
