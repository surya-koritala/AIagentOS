use std::process::Command;
use std::sync::Arc;

use kernel::agent::AgentKernel;

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

    let status_output = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--addr")
        .arg(addr.to_string())
        .arg("backup-status")
        .output()
        .expect("run backup-status");
    assert!(
        status_output.status.success(),
        "backup-status failed: {}",
        String::from_utf8_lossy(&status_output.stderr)
    );
    let status: kernel::storage::BackupMaintenanceStatus =
        serde_json::from_slice(&status_output.stdout).expect("backup status JSON");
    assert!(!status.enabled);
    assert_eq!(status.attempts_total, 0);

    let inventory_output = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--addr")
        .arg(addr.to_string())
        .arg("data-inventory")
        .output()
        .expect("run data-inventory");
    assert!(
        inventory_output.status.success(),
        "data-inventory failed: {}",
        String::from_utf8_lossy(&inventory_output.stderr)
    );
    let inventory: kernel::data_inventory::StorageDataInventory =
        serde_json::from_slice(&inventory_output.stdout).expect("data inventory JSON");
    assert_eq!(
        inventory.schema_version,
        kernel::data_inventory::STORAGE_DATA_INVENTORY_SCHEMA_VERSION
    );
    assert!(inventory
        .entries
        .iter()
        .any(|entry| entry.id == "file/published-database-backups"));

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
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    kernel
        .context_manager
        .create_backup(&backup_root, "operator_002")
        .expect("second backup");

    let unconfirmed = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--addr")
        .arg(addr.to_string())
        .arg("backup-retention")
        .arg(&backup_root)
        .arg("1")
        .arg("1")
        .output()
        .expect("run unconfirmed backup-retention");
    assert_eq!(unconfirmed.status.code(), Some(2));
    assert!(backup_root.join("operator_001").exists());

    let preview = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--addr")
        .arg(addr.to_string())
        .arg("backup-retention")
        .arg(&backup_root)
        .arg("1")
        .arg("1")
        .arg("--dry-run")
        .output()
        .expect("run backup-retention dry-run");
    assert!(
        preview.status.success(),
        "backup-retention dry-run failed: {}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: kernel::storage::BackupRetentionReport =
        serde_json::from_slice(&preview.stdout).expect("retention preview JSON");
    assert!(preview.dry_run);
    assert_eq!(preview.eligible.len(), 1);
    assert!(backup_root.join("operator_001").exists());

    let applied = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--addr")
        .arg(addr.to_string())
        .arg("backup-retention")
        .arg(&backup_root)
        .arg("1")
        .arg("1")
        .arg("--confirm")
        .output()
        .expect("run confirmed backup-retention");
    assert!(
        applied.status.success(),
        "backup-retention failed: {}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied: kernel::storage::BackupRetentionReport =
        serde_json::from_slice(&applied.stdout).expect("retention report JSON");
    assert_eq!(applied.deleted.len(), 1);
    assert!(!backup_root.join("operator_001").exists());
    assert!(backup_root.join("operator_002").exists());

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn erasure_commands_require_confirmation_and_use_live_operator_api() {
    let kernel = Arc::new(kernel::AgentKernelImpl::new().expect("kernel"));
    let agent = kernel
        .create_agent_full(kernel::AgentConfig {
            name: "cli-erasure".into(),
            task: "private task".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: kernel::Priority::default(),
            sandbox_config: None,
        })
        .await
        .expect("create agent");
    let server = kernel::syscall_server::SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("server address");
    let server_task = tokio::spawn(server.serve());

    let agent_id = agent.id;
    let unconfirmed = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_agentctl"))
            .arg("--addr")
            .arg(addr.to_string())
            .arg("erase-agent")
            .arg(agent_id.to_string())
            .output()
            .expect("run unconfirmed erase-agent")
    })
    .await
    .expect("join unconfirmed erase-agent");
    assert_eq!(unconfirmed.status.code(), Some(2));
    assert!(kernel
        .context_manager
        .agent_tenant(agent.id)
        .unwrap()
        .is_some());

    let confirmed = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_agentctl"))
            .arg("--addr")
            .arg(addr.to_string())
            .arg("erase-agent")
            .arg(agent.id.to_string())
            .arg("--confirm")
            .output()
            .expect("run confirmed erase-agent")
    })
    .await
    .expect("join confirmed erase-agent");
    assert!(
        confirmed.status.success(),
        "erase-agent failed: {}",
        String::from_utf8_lossy(&confirmed.stderr)
    );
    let receipt: Option<kernel::context::DeletionReceipt> =
        serde_json::from_slice(&confirmed.stdout).expect("deletion receipt JSON");
    assert_eq!(
        receipt.expect("agent existed").subject_kind,
        kernel::context::DeletionSubjectKind::Agent
    );
    assert!(kernel
        .context_manager
        .agent_tenant(agent_id)
        .unwrap()
        .is_none());
    assert!(kernel.agent_manager.get_agent_state(agent_id).is_none());

    let user_tenant = kernel.create_tenant("cli-user-erasure").await.unwrap();
    let user_id = kernel
        .register_user(
            &user_tenant,
            "cli-user",
            "cli-user@erasure.test",
            kernel::auth::Role::User,
        )
        .await
        .unwrap();
    let user_output = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--addr")
        .arg(addr.to_string())
        .arg("erase-user")
        .arg(&user_id)
        .arg("--confirm")
        .output()
        .expect("run erase-user");
    assert!(
        user_output.status.success(),
        "erase-user failed: {}",
        String::from_utf8_lossy(&user_output.stderr)
    );
    let user_receipt: Option<kernel::context::DeletionReceipt> =
        serde_json::from_slice(&user_output.stdout).expect("user deletion receipt JSON");
    assert_eq!(
        user_receipt.expect("user existed").subject_kind,
        kernel::context::DeletionSubjectKind::User
    );
    assert!(kernel.auth.read().await.get_user(&user_id).is_none());

    let tenant_id = kernel.create_tenant("cli-tenant-erasure").await.unwrap();
    let tenant_agent = kernel
        .create_agent_for_tenant(
            &tenant_id,
            kernel::AgentConfig {
                name: "cli-tenant-agent".into(),
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
    let tenant_output = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--addr")
        .arg(addr.to_string())
        .arg("erase-tenant")
        .arg(&tenant_id)
        .arg("--confirm")
        .output()
        .expect("run erase-tenant");
    assert!(
        tenant_output.status.success(),
        "erase-tenant failed: {}",
        String::from_utf8_lossy(&tenant_output.stderr)
    );
    let tenant_receipt: Option<kernel::context::DeletionReceipt> =
        serde_json::from_slice(&tenant_output.stdout).expect("tenant deletion receipt JSON");
    assert_eq!(
        tenant_receipt.expect("tenant existed").subject_kind,
        kernel::context::DeletionSubjectKind::Tenant
    );
    assert!(kernel.auth.read().await.get_tenant(&tenant_id).is_none());
    assert!(kernel.agent_manager.get_agent_state(tenant_agent).is_none());

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

#[test]
fn signed_backup_cli_requires_external_trust_for_verified_restore() {
    let root = TestRoot::new();
    let source = root.0.join("source.db");
    let backup_root = root.0.join("backups");
    let backup_dir = backup_root.join("signed_001");
    let destination = root.0.join("fresh-host/agent_os.db");
    let private_key = root.0.join("backup-signing.pk8");
    let public_trust = root.0.join("backup-trust.json");

    let keygen = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-key-generate")
        .arg("cli-release-2026.1")
        .arg(&private_key)
        .arg(&public_trust)
        .output()
        .expect("run backup-key-generate");
    assert!(
        keygen.status.success(),
        "backup-key-generate failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    let trust: kernel::storage::BackupTrustRoot =
        serde_json::from_slice(&keygen.stdout).expect("trust root JSON");
    assert_eq!(trust.key_id, "cli-release-2026.1");

    {
        let kernel = kernel::AgentKernelImpl::with_db_path(&source).expect("source kernel");
        let signer = kernel::storage::load_backup_signing_key(&private_key, "cli-release-2026.1")
            .expect("load generated signing key");
        kernel
            .context_manager
            .create_signed_backup(&backup_root, "signed_001", &signer)
            .expect("signed source backup");
    }

    let verify = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-verify")
        .arg(&backup_dir)
        .arg("--require-signature")
        .arg(&public_trust)
        .output()
        .expect("run signature-required backup-verify");
    assert!(
        verify.status.success(),
        "trusted backup-verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let manifest: kernel::storage::BackupManifest =
        serde_json::from_slice(&verify.stdout).expect("signed manifest JSON");
    assert_eq!(
        manifest.authenticity.as_ref().expect("authenticity").key_id,
        trust.key_id
    );

    let unsigned_root = root.0.join("unsigned-backups");
    let unsigned_dir = unsigned_root.join("unsigned_001");
    {
        let kernel = kernel::AgentKernelImpl::with_db_path(&source).expect("source kernel");
        kernel
            .context_manager
            .create_backup(&unsigned_root, "unsigned_001")
            .expect("unsigned source backup");
    }
    let unsigned_verify = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-verify")
        .arg(&unsigned_dir)
        .arg("--require-signature")
        .arg(&public_trust)
        .output()
        .expect("verify unsigned backup with signature required");
    assert!(!unsigned_verify.status.success());
    assert!(
        String::from_utf8_lossy(&unsigned_verify.stderr).contains("backup is unsigned"),
        "unexpected unsigned verification error: {}",
        String::from_utf8_lossy(&unsigned_verify.stderr)
    );

    let restore = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-restore")
        .arg(&backup_dir)
        .arg(&destination)
        .arg("--require-signature")
        .arg(&public_trust)
        .arg("--confirm-offline")
        .output()
        .expect("run trusted backup-restore");
    assert!(
        restore.status.success(),
        "trusted backup-restore failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );
    let report: kernel::storage::RestoreReport =
        serde_json::from_slice(&restore.stdout).expect("restore report JSON");
    assert_eq!(report.manifest, manifest);
    kernel::AgentKernelImpl::with_db_path(&destination).expect("boot trusted restored database");
}

#[test]
fn storage_encryption_cli_migrates_backs_up_restores_and_rotates_offline() {
    let root = TestRoot::new();
    let source = root.0.join("source.db");
    let key_one = root.0.join("storage-generation-1.json");
    let key_two = root.0.join("storage-generation-2.json");
    let backup_signing_key = root.0.join("backup-signing.pk8");
    let backup_trust = root.0.join("backup-trust.json");
    let backup_root = root.0.join("encrypted-backups");
    let backup_dir = backup_root.join("encrypted_001");
    let restored = root.0.join("fresh-host/agent_os.db");

    drop(kernel::AgentKernelImpl::with_db_path(&source).expect("plaintext source"));
    for (key_id, path) in [
        ("storage-generation-1", &key_one),
        ("storage-generation-2", &key_two),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agentctl"))
            .arg("storage-key-generate")
            .arg(key_id)
            .arg(path)
            .output()
            .expect("run storage-key-generate");
        assert!(
            output.status.success(),
            "storage-key-generate failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let signing_keygen = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-key-generate")
        .arg("encrypted-backup-signer-1")
        .arg(&backup_signing_key)
        .arg(&backup_trust)
        .output()
        .expect("run backup-key-generate");
    assert!(
        signing_keygen.status.success(),
        "backup-key-generate failed: {}",
        String::from_utf8_lossy(&signing_keygen.stderr)
    );

    let unconfirmed = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("storage-encrypt")
        .arg(&source)
        .arg(&key_one)
        .output()
        .expect("run unconfirmed storage-encrypt");
    assert_eq!(unconfirmed.status.code(), Some(2));
    kernel::AgentKernelImpl::with_db_path(&source).expect("unconfirmed command did not mutate");

    let migration = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("storage-encrypt")
        .arg(&source)
        .arg(&key_one)
        .arg("--confirm-offline")
        .output()
        .expect("run storage-encrypt");
    assert!(
        migration.status.success(),
        "storage-encrypt failed: {}",
        String::from_utf8_lossy(&migration.stderr)
    );
    let migration_report: kernel::storage_encryption::StorageEncryptionChangeReport =
        serde_json::from_slice(&migration.stdout).expect("migration report JSON");
    assert_eq!(migration_report.operation, "encrypt");
    assert_eq!(migration_report.current_key_id, "storage-generation-1");

    {
        let key = kernel::storage_encryption::load_storage_encryption_key(&key_one)
            .expect("load first key");
        let manager =
            kernel::context::SqliteContextManager::new_encrypted(&source, key).expect("encrypted");
        let signer = kernel::storage::load_backup_signing_key(
            &backup_signing_key,
            "encrypted-backup-signer-1",
        )
        .expect("load signer");
        manager
            .create_signed_backup(&backup_root, "encrypted_001", &signer)
            .expect("encrypted backup");
    }
    let unkeyed_verify = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-verify")
        .arg(&backup_dir)
        .output()
        .expect("run unkeyed encrypted verification");
    assert!(!unkeyed_verify.status.success());
    assert!(
        String::from_utf8_lossy(&unkeyed_verify.stderr).contains("supply that independently"),
        "{}",
        String::from_utf8_lossy(&unkeyed_verify.stderr)
    );
    let keyed_verify = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-verify")
        .arg(&backup_dir)
        .arg("--storage-key")
        .arg(&key_one)
        .output()
        .expect("run keyed backup verification");
    assert!(
        keyed_verify.status.success(),
        "keyed verification failed: {}",
        String::from_utf8_lossy(&keyed_verify.stderr)
    );
    let fully_verified = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-verify")
        .arg(&backup_dir)
        .arg("--require-signature")
        .arg(&backup_trust)
        .arg("--storage-key")
        .arg(&key_one)
        .output()
        .expect("run encrypted and signed backup verification");
    assert!(
        fully_verified.status.success(),
        "encrypted signed verification failed: {}",
        String::from_utf8_lossy(&fully_verified.stderr)
    );

    let restore = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("backup-restore")
        .arg(&backup_dir)
        .arg(&restored)
        .arg("--storage-key")
        .arg(&key_one)
        .arg("--require-signature")
        .arg(&backup_trust)
        .arg("--confirm-offline")
        .output()
        .expect("run encrypted restore");
    assert!(
        restore.status.success(),
        "encrypted restore failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );
    let restored_key =
        kernel::storage_encryption::load_storage_encryption_key(&key_one).expect("restore key");
    drop(
        kernel::context::SqliteContextManager::new_encrypted(&restored, restored_key)
            .expect("boot fresh-host encrypted restore"),
    );

    let rotation = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("storage-key-rotate")
        .arg(&source)
        .arg(&key_one)
        .arg(&key_two)
        .arg("--confirm-offline")
        .output()
        .expect("run storage-key-rotate");
    assert!(
        rotation.status.success(),
        "storage-key-rotate failed: {}",
        String::from_utf8_lossy(&rotation.stderr)
    );
    let rotation_report: kernel::storage_encryption::StorageEncryptionChangeReport =
        serde_json::from_slice(&rotation.stdout).expect("rotation report JSON");
    assert_eq!(
        rotation_report.previous_key_id.as_deref(),
        Some("storage-generation-1")
    );
    assert_eq!(rotation_report.current_key_id, "storage-generation-2");
    assert!(kernel::context::SqliteContextManager::new_encrypted(
        &source,
        kernel::storage_encryption::load_storage_encryption_key(&key_one).unwrap()
    )
    .is_err());
    kernel::context::SqliteContextManager::new_encrypted(
        &source,
        kernel::storage_encryption::load_storage_encryption_key(&key_two).unwrap(),
    )
    .expect("rotated database accepts new key");
}
