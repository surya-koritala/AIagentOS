//! Actual local maintenance and restart: no path override or remote authority.

use std::path::{Path, PathBuf};
use std::process::Command;

use kernel::agent::AgentKernel;
use kernel::{AgentConfig, AgentKernelImpl, Priority, SandboxConfig};
use serde_json::Value;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "workspace-maintenance-{}",
            kernel::AgentId::new_v4()
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn command(root: &Path, args: &[&str]) -> std::process::Output {
    let temporary = root.join("process-temp");
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentctl"));
    command.args(args).env("RUST_LOG", "error");
    for name in ["TMPDIR", "TMP", "TEMP"] {
        command.env(name, &temporary);
    }
    command.output().unwrap()
}
fn success(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn agent(name: &str) -> AgentConfig {
    AgentConfig {
        name: name.into(),
        task: "local workspace ownership fixture".into(),
        llm_provider: "offline-ci-fixture".into(),
        permission_profile: "full-access".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }
}

#[tokio::test]
async fn local_operator_lists_and_retains_one_record_without_losing_legacy_data_or_valid_peers() {
    let root = Fixture::new();
    let temporary = root.0.join("process-temp");
    let legacy_root = temporary.join("aiagentos-workspaces");
    std::fs::create_dir_all(&legacy_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&legacy_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = kernel::config::Config {
        data_dir: root.0.join("data"),
        ..Default::default()
    };
    let config_path = root.0.join("config.toml");
    config.save_to(&config_path).unwrap();
    let legacy;
    let peer;
    let malformed;
    let stopped;
    let malformed_workspace;
    let invalid_lifecycle;
    let invalid_lifecycle_workspace;
    let workspace;
    {
        let kernel = AgentKernelImpl::from_config(&config).unwrap();
        legacy = kernel
            .create_agent_full(agent("legacy unresolved"))
            .await
            .unwrap()
            .id;
        peer = kernel
            .create_agent_full(agent("valid owned peer"))
            .await
            .unwrap()
            .id;
        malformed = kernel
            .create_agent_full(agent("malformed preserved"))
            .await
            .unwrap()
            .id;
        stopped = kernel
            .create_agent_full(agent("normally stopped"))
            .await
            .unwrap()
            .id;
        invalid_lifecycle = kernel
            .create_agent_full(agent("invalid lifecycle preserved"))
            .await
            .unwrap()
            .id;
        kernel.stop_agent(stopped).await.unwrap();
        let mut broken = kernel
            .context_manager
            .load_all_agents()
            .unwrap()
            .into_iter()
            .find(|record| record.id == malformed)
            .unwrap();
        malformed_workspace =
            serde_json::from_str::<SandboxConfig>(broken.sandbox_config_json.as_deref().unwrap())
                .unwrap()
                .workspace_dir;
        std::fs::write(
            malformed_workspace.join("sentinel.txt"),
            "malformed record bytes remain intact",
        )
        .unwrap();
        broken.sandbox_config_json = Some("{original-malformed-sandbox".into());
        kernel.context_manager.save_agent(&broken).unwrap();
        let mut invalid = kernel
            .context_manager
            .load_all_agents()
            .unwrap()
            .into_iter()
            .find(|record| record.id == invalid_lifecycle)
            .unwrap();
        invalid_lifecycle_workspace =
            serde_json::from_str::<SandboxConfig>(invalid.sandbox_config_json.as_deref().unwrap())
                .unwrap()
                .workspace_dir;
        std::fs::write(
            invalid_lifecycle_workspace.join("sentinel.txt"),
            "invalid lifecycle bytes remain intact",
        )
        .unwrap();
        invalid.status = "original-invalid-lifecycle".into();
        kernel.context_manager.save_agent(&invalid).unwrap();
        let record = kernel
            .context_manager
            .load_all_agents()
            .unwrap()
            .into_iter()
            .find(|record| record.id == legacy)
            .unwrap();
        let mut sandbox: SandboxConfig =
            serde_json::from_str(record.sandbox_config_json.as_deref().unwrap()).unwrap();
        workspace = legacy_root.join(kernel::AgentId::new_v4().to_string());
        std::fs::create_dir(&workspace).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(workspace.join(".aiagentos-managed"), []).unwrap();
        std::fs::write(workspace.join("sentinel.txt"), "preserved legacy bytes").unwrap();
        sandbox.workspace_dir = std::fs::canonicalize(&workspace).unwrap();
        let mut record = record;
        record.sandbox_config_json = Some(serde_json::to_string(&sandbox).unwrap());
        kernel.context_manager.save_agent(&record).unwrap();
    }
    let config_arg = config_path.to_str().unwrap();
    let before = success(command(
        &root.0,
        &["workspace-ownership", config_arg, "list"],
    ));
    assert!(before["unresolved"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["agent_id"] == legacy.to_string()));
    assert!(
        before["admitted_agents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| *id == peer.to_string()),
        "one unresolved record blocked another verified agent"
    );
    assert!(!before["admitted_agents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| *id == legacy.to_string()));
    assert!(!before["admitted_agents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| *id == malformed.to_string()));
    assert_eq!(
        std::fs::read_to_string(malformed_workspace.join("sentinel.txt")).unwrap(),
        "malformed record bytes remain intact"
    );
    assert!(
        !before["unresolved"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["agent_id"] == stopped.to_string()),
        "an intentionally retired terminal agent became a false ownership alarm"
    );
    assert!(before["unresolved"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["agent_id"] == malformed.to_string()
            && entry["reason"].as_str().unwrap().contains("malformed")));
    assert!(!before["admitted_agents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| *id == invalid_lifecycle.to_string()));
    assert!(before["unresolved"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["agent_id"] == invalid_lifecycle.to_string()
            && entry["reason"].as_str().unwrap().contains("lifecycle")));
    assert_eq!(
        std::fs::read_to_string(invalid_lifecycle_workspace.join("sentinel.txt")).unwrap(),
        "invalid lifecycle bytes remain intact"
    );
    let legacy_id = legacy.to_string();
    let denied = command(
        &root.0,
        &["workspace-ownership", config_arg, "retain", &legacy_id],
    );
    assert!(
        !denied.status.success(),
        "retention must require explicit local confirmation"
    );
    let retained = success(command(
        &root.0,
        &[
            "workspace-ownership",
            config_arg,
            "retain",
            &legacy_id,
            "--confirm-offline",
        ],
    ));
    assert_eq!(retained["automatic_deletion"], false);
    assert_eq!(
        std::fs::read_to_string(workspace.join("sentinel.txt")).unwrap(),
        "preserved legacy bytes"
    );
    let restarted = success(command(
        &root.0,
        &["workspace-ownership", config_arg, "list"],
    ));
    assert_eq!(restarted["unresolved"].as_array().unwrap().len(), 2);
    assert!(restarted["unresolved"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["agent_id"] == malformed.to_string()));
    assert!(restarted["unresolved"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["agent_id"] == invalid_lifecycle.to_string()));
    assert!(restarted["admitted_agents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| *id == legacy.to_string()));
    assert!(restarted["admitted_agents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| *id == peer.to_string()));
    assert_eq!(
        std::fs::read_to_string(workspace.join("sentinel.txt")).unwrap(),
        "preserved legacy bytes"
    );
    assert_eq!(
        std::fs::metadata(workspace.join(".aiagentos-managed"))
            .unwrap()
            .len(),
        0
    );
    {
        let reopened = AgentKernelImpl::from_config(&config).unwrap();
        let record = reopened
            .context_manager
            .load_all_agents()
            .unwrap()
            .into_iter()
            .find(|record| record.id == malformed)
            .unwrap();
        assert_eq!(
            record.sandbox_config_json.as_deref(),
            Some("{original-malformed-sandbox")
        );
        assert_eq!(
            serde_json::from_str::<kernel::AgentState>(&record.status).unwrap(),
            kernel::AgentState::Running
        );
        assert_eq!(
            std::fs::read_to_string(malformed_workspace.join("sentinel.txt")).unwrap(),
            "malformed record bytes remain intact"
        );
        let invalid = reopened
            .context_manager
            .load_all_agents()
            .unwrap()
            .into_iter()
            .find(|record| record.id == invalid_lifecycle)
            .unwrap();
        assert_eq!(invalid.status, "original-invalid-lifecycle");
        assert!(reopened
            .agent_manager
            .get_agent_state(invalid_lifecycle)
            .is_none());
        assert_eq!(
            std::fs::read_to_string(invalid_lifecycle_workspace.join("sentinel.txt")).unwrap(),
            "invalid lifecycle bytes remain intact"
        );
    }
    let override_attempt = command(
        &root.0,
        &[
            "workspace-ownership",
            config_arg,
            "retain",
            &legacy_id,
            "--confirm-offline",
            workspace.to_str().unwrap(),
        ],
    );
    assert!(
        !override_attempt.status.success(),
        "raw target overrides must never become ownership grants"
    );
}
