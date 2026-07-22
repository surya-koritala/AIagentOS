//! Regression coverage for the kernel-wide lifecycle coordinator (#112).

use std::time::Duration;

use kernel::permissions::{AccessDecision, PermissionSystem};
use kernel::resources::ResourceType;
use kernel::sandbox::SandboxManager;
use kernel::{AgentConfig, AgentKernelImpl, AgentState, Priority};

fn config(name: &str) -> AgentConfig {
    AgentConfig {
        name: name.to_string(),
        task: "lifecycle regression".to_string(),
        llm_provider: "stub".to_string(),
        permission_profile: "standard".to_string(),
        priority: Priority::default(),
        sandbox_config: None,
    }
}

#[tokio::test]
async fn stop_is_idempotent_and_purges_every_live_subsystem() {
    let kernel = AgentKernelImpl::new().expect("kernel");
    let handle = kernel
        .create_agent_full(config("cleanup"))
        .await
        .expect("create");
    let id = handle.id;
    let pid = kernel.syscall_gate.pid_of(id).expect("gate pid");
    let workspace = kernel
        .agent_manager
        .get_agent_config(id)
        .and_then(|config| config.sandbox_config)
        .expect("managed sandbox")
        .workspace_dir;

    assert!(workspace.exists());
    assert!(kernel.scheduler.contains(id));
    assert!(kernel.ipc.is_registered(id));
    assert!(kernel.sandbox_manager.get_sandbox_for_agent(id).is_some());

    assert_eq!(kernel.stop_agent(id).await.unwrap(), AgentState::Stopped);
    assert_eq!(kernel.stop_agent(id).await.unwrap(), AgentState::Stopped);

    assert!(!kernel.scheduler.contains(id));
    assert!(!kernel.ipc.is_registered(id));
    assert!(kernel.syscall_gate.agent_info(id).is_none());
    assert!(kernel.sandbox_manager.get_sandbox_for_agent(id).is_none());
    assert!(!workspace.exists(), "managed workspace must be removed");
    assert_eq!(kernel.os.cfs.lock().await.nice_of(pid), None);
    assert_eq!(
        kernel.permission_manager.check_access(
            id,
            &ResourceType::Filesystem,
            "read",
            Some("/tmp/file")
        ),
        AccessDecision::Denied,
        "terminated agents must lose their permission assignment"
    );
}

#[tokio::test]
async fn pause_blocks_work_resume_rearms_and_wait_observes_terminal_state() {
    let kernel = AgentKernelImpl::new().expect("kernel");
    let id = kernel
        .create_agent_full(config("pause-resume"))
        .await
        .unwrap()
        .id;

    assert_eq!(kernel.pause_agent(id).await.unwrap(), AgentState::Paused);
    assert_eq!(kernel.pause_agent(id).await.unwrap(), AgentState::Paused);
    let denied = kernel.send_message(id, "must not run").await.unwrap_err();
    assert!(denied.to_string().contains("Invalid state transition"));

    assert_eq!(kernel.resume_agent(id).await.unwrap(), AgentState::Running);
    assert_eq!(kernel.resume_agent(id).await.unwrap(), AgentState::Running);
    assert!(kernel
        .wait_agent(id, Duration::from_millis(20))
        .await
        .is_err());

    assert_eq!(kernel.kill_agent(id).await.unwrap(), AgentState::Stopped);
    assert_eq!(
        kernel.wait_agent(id, Duration::from_secs(1)).await.unwrap(),
        AgentState::Stopped
    );
}

#[test]
fn paused_state_survives_restart_but_terminal_agents_are_not_readmitted() {
    let root = std::env::temp_dir().join(format!(
        "aiagentos-lifecycle-restart-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("kernel.sqlite");

    let (paused_id, stopped_id) = {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let kernel = AgentKernelImpl::with_db_path(&db).expect("first boot");
        runtime.block_on(async {
            let paused_id = kernel.create_agent_full(config("paused")).await.unwrap().id;
            let stopped_id = kernel
                .create_agent_full(config("stopped"))
                .await
                .unwrap()
                .id;
            kernel.pause_agent(paused_id).await.unwrap();
            kernel.stop_agent(stopped_id).await.unwrap();
            (paused_id, stopped_id)
        })
    };

    let kernel = AgentKernelImpl::with_db_path(&db).expect("restart");
    assert_eq!(
        kernel.get_agent_status(paused_id).unwrap(),
        AgentState::Paused
    );
    assert!(kernel.scheduler.contains(paused_id));
    assert!(kernel.ipc.is_registered(paused_id));
    assert!(kernel.syscall_gate.agent_info(paused_id).is_some());
    assert!(kernel
        .sandbox_manager
        .get_sandbox_for_agent(paused_id)
        .is_some());

    assert_eq!(
        kernel.get_agent_status(stopped_id).unwrap(),
        AgentState::Stopped
    );
    assert!(!kernel.scheduler.contains(stopped_id));
    assert!(!kernel.ipc.is_registered(stopped_id));
    assert!(kernel.syscall_gate.agent_info(stopped_id).is_none());
    assert!(kernel
        .sandbox_manager
        .get_sandbox_for_agent(stopped_id)
        .is_none());

    drop(kernel);
    std::fs::remove_dir_all(root).unwrap();
}
