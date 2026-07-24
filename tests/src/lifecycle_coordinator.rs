//! Regression coverage for the kernel-wide lifecycle coordinator (#112).

use std::time::Duration;

use kernel::context::{PersistedAgent, SqliteContextManager, DEFAULT_TENANT};
use kernel::ipc::{AgentIpc, DelegationStatus};
use kernel::permissions::{AccessDecision, PermissionSystem};
use kernel::resources::ResourceType;
use kernel::sandbox::SandboxManager;
use kernel::sandbox::SandboxManagerImpl;
use kernel::{
    AgentConfig, AgentKernelImpl, AgentState, IsolationLevel, KernelEvent, LifecycleOperation,
    LifecycleOutcome, Priority, SandboxConfig,
};

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

#[tokio::test]
async fn kill_during_pending_ipc_delegation_removes_task_and_only_target_mailbox() {
    let kernel = AgentKernelImpl::new().expect("kernel");
    let delegator = kernel
        .create_agent_full(config("delegator"))
        .await
        .unwrap()
        .id;
    let assignee = kernel
        .create_agent_full(config("assignee"))
        .await
        .unwrap()
        .id;

    let task_id = kernel
        .ipc
        .delegate(delegator, assignee, "pending lifecycle work".into())
        .await
        .unwrap();
    assert_eq!(
        kernel.ipc.get_delegation_status(delegator, task_id),
        Some(DelegationStatus::Pending)
    );

    assert_eq!(
        kernel.kill_agent(assignee).await.unwrap(),
        AgentState::Stopped
    );
    assert_eq!(
        kernel.ipc.get_delegation_status(delegator, task_id),
        None,
        "killing either party must remove its pending delegation"
    );
    assert!(
        kernel.ipc.is_registered(delegator),
        "the surviving peer mailbox must remain registered"
    );
    assert!(!kernel.ipc.is_registered(assignee));
    assert!(kernel
        .ipc
        .send(delegator, assignee, serde_json::json!({"after": "kill"}),)
        .await
        .is_err());

    let second_assignee = kernel
        .create_agent_full(config("second-assignee"))
        .await
        .unwrap()
        .id;
    let second_task = kernel
        .ipc
        .delegate(delegator, second_assignee, "kill delegator".into())
        .await
        .unwrap();
    assert_eq!(
        kernel
            .ipc
            .get_delegation_status(second_assignee, second_task),
        Some(DelegationStatus::Pending)
    );

    assert_eq!(
        kernel.kill_agent(delegator).await.unwrap(),
        AgentState::Stopped
    );
    assert_eq!(
        kernel
            .ipc
            .get_delegation_status(second_assignee, second_task),
        None,
        "killing the delegator must remove the pending task"
    );
    assert!(kernel.ipc.is_registered(second_assignee));
    assert!(!kernel.ipc.is_registered(delegator));
}

#[tokio::test]
async fn lifecycle_events_and_metrics_report_bounded_outcomes() {
    let kernel = AgentKernelImpl::new().expect("kernel");
    let mut events = kernel.subscribe_events();
    let id = kernel
        .create_agent_full(config("lifecycle-telemetry"))
        .await
        .unwrap()
        .id;

    kernel.pause_agent(id).await.unwrap();
    kernel.resume_agent(id).await.unwrap();
    assert!(kernel
        .wait_agent(id, Duration::from_millis(10))
        .await
        .is_err());
    kernel.kill_agent(id).await.unwrap();
    let missing = uuid::Uuid::new_v4();
    assert!(kernel.pause_agent(missing).await.is_err());

    let snapshot = kernel::metrics::MetricsSnapshot::collect(&kernel);
    assert_eq!(snapshot.lifecycle.pause.requested, 2);
    assert_eq!(snapshot.lifecycle.pause.completed, 1);
    assert_eq!(snapshot.lifecycle.pause.failed, 1);
    assert_eq!(snapshot.lifecycle.pause.duration_samples, 2);
    assert_eq!(snapshot.lifecycle.resume.requested, 1);
    assert_eq!(snapshot.lifecycle.resume.completed, 1);
    assert_eq!(snapshot.lifecycle.resume.duration_samples, 1);
    assert_eq!(snapshot.lifecycle.wait.requested, 1);
    assert_eq!(snapshot.lifecycle.wait.timed_out, 1);
    assert_eq!(snapshot.lifecycle.wait.duration_samples, 1);
    assert_eq!(snapshot.lifecycle.kill.requested, 1);
    assert_eq!(snapshot.lifecycle.kill.forced, 1);
    assert_eq!(snapshot.lifecycle.kill.duration_samples, 1);
    assert_eq!(
        snapshot.lifecycle.kill.requested,
        snapshot.lifecycle.kill.forced
            + snapshot.lifecycle.kill.completed
            + snapshot.lifecycle.kill.timed_out
            + snapshot.lifecycle.kill.failed
    );
    let prometheus = snapshot.render_prometheus();
    assert!(prometheus.contains("agentos_lifecycle_duration_seconds_count{operation=\"pause\"} 2"));
    assert!(prometheus.contains("agentos_lifecycle_duration_seconds_count{operation=\"resume\"} 1"));

    let mut observed = Vec::new();
    let mut missing_failed = false;
    while let Ok(event) = events.try_recv() {
        if let KernelEvent::AgentLifecycle {
            agent_id,
            operation,
            outcome,
        } = event
        {
            if agent_id == id {
                observed.push((operation, outcome));
            } else if agent_id == missing
                && operation == LifecycleOperation::Pause
                && outcome == LifecycleOutcome::Failed
            {
                missing_failed = true;
            }
        }
    }
    for expected in [
        (LifecycleOperation::Pause, LifecycleOutcome::Requested),
        (LifecycleOperation::Pause, LifecycleOutcome::Completed),
        (LifecycleOperation::Resume, LifecycleOutcome::Requested),
        (LifecycleOperation::Resume, LifecycleOutcome::Completed),
        (LifecycleOperation::Wait, LifecycleOutcome::Requested),
        (LifecycleOperation::Wait, LifecycleOutcome::TimedOut),
        (LifecycleOperation::Kill, LifecycleOutcome::Requested),
        (LifecycleOperation::Kill, LifecycleOutcome::Forced),
    ] {
        assert!(
            observed.contains(&expected),
            "missing lifecycle event {expected:?}: {observed:?}"
        );
    }
    assert!(
        missing_failed,
        "failed lifecycle calls must emit an outcome"
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

#[test]
fn restart_resolves_interrupted_lifecycle_states_without_readmission() {
    let root = std::env::temp_dir().join(format!(
        "aiagentos-lifecycle-interrupted-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("kernel.sqlite");
    let context = SqliteContextManager::new(&db).expect("seed database");
    let now = chrono::Utc::now();

    let initializing_id = uuid::Uuid::new_v4();
    let stopping_id = uuid::Uuid::new_v4();
    let malformed_id = uuid::Uuid::new_v4();
    let interrupted_workspace =
        SandboxManagerImpl::managed_root().join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&interrupted_workspace).unwrap();
    std::fs::write(
        interrupted_workspace.join(".aiagentos-managed"),
        b"managed-by=aiagentos\n",
    )
    .unwrap();
    let interrupted_sandbox = serde_json::to_string(&SandboxConfig {
        workspace_dir: interrupted_workspace.clone(),
        allowed_network_hosts: Some(Vec::new()),
        max_disk_usage_bytes: Some(1024),
        max_memory_bytes: Some(1024),
        isolation_level: IsolationLevel::Filesystem,
        container_image: None,
    })
    .unwrap();

    let record = |id, status: &str, sandbox_config_json| PersistedAgent {
        id,
        session_id: uuid::Uuid::new_v4(),
        tenant_id: DEFAULT_TENANT.to_string(),
        name: format!("interrupted-{id}"),
        task: "restart recovery regression".into(),
        llm_provider: "stub".into(),
        permission_profile: "standard".into(),
        priority: Priority::default().value(),
        status: status.into(),
        sandbox_config_json,
        created_at: now,
        last_activity_at: now,
    };
    context
        .save_agent(&record(
            initializing_id,
            &serde_json::to_string(&AgentState::Initializing).unwrap(),
            None,
        ))
        .unwrap();
    context
        .save_agent(&record(
            stopping_id,
            &serde_json::to_string(&AgentState::Stopping).unwrap(),
            Some(interrupted_sandbox),
        ))
        .unwrap();
    context
        .save_agent(&record(malformed_id, "{\"unknown\":\"state\"}", None))
        .unwrap();
    drop(context);

    let kernel = AgentKernelImpl::with_db_path(&db).expect("restart");
    assert_eq!(
        kernel.get_agent_status(initializing_id).unwrap(),
        AgentState::Error("initialization interrupted by process restart".into())
    );
    assert_eq!(
        kernel.get_agent_status(stopping_id).unwrap(),
        AgentState::Stopped
    );
    assert!(
        kernel.get_agent_status(malformed_id).is_err(),
        "corrupt lifecycle state must fail closed instead of becoming Running"
    );
    for id in [initializing_id, stopping_id, malformed_id] {
        assert!(!kernel.scheduler.contains(id));
        assert!(!kernel.ipc.is_registered(id));
        assert!(kernel.syscall_gate.agent_info(id).is_none());
        assert!(kernel.sandbox_manager.get_sandbox_for_agent(id).is_none());
    }
    assert!(
        !interrupted_workspace.exists(),
        "interrupted terminal workspace must be reconciled"
    );

    let persisted = kernel.context_manager.load_all_agents().unwrap();
    let state_for = |id| {
        let status = &persisted
            .iter()
            .find(|record| record.id == id)
            .unwrap()
            .status;
        serde_json::from_str::<AgentState>(status)
    };
    assert_eq!(
        state_for(initializing_id).unwrap(),
        AgentState::Error("initialization interrupted by process restart".into())
    );
    assert_eq!(state_for(stopping_id).unwrap(), AgentState::Stopped);
    assert!(state_for(malformed_id).is_err());

    drop(kernel);
    std::fs::remove_dir_all(root).unwrap();
}
