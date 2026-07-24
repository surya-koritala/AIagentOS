use kernel::agent::AgentKernel;
use kernel::init_system::{
    DependencyConfig, ExecConfig, HealthConfig, ResourceConfig, RestartPolicy, ServiceConfig,
    ServiceDef, ServicePolicyConfig, ServiceStatus, ServiceType,
};
use kernel::runtime::KernelRuntime;
use kernel::{AgentKernelImpl, AgentState, IsolationLevel, KernelEvent, SandboxConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

fn service(name: &str, requires: &[&str]) -> ServiceDef {
    ServiceDef {
        name: name.into(),
        description: Some(format!("service {name}")),
        exec: ExecConfig {
            provider: "stub".into(),
            system_prompt: format!("run {name}"),
            tools: Vec::new(),
            model: None,
        },
        service: ServiceConfig {
            restart: RestartPolicy::OnFailure,
            restart_delay_ms: 0,
            max_restarts: 3,
            service_type: ServiceType::Simple,
            ..ServiceConfig::default()
        },
        dependencies: DependencyConfig {
            requires: requires.iter().map(|name| (*name).to_string()).collect(),
            wants: Vec::new(),
            after: Vec::new(),
            before: Vec::new(),
        },
        resources: ResourceConfig {
            token_budget: None,
            max_context: None,
            max_concurrent_tool_calls: None,
            nice: Some(0),
        },
        policy: ServicePolicyConfig::default(),
        health: HealthConfig::default(),
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("agentos-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_definitions(directory: &Path, definitions: &[ServiceDef]) {
    std::fs::create_dir_all(directory).unwrap();
    for entry in std::fs::read_dir(directory).unwrap().filter_map(Result::ok) {
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    for definition in definitions {
        let path = directory.join(format!("{}.toml", definition.name));
        std::fs::write(path, toml::to_string_pretty(definition).unwrap()).unwrap();
    }
}

async fn wait_for_service(
    kernel: &AgentKernelImpl,
    name: &str,
    predicate: impl Fn(&kernel::init_system::ServiceRuntimeInfo) -> bool,
) -> kernel::init_system::ServiceRuntimeInfo {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let state = kernel
                .list_services()
                .await
                .into_iter()
                .find(|service| service.name == name)
                .unwrap();
            if predicate(&state) {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("service state did not converge")
}

#[tokio::test]
async fn boot_restart_stop_and_dependency_block_use_coordinated_lifecycle() {
    let kernel = AgentKernelImpl::new().unwrap();
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(vec![
            service("worker", &["database"]),
            service("database", &[]),
        ])
        .unwrap();

    let blocked = kernel.start_service("worker").await.unwrap_err();
    assert!(blocked.to_string().contains("blocked by required service"));

    let started = tokio::time::timeout(std::time::Duration::from_secs(5), kernel.boot_services())
        .await
        .expect("service boot timed out")
        .unwrap();
    assert_eq!(started.len(), 2);
    let services = kernel.list_services().await;
    assert!(services
        .iter()
        .all(|service| service.status == ServiceStatus::Running));
    let worker_before = services
        .iter()
        .find(|service| service.name == "worker")
        .and_then(|service| service.agent_id)
        .unwrap();

    let worker_after = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        kernel.restart_service("worker"),
    )
    .await
    .expect("service restart timed out")
    .unwrap();
    assert_ne!(worker_before, worker_after);
    assert_eq!(
        kernel.get_agent_status(worker_before).unwrap(),
        AgentState::Stopped
    );
    let worker = kernel
        .list_services()
        .await
        .into_iter()
        .find(|service| service.name == "worker")
        .unwrap();
    assert_eq!(worker.status, ServiceStatus::Running);
    assert_eq!(worker.restart_count, 1);

    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        kernel.stop_service("worker"),
    )
    .await
    .expect("service stop timed out")
    .unwrap();
    let worker = kernel
        .list_services()
        .await
        .into_iter()
        .find(|service| service.name == "worker")
        .unwrap();
    assert_eq!(worker.status, ServiceStatus::Inactive);
    assert!(worker.agent_id.is_none());

    let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), kernel.shutdown())
        .await
        .expect("kernel shutdown timed out")
        .unwrap();
    assert!(stopped.contains(
        &services
            .iter()
            .find(|service| service.name == "database")
            .and_then(|service| service.agent_id)
            .unwrap()
    ));
}

#[tokio::test]
async fn required_dependency_failure_stops_and_blocks_the_live_dependent() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let mut database = service("database", &[]);
    database.service.restart = RestartPolicy::Never;
    database.health.liveness_interval_ms = 50;
    let mut worker = service("worker", &["database"]);
    worker.service.restart = RestartPolicy::Never;
    worker.health.liveness_interval_ms = 50;
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(vec![worker, database])
        .unwrap();
    kernel.boot_services().await.unwrap();
    let before = kernel.list_services().await;
    let database_id = before
        .iter()
        .find(|service| service.name == "database")
        .and_then(|service| service.agent_id)
        .unwrap();
    let worker_id = before
        .iter()
        .find(|service| service.name == "worker")
        .and_then(|service| service.agent_id)
        .unwrap();
    let runtime = kernel.start_runtime();

    kernel
        .agent_manager
        .transition_state(
            database_id,
            AgentState::Error("database process crashed".into()),
        )
        .unwrap();
    let database = wait_for_service(&kernel, "database", |state| {
        state.status == ServiceStatus::Failed && state.agent_id.is_none()
    })
    .await;
    assert!(database
        .last_failure
        .as_deref()
        .is_some_and(|failure| failure.contains("liveness failed")));
    let worker = wait_for_service(&kernel, "worker", |state| {
        state.status == ServiceStatus::Failed
            && state.agent_id.is_none()
            && state.dependency_blocks > 0
    })
    .await;
    assert!(worker
        .last_failure
        .as_deref()
        .is_some_and(|failure| failure.contains("required service 'database'")));
    assert_eq!(
        kernel.get_agent_status(database_id).unwrap(),
        AgentState::Stopped
    );
    assert_eq!(
        kernel.get_agent_status(worker_id).unwrap(),
        AgentState::Stopped
    );
    assert!(kernel.syscall_gate.agent_info(database_id).is_none());
    assert!(kernel.syscall_gate.agent_info(worker_id).is_none());
    runtime.stop();
}

#[tokio::test]
async fn manual_dependency_restart_restarts_required_dependents_in_order() {
    let kernel = AgentKernelImpl::new().unwrap();
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(vec![
            service("worker", &["database"]),
            service("database", &[]),
        ])
        .unwrap();
    kernel.boot_services().await.unwrap();
    let before = kernel.list_services().await;
    let old_database = before
        .iter()
        .find(|service| service.name == "database")
        .and_then(|service| service.agent_id)
        .unwrap();
    let old_worker = before
        .iter()
        .find(|service| service.name == "worker")
        .and_then(|service| service.agent_id)
        .unwrap();

    let new_database = kernel.restart_service("database").await.unwrap();
    let after = kernel.list_services().await;
    let database = after
        .iter()
        .find(|service| service.name == "database")
        .unwrap();
    let worker = after
        .iter()
        .find(|service| service.name == "worker")
        .unwrap();
    assert_eq!(database.agent_id, Some(new_database));
    assert_ne!(database.agent_id, Some(old_database));
    assert_ne!(worker.agent_id, Some(old_worker));
    assert!(database.ready && worker.ready);
    assert_eq!(
        kernel.get_agent_status(old_database).unwrap(),
        AgentState::Stopped
    );
    assert_eq!(
        kernel.get_agent_status(old_worker).unwrap(),
        AgentState::Stopped
    );
    let history = kernel.list_service_history(None, 100).unwrap();
    let worker_stop = history
        .iter()
        .find(|entry| entry.name == "worker" && entry.event == "stopping")
        .unwrap()
        .id;
    let database_stop = history
        .iter()
        .find(|entry| entry.name == "database" && entry.event == "stopping")
        .unwrap()
        .id;
    assert!(worker_stop < database_stop);
}

#[tokio::test]
async fn runtime_restarts_failed_services_and_exhausts_without_leaking_owners() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let mut definition = service("restartable", &[]);
    definition.service.restart_delay_ms = 0;
    definition.service.restart_max_delay_ms = 1;
    definition.service.restart_jitter_ms = 0;
    definition.service.restart_window_ms = 10_000;
    definition.service.max_restarts = 2;
    definition.health.liveness_interval_ms = 50;
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(vec![definition])
        .unwrap();
    let first = kernel.boot_services().await.unwrap()[0];
    let mut events = kernel.subscribe_events();
    let runtime = kernel.start_runtime();

    kernel
        .agent_manager
        .transition_state(first, AgentState::Error("injected crash one".into()))
        .unwrap();
    let after_first = wait_for_service(&kernel, "restartable", |state| {
        state.ready && state.agent_id.is_some_and(|id| id != first)
    })
    .await;
    let second = after_first.agent_id.unwrap();
    assert_eq!(after_first.restart_count, 1);
    assert_eq!(kernel.get_agent_status(first).unwrap(), AgentState::Stopped);
    assert!(kernel.syscall_gate.agent_info(first).is_none());

    kernel
        .agent_manager
        .transition_state(second, AgentState::Error("injected crash two".into()))
        .unwrap();
    let after_second = wait_for_service(&kernel, "restartable", |state| {
        state.ready && state.agent_id.is_some_and(|id| id != second)
    })
    .await;
    let third = after_second.agent_id.unwrap();
    assert_eq!(after_second.restart_count, 2);
    assert_eq!(after_second.restart_attempts_total, 2);

    kernel
        .agent_manager
        .transition_state(third, AgentState::Error("injected crash three".into()))
        .unwrap();
    let exhausted = wait_for_service(&kernel, "restartable", |state| {
        state.status == ServiceStatus::Failed && state.restart_exhausted
    })
    .await;
    assert!(exhausted.agent_id.is_none());
    assert_eq!(exhausted.restart_count, 2);
    assert_eq!(exhausted.restart_attempts_total, 2);
    assert_eq!(kernel.get_agent_status(third).unwrap(), AgentState::Stopped);
    assert!(kernel.syscall_gate.agent_info(third).is_none());
    assert_eq!(
        kernel
            .agent_manager
            .list_agents(None)
            .into_iter()
            .filter(|agent| agent.state == AgentState::Running)
            .count(),
        0
    );
    let metrics = kernel::metrics::MetricsSnapshot::collect(&kernel);
    assert_eq!(metrics.service_failed, 1);
    assert_eq!(metrics.service_restarts_total, 2);
    assert!(metrics
        .render_prometheus()
        .contains("agentos_services{state=\"failed\"} 1"));
    let failure_event = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let KernelEvent::ServiceStateChanged {
                name,
                reason: Some(reason),
                ..
            } = events.recv().await.unwrap()
            {
                if name == "restartable" && reason.contains("injected crash three") {
                    return reason;
                }
            }
        }
    })
    .await
    .expect("service failure event was not emitted");
    assert!(failure_event.contains("liveness failed"));

    runtime.stop();
}

#[tokio::test]
async fn readiness_timeout_is_fail_closed_and_reclaims_the_created_agent() {
    let kernel = AgentKernelImpl::new().unwrap();
    let mut definition = service("slow-readiness", &[]);
    definition.health.startup_timeout_ms = 10;
    definition.health.readiness_delay_ms = 50;
    definition.service.restart = RestartPolicy::Never;
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(vec![definition])
        .unwrap();

    let error = kernel.boot_services().await.unwrap_err();
    assert!(error.to_string().contains("startup exceeded"));
    let state = kernel.list_services().await.remove(0);
    assert_eq!(state.status, ServiceStatus::Failed);
    assert!(!state.ready);
    assert!(!state.healthy);
    assert!(state.agent_id.is_none());
    assert_eq!(
        kernel
            .agent_manager
            .list_agents(None)
            .into_iter()
            .filter(|agent| agent.state == AgentState::Running)
            .count(),
        0
    );
    assert!(kernel
        .list_service_history(Some("slow-readiness"), 20)
        .unwrap()
        .iter()
        .any(|entry| entry.event == "startup_timeout"));
}

#[tokio::test]
async fn rolling_reload_restarts_dependency_closure_and_rolls_back_atomically() {
    let kernel = AgentKernelImpl::new().unwrap();
    let original = vec![service("worker", &["database"]), service("database", &[])];
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(original.clone())
        .unwrap();
    kernel.boot_services().await.unwrap();
    let before = kernel.list_services().await;
    let old_database = before
        .iter()
        .find(|service| service.name == "database")
        .and_then(|service| service.agent_id)
        .unwrap();
    let old_worker = before
        .iter()
        .find(|service| service.name == "worker")
        .and_then(|service| service.agent_id)
        .unwrap();

    let directory = TestDirectory::new("service-reload");
    let mut broken = original.clone();
    broken
        .iter_mut()
        .find(|definition| definition.name == "database")
        .unwrap()
        .exec
        .provider = "unregistered-provider".into();
    let mut broken_addition = service("broken-addon", &[]);
    broken_addition.exec.provider = "unregistered-provider".into();
    broken.push(broken_addition);
    write_definitions(directory.path(), &broken);
    let error = kernel
        .reload_service_directory(directory.path())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("restored the previous graph"));
    let restored = kernel.list_services().await;
    assert!(restored
        .iter()
        .all(|state| state.status == ServiceStatus::Running && state.ready));
    assert!(restored.iter().all(|state| {
        kernel
            .os
            .init
            .try_lock()
            .ok()
            .and_then(|init| init.definition(&state.name))
            .is_some_and(|definition| definition.exec.provider == "stub")
    }));
    assert!(kernel
        .context_manager
        .load_service_runtime()
        .unwrap()
        .iter()
        .all(|runtime| runtime.name != "broken-addon"));

    let after_rollback_database = restored
        .iter()
        .find(|service| service.name == "database")
        .and_then(|service| service.agent_id)
        .unwrap();
    let after_rollback_worker = restored
        .iter()
        .find(|service| service.name == "worker")
        .and_then(|service| service.agent_id)
        .unwrap();
    assert_ne!(old_database, after_rollback_database);
    assert_ne!(old_worker, after_rollback_worker);

    let mut valid = original;
    valid
        .iter_mut()
        .find(|definition| definition.name == "database")
        .unwrap()
        .description = Some("validated replacement".into());
    write_definitions(directory.path(), &valid);
    assert_eq!(
        kernel
            .reload_service_directory(directory.path())
            .await
            .unwrap(),
        vec!["database", "worker"]
    );
    let reloaded = kernel.list_services().await;
    let final_database = reloaded
        .iter()
        .find(|service| service.name == "database")
        .and_then(|service| service.agent_id)
        .unwrap();
    let final_worker = reloaded
        .iter()
        .find(|service| service.name == "worker")
        .and_then(|service| service.agent_id)
        .unwrap();
    assert_ne!(after_rollback_database, final_database);
    assert_ne!(after_rollback_worker, final_worker);
    assert!(reloaded
        .iter()
        .all(|state| state.status == ServiceStatus::Running && state.ready));
    assert_eq!(
        kernel
            .agent_manager
            .list_agents(None)
            .into_iter()
            .filter(|agent| agent.state == AgentState::Running)
            .count(),
        2
    );
}

#[tokio::test]
async fn crash_recovery_reuses_durable_owner_without_duplicate_agent() {
    let root = TestDirectory::new("service-crash-recovery");
    let service_directory = root.path().join("services");
    let data_directory = root.path().join("data");
    write_definitions(&service_directory, &[service("durable", &[])]);
    let config = kernel::config::Config {
        data_dir: data_directory,
        service_dir: Some(service_directory),
        ..kernel::config::Config::default()
    };

    let original_id = {
        let kernel = AgentKernelImpl::from_config(&config).unwrap();
        let id = kernel.boot_services().await.unwrap()[0];
        assert!(kernel.list_services().await[0].ready);
        id
    };

    let recovered = AgentKernelImpl::from_config(&config).unwrap();
    let recovered_state = recovered.list_services().await.remove(0);
    assert_eq!(recovered_state.agent_id, Some(original_id));
    assert_eq!(recovered_state.status, ServiceStatus::Running);
    assert!(recovered_state.ready);
    assert_eq!(recovered.boot_services().await.unwrap(), vec![original_id]);
    assert_eq!(
        recovered
            .agent_manager
            .list_agents(None)
            .into_iter()
            .filter(|agent| agent.state == AgentState::Running)
            .count(),
        1
    );
    assert!(recovered
        .list_service_history(Some("durable"), 20)
        .unwrap()
        .iter()
        .any(|entry| entry.event == "process_recovered"));
    recovered.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_new_boot_service_does_not_roll_back_a_recovered_live_owner() {
    let root = TestDirectory::new("service-mixed-boot-recovery");
    let service_directory = root.path().join("services");
    let data_directory = root.path().join("data");
    let stable = service("stable", &[]);
    write_definitions(&service_directory, std::slice::from_ref(&stable));
    let config = kernel::config::Config {
        data_dir: data_directory,
        service_dir: Some(service_directory.clone()),
        ..kernel::config::Config::default()
    };
    let stable_id = {
        let kernel = AgentKernelImpl::from_config(&config).unwrap();
        kernel.boot_services().await.unwrap()[0]
    };

    let mut broken = service("z-broken", &[]);
    broken.exec.provider = "unregistered-provider".into();
    write_definitions(&service_directory, &[stable, broken]);
    let recovered = AgentKernelImpl::from_config(&config).unwrap();
    assert!(recovered.boot_services().await.is_err());
    let stable_state = recovered
        .list_services()
        .await
        .into_iter()
        .find(|service| service.name == "stable")
        .unwrap();
    assert_eq!(stable_state.agent_id, Some(stable_id));
    assert_eq!(stable_state.status, ServiceStatus::Running);
    assert!(stable_state.ready && stable_state.healthy);
    assert_eq!(
        recovered.get_agent_status(stable_id).unwrap(),
        AgentState::Running
    );
    recovered.shutdown().await.unwrap();
}

#[tokio::test]
async fn offline_definition_removal_reclaims_the_durable_owner_on_recovery() {
    let root = TestDirectory::new("service-offline-removal");
    let service_directory = root.path().join("services");
    let data_directory = root.path().join("data");
    write_definitions(&service_directory, &[service("removed-offline", &[])]);
    let config = kernel::config::Config {
        data_dir: data_directory,
        service_dir: Some(service_directory.clone()),
        ..kernel::config::Config::default()
    };

    let original_id = {
        let kernel = AgentKernelImpl::from_config(&config).unwrap();
        kernel.boot_services().await.unwrap()[0]
    };
    write_definitions(&service_directory, &[]);

    let recovered = AgentKernelImpl::from_config(&config).unwrap();
    assert!(recovered.list_services().await.is_empty());
    assert_eq!(
        recovered.get_agent_status(original_id).unwrap(),
        AgentState::Stopped
    );
    assert!(recovered.syscall_gate.agent_info(original_id).is_none());
    assert!(recovered
        .context_manager
        .load_service_runtime()
        .unwrap()
        .is_empty());
    assert!(recovered
        .list_service_history(Some("removed-offline"), 20)
        .unwrap()
        .iter()
        .any(|entry| entry.event == "definition_removed"));
}

#[tokio::test]
async fn paused_owner_is_replaced_once_during_crash_recovery() {
    let root = TestDirectory::new("service-paused-recovery");
    let service_directory = root.path().join("services");
    let data_directory = root.path().join("data");
    write_definitions(&service_directory, &[service("paused-owner", &[])]);
    let config = kernel::config::Config {
        data_dir: data_directory,
        service_dir: Some(service_directory),
        ..kernel::config::Config::default()
    };

    let paused_id = {
        let kernel = AgentKernelImpl::from_config(&config).unwrap();
        let id = kernel.boot_services().await.unwrap()[0];
        assert_eq!(kernel.pause_agent(id).await.unwrap(), AgentState::Paused);
        id
    };

    let recovered = Arc::new(AgentKernelImpl::from_config(&config).unwrap());
    assert!(recovered.boot_services().await.unwrap().is_empty());
    let runtime = recovered.start_runtime();
    let replacement = wait_for_service(&recovered, "paused-owner", |state| {
        state.ready && state.agent_id.is_some_and(|id| id != paused_id)
    })
    .await
    .agent_id
    .unwrap();
    assert_ne!(replacement, paused_id);
    assert_eq!(
        recovered.get_agent_status(paused_id).unwrap(),
        AgentState::Stopped
    );
    assert_eq!(
        recovered
            .agent_manager
            .list_agents(None)
            .into_iter()
            .filter(|agent| agent.state == AgentState::Running)
            .count(),
        1
    );
    runtime.stop();
    recovered.shutdown().await.unwrap();
}

#[tokio::test]
async fn crash_recovery_preserves_restart_exhaustion_until_operator_reset() {
    let root = TestDirectory::new("service-exhaustion-recovery");
    let service_directory = root.path().join("services");
    let data_directory = root.path().join("data");
    let mut definition = service("exhausted", &[]);
    definition.service.restart_delay_ms = 0;
    definition.service.restart_max_delay_ms = 1;
    definition.service.restart_jitter_ms = 0;
    definition.service.restart_window_ms = 60_000;
    definition.service.max_restarts = 1;
    definition.health.liveness_interval_ms = 50;
    write_definitions(&service_directory, &[definition]);
    let config = kernel::config::Config {
        data_dir: data_directory,
        service_dir: Some(service_directory),
        ..kernel::config::Config::default()
    };

    {
        let kernel = Arc::new(AgentKernelImpl::from_config(&config).unwrap());
        let first = kernel.boot_services().await.unwrap()[0];
        let runtime = kernel.start_runtime();
        kernel
            .agent_manager
            .transition_state(first, AgentState::Error("first crash".into()))
            .unwrap();
        let restarted = wait_for_service(&kernel, "exhausted", |state| {
            state.ready && state.restart_count == 1
        })
        .await
        .agent_id
        .unwrap();
        kernel
            .agent_manager
            .transition_state(restarted, AgentState::Error("second crash".into()))
            .unwrap();
        wait_for_service(&kernel, "exhausted", |state| {
            state.status == ServiceStatus::Failed && state.restart_exhausted
        })
        .await;
        runtime.stop();
    }

    let recovered = Arc::new(AgentKernelImpl::from_config(&config).unwrap());
    let state = recovered.list_services().await.remove(0);
    assert!(state.restart_exhausted);
    assert_eq!(state.status, ServiceStatus::Failed);
    assert!(recovered.boot_services().await.unwrap().is_empty());
    let runtime = recovered.start_runtime();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(recovered.list_services().await[0].restart_exhausted);
    assert_eq!(
        recovered
            .agent_manager
            .list_agents(None)
            .into_iter()
            .filter(|agent| agent.state == AgentState::Running)
            .count(),
        0
    );

    let operator_started = recovered.start_service("exhausted").await.unwrap();
    assert_eq!(
        recovered.get_agent_status(operator_started).unwrap(),
        AgentState::Running
    );
    assert!(!recovered.list_services().await[0].restart_exhausted);
    runtime.stop();
    recovered.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_is_reverse_ordered_and_runtime_start_is_idempotent() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(vec![
            service("worker", &["database"]),
            service("database", &[]),
        ])
        .unwrap();
    kernel.boot_services().await.unwrap();

    let runtime = KernelRuntime::new(Arc::clone(&kernel));
    let handles = runtime.start();
    assert_eq!(handles.len(), 3);
    assert!(runtime.start().is_empty());
    runtime.stop();
    for handle in handles {
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("runtime task leaked")
            .unwrap();
    }

    kernel.shutdown().await.unwrap();
    let history = kernel.list_service_history(None, 100).unwrap();
    let worker_stopping = history
        .iter()
        .find(|entry| entry.name == "worker" && entry.event == "stopping")
        .unwrap()
        .id;
    let database_stopping = history
        .iter()
        .find(|entry| entry.name == "database" && entry.event == "stopping")
        .unwrap()
        .id;
    assert!(worker_stopping < database_stopping);
}

#[tokio::test]
async fn service_shutdown_deadline_escalates_to_forced_cleanup() {
    let kernel = AgentKernelImpl::new().unwrap();
    let mut definition = service("deadline", &[]);
    definition.health.shutdown_timeout_ms = 1;
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(vec![definition])
        .unwrap();
    let agent_id = kernel.boot_services().await.unwrap()[0];
    let held_tool_call = kernel.syscall_gate.acquire_tool_call(agent_id).unwrap();

    kernel.stop_service("deadline").await.unwrap();
    let state = kernel.list_services().await.remove(0);
    assert_eq!(state.status, ServiceStatus::Inactive);
    assert!(state.agent_id.is_none());
    assert_eq!(
        kernel.get_agent_status(agent_id).unwrap(),
        AgentState::Stopped
    );
    assert!(kernel.syscall_gate.agent_info(agent_id).is_none());
    assert!(kernel
        .list_service_history(Some("deadline"), 20)
        .unwrap()
        .iter()
        .any(|entry| entry.event == "shutdown_forced"));
    drop(held_tool_call);
}

#[tokio::test]
async fn service_policy_is_enforced_for_tenant_sandbox_budget_profile_and_namespace() {
    let root = TestDirectory::new("service-policy");
    let kernel = AgentKernelImpl::new().unwrap();
    let tenant_id = kernel.create_tenant("service tenant").await.unwrap();
    let mut alpha = service("alpha", &[]);
    alpha.policy = ServicePolicyConfig {
        tenant_id: tenant_id.clone(),
        profile: "read-only".into(),
        namespace: Some("alpha-space".into()),
        sandbox: Some(SandboxConfig {
            workspace_dir: root.path().join("alpha"),
            allowed_network_hosts: Some(vec!["example.com".into()]),
            max_disk_usage_bytes: Some(1_000_000),
            max_memory_bytes: Some(2_000_000),
            isolation_level: IsolationLevel::Filesystem,
            container_image: None,
        }),
        secret_refs: vec!["openai".into()],
    };
    alpha.resources.token_budget = Some("600/minute".into());
    alpha.resources.max_context = Some(12_345);
    alpha.resources.max_concurrent_tool_calls = Some(2);
    alpha.resources.nice = Some(-5);

    let mut beta = service("beta", &[]);
    beta.policy.tenant_id = tenant_id.clone();
    beta.policy.namespace = Some("beta-space".into());
    {
        let mut init = kernel.os.init.lock().await;
        init.set_allowed_secret_refs(["openai".to_string()])
            .unwrap();
        init.replace_definitions(vec![alpha, beta]).unwrap();
    }
    let started = kernel.boot_services().await.unwrap();
    let states = kernel.list_services().await;
    let alpha_id = states
        .iter()
        .find(|state| state.name == "alpha")
        .and_then(|state| state.agent_id)
        .unwrap();
    let beta_id = states
        .iter()
        .find(|state| state.name == "beta")
        .and_then(|state| state.agent_id)
        .unwrap();
    assert_eq!(started.len(), 2);
    assert!(!kernel.syscall_gate.shares_namespace(alpha_id, beta_id));

    let persisted = kernel
        .context_manager
        .load_all_agents()
        .unwrap()
        .into_iter()
        .find(|agent| agent.id == alpha_id)
        .unwrap();
    assert_eq!(persisted.tenant_id, tenant_id);
    assert_eq!(persisted.permission_profile, "read-only");
    assert_eq!(persisted.llm_provider, "stub");
    let persisted_sandbox: SandboxConfig =
        serde_json::from_str(persisted.sandbox_config_json.as_deref().unwrap()).unwrap();
    assert_eq!(persisted_sandbox.workspace_dir, root.path().join("alpha"));

    let gate = kernel.syscall_gate.agent_info(alpha_id).unwrap();
    let cgroup = kernel.cgroups.get(gate.cgroup).unwrap();
    assert_eq!(cgroup.limits.tokens_per_min, 600);
    assert_eq!(cgroup.limits.max_context_tokens, 12_345);
    assert_eq!(cgroup.limits.max_concurrent_tool_calls, 2);
    let pid = kernel.syscall_gate.pid_of(alpha_id).unwrap();
    assert_eq!(kernel.os.cfs.lock().await.nice_of(pid), Some(-5));
    kernel.shutdown().await.unwrap();
}

#[tokio::test]
async fn foreign_tenant_service_fails_before_an_owner_is_created() {
    let kernel = AgentKernelImpl::new().unwrap();
    let mut definition = service("foreign", &[]);
    definition.policy.tenant_id = "foreign-tenant".into();
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(vec![definition])
        .unwrap();

    let error = kernel.start_service("foreign").await.unwrap_err();
    assert!(error
        .to_string()
        .contains("tenant 'foreign-tenant' is not registered"));
    let state = kernel.list_services().await.remove(0);
    assert_eq!(state.status, ServiceStatus::Failed);
    assert!(state.agent_id.is_none());
    assert!(kernel.agent_manager.list_agents(None).is_empty());
}

#[tokio::test]
async fn load_supervises_many_services_without_duplicate_owners_or_runtime_tasks() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let mut definitions = Vec::new();
    for index in 0..64 {
        let name = format!("service-{index:02}");
        let mut definition = service(&name, &[]);
        if index > 0 {
            definition.dependencies.requires = vec![format!("service-{:02}", index - 1)];
        }
        definitions.push(definition);
    }
    kernel
        .os
        .init
        .lock()
        .await
        .replace_definitions(definitions)
        .unwrap();
    assert_eq!(kernel.boot_services().await.unwrap().len(), 64);

    let runtime = KernelRuntime::new(Arc::clone(&kernel));
    let handles = runtime.start();
    assert_eq!(handles.len(), 3);
    assert!(runtime.start().is_empty());
    tokio::time::sleep(Duration::from_millis(350)).await;

    let services = kernel.list_services().await;
    assert_eq!(services.len(), 64);
    assert!(services
        .iter()
        .all(|service| service.status == ServiceStatus::Running && service.ready));
    let owners = services
        .iter()
        .filter_map(|service| service.agent_id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(owners.len(), 64);
    assert_eq!(
        kernel
            .agent_manager
            .list_agents(None)
            .into_iter()
            .filter(|agent| agent.state == AgentState::Running)
            .count(),
        64
    );

    runtime.stop();
    for handle in handles {
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("runtime task leaked under service load")
            .unwrap();
    }
    assert_eq!(kernel.shutdown().await.unwrap().len(), 64);
}
