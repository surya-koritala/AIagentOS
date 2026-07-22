use kernel::init_system::{
    DependencyConfig, ExecConfig, ResourceConfig, RestartPolicy, ServiceConfig, ServiceDef,
    ServiceStatus, ServiceType,
};
use kernel::{AgentKernelImpl, AgentState};

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
            nice: Some(0),
        },
    }
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
