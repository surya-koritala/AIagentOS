//! Multi-tenancy isolation tests.
//!
//! Tenancy rides on the OS primitives the kernel already enforces: each tenant
//! gets its own **namespace group** (so agents/tools/IPC are invisible across
//! tenants — denied at the syscall gate) and its own **cgroup** (so one tenant
//! exhausting its token budget can't starve another). State is scoped by
//! `tenant_id` at the SQLite layer so cross-tenant reads are impossible, and the
//! tenant survives a restart so isolation is re-armed on rehydrate.
//!
//! These tests prove, against the real `AgentKernelImpl`:
//!   (a) cross-tenant tool/IPC denial at the gate,
//!   (b) no cross-tenant reads of agents / memory facts / KV,
//!   (c) per-tenant cgroup budget isolation,
//!   (d) tenancy survives a restart,
//! plus the auth → `(user, tenant, role)` resolution.

use kernel::auth::Role;
use kernel::context::{Fact, FactCategory};
use kernel::{AgentConfig, AgentKernelImpl};

fn cfg(name: &str, profile: &str) -> AgentConfig {
    AgentConfig {
        name: name.into(),
        task: "test".into(),
        llm_provider: "stub".into(),
        permission_profile: profile.into(),
        priority: kernel::Priority::new(3).unwrap(),
        sandbox_config: None,
    }
}

/// (auth resolution) An API key and a session token each resolve to the right
/// `(user, tenant, role)`, and the secret is hashed at rest.
#[tokio::test]
async fn auth_resolves_principal_for_key_and_session() {
    let kernel = AgentKernelImpl::new().expect("kernel");
    let tenant = kernel.create_tenant("acme").await.unwrap();
    let user = kernel
        .register_user(&tenant, "alice", "alice@acme.test", Role::Admin)
        .await
        .unwrap();

    let key = kernel.issue_api_key(&user, "ci").await.unwrap();
    let p = kernel.resolve_principal(&key).await.expect("key resolves");
    assert_eq!(p.user_id, user);
    assert_eq!(p.tenant_id, tenant);
    assert_eq!(p.role, Role::Admin);

    let token = kernel.open_session(&user).await.unwrap();
    let p2 = kernel
        .resolve_principal(&token)
        .await
        .expect("session resolves");
    assert_eq!(p2.tenant_id, tenant);

    // An unknown / bogus secret resolves to nothing.
    assert!(kernel.resolve_principal("ak_bogus").await.is_none());
}

/// (a) Two tenants' agents cannot message each other (gate denies cross-tenant
/// IPC like a non-existent agent), but same-tenant IPC works.
#[tokio::test]
async fn cross_tenant_ipc_is_denied() {
    use kernel::ipc::AgentIpc;
    use kernel::IpcError;

    let kernel = AgentKernelImpl::new().expect("kernel");
    let t_a = kernel.create_tenant("tenant-a").await.unwrap();
    let t_b = kernel.create_tenant("tenant-b").await.unwrap();

    let a1 = kernel
        .create_agent_for_tenant(&t_a, cfg("a1", "full-access"))
        .await
        .unwrap();
    let a2 = kernel
        .create_agent_for_tenant(&t_a, cfg("a2", "full-access"))
        .await
        .unwrap();
    let b1 = kernel
        .create_agent_for_tenant(&t_b, cfg("b1", "full-access"))
        .await
        .unwrap();

    // Same tenant: a1 → a2 succeeds.
    kernel
        .ipc
        .send(a1.id, a2.id, serde_json::json!({"hi": "a2"}))
        .await
        .expect("same-tenant IPC should succeed");

    // Cross tenant: a1 → b1 is denied as if b1 did not exist.
    let r = kernel
        .ipc
        .send(a1.id, b1.id, serde_json::json!({"leak": true}))
        .await;
    match r {
        Err(IpcError::AgentNotFound(id)) => assert_eq!(id, b1.id),
        other => panic!("expected AgentNotFound for cross-tenant IPC, got {other:?}"),
    }
}

/// (a) A tool registered in tenant A's namespace is invisible to a tenant-B
/// agent: the gate denies with `NotInNamespace`. A tenant-A agent can use it.
#[tokio::test]
async fn cross_tenant_namespaced_tool_is_denied() {
    use kernel::syscall_gate::GateDenial;
    use kernel::tools::ToolBinding;

    let kernel = AgentKernelImpl::new().expect("kernel");
    let t_a = kernel.create_tenant("tenant-a").await.unwrap();
    let t_b = kernel.create_tenant("tenant-b").await.unwrap();

    // The tenant's namespace group is keyed by its tenant id, so registering a
    // group tool under that id tags it with tenant-A's tool namespace.
    kernel.register_group_tool(
        &t_a,
        ToolBinding {
            name: "tenant_a_tool".into(),
            description: "tenant A only".into(),
            parameters_schema: serde_json::json!({}),
            resource_type: kernel::resources::ResourceType::Filesystem,
            operation: "read".into(),
        },
    );

    let a1 = kernel
        .create_agent_for_tenant(&t_a, cfg("a1", "full-access"))
        .await
        .unwrap();
    let b1 = kernel
        .create_agent_for_tenant(&t_b, cfg("b1", "full-access"))
        .await
        .unwrap();

    // Tenant-A agent: allowed (it is a member of tenant A's tool namespace).
    assert!(
        kernel
            .syscall_gate
            .check_tool_call(a1.id, "tenant_a_tool", "/x", 5)
            .await
            .is_ok(),
        "tenant-A agent should see tenant-A's tool"
    );

    // Tenant-B agent: denied with NotInNamespace — never learns the tool exists.
    let r = kernel
        .syscall_gate
        .check_tool_call(b1.id, "tenant_a_tool", "/x", 5)
        .await;
    assert!(
        matches!(r, Err(GateDenial::NotInNamespace { .. })),
        "tenant-B agent should be denied NotInNamespace, got {r:?}"
    );
}

/// (b) A tenant-A caller cannot read tenant-B agents / memory facts / KV via the
/// tenant-scoped storage reads.
#[tokio::test]
async fn cross_tenant_state_reads_are_impossible() {
    let kernel = AgentKernelImpl::new().expect("kernel");
    let t_a = kernel.create_tenant("tenant-a").await.unwrap();
    let t_b = kernel.create_tenant("tenant-b").await.unwrap();

    let a1 = kernel
        .create_agent_for_tenant(&t_a, cfg("a1", "standard"))
        .await
        .unwrap();
    let b1 = kernel
        .create_agent_for_tenant(&t_b, cfg("b1", "standard"))
        .await
        .unwrap();

    let cm = &kernel.context_manager;

    // Agent registry: each tenant sees only its own agents.
    let a_ids = cm.list_agents_for_tenant(&t_a).unwrap();
    let b_ids = cm.list_agents_for_tenant(&t_b).unwrap();
    assert_eq!(a_ids, vec![a1.id]);
    assert_eq!(b_ids, vec![b1.id]);

    // Seed tenant-B agent's memory + KV.
    use kernel::context::ContextManager;
    cm.store_fact(
        b1.id,
        Fact {
            id: uuid::Uuid::new_v4(),
            content: "tenant B secret".into(),
            category: FactCategory::Fact,
            created_at: chrono::Utc::now(),
            last_accessed_at: chrono::Utc::now(),
            embedding: None,
        },
    )
    .await
    .unwrap();
    cm.kv_put(b1.id, "secret", "B-only").unwrap();

    // Tenant A reading tenant B's agent data through the scoped reads → empty.
    let facts = cm
        .query_memory_for_tenant(&t_a, b1.id, "secret")
        .await
        .unwrap();
    assert!(facts.is_empty(), "tenant A must not read tenant B's facts");

    let kv = cm.kv_get_for_tenant(&t_a, b1.id, "secret").unwrap();
    assert!(kv.is_none(), "tenant A must not read tenant B's KV");

    let keys = cm.kv_list_for_tenant(&t_a, b1.id).unwrap();
    assert!(keys.is_empty(), "tenant A must not list tenant B's KV keys");

    // Tenant B reading its own data through the scoped reads → present.
    let own = cm
        .query_memory_for_tenant(&t_b, b1.id, "secret")
        .await
        .unwrap();
    assert!(!own.is_empty(), "tenant B should read its own facts");
    assert_eq!(
        cm.kv_get_for_tenant(&t_b, b1.id, "secret")
            .unwrap()
            .as_deref(),
        Some("B-only")
    );
}

/// (c) Per-tenant cgroup budget: tenant A exhausting its per-minute token quota
/// does NOT block tenant B — their cgroups are independent.
#[tokio::test]
async fn per_tenant_cgroup_budget_is_isolated() {
    use kernel::syscall_gate::GateDenial;

    // A tiny per-minute token budget makes the quota easy to exhaust.
    let budgets = kernel::config::BudgetConfig {
        tpm: 1_000,
        ..Default::default()
    };
    let cm = std::sync::Arc::new(kernel::context::SqliteContextManager::in_memory().unwrap());
    let kernel = AgentKernelImpl::with_context_manager(cm, &budgets, false, &[]).expect("kernel");

    let t_a = kernel.create_tenant("tenant-a").await.unwrap();
    let t_b = kernel.create_tenant("tenant-b").await.unwrap();
    let a1 = kernel
        .create_agent_for_tenant(&t_a, cfg("a1", "full-access"))
        .await
        .unwrap();
    let b1 = kernel
        .create_agent_for_tenant(&t_b, cfg("b1", "full-access"))
        .await
        .unwrap();

    // Tenant A spends its whole budget on a tool call (record usage against its
    // cgroup), then a further call over budget is denied with CgroupQuota.
    assert!(kernel
        .syscall_gate
        .check_tool_call(a1.id, "read_file", "/x", 900)
        .await
        .is_ok());
    kernel.syscall_gate.record_tool_usage(a1.id, 900);
    let denied = kernel
        .syscall_gate
        .check_tool_call(a1.id, "read_file", "/x", 900)
        .await;
    assert!(
        matches!(denied, Err(GateDenial::CgroupQuota)),
        "tenant A over its own budget should be denied, got {denied:?}"
    );

    // Tenant B is unaffected — its cgroup still has the full budget.
    assert!(
        kernel
            .syscall_gate
            .check_tool_call(b1.id, "read_file", "/y", 900)
            .await
            .is_ok(),
        "tenant B must not be blocked by tenant A exhausting its quota"
    );
}

/// (d) Tenancy survives a restart: after dropping and reopening the kernel on the
/// same DB, the agent comes back with the right tenant_id and its cross-tenant
/// isolation (namespace + cgroup) is re-armed.
#[tokio::test]
async fn tenancy_survives_restart() {
    use kernel::ipc::AgentIpc;
    use kernel::IpcError;

    let dir = std::env::temp_dir().join(format!("tenancy-restart-{}", uuid::Uuid::new_v4()));
    let db = dir.join("agent_os.db");

    let (t_a, t_b, a1_id, b1_id) = {
        let kernel = AgentKernelImpl::with_db_path(&db).expect("kernel boot");
        let t_a = kernel.create_tenant("tenant-a").await.unwrap();
        let t_b = kernel.create_tenant("tenant-b").await.unwrap();
        let a1 = kernel
            .create_agent_for_tenant(&t_a, cfg("a1", "full-access"))
            .await
            .unwrap();
        let b1 = kernel
            .create_agent_for_tenant(&t_b, cfg("b1", "full-access"))
            .await
            .unwrap();
        kernel.context_manager.checkpoint().ok();
        (t_a, t_b, a1.id, b1.id)
    };

    // Restart: a fresh kernel on the same DB rehydrates tenants + agents.
    let kernel = AgentKernelImpl::with_db_path(&db).expect("kernel reboot");

    // The agent's tenant came back.
    assert_eq!(
        kernel
            .context_manager
            .agent_tenant(a1_id)
            .unwrap()
            .as_deref(),
        Some(t_a.as_str())
    );
    assert_eq!(
        kernel.context_manager.list_agents_for_tenant(&t_b).unwrap(),
        vec![b1_id]
    );

    // Isolation is re-armed: cross-tenant IPC is still denied after restart.
    let r = kernel
        .ipc
        .send(a1_id, b1_id, serde_json::json!({"leak": true}))
        .await;
    assert!(
        matches!(r, Err(IpcError::AgentNotFound(id)) if id == b1_id),
        "cross-tenant IPC must remain denied after restart, got {r:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
