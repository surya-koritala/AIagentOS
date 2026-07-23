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
//!   (c) cgroup resource isolation across tenants,
//!   (d) tenancy survives a restart,
//! plus the auth → `(user, tenant, role)` resolution.

use std::sync::atomic::Ordering;

use kernel::auth::Role;
use kernel::config::Config;
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
    use kernel::tools::{SecurityAction, ToolBinding, ToolSecurity};

    let kernel = AgentKernelImpl::new().expect("kernel");
    let t_a = kernel.create_tenant("tenant-a").await.unwrap();
    let t_b = kernel.create_tenant("tenant-b").await.unwrap();

    // The tenant's namespace group is keyed by its tenant id, so registering a
    // group tool under that id tags it with tenant-A's tool namespace.
    kernel
        .register_group_tool(
            &t_a,
            ToolBinding {
                name: "tenant_a_tool".into(),
                description: "tenant A only".into(),
                parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
                resource_type: kernel::resources::ResourceType::Filesystem,
                operation: "read".into(),
                security: ToolSecurity::constant(SecurityAction::Read, "tenant-a:tool"),
            },
        )
        .unwrap();

    let a1 = kernel
        .create_agent_for_tenant(&t_a, cfg("a1", "full-access"))
        .await
        .unwrap();
    let b1 = kernel
        .create_agent_for_tenant(&t_b, cfg("b1", "full-access"))
        .await
        .unwrap();
    let security = kernel.tool_registry.security("tenant_a_tool").unwrap();

    // Tenant-A agent: allowed (it is a member of tenant A's tool namespace).
    assert!(
        kernel
            .syscall_gate
            .check_tool_call_declared(a1.id, "tenant_a_tool", "/x", 5, &security)
            .await
            .is_ok(),
        "tenant-A agent should see tenant-A's tool"
    );

    // Tenant-B agent: denied with NotInNamespace — never learns the tool exists.
    let r = kernel
        .syscall_gate
        .check_tool_call_declared(b1.id, "tenant_a_tool", "/x", 5, &security)
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
        .create_agent_for_tenant(&t_a, cfg("a1", "full-access"))
        .await
        .unwrap();
    let b1 = kernel
        .create_agent_for_tenant(&t_b, cfg("b1", "full-access"))
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

/// (c) Cgroup resource isolation: tenant A filling its agent's concurrent-tool
/// slot does not block tenant B.
#[tokio::test]
async fn per_tenant_cgroup_tool_capacity_is_isolated() {
    use kernel::syscall_gate::GateDenial;

    let budgets = kernel::config::BudgetConfig {
        max_concurrent_tool_calls: 1,
        ..Default::default()
    };
    let cm = std::sync::Arc::new(kernel::context::SqliteContextManager::in_memory().unwrap());
    let kernel = AgentKernelImpl::with_context_manager(cm, &budgets, false, &[]).expect("kernel");

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

    let held = kernel.syscall_gate.acquire_tool_call(a1.id).unwrap();
    let denied = kernel.syscall_gate.acquire_tool_call(a1.id);
    assert!(
        matches!(denied, Err(GateDenial::CgroupToolLimit)),
        "tenant A's second concurrent call should be denied"
    );

    // Tenant B is unaffected because it has an independent hierarchy.
    let peer = kernel.syscall_gate.acquire_tool_call(b1.id);
    assert!(peer.is_ok(), "tenant B must retain independent capacity");
    drop((held, peer));
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

/// Revocation is durable, not merely a process-local cache mutation. Session
/// and API-key secrets remain invalid after reopening the same database.
#[tokio::test]
async fn credential_revocation_survives_restart() {
    let dir = std::env::temp_dir().join(format!("auth-restart-{}", uuid::Uuid::new_v4()));
    let db = dir.join("agent_os.db");
    let (session, key) = {
        let kernel = AgentKernelImpl::with_db_path(&db).expect("kernel boot");
        let tenant = kernel.create_tenant("acme").await.unwrap();
        let user = kernel
            .register_user(&tenant, "alice", "alice@acme.test", Role::User)
            .await
            .unwrap();
        let session = kernel.open_session(&user).await.unwrap();
        let key = kernel.issue_api_key(&user, "automation").await.unwrap();
        assert!(kernel.revoke_session(&session).await.unwrap());
        assert!(kernel.revoke_api_key(&key).await.unwrap());
        (session, key)
    };

    let kernel = AgentKernelImpl::with_db_path(&db).expect("kernel reboot");
    assert!(kernel.resolve_principal(&session).await.is_none());
    assert!(kernel.resolve_principal(&key).await.is_none());
    std::fs::remove_dir_all(&dir).ok();
}

/// User and tenant revocation cascade to all credentials and survive restart.
#[tokio::test]
async fn identity_revocation_cascades_and_survives_restart() {
    let dir = std::env::temp_dir().join(format!("identity-restart-{}", uuid::Uuid::new_v4()));
    let db = dir.join("agent_os.db");
    let (user_session, user_key, tenant_session, tenant_key) = {
        let kernel = AgentKernelImpl::with_db_path(&db).expect("kernel boot");
        let user_tenant = kernel.create_tenant("user-revoke").await.unwrap();
        let tenant_to_revoke = kernel.create_tenant("tenant-revoke").await.unwrap();
        let user = kernel
            .register_user(&user_tenant, "alice", "alice@test", Role::User)
            .await
            .unwrap();
        let tenant_user = kernel
            .register_user(&tenant_to_revoke, "bob", "bob@test", Role::Admin)
            .await
            .unwrap();
        let user_session = kernel.open_session(&user).await.unwrap();
        let user_key = kernel.issue_api_key(&user, "user-key").await.unwrap();
        let tenant_session = kernel.open_session(&tenant_user).await.unwrap();
        let tenant_key = kernel
            .issue_api_key(&tenant_user, "tenant-key")
            .await
            .unwrap();
        assert!(kernel.revoke_user(&user).await.unwrap());
        assert!(kernel.revoke_tenant(&tenant_to_revoke).await.unwrap());
        (user_session, user_key, tenant_session, tenant_key)
    };

    let kernel = AgentKernelImpl::with_db_path(&db).expect("kernel reboot");
    for revoked in [user_session, user_key, tenant_session, tenant_key] {
        assert!(
            kernel.resolve_principal(&revoked).await.is_none(),
            "revoked credential reappeared after restart"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// Rehydration preserves the exact tenant and role, while an unknown persisted
/// role is skipped rather than silently downgraded to a writable default.
#[tokio::test]
async fn rehydrated_credentials_preserve_authority_and_unknown_roles_fail_closed() {
    let dir = std::env::temp_dir().join(format!("role-restart-{}", uuid::Uuid::new_v4()));
    let db = dir.join("agent_os.db");
    let (tenant, user, key, session) = {
        let kernel = AgentKernelImpl::with_db_path(&db).expect("kernel boot");
        let tenant = kernel.create_tenant("role-test").await.unwrap();
        let user = kernel
            .register_user(&tenant, "admin", "admin@test", Role::Admin)
            .await
            .unwrap();
        let key = kernel.issue_api_key(&user, "role-key").await.unwrap();
        let session = kernel.open_session(&user).await.unwrap();
        (tenant, user, key, session)
    };

    {
        let kernel = AgentKernelImpl::with_db_path(&db).expect("kernel reboot");
        for credential in [&key, &session] {
            let principal = kernel
                .resolve_principal(credential)
                .await
                .expect("valid credential must rehydrate");
            assert_eq!(principal.tenant_id, tenant);
            assert_eq!(principal.role, Role::Admin);
        }
    }

    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE users SET role = 'unknown-owner' WHERE id = ?1",
            rusqlite::params![user],
        )
        .unwrap();
    }
    let kernel = AgentKernelImpl::with_db_path(&db).expect("kernel reboot with invalid role");
    assert!(kernel.resolve_principal(&key).await.is_none());
    assert!(kernel.resolve_principal(&session).await.is_none());
    std::fs::remove_dir_all(&dir).ok();
}

/// Durable accounting is tenant-scoped: two agents in one tenant contribute to
/// the same restored ceiling, while an equally active agent in another tenant
/// retains an independent allowance after restart.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_spend_rehydrates_shared_within_tenant_and_isolated_across_tenants() {
    use kernel::budget::BudgetScope;

    const PROVIDER: &str = "fixed-tenant-accounting";
    const PER_AGENT_MICROS: u64 = 20_000;

    let dir = std::env::temp_dir().join(format!("tenant-spend-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    let mut first_config = Config {
        data_dir: dir.clone(),
        ..Config::default()
    };
    first_config.budgets.usd_per_1k_tokens = 1.0;
    first_config.budgets.max_usd = 0.0;
    first_config.budgets.per_agent_max_usd = 0.0;
    first_config.budgets.per_tenant_max_usd = 1.0;

    let (tenant_a, tenant_b, a1, a2, b1) = {
        let kernel = AgentKernelImpl::from_config(&first_config).expect("first boot");
        let calls =
            super::persistence_props::register_fixed_usage_provider(&kernel, PROVIDER, 12, 8);
        let tenant_a = kernel.create_tenant("accounting-a").await.unwrap();
        let tenant_b = kernel.create_tenant("accounting-b").await.unwrap();
        let provider_cfg = |name: &str| AgentConfig {
            name: name.into(),
            task: "exercise tenant accounting".into(),
            llm_provider: PROVIDER.into(),
            permission_profile: "standard".into(),
            priority: kernel::Priority::default(),
            sandbox_config: None,
        };
        let a1 = kernel
            .create_agent_for_tenant(&tenant_a, provider_cfg("a1"))
            .await
            .unwrap()
            .id;
        let a2 = kernel
            .create_agent_for_tenant(&tenant_a, provider_cfg("a2"))
            .await
            .unwrap()
            .id;
        let b1 = kernel
            .create_agent_for_tenant(&tenant_b, provider_cfg("b1"))
            .await
            .unwrap()
            .id;

        for agent in [a1, a2, b1] {
            let output = kernel
                .send_message(agent, "record tenant-scoped spend")
                .await
                .expect("provider request");
            assert_eq!(output.usage.charged_cost_micros, PER_AGENT_MICROS);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        drop(kernel);
        (tenant_a, tenant_b, a1, a2, b1)
    };

    // Reboot with a different price and a ceiling exactly equal to tenant A's
    // prior aggregate. Historical charges remain fixed; both A agents are
    // denied by their shared restored total, while tenant B remains eligible.
    let mut restart_config = first_config.clone();
    restart_config.budgets.usd_per_1k_tokens = 50.0;
    restart_config.budgets.per_tenant_max_usd = 0.04;
    let kernel = AgentKernelImpl::from_config(&restart_config).expect("restart");
    let snapshot = kernel
        .context_manager
        .load_budget_usage_snapshot()
        .expect("load exact usage snapshot");
    assert_eq!(snapshot.global_micros, PER_AGENT_MICROS * 3);
    for agent in [a1, a2, b1] {
        assert_eq!(
            snapshot.per_agent_micros.get(&agent),
            Some(&PER_AGENT_MICROS)
        );
    }
    assert_eq!(
        snapshot.per_tenant_micros.get(&tenant_a),
        Some(&(PER_AGENT_MICROS * 2))
    );
    assert_eq!(
        snapshot.per_tenant_micros.get(&tenant_b),
        Some(&PER_AGENT_MICROS)
    );
    assert_eq!(kernel.budget_enforcer.tenant_spent_usd(&tenant_a), 0.04);
    assert_eq!(kernel.budget_enforcer.tenant_spent_usd(&tenant_b), 0.02);

    for agent in [a1, a2] {
        let denial = kernel
            .budget_enforcer
            .check(agent)
            .expect_err("tenant A must share its restored ceiling");
        assert_eq!(denial.scope, BudgetScope::Tenant);
        assert_eq!(denial.spent_usd, 0.04);
        assert_eq!(denial.limit_usd, 0.04);
    }
    kernel
        .budget_enforcer
        .check(b1)
        .expect("tenant B spend must remain isolated from tenant A");

    drop(kernel);
    std::fs::remove_dir_all(&dir).ok();
}
