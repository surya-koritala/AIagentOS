use super::*;

use crate::agent_struct::CapabilitySet;
use crate::syscall_gate::{GateDenial, GateStats};
use crate::tools::{SecurityAction, ToolSecurity};

const SYSTEM_TOKEN: &str = "gate-statistics-fixture-system";

async fn connect(addr: std::net::SocketAddr, token: &str) -> SyscallClient {
    let mut client = SyscallClient::connect(addr).await.unwrap();
    assert!(matches!(
        client
            .call(Syscall::Hello {
                protocol_version: PROTOCOL_VERSION
            })
            .await
            .unwrap(),
        SyscallReply::Hello { .. }
    ));
    assert!(matches!(
        client.authenticate(token).await.unwrap(),
        SyscallReply::Authenticated
    ));
    client
}

fn config(name: &str) -> AgentConfig {
    AgentConfig {
        name: name.into(),
        task: "counter fixture".into(),
        llm_provider: "stub".into(),
        permission_profile: "standard".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }
}

async fn counters(client: &mut SyscallClient, id: uuid::Uuid) -> GateStats {
    match client
        .call(Syscall::AgentInfo {
            agent_id: id.to_string(),
        })
        .await
        .unwrap()
    {
        SyscallReply::AgentInfo { gate_decisions, .. } => gate_decisions,
        other => panic!("expected owned agent counters, got {other:?}"),
    }
}

#[derive(Clone, Copy)]
enum DenialClass {
    Declaration,
    Namespace,
    Capability,
    Mac,
    Approval,
    Cgroup,
}

async fn assert_denial_exposed(class: DenialClass) {
    let mut security = crate::config::Config::default();
    security.budgets.max_concurrent_tool_calls = 1;
    let context = Arc::new(crate::context::SqliteContextManager::in_memory().unwrap());
    let kernel = Arc::new(
        AgentKernelImpl::with_context_manager(
            context,
            &security.budgets,
            security.mac_enforcing,
            &security.mac_rules,
        )
        .unwrap(),
    );
    let tenant = kernel.create_tenant("counter-owner").await.unwrap();
    let reader = kernel
        .register_user(&tenant, "reader", "reader@counter.invalid", Role::ReadOnly)
        .await
        .unwrap();
    let key = kernel.issue_api_key(&reader, "counters").await.unwrap();
    let agent = kernel
        .create_agent_for_tenant(&tenant, config("owned-counter"))
        .await
        .unwrap();
    kernel
        .syscall_gate
        .set_capabilities(agent.id, CapabilitySet::all());
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap()
        .with_auth_token(SYSTEM_TOKEN);
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut system = connect(addr, SYSTEM_TOKEN).await;
    let mut reader = connect(addr, &key).await;
    assert_eq!(counters(&mut reader, agent.id).await, GateStats::default());

    let mut expected = GateStats::default();
    let mut slot = None;
    let (tool, args) = match class {
        DenialClass::Declaration => {
            expected.denied_unknown = 1;
            ("absent-counter-tool", serde_json::json!({}))
        }
        DenialClass::Namespace => {
            // An operator with the declared contract can observe the actual
            // gate's namespace verdict. Public hidden-name lookups instead
            // use the unknown class, proved separately below.
            kernel
                .syscall_gate
                .register_tool_namespace("read_file", u64::MAX);
            let security = ToolSecurity::constant(SecurityAction::Read, "counter:declared");
            assert!(matches!(
                kernel
                    .syscall_gate
                    .check_tool_call_declared(
                        agent.id,
                        "read_file",
                        "counter:declared",
                        0,
                        &security
                    )
                    .await,
                Err(GateDenial::NotInNamespace { .. })
            ));
            expected.denied_namespace = 1;
            ("", serde_json::Value::Null)
        }
        DenialClass::Capability => {
            kernel
                .syscall_gate
                .set_capabilities(agent.id, CapabilitySet::none());
            expected.denied_capability = 1;
            (
                "http_get",
                serde_json::json!({"url": "https://counter.invalid/never-requested"}),
            )
        }
        DenialClass::Mac => {
            kernel
                .syscall_gate
                .load_mac_policy(vec![crate::mac::PolicyRule {
                    subject: "*".into(),
                    action: "*".into(),
                    object: "*".into(),
                    decision: "deny".into(),
                }])
                .await;
            kernel.syscall_gate.set_mac_enforcing(true).await;
            expected.denied_mac = 1;
            (
                "read_file",
                serde_json::json!({"path": "counter-never-read.txt"}),
            )
        }
        DenialClass::Approval => {
            expected.denied_approval = 1;
            (
                "run_command",
                serde_json::json!({"command": "counter-never-executed", "args": []}),
            )
        }
        DenialClass::Cgroup => {
            // Exhaust the managed leaf's configured slot. Its membership is
            // immutable and must not be reassigned to manufacture a denial.
            let group = kernel.syscall_gate.agent_info(agent.id).unwrap().cgroup;
            assert_eq!(
                kernel
                    .cgroups
                    .get(group)
                    .unwrap()
                    .limits
                    .max_concurrent_tool_calls,
                1
            );
            slot = Some(kernel.syscall_gate.acquire_tool_call(agent.id).unwrap());
            expected.denied_cgroup = 1;
            (
                "read_file",
                serde_json::json!({"path": "counter-never-read.txt"}),
            )
        }
    };
    if !tool.is_empty() {
        assert!(matches!(
            system
                .call(Syscall::CallTool {
                    agent_id: agent.id.to_string(),
                    tool: tool.into(),
                    args,
                })
                .await
                .unwrap(),
            SyscallReply::TypedError { .. }
        ));
    }
    assert_eq!(counters(&mut reader, agent.id).await, expected);
    assert_eq!(
        counters(&mut reader, agent.id).await,
        expected,
        "introspection must not count itself"
    );
    assert_eq!(
        kernel.syscall_gate.stats(),
        expected,
        "one terminal verdict, without double counting"
    );
    drop(slot);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn declaration_denial_is_exposed_per_agent() {
    assert_denial_exposed(DenialClass::Declaration).await;
}
#[tokio::test]
async fn namespace_denial_is_exposed_per_agent() {
    assert_denial_exposed(DenialClass::Namespace).await;
}
#[tokio::test]
async fn capability_denial_is_exposed_per_agent() {
    assert_denial_exposed(DenialClass::Capability).await;
}
#[tokio::test]
async fn mac_denial_is_exposed_per_agent() {
    assert_denial_exposed(DenialClass::Mac).await;
}
#[tokio::test]
async fn approval_denial_is_exposed_per_agent() {
    assert_denial_exposed(DenialClass::Approval).await;
}
#[tokio::test]
async fn cgroup_denial_is_exposed_per_agent() {
    assert_denial_exposed(DenialClass::Cgroup).await;
}

#[tokio::test]
async fn hidden_and_absent_names_have_identical_errors_and_counter_deltas() {
    let kernel = AgentKernelImpl::new().unwrap();
    let tenant = kernel.create_tenant("counter-oracle").await.unwrap();
    let user = kernel
        .register_user(&tenant, "user", "user@counter.invalid", Role::User)
        .await
        .unwrap();
    let principal = Principal {
        user_id: user,
        tenant_id: tenant.clone(),
        role: Role::User,
        credential: None,
    };
    let agent = kernel
        .create_agent_for_tenant(&tenant, config("counter-oracle"))
        .await
        .unwrap();
    kernel
        .syscall_gate
        .register_tool_namespace("read_file", u64::MAX);
    let read = || Syscall::AgentInfo {
        agent_id: agent.id.to_string(),
    };
    let snapshot = |reply| match reply {
        SyscallReply::AgentInfo { gate_decisions, .. } => gate_decisions,
        other => panic!("expected owned counter reply, got {other:?}"),
    };
    let before = snapshot(dispatch_scoped(&kernel, read(), Some(&principal)).await);
    let hidden = dispatch_scoped(
        &kernel,
        Syscall::CallTool {
            agent_id: agent.id.to_string(),
            tool: "read_file".into(),
            args: serde_json::json!({"path":"never-read"}),
        },
        Some(&principal),
    )
    .await;
    let after_hidden = snapshot(dispatch_scoped(&kernel, read(), Some(&principal)).await);
    let absent = dispatch_scoped(
        &kernel,
        Syscall::CallTool {
            agent_id: agent.id.to_string(),
            tool: "absent-counter-tool".into(),
            args: serde_json::json!({}),
        },
        Some(&principal),
    )
    .await;
    let after_absent = snapshot(dispatch_scoped(&kernel, read(), Some(&principal)).await);
    assert_eq!(
        serde_json::to_value(hidden).unwrap(),
        serde_json::to_value(absent).unwrap()
    );
    assert_eq!(before, GateStats::default());
    assert_eq!(
        after_hidden,
        GateStats {
            denied_unknown: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        after_absent,
        GateStats {
            denied_unknown: 2,
            ..Default::default()
        }
    );
}

#[tokio::test]
async fn invalid_tool_declaration_counts_once_without_admitting_the_call() {
    let kernel = AgentKernelImpl::new().unwrap();
    let agent = kernel
        .create_agent_full(config("invalid-declaration"))
        .await
        .unwrap();
    assert!(matches!(
        dispatch(
            &kernel,
            Syscall::CallTool {
                agent_id: agent.id.to_string(),
                tool: "http_get".into(),
                args: serde_json::json!({"url":7}),
            }
        )
        .await,
        SyscallReply::Error { .. }
    ));
    assert_eq!(
        kernel.syscall_gate.agent_stats(agent.id),
        GateStats {
            denied_unknown: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        kernel.syscall_gate.stats(),
        GateStats {
            denied_unknown: 1,
            ..Default::default()
        }
    );
}

#[tokio::test]
async fn tenant_readonly_counters_reject_foreign_and_unknown_ids_with_typed_error() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let tenant_a = kernel.create_tenant("counter-a").await.unwrap();
    let tenant_b = kernel.create_tenant("counter-b").await.unwrap();
    let reader = kernel
        .register_user(
            &tenant_a,
            "reader",
            "reader@counter.invalid",
            Role::ReadOnly,
        )
        .await
        .unwrap();
    let key = kernel.issue_api_key(&reader, "counters").await.unwrap();
    let own = kernel
        .create_agent_for_tenant(&tenant_a, config("own"))
        .await
        .unwrap();
    let foreign = kernel
        .create_agent_for_tenant(&tenant_b, config("foreign"))
        .await
        .unwrap();
    kernel
        .syscall_gate
        .check_tool_call(foreign.id, "absent-counter-tool", "counter:absent", 0)
        .await
        .unwrap_err();
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap()
        .with_auth_token(SYSTEM_TOKEN);
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut client = connect(addr, &key).await;
    assert_eq!(counters(&mut client, own.id).await, GateStats::default());
    for id in [foreign.id, uuid::Uuid::new_v4()] {
        let reply = client
            .call(Syscall::AgentInfo {
                agent_id: id.to_string(),
            })
            .await
            .unwrap();
        assert!(matches!(
            reply,
            SyscallReply::TypedError {
                code: WireErrorCode::AuthorizationDenied,
                retryable: false,
                ..
            }
        ));
        assert!(!serde_json::to_string(&reply)
            .unwrap()
            .contains("gate_decisions"));
    }
    assert!(matches!(
        client.call(Syscall::GateStats).await.unwrap(),
        SyscallReply::TypedError {
            code: WireErrorCode::AuthorizationDenied,
            ..
        }
    ));
    assert_eq!(
        kernel.syscall_gate.agent_stats(foreign.id).denied_unknown,
        1
    );
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn allowed_and_audited_fields_are_reported_without_extra_decisions() {
    let kernel = AgentKernelImpl::new().unwrap();
    let agent = kernel
        .create_agent_full(config("audited-counter"))
        .await
        .unwrap();
    kernel
        .syscall_gate
        .load_mac_policy(vec![crate::mac::PolicyRule {
            subject: "*".into(),
            action: "read".into(),
            object: "*".into(),
            decision: "audit".into(),
        }])
        .await;
    kernel.syscall_gate.set_mac_enforcing(true).await;
    let (_, guard) = kernel
        .tool_registry
        .authorize_and_acquire_call(
            &kernel.syscall_gate,
            agent.id,
            "read_file",
            &serde_json::json!({"path":"counter-no-execution"}),
        )
        .await
        .unwrap();
    drop(guard);
    match dispatch(
        &kernel,
        Syscall::AgentInfo {
            agent_id: agent.id.to_string(),
        },
    )
    .await
    {
        SyscallReply::AgentInfo { gate_decisions, .. } => assert_eq!(
            gate_decisions,
            GateStats {
                allowed: 1,
                audited: 1,
                ..Default::default()
            }
        ),
        other => panic!("expected counters, got {other:?}"),
    }
}

#[test]
fn old_agent_info_defaults_counters_without_protocol_bump() {
    let old = r#"{"status":"agent_info","pid":7,"capabilities":[],"namespaces":[1]}"#;
    match serde_json::from_str::<SyscallReply>(old).unwrap() {
        SyscallReply::AgentInfo { gate_decisions, .. } => {
            assert_eq!(gate_decisions, GateStats::default())
        }
        other => panic!("expected backward-compatible AgentInfo, got {other:?}"),
    }
    assert_eq!(PROTOCOL_VERSION, 2);
    assert_eq!(MIN_PROTOCOL_VERSION, 1);
}

#[tokio::test]
async fn restored_agent_counters_reset_on_kernel_restart() {
    let root = std::env::temp_dir().join(format!("gate-counter-restart-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let database = root.join("agent_os.db");
    let id = {
        let kernel = AgentKernelImpl::with_db_path(&database).unwrap();
        let agent = kernel
            .create_agent_full(config("restart-counter"))
            .await
            .unwrap();
        assert!(matches!(
            dispatch(
                &kernel,
                Syscall::CallTool {
                    agent_id: agent.id.to_string(),
                    tool: "absent-counter-tool".into(),
                    args: serde_json::json!({}),
                }
            )
            .await,
            SyscallReply::Error { .. }
        ));
        assert_eq!(kernel.syscall_gate.agent_stats(agent.id).denied_unknown, 1);
        agent.id
    };
    {
        let restored = AgentKernelImpl::with_db_path(&database).unwrap();
        match dispatch(
            &restored,
            Syscall::AgentInfo {
                agent_id: id.to_string(),
            },
        )
        .await
        {
            SyscallReply::AgentInfo { gate_decisions, .. } => {
                assert_eq!(gate_decisions, GateStats::default())
            }
            other => panic!("restored agent should have fresh counters: {other:?}"),
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
