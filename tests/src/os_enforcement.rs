//! OS-ness end-to-end enforcement tests.
//!
//! These tests are the proof that the Linux-mapped subsystems are load-bearing
//! on the runtime path: registering an agent with the kernel and exercising
//! the syscall gate must produce the right denials for capability, MAC, and
//! cgroup violations. If any of these flake, the "AI Agent OS" framing is
//! broken — these are the contract.

use std::sync::Arc;

use kernel::agent_struct::CapabilitySet;
use kernel::cgroups::{CgroupLimits, CgroupManager};
use kernel::mac::PolicyRule;
use kernel::syscall_gate::{GateDenial, SyscallGate};

fn fresh_gate() -> (Arc<SyscallGate>, Arc<CgroupManager>) {
    let cgroups = Arc::new(CgroupManager::new());
    let gate = Arc::new(SyscallGate::new(cgroups.clone()));
    (gate, cgroups)
}

/// Capability layer: an agent with no CAP_NET_ACCESS is denied a network tool.
#[tokio::test]
async fn capability_denies_network_tool_without_cap_net() {
    let (gate, _cg) = fresh_gate();
    let kid = uuid::Uuid::new_v4();
    // Read-only-ish caps: no CAP_NET_ACCESS.
    gate.register_agent(kid, CapabilitySet::none(), None);

    let result = gate
        .check_tool_call(kid, "http_get", "https://example.com", 5)
        .await;
    match result {
        Err(GateDenial::MissingCapability(cap)) => assert_eq!(cap, CapabilitySet::CAP_NET_ACCESS),
        other => panic!(
            "expected MissingCapability(CAP_NET_ACCESS), got {:?}",
            other
        ),
    }

    // Reads should still pass — no capability required.
    let result = gate
        .check_tool_call(kid, "read_file", "/etc/hosts", 5)
        .await;
    assert!(
        result.is_ok(),
        "read_file should pass without capability requirements"
    );

    // Granting CAP_NET_ACCESS unblocks the network tool.
    let mut caps = CapabilitySet::none();
    caps.grant(CapabilitySet::CAP_NET_ACCESS);
    gate.set_capabilities(kid, caps);
    let result = gate
        .check_tool_call(kid, "http_get", "https://example.com", 5)
        .await;
    assert!(result.is_ok(), "http_get should pass with CAP_NET_ACCESS");
}

/// Cgroup layer: an agent over its cgroup token quota is denied with quota error.
#[tokio::test]
async fn cgroup_quota_blocks_when_over_budget() {
    let (gate, cgroups) = fresh_gate();
    let cg = cgroups.create(
        "tight".into(),
        cgroups.root(),
        CgroupLimits {
            tokens_per_min: 100,
            ..Default::default()
        },
    );

    let kid = uuid::Uuid::new_v4();
    gate.register_agent(kid, CapabilitySet::all(), Some(cg));

    // Burn 90 tokens; now 30 more would breach the 100-token-per-minute cap.
    gate.record_tool_usage(kid, 90);
    let result = gate
        .check_tool_call(kid, "read_file", "/etc/hosts", 30)
        .await;
    assert_eq!(result, Err(GateDenial::CgroupQuota));

    // Resetting the per-minute counter restores headroom.
    cgroups.reset_minute_counters();
    let result = gate
        .check_tool_call(kid, "read_file", "/etc/hosts", 30)
        .await;
    assert!(result.is_ok(), "after reset the call should succeed");
}

/// MAC layer: an enforcing MAC policy denies a labelled agent's tool action.
#[tokio::test]
async fn mac_policy_denies_labelled_agent() {
    let (gate, _cg) = fresh_gate();
    let kid = uuid::Uuid::new_v4();
    let pid = gate.register_agent(kid, CapabilitySet::all(), None);

    {
        let mut mac = gate.mac.lock().await;
        mac.set_enforcing(true);
        mac.label_agent(pid, "untrusted".into());
        // Deny writes; allow everything else.
        mac.load_policy(vec![
            PolicyRule {
                subject: "untrusted".into(),
                action: "write".into(),
                object: "*".into(),
                decision: "deny".into(),
            },
            PolicyRule {
                subject: "untrusted".into(),
                action: "*".into(),
                object: "*".into(),
                decision: "allow".into(),
            },
        ]);
    }

    let result = gate
        .check_tool_call(kid, "write_file", "/tmp/secret", 5)
        .await;
    assert!(matches!(result, Err(GateDenial::MacDeny { .. })));

    // Reads must still pass under the same policy.
    let result = gate
        .check_tool_call(kid, "read_file", "/tmp/secret", 5)
        .await;
    assert!(
        result.is_ok(),
        "read should be allowed by the * → allow rule"
    );
}

/// Three layers stack: the gate hits whichever fires first, but counters
/// reflect the actual layer denied.
#[tokio::test]
async fn enforcement_stacks_in_order_capability_then_mac_then_cgroup() {
    let (gate, cgroups) = fresh_gate();
    let cg = cgroups.create(
        "stacked".into(),
        cgroups.root(),
        CgroupLimits {
            tokens_per_min: 50,
            ..Default::default()
        },
    );

    // Agent A: no CAP_FILE_WRITE. Capability layer should fire first.
    let a = uuid::Uuid::new_v4();
    gate.register_agent(a, CapabilitySet::none(), Some(cg));
    let r = gate.check_tool_call(a, "write_file", "/tmp/x", 5).await;
    assert!(matches!(r, Err(GateDenial::MissingCapability(_))));

    // Agent B: has all caps but MAC denies writes.
    let b = uuid::Uuid::new_v4();
    let pid_b = gate.register_agent(b, CapabilitySet::all(), Some(cg));
    {
        let mut mac = gate.mac.lock().await;
        mac.set_enforcing(true);
        mac.label_agent(pid_b, "ro".into());
        mac.load_policy(vec![
            PolicyRule {
                subject: "ro".into(),
                action: "write".into(),
                object: "*".into(),
                decision: "deny".into(),
            },
            PolicyRule {
                subject: "*".into(),
                action: "*".into(),
                object: "*".into(),
                decision: "allow".into(),
            },
        ]);
    }
    let r = gate.check_tool_call(b, "write_file", "/tmp/y", 5).await;
    assert!(matches!(r, Err(GateDenial::MacDeny { .. })));

    // Agent C: has caps, MAC allows, but the cgroup is already at quota.
    let c = uuid::Uuid::new_v4();
    let pid_c = gate.register_agent(c, CapabilitySet::all(), Some(cg));
    {
        let mut mac = gate.mac.lock().await;
        mac.label_agent(pid_c, "ok".into());
        // Existing rules already include subject "*" allow which matches "ok".
    }
    gate.record_tool_usage(c, 49);
    let r = gate.check_tool_call(c, "read_file", "/tmp/z", 5).await;
    assert_eq!(r, Err(GateDenial::CgroupQuota));

    let stats = gate.stats();
    assert_eq!(stats.denied_capability, 1);
    assert_eq!(stats.denied_mac, 1);
    assert_eq!(stats.denied_cgroup, 1);
}

/// Phase 2: creating an agent through the unified kernel really places it in
/// CFS, the default namespaces, and procfs — the OS-style subsystems are no
/// longer just decorative on a separate `OsKernel`.
#[tokio::test]
async fn unified_kernel_places_agent_in_os_subsystems() {
    use kernel::namespaces::NamespaceType;
    use kernel::{AgentConfig, AgentKernelImpl};

    let kernel = AgentKernelImpl::new().expect("kernel new");

    let config = AgentConfig {
        name: "phase-2-agent".into(),
        task: "test".into(),
        llm_provider: "stub".into(),
        permission_profile: "standard".into(),
        priority: kernel::Priority::new(3).unwrap(),
        sandbox_config: None,
    };
    let handle = kernel.create_agent_full(config).await.expect("create");
    let pid = kernel
        .syscall_gate
        .pid_of(handle.id)
        .expect("pid registered with gate");

    // 1. CFS scheduler holds the agent.
    {
        let sched = kernel.os.cfs.lock().await;
        assert!(
            sched.runnable_count() >= 1,
            "CFS should have the new agent enqueued"
        );
    }

    // 2. Default Agent namespace contains the PID.
    let agent_ns = kernel
        .os
        .namespaces
        .default_ns(NamespaceType::Agent)
        .expect("default agent ns");
    assert!(
        kernel.os.namespaces.members(agent_ns).contains(&pid),
        "agent should be a member of the default Agent namespace"
    );

    // 3. ProcFs has agent metadata.
    {
        let procfs = kernel.os.procfs.lock().await;
        let entry = procfs.read(&format!("/agents/{}/state", pid));
        assert!(
            entry.is_some(),
            "procfs should expose state for the new agent"
        );
    }

    // 4. After shutdown, the gate has unregistered the agent.
    kernel.shutdown().await.expect("shutdown");
    assert!(
        kernel.syscall_gate.pid_of(handle.id).is_none(),
        "syscall gate should drop the agent on shutdown"
    );
}

/// Phase 3: a tool registered in namespace X is invisible to an agent in
/// namespace Y. The gate denies with `NotInNamespace` (≈ ENOENT) — the LLM
/// learns nothing about a tool it cannot see.
#[tokio::test]
async fn namespace_isolation_denies_foreign_tool() {
    let (gate, _cg) = fresh_gate();

    // Two namespaces: "team-a" (id 100) and "team-b" (id 200). The actual ids
    // are arbitrary u64s — in production they come from `NamespaceRegistry`.
    let ns_a: u64 = 100;
    let ns_b: u64 = 200;

    // Tool `db_admin` is exclusive to team-a's namespace.
    gate.register_tool_namespace("db_admin", ns_a);

    // Agent in team-a can call it.
    let alice = uuid::Uuid::new_v4();
    gate.register_agent(alice, CapabilitySet::all(), None);
    gate.set_agent_namespaces(alice, vec![ns_a]);
    let r = gate
        .check_tool_call(alice, "db_admin", "/db/users", 5)
        .await;
    assert!(
        r.is_ok(),
        "agent in tool's namespace should resolve the tool"
    );

    // Agent in team-b is denied with NotInNamespace.
    let bob = uuid::Uuid::new_v4();
    gate.register_agent(bob, CapabilitySet::all(), None);
    gate.set_agent_namespaces(bob, vec![ns_b]);
    let r = gate.check_tool_call(bob, "db_admin", "/db/users", 5).await;
    match r {
        Err(GateDenial::NotInNamespace { tool, namespace }) => {
            assert_eq!(tool, "db_admin");
            assert_eq!(namespace, ns_a);
        }
        other => panic!("expected NotInNamespace denial, got {:?}", other),
    }

    // Untagged tools remain global — bob can still call read_file.
    let r = gate
        .check_tool_call(bob, "read_file", "/etc/hosts", 5)
        .await;
    assert!(r.is_ok(), "global (untagged) tools must remain visible");

    // Adding bob to team-a unblocks db_admin for him without restarting.
    gate.add_agent_namespace(bob, ns_a);
    let r = gate.check_tool_call(bob, "db_admin", "/db/users", 5).await;
    assert!(
        r.is_ok(),
        "after joining the namespace bob can resolve the tool"
    );

    // Counter increment is observable.
    let stats = gate.stats();
    assert_eq!(
        stats.denied_namespace, 1,
        "one namespace denial recorded across the run"
    );
}

/// Phase 3: namespace check runs *before* MAC and capability so the agent
/// receives a uniform "doesn't exist" denial and cannot probe foreign tools
/// to discover whether they would be MAC-allowed.
#[tokio::test]
async fn namespace_denial_precedes_capability_and_mac() {
    let (gate, _cg) = fresh_gate();
    let ns_secure: u64 = 42;
    gate.register_tool_namespace("write_file", ns_secure);

    // Agent has CAP_FILE_WRITE *and* MAC would allow, but it's not in the
    // namespace — namespace must fire first.
    let kid = uuid::Uuid::new_v4();
    let pid = gate.register_agent(kid, CapabilitySet::all(), None);
    {
        let mut mac = gate.mac.lock().await;
        mac.set_enforcing(true);
        mac.label_agent(pid, "trusted".into());
        mac.load_policy(vec![PolicyRule {
            subject: "*".into(),
            action: "*".into(),
            object: "*".into(),
            decision: "allow".into(),
        }]);
    }
    // Note: agent intentionally has no namespaces.
    let r = gate.check_tool_call(kid, "write_file", "/tmp/x", 5).await;
    match r {
        Err(GateDenial::NotInNamespace { .. }) => {}
        other => panic!(
            "namespace must take precedence over capability/MAC, got {:?}",
            other
        ),
    }

    let stats = gate.stats();
    assert_eq!(stats.denied_namespace, 1);
    assert_eq!(stats.denied_capability, 0);
    assert_eq!(stats.denied_mac, 0);
}

/// Phase 3: nice values change observable scheduler ordering. After both
/// agents accumulate equal "token spend", the lower-nice agent (higher
/// priority, larger weight) has lower vruntime and is the one CFS picks next.
#[tokio::test]
async fn nice_values_change_scheduler_pick_next() {
    use kernel::{AgentConfig, AgentKernelImpl};

    let kernel = AgentKernelImpl::new().expect("kernel new");

    let config_for = |name: &str| AgentConfig {
        name: name.to_string(),
        task: "test".into(),
        llm_provider: "stub".into(),
        permission_profile: "standard".into(),
        priority: kernel::Priority::new(3).unwrap(),
        sandbox_config: None,
    };

    let high_pri = kernel
        .create_agent_full(config_for("high-priority"))
        .await
        .expect("create high");
    let low_pri = kernel
        .create_agent_full(config_for("low-priority"))
        .await
        .expect("create low");

    kernel
        .set_nice(high_pri.id, -10)
        .await
        .expect("set nice high");
    kernel.set_nice(low_pri.id, 10).await.expect("set nice low");

    let high_pid = kernel.syscall_gate.pid_of(high_pri.id).unwrap();
    let low_pid = kernel.syscall_gate.pid_of(low_pri.id).unwrap();

    {
        let mut sched = kernel.os.cfs.lock().await;
        sched.account_tokens(high_pid, 1000);
        sched.account_tokens(low_pid, 1000);
    }

    let next = kernel.next_runnable_agent().await;
    assert_eq!(
        next,
        Some(high_pri.id),
        "after equal token spend, CFS must pick the lower-nice agent first"
    );

    let (high_share, low_share) = {
        let sched = kernel.os.cfs.lock().await;
        (sched.fair_share(high_pid), sched.fair_share(low_pid))
    };
    assert!(
        high_share > low_share,
        "fair_share for nice=-10 ({}) must exceed nice=+10 ({})",
        high_share,
        low_share
    );
}

/// Phase 3: IPC respects namespace isolation. An agent in namespace X cannot
/// send a message to an agent in namespace Y. The error is `AgentNotFound` —
/// the same response as a non-existent agent — so a sender cannot probe for
/// the existence of foreign mailboxes.
#[tokio::test]
async fn namespace_isolation_blocks_cross_namespace_ipc() {
    use kernel::ipc::AgentIpc;
    use kernel::IpcError;

    let (gate, _cg) = fresh_gate();
    let alice = uuid::Uuid::new_v4();
    let bob = uuid::Uuid::new_v4();
    let carol = uuid::Uuid::new_v4();

    gate.register_agent(alice, CapabilitySet::all(), None);
    gate.register_agent(bob, CapabilitySet::all(), None);
    gate.register_agent(carol, CapabilitySet::all(), None);

    gate.set_agent_namespaces(alice, vec![100]);
    gate.set_agent_namespaces(bob, vec![100]);
    gate.set_agent_namespaces(carol, vec![200]);

    let ipc = std::sync::Arc::new(kernel::ipc::IpcManager::new());
    ipc.set_namespace_visibility(gate.clone());
    ipc.register_agent(alice);
    ipc.register_agent(bob);
    ipc.register_agent(carol);

    ipc.send(alice, bob, serde_json::json!({"hello": "bob"}))
        .await
        .expect("alice → bob (same ns) should succeed");

    let r = ipc
        .send(alice, carol, serde_json::json!({"leak": true}))
        .await;
    match r {
        Err(IpcError::AgentNotFound(id)) => assert_eq!(id, carol),
        other => panic!("expected AgentNotFound, got {:?}", other),
    }

    gate.add_agent_namespace(alice, 200);
    ipc.send(alice, carol, serde_json::json!({"now visible": true}))
        .await
        .expect("after joining team-b, alice → carol should succeed");
}

/// LIVE-PATH cgroup enforcement: an agent created via `create_agent_full` now
/// lands in a bounded per-profile cgroup, so `CgroupQuota` fires for a
/// non-`full-access` profile while `full-access` stays unlimited. (The existing
/// `cgroup_quota_blocks_when_over_budget` only exercises a hand-built cgroup;
/// this covers the real agent-creation path the CLI/Tauri use.)
#[tokio::test]
async fn live_create_path_enforces_cgroup_quota() {
    use kernel::{AgentConfig, AgentKernelImpl};

    let kernel = AgentKernelImpl::new().expect("kernel new");
    let cfg = |name: &str, profile: &str| AgentConfig {
        name: name.into(),
        task: "test".into(),
        llm_provider: "stub".into(),
        permission_profile: profile.into(),
        priority: kernel::Priority::new(3).unwrap(),
        sandbox_config: None,
    };

    // "standard" → bounded cgroup (default 50_000 tok/min). A single call
    // estimating more than the per-minute budget is denied with CgroupQuota.
    let std_agent = kernel
        .create_agent_full(cfg("std", "standard"))
        .await
        .unwrap();
    let denied = kernel
        .syscall_gate
        .check_tool_call(std_agent.id, "read_file", "/x", 60_000)
        .await;
    assert!(
        matches!(denied, Err(GateDenial::CgroupQuota)),
        "standard agent over budget should be denied CgroupQuota, got {denied:?}"
    );
    // A small call stays within budget.
    assert!(kernel
        .syscall_gate
        .check_tool_call(std_agent.id, "read_file", "/x", 10)
        .await
        .is_ok());

    // "full-access" → unlimited cgroup: the same large call is allowed.
    let fa = kernel
        .create_agent_full(cfg("fa", "full-access"))
        .await
        .unwrap();
    assert!(
        kernel
            .syscall_gate
            .check_tool_call(fa.id, "read_file", "/x", 60_000)
            .await
            .is_ok(),
        "full-access agent should be unlimited"
    );
}

/// Shutdown frees CFS run-queue entries — previously `runnable_count` only ever
/// grew because agents were enqueued at creation and never dequeued.
#[tokio::test]
async fn shutdown_dequeues_agents_from_cfs() {
    use kernel::{AgentConfig, AgentKernelImpl};

    let kernel = AgentKernelImpl::new().expect("kernel new");
    let cfg = |name: &str| AgentConfig {
        name: name.into(),
        task: "test".into(),
        llm_provider: "stub".into(),
        permission_profile: "standard".into(),
        priority: kernel::Priority::new(3).unwrap(),
        sandbox_config: None,
    };
    for i in 0..3 {
        kernel
            .create_agent_full(cfg(&format!("a{i}")))
            .await
            .unwrap();
    }
    assert_eq!(kernel.os.cfs.lock().await.runnable_count(), 3);

    kernel.shutdown().await.unwrap();
    assert_eq!(
        kernel.os.cfs.lock().await.runnable_count(),
        0,
        "shutdown should dequeue every agent from the CFS run queue"
    );
}
