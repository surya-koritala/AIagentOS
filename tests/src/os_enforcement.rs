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

    let result = gate.check_tool_call(kid, "http_get", "https://example.com", 5).await;
    match result {
        Err(GateDenial::MissingCapability(cap)) => assert_eq!(cap, CapabilitySet::CAP_NET_ACCESS),
        other => panic!("expected MissingCapability(CAP_NET_ACCESS), got {:?}", other),
    }

    // Reads should still pass — no capability required.
    let result = gate.check_tool_call(kid, "read_file", "/etc/hosts", 5).await;
    assert!(result.is_ok(), "read_file should pass without capability requirements");

    // Granting CAP_NET_ACCESS unblocks the network tool.
    let mut caps = CapabilitySet::none();
    caps.grant(CapabilitySet::CAP_NET_ACCESS);
    gate.set_capabilities(kid, caps);
    let result = gate.check_tool_call(kid, "http_get", "https://example.com", 5).await;
    assert!(result.is_ok(), "http_get should pass with CAP_NET_ACCESS");
}

/// Cgroup layer: an agent over its cgroup token quota is denied with quota error.
#[tokio::test]
async fn cgroup_quota_blocks_when_over_budget() {
    let (gate, cgroups) = fresh_gate();
    let cg = cgroups.create(
        "tight".into(),
        cgroups.root(),
        CgroupLimits { tokens_per_min: 100, ..Default::default() },
    );

    let kid = uuid::Uuid::new_v4();
    gate.register_agent(kid, CapabilitySet::all(), Some(cg));

    // Burn 90 tokens; now 30 more would breach the 100-token-per-minute cap.
    gate.record_tool_usage(kid, 90);
    let result = gate.check_tool_call(kid, "read_file", "/etc/hosts", 30).await;
    assert_eq!(result, Err(GateDenial::CgroupQuota));

    // Resetting the per-minute counter restores headroom.
    cgroups.reset_minute_counters();
    let result = gate.check_tool_call(kid, "read_file", "/etc/hosts", 30).await;
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

    let result = gate.check_tool_call(kid, "write_file", "/tmp/secret", 5).await;
    assert!(matches!(result, Err(GateDenial::MacDeny { .. })));

    // Reads must still pass under the same policy.
    let result = gate.check_tool_call(kid, "read_file", "/tmp/secret", 5).await;
    assert!(result.is_ok(), "read should be allowed by the * → allow rule");
}

/// Three layers stack: the gate hits whichever fires first, but counters
/// reflect the actual layer denied.
#[tokio::test]
async fn enforcement_stacks_in_order_capability_then_mac_then_cgroup() {
    let (gate, cgroups) = fresh_gate();
    let cg = cgroups.create(
        "stacked".into(),
        cgroups.root(),
        CgroupLimits { tokens_per_min: 50, ..Default::default() },
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
            PolicyRule { subject: "ro".into(), action: "write".into(), object: "*".into(), decision: "deny".into() },
            PolicyRule { subject: "*".into(),  action: "*".into(),     object: "*".into(), decision: "allow".into() },
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
