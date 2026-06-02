//! Governed multi-agent execution — the product-thesis proof, offline.
//!
//! This is the end-to-end demonstration that AI Agent OS *contains and audits*
//! policy-violating agents while compliant agents keep working. It boots a real
//! `AgentKernelImpl`, creates several agents through the live `create_agent_full`
//! path, and drives the *same* `SyscallGate::check_tool_call` chokepoint that
//! `AgentExecutor` uses in production (`crates/kernel/src/execution.rs`). The
//! enforcement happens at the gate **before** the resource broker and requires
//! **no LLM** — so the whole governance story is deterministic and runs in CI
//! with no API keys and no network.
//!
//! The scenario, and what it proves:
//!  - A read-only agent's `write_file` is denied at the *capability* layer — the
//!    broker is never reached.
//!  - A budget-capped agent exhausts a tiny cgroup token quota and is then denied
//!    at the *cgroup* layer, while a well-funded agent's identical call succeeds.
//!  - A namespaced agent is denied a foreign-namespace tool with `NotInNamespace`
//!    (≈ ENOENT), while a member of that namespace calls the same tool fine.
//!  - A MAC-policy violator's write is denied at the *MAC* layer and the denial
//!    lands in the audit trail (a wired `AuditSink` receives the deny event).
//!  - A compliant agent's allowed calls succeed throughout — one agent's
//!    violations never take the others down. Containment / isolation holds.
//!
//! Patterns (gate construction, profiles, cgroup budgets, namespace tagging,
//! audit sink) are adapted from `tests/src/os_enforcement.rs`.

use std::sync::{Arc, Mutex};

use kernel::cgroups::CgroupLimits;
use kernel::mac::PolicyRule;
use kernel::syscall_gate::{AuditDecision, AuditEvent, AuditSink, GateDenial};
use kernel::{AgentConfig, AgentKernelImpl};

/// A test audit sink that records every event the gate emits (MAC audit/deny).
/// The kernel wires its observability engine in as the real sink; here we use a
/// recording sink so the test can assert the audit trail captured the violation.
struct RecordingSink(Mutex<Vec<AuditEvent>>);

impl AuditSink for RecordingSink {
    fn audit(&self, event: AuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

impl RecordingSink {
    fn new() -> Arc<Self> {
        Arc::new(RecordingSink(Mutex::new(Vec::new())))
    }

    fn events(&self) -> Vec<AuditEvent> {
        self.0.lock().unwrap().clone()
    }
}

fn agent_cfg(name: &str, profile: &str) -> AgentConfig {
    AgentConfig {
        name: name.into(),
        task: "governed-execution".into(),
        llm_provider: "stub".into(),
        permission_profile: profile.into(),
        priority: kernel::Priority::new(3).unwrap(),
        sandbox_config: None,
    }
}

/// The full governed multi-agent scenario in one deterministic, offline test:
/// several agents run, the violators are contained and audited, the compliant
/// ones keep working.
#[tokio::test]
async fn governed_multi_agent_execution_contains_and_audits_violators() {
    let kernel = AgentKernelImpl::new().expect("kernel new");

    // Wire a recording audit sink so MAC-layer denials/audits are observable as
    // a real audit trail (the production kernel wires observability here).
    let sink = RecordingSink::new();
    kernel.syscall_gate.set_audit_sink(sink.clone());

    // The cast of agents in our governed workspace.
    //  - `analyst`    : read-only profile (no write/exec/net caps).
    //  - `frugal`     : standard profile, placed in a *tiny* token budget.
    //  - `funded`     : standard profile, generous budget — the control.
    //  - `compliant`  : standard profile, only ever makes allowed calls.
    //  - `intruder`   : standard profile, will trip an enforcing MAC rule.
    let analyst = kernel
        .create_agent_full(agent_cfg("analyst", "read-only"))
        .await
        .expect("create analyst");
    let frugal = kernel
        .create_agent_full(agent_cfg("frugal", "standard"))
        .await
        .expect("create frugal");
    let funded = kernel
        .create_agent_full(agent_cfg("funded", "standard"))
        .await
        .expect("create funded");
    let compliant = kernel
        .create_agent_full(agent_cfg("compliant", "standard"))
        .await
        .expect("create compliant");
    let intruder = kernel
        .create_agent_full(agent_cfg("intruder", "standard"))
        .await
        .expect("create intruder");

    // ── Baseline: every agent starts compliant; a read is universally allowed. ──
    for who in [analyst.id, frugal.id, funded.id, compliant.id, intruder.id] {
        let r = kernel
            .syscall_gate
            .check_tool_call(who, "read_file", "/workspace/notes.txt", 5)
            .await;
        assert!(r.is_ok(), "baseline read should be allowed, got {r:?}");
    }

    // ── VIOLATION 1: capability — read-only agent attempts a write. ───────────
    // Denied at the capability layer. The broker is never consulted (the gate is
    // the chokepoint *before* the resource broker), so nothing is written.
    let r = kernel
        .syscall_gate
        .check_tool_call(analyst.id, "write_file", "/workspace/out.txt", 5)
        .await;
    assert!(
        matches!(r, Err(GateDenial::MissingCapability(_))),
        "read-only write must be denied at capability layer, got {r:?}"
    );

    // ── VIOLATION 2: cgroup quota — exhaust a tiny budget, then deny. ─────────
    // Attach `frugal` to a 100-token/min cgroup; `funded` to a generous one.
    let tight = kernel.cgroups.create(
        "gov-tight".into(),
        kernel.cgroups.root(),
        CgroupLimits {
            tokens_per_min: 100,
            ..Default::default()
        },
    );
    let generous = kernel.cgroups.create(
        "gov-generous".into(),
        kernel.cgroups.root(),
        CgroupLimits {
            tokens_per_min: 1_000_000,
            ..Default::default()
        },
    );
    kernel.syscall_gate.set_cgroup(frugal.id, tight);
    kernel.syscall_gate.set_cgroup(funded.id, generous);

    // Burn 90 of frugal's 100 tokens, then a 30-token call breaches the cap.
    kernel.syscall_gate.record_tool_usage(frugal.id, 90);
    let r = kernel
        .syscall_gate
        .check_tool_call(frugal.id, "read_file", "/workspace/big.txt", 30)
        .await;
    assert_eq!(
        r,
        Err(GateDenial::CgroupQuota),
        "frugal over budget (90+30 > 100) must be denied CgroupQuota"
    );

    // The *identical* call by the well-funded agent still succeeds — the
    // over-budget agent is contained without affecting its peer.
    let r = kernel
        .syscall_gate
        .check_tool_call(funded.id, "read_file", "/workspace/big.txt", 30)
        .await;
    assert!(
        r.is_ok(),
        "well-funded agent's identical call must still succeed, got {r:?}"
    );

    // ── VIOLATION 3: namespace — foreign-namespace tool is invisible. ─────────
    // A privileged tool lives only in the `secure-ops` namespace (id 7000). The
    // intruder never joined it; `compliant` (the "operator") is a member.
    let secure_ns: u64 = 7000;
    kernel
        .syscall_gate
        .register_tool_namespace("rotate_secrets", secure_ns);
    kernel
        .syscall_gate
        .add_agent_namespace(compliant.id, secure_ns);

    let r = kernel
        .syscall_gate
        .check_tool_call(intruder.id, "rotate_secrets", "/vault/key", 5)
        .await;
    assert!(
        matches!(
            r,
            Err(GateDenial::NotInNamespace { ref tool, namespace })
                if tool == "rotate_secrets" && namespace == secure_ns
        ),
        "intruder must be denied the foreign-namespace tool, got {r:?}"
    );

    // A member of the namespace calls the *same* tool successfully.
    let r = kernel
        .syscall_gate
        .check_tool_call(compliant.id, "rotate_secrets", "/vault/key", 5)
        .await;
    assert!(
        r.is_ok(),
        "namespace member must resolve the same tool, got {r:?}"
    );

    // ── VIOLATION 4: MAC — an enforcing policy denies the intruder's write, ──
    // and the denial is captured by the audit sink (the audit trail).
    {
        let mut mac = kernel.syscall_gate.mac.lock().await;
        mac.set_enforcing(true);
        mac.load_policy(vec![
            // Deny writes under /etc by any subject.
            PolicyRule {
                subject: "*".into(),
                action: "write".into(),
                object: "/etc/**".into(),
                decision: "deny".into(),
            },
            // Allow everything else, so the rest of the scenario is unaffected.
            PolicyRule {
                subject: "*".into(),
                action: "*".into(),
                object: "*".into(),
                decision: "allow".into(),
            },
        ]);
    }
    let r = kernel
        .syscall_gate
        .check_tool_call(intruder.id, "write_file", "/etc/passwd", 5)
        .await;
    assert!(
        matches!(r, Err(GateDenial::MacDeny { .. })),
        "intruder's write to /etc must be denied at MAC layer, got {r:?}"
    );

    // ── CONTAINMENT: the compliant agent keeps working throughout. ───────────
    // A normal write to its own workspace (outside /etc) passes capability and
    // the MAC catch-all, and it is well within the default budget.
    let r = kernel
        .syscall_gate
        .check_tool_call(compliant.id, "write_file", "/workspace/report.txt", 5)
        .await;
    assert!(
        r.is_ok(),
        "compliant agent's allowed write must still succeed — isolation holds, got {r:?}"
    );
    // And the funded agent can still work too — no global lockout from the
    // enforcing MAC policy (its writes are outside /etc).
    let r = kernel
        .syscall_gate
        .check_tool_call(funded.id, "write_file", "/workspace/data.txt", 5)
        .await;
    assert!(
        r.is_ok(),
        "funded agent unaffected by another agent's MAC violation, got {r:?}"
    );

    // ── AUDIT TRAIL: violations are recorded. ─────────────────────────────────
    // 1. GateStats denial counters incremented for the right buckets.
    let stats = kernel.syscall_gate.stats();
    assert_eq!(
        stats.denied_capability, 1,
        "exactly one capability denial recorded"
    );
    assert_eq!(
        stats.denied_cgroup, 1,
        "exactly one cgroup-quota denial recorded"
    );
    assert_eq!(
        stats.denied_namespace, 1,
        "exactly one namespace denial recorded"
    );
    assert_eq!(stats.denied_mac, 1, "exactly one MAC denial recorded");

    // 2. The MAC denial reached the audit sink as a Denied event with full
    //    forensic detail (subject, tool, action, resource). Capability/cgroup/
    //    namespace denials are counter-only by design (they never reach the MAC
    //    stage), so the sink captures the MAC-layer violation specifically.
    let events = sink.events();
    let deny = events
        .iter()
        .find(|e| e.decision == AuditDecision::Denied)
        .expect("a denial event must be in the audit trail");
    assert_eq!(deny.agent, intruder.id, "audit names the violating agent");
    assert_eq!(deny.tool, "write_file");
    assert_eq!(deny.action, "write");
    assert_eq!(deny.resource, "/etc/passwd");

    // 3. Compliant work outnumbered violations and was allowed — containment.
    assert!(
        stats.allowed >= 6,
        "compliant calls (baseline reads + allowed writes + member tool) must have \
         succeeded throughout, allowed={}",
        stats.allowed
    );

    kernel.shutdown().await.expect("shutdown");
}
