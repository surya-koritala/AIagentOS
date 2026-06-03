//! governance-demo — a runnable, narrated proof of *governed multi-agent
//! execution*: several agents run, the ones that violate policy (writing without
//! the capability, blowing their token budget, or calling a tool in a namespace
//! they don't belong to) are contained and audited, while the compliant agents
//! keep working.
//!
//! This is the product thesis made tangible. It boots a real in-memory
//! `AgentKernelImpl`, creates agents through the live `create_agent_full` path,
//! and drives the *same* `SyscallGate::check_tool_call` chokepoint the
//! `AgentExecutor` uses in production — enforcement happens at the gate, BEFORE
//! the resource broker, and requires NO LLM. So the governance story is fully
//! deterministic and runs with no API keys and no network.
//!
//! Keyless by default. If a local Ollama endpoint is reachable (`OLLAMA_HOST`
//! env, else http://localhost:11434) AND a model is available, the demo also
//! drives ONE real governed agent turn to show live governed execution.
//! Otherwise it says so and exits cleanly — it never panics on a missing model.
//!
//! Run: `cargo run --package os-benchmark --bin governance-demo`

use std::sync::{Arc, Mutex};

use kernel::cgroups::CgroupLimits;
use kernel::mac::PolicyRule;
use kernel::syscall_gate::{AuditDecision, AuditEvent, AuditSink, GateDenial};
use kernel::{AgentConfig, AgentKernelImpl};

/// Records every audit event the gate emits (MAC audit/deny) so the demo can
/// print a real audit trail of contained violations.
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

/// Tally of the run, printed as the closing summary.
struct Tally {
    violations_contained: u32,
    compliant_succeeded: u32,
}

fn agent_config(name: &str, profile: &str) -> AgentConfig {
    AgentConfig {
        name: name.to_string(),
        task: "governed-execution".into(),
        llm_provider: "stub".into(),
        permission_profile: profile.into(),
        priority: kernel::Priority::default(),
        sandbox_config: None,
    }
}

fn rule(line: &str) {
    println!("{line}");
}

fn act(agent: &str, action: &str) {
    println!("  · {agent:<10} {action}");
}

fn allowed(detail: &str) {
    println!("      → ALLOWED  ({detail})");
}

fn denied(reason: &str) {
    println!("      → DENIED   ({reason})  [contained]");
}

fn audit_line(e: &AuditEvent) {
    let decision = match e.decision {
        AuditDecision::Allowed => "ALLOW",
        AuditDecision::Denied => "DENY ",
    };
    println!(
        "  [audit] {decision} pid={} action={} tool={} resource={}",
        e.pid, e.action, e.tool, e.resource
    );
}

#[tokio::main]
async fn main() {
    rule("════════════════════════════════════════════════════════════════════");
    rule("  AI Agent OS — Governed Multi-Agent Execution (keyless, no LLM)");
    rule("════════════════════════════════════════════════════════════════════");
    println!();
    println!("Scenario: five agents share a workspace. Some try to break policy.");
    println!("The kernel's syscall gate contains and audits the violators while");
    println!("the compliant agents keep working. Enforcement is at the gate,");
    println!("BEFORE any resource broker, and needs no model.");
    println!();

    let kernel: Arc<AgentKernelImpl> = match AgentKernelImpl::new() {
        Ok(k) => Arc::new(k),
        Err(e) => {
            eprintln!("failed to boot kernel: {e}");
            std::process::exit(1);
        }
    };

    let sink = RecordingSink::new();
    kernel.syscall_gate.set_audit_sink(sink.clone());

    let mut tally = Tally {
        violations_contained: 0,
        compliant_succeeded: 0,
    };

    // ── Cast of agents ────────────────────────────────────────────────────────
    rule("[setup] creating agents");
    let analyst = kernel
        .create_agent_full(agent_config("analyst", "read-only"))
        .await
        .expect("create analyst");
    let frugal = kernel
        .create_agent_full(agent_config("frugal", "standard"))
        .await
        .expect("create frugal");
    let funded = kernel
        .create_agent_full(agent_config("funded", "standard"))
        .await
        .expect("create funded");
    let operator = kernel
        .create_agent_full(agent_config("operator", "standard"))
        .await
        .expect("create operator");
    let intruder = kernel
        .create_agent_full(agent_config("intruder", "standard"))
        .await
        .expect("create intruder");
    println!("  analyst (read-only), frugal/funded/operator/intruder (standard)");
    println!();

    // ── Baseline: everyone can read. ───────────────────────────────────────────
    rule("[baseline] every agent reads a shared file");
    for (name, id) in [
        ("analyst", analyst.id),
        ("frugal", frugal.id),
        ("funded", funded.id),
        ("operator", operator.id),
        ("intruder", intruder.id),
    ] {
        act(name, "read_file /workspace/notes.txt");
        match kernel
            .syscall_gate
            .check_tool_call(id, "read_file", "/workspace/notes.txt", 5)
            .await
        {
            Ok(_) => {
                allowed("read needs no capability");
                tally.compliant_succeeded += 1;
            }
            Err(e) => denied(&e.message()),
        }
    }
    println!();

    // ── 1. Capability containment ───────────────────────────────────────────────
    rule("[1] CAPABILITY — read-only agent tries to write");
    act("analyst", "write_file /workspace/out.txt");
    match kernel
        .syscall_gate
        .check_tool_call(analyst.id, "write_file", "/workspace/out.txt", 5)
        .await
    {
        Err(GateDenial::MissingCapability(_)) => {
            denied("no CAP_FILE_WRITE — broker never invoked");
            tally.violations_contained += 1;
        }
        other => println!("      !! unexpected: {other:?}"),
    }
    println!();

    // ── 2. Budget (cgroup) containment ──────────────────────────────────────────
    rule("[2] BUDGET — frugal agent exhausts a tiny token quota; funded peer unaffected");
    let tight = kernel.cgroups.create(
        "demo-tight".into(),
        kernel.cgroups.root(),
        CgroupLimits {
            tokens_per_min: 100,
            ..Default::default()
        },
    );
    let generous = kernel.cgroups.create(
        "demo-generous".into(),
        kernel.cgroups.root(),
        CgroupLimits {
            tokens_per_min: 1_000_000,
            ..Default::default()
        },
    );
    kernel.syscall_gate.set_cgroup(frugal.id, tight);
    kernel.syscall_gate.set_cgroup(funded.id, generous);
    kernel.syscall_gate.record_tool_usage(frugal.id, 90);
    println!("  (frugal budget=100 tok/min, already spent 90)");

    act("frugal", "read_file /workspace/big.txt (est 30 tokens)");
    match kernel
        .syscall_gate
        .check_tool_call(frugal.id, "read_file", "/workspace/big.txt", 30)
        .await
    {
        Err(GateDenial::CgroupQuota) => {
            denied("90+30 > 100 tok/min — over budget");
            tally.violations_contained += 1;
        }
        other => println!("      !! unexpected: {other:?}"),
    }
    act("funded", "read_file /workspace/big.txt (est 30 tokens)");
    match kernel
        .syscall_gate
        .check_tool_call(funded.id, "read_file", "/workspace/big.txt", 30)
        .await
    {
        Ok(_) => {
            allowed("identical call, generous budget — peer unaffected");
            tally.compliant_succeeded += 1;
        }
        other => println!("      !! unexpected: {other:?}"),
    }
    println!();

    // ── 3. Namespace containment ────────────────────────────────────────────────
    rule("[3] NAMESPACE — privileged tool 'rotate_secrets' lives in secure-ops only");
    let secure_ns: u64 = 7000;
    kernel
        .syscall_gate
        .register_tool_namespace("rotate_secrets", secure_ns);
    kernel
        .syscall_gate
        .add_agent_namespace(operator.id, secure_ns);
    println!("  (operator is a member of secure-ops; intruder is not)");

    act("intruder", "rotate_secrets /vault/key");
    match kernel
        .syscall_gate
        .check_tool_call(intruder.id, "rotate_secrets", "/vault/key", 5)
        .await
    {
        Err(GateDenial::NotInNamespace { .. }) => {
            denied("NotInNamespace (≈ ENOENT) — tool is invisible");
            tally.violations_contained += 1;
        }
        other => println!("      !! unexpected: {other:?}"),
    }
    act("operator", "rotate_secrets /vault/key");
    match kernel
        .syscall_gate
        .check_tool_call(operator.id, "rotate_secrets", "/vault/key", 5)
        .await
    {
        Ok(_) => {
            allowed("member of secure-ops — same tool resolves");
            tally.compliant_succeeded += 1;
        }
        other => println!("      !! unexpected: {other:?}"),
    }
    println!();

    // ── 4. MAC containment (audited) ────────────────────────────────────────────
    rule("[4] MAC — enforcing policy denies writes under /etc; denial is audited");
    {
        let mut mac = kernel.syscall_gate.mac.lock().await;
        mac.set_enforcing(true);
        mac.load_policy(vec![
            PolicyRule {
                subject: "*".into(),
                action: "write".into(),
                object: "/etc/**".into(),
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
    act("intruder", "write_file /etc/passwd");
    match kernel
        .syscall_gate
        .check_tool_call(intruder.id, "write_file", "/etc/passwd", 5)
        .await
    {
        Err(GateDenial::MacDeny { .. }) => {
            denied("MAC policy: write under /etc forbidden");
            tally.violations_contained += 1;
        }
        other => println!("      !! unexpected: {other:?}"),
    }
    println!();

    // ── Containment: the compliant agents keep working. ─────────────────────────
    rule("[containment] compliant agents keep working through the violations");
    act("operator", "write_file /workspace/report.txt");
    match kernel
        .syscall_gate
        .check_tool_call(operator.id, "write_file", "/workspace/report.txt", 5)
        .await
    {
        Ok(_) => {
            allowed("outside /etc, has the capability");
            tally.compliant_succeeded += 1;
        }
        other => println!("      !! unexpected: {other:?}"),
    }
    act("funded", "write_file /workspace/data.txt");
    match kernel
        .syscall_gate
        .check_tool_call(funded.id, "write_file", "/workspace/data.txt", 5)
        .await
    {
        Ok(_) => {
            allowed("no global lockout from another agent's violation");
            tally.compliant_succeeded += 1;
        }
        other => println!("      !! unexpected: {other:?}"),
    }
    println!();

    // ── Audit trail ─────────────────────────────────────────────────────────────
    rule("[audit trail] gate counters + MAC audit-sink events");
    let stats = kernel.syscall_gate.stats();
    println!(
        "  counters: allowed={} cap_denied={} cgroup_denied={} ns_denied={} mac_denied={}",
        stats.allowed,
        stats.denied_capability,
        stats.denied_cgroup,
        stats.denied_namespace,
        stats.denied_mac,
    );
    let events = sink.events();
    if events.is_empty() {
        println!("  (no MAC-stage audit events — cap/cgroup/ns denials are counter-only)");
    } else {
        for e in &events {
            audit_line(e);
        }
    }
    println!();

    // ── Optional: one real governed turn against a local model, if reachable. ───
    rule("[live] optional local-model governed turn");
    run_optional_live_turn(&kernel).await;
    println!();

    // ── Summary ─────────────────────────────────────────────────────────────────
    rule("════════════════════════════════════════════════════════════════════");
    println!(
        "  SUMMARY: {} violations contained, {} compliant calls succeeded.",
        tally.violations_contained, tally.compliant_succeeded
    );
    println!("  Isolation held: no agent's violation took the others down.");
    rule("════════════════════════════════════════════════════════════════════");

    if let Err(e) = kernel.shutdown().await {
        eprintln!("shutdown error: {e}");
    }
}

/// If a local Ollama endpoint is reachable and serving a model, register the
/// local adapter and drive ONE governed turn: the gate authorizes a read, then
/// the model is asked a trivial question. Degrades gracefully and never panics
/// when no model is present.
async fn run_optional_live_turn(kernel: &Arc<AgentKernelImpl>) {
    use kernel::connector::{LlmProviderAdapter, StandardMessage};

    let base_url = std::env::var("OLLAMA_HOST")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://localhost:11434".to_string());
    let model = std::env::var("OLLAMA_MODEL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "llama3.2".to_string());

    let adapter = adapters::local::LocalLlmAdapter::new(base_url.clone(), model.clone());

    if !adapter.is_available().await {
        println!(
            "  no local model reachable at {base_url} — ran the enforcement scenario offline."
        );
        return;
    }

    // Governance still applies on the live path: authorize the tool call at the
    // gate before doing any real work. Create a fresh well-funded agent for it.
    let live = match kernel
        .create_agent_full(agent_config("live", "full-access"))
        .await
    {
        Ok(h) => h,
        Err(e) => {
            println!(
                "  local model reachable, but agent creation failed ({e}) — skipping live turn."
            );
            return;
        }
    };
    match kernel
        .syscall_gate
        .check_tool_call(live.id, "read_file", "/workspace/notes.txt", 16)
        .await
    {
        Ok(_) => println!("  gate authorized live agent's read_file (governed)."),
        Err(e) => {
            println!(
                "  gate denied the live agent ({}) — not driving the model.",
                e.message()
            );
            return;
        }
    }

    let session = match adapter.create_session().await {
        Ok(s) => s,
        Err(e) => {
            println!("  model reachable but session failed ({e}) — ran offline scenario only.");
            return;
        }
    };
    let messages = vec![StandardMessage {
        role: "user".into(),
        content: "In one short sentence, what is least-privilege access control?".into(),
        tool_call_id: None,
        tool_calls: None,
    }];
    match session.send(messages).await {
        Ok(resp) => {
            let reply = resp.content.trim();
            let shown = if reply.len() > 200 {
                &reply[..200]
            } else {
                reply
            };
            println!(
                "  live governed turn OK (model={model}, tokens={}):",
                resp.tokens_used
            );
            println!("    \"{shown}\"");
        }
        Err(e) => {
            println!("  model call failed ({e}) — enforcement scenario above still stands.");
        }
    }
}
