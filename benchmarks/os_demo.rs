//! os-demo — a keyless, LLM-free proof that the AI Agent OS enforcement layer
//! is load-bearing on the live runtime path.
//!
//! Every check below boots a real in-memory `AgentKernelImpl` and spawns the
//! scheduler observer through `start_runtime`, creates real agents through
//! `create_agent_full`, and drives
//! the *same* `SyscallGate::check_tool_call` chokepoint that `AgentExecutor`
//! uses in production. No API keys, no network, no LLM provider — the
//! `llm_provider` is the inert `"stub"`. The denials are produced by the
//! capability, cgroup-concurrency, and namespace layers, not by mocks.
//!
//! The proven denial patterns are adapted from `tests/src/os_enforcement.rs`.
//!
//! Run: `cargo run --package os-benchmark --bin os-demo`

use std::sync::Arc;

use kernel::procfs::ProcEntry;
use kernel::syscall_gate::GateDenial;
use kernel::tools::{SecurityAction, ToolSecurity};
use kernel::{AgentConfig, AgentKernelImpl};

/// Tracks PASS/FAIL across all checks so the process can exit non-zero if the
/// OS framing is ever broken.
struct Scoreboard {
    passed: u32,
    failed: u32,
}

impl Scoreboard {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
        }
    }

    fn check(&mut self, label: &str, ok: bool, detail: &str) {
        if ok {
            self.passed += 1;
            println!("  [PASS] {label} — {detail}");
        } else {
            self.failed += 1;
            println!("  [FAIL] {label} — {detail}");
        }
    }

    fn report(&self) -> bool {
        println!();
        println!("════════════════════════════════════════════════════════════");
        println!("  RESULT: {} passed, {} failed", self.passed, self.failed);
        println!("════════════════════════════════════════════════════════════");
        self.failed == 0
    }
}

fn agent_config(name: &str, profile: &str) -> AgentConfig {
    AgentConfig {
        name: name.to_string(),
        task: "demo".into(),
        llm_provider: "stub".into(),
        permission_profile: profile.into(),
        priority: kernel::Priority::default(),
        sandbox_config: None,
    }
}

#[tokio::main]
async fn main() {
    let mut board = Scoreboard::new();

    println!("════════════════════════════════════════════════════════════");
    println!("  AI Agent OS — load-bearing enforcement demo (keyless, no LLM)");
    println!("════════════════════════════════════════════════════════════");
    println!();

    // ── 1. BOOT ──────────────────────────────────────────────────────────────
    println!("[1] BOOT: in-memory kernel with managed cgroup limits");
    let security = kernel::config::Config::default();
    let budgets = kernel::config::BudgetConfig {
        max_concurrent_tool_calls: 1,
        ..security.budgets.clone()
    };
    let context =
        Arc::new(kernel::context::SqliteContextManager::in_memory().expect("context manager"));
    let kernel = Arc::new(
        AgentKernelImpl::with_context_manager(
            context,
            &budgets,
            security.mac_enforcing,
            &security.mac_rules,
        )
        .expect("boot kernel"),
    );
    let _runtime = kernel.start_runtime();

    let full = kernel
        .create_agent_full(agent_config("full-access-agent", "full-access"))
        .await
        .expect("create full-access agent");
    let readonly = kernel
        .create_agent_full(agent_config("read-only-agent", "read-only"))
        .await
        .expect("create read-only agent");

    let full_pid = kernel.syscall_gate.pid_of(full.id).expect("full pid");
    let ro_pid = kernel.syscall_gate.pid_of(readonly.id).expect("ro pid");
    println!(
        "    booted; full-access agent uuid={} pid={}",
        full.id, full_pid
    );
    println!(
        "    booted; read-only  agent uuid={} pid={}",
        readonly.id, ro_pid
    );
    board.check(
        "boot",
        full_pid != ro_pid,
        "two agents registered with distinct PIDs on the syscall gate",
    );
    println!();

    // ── 2. CAPABILITY ─────────────────────────────────────────────────────────
    // full-access (CapabilitySet::all) may write; read-only (CAP_NET_ACCESS only)
    // may NOT write or exec, but MAY read (read_file requires no capability).
    println!("[2] CAPABILITY: caps are derived from permission_profile at agent creation");

    let r = kernel
        .syscall_gate
        .check_tool_call(full.id, "write_file", "/tmp/out.txt", 5)
        .await;
    board.check(
        "capability/full-access write_file allowed",
        r.is_ok(),
        &format!("expected Ok, got {r:?}"),
    );

    let r = kernel
        .syscall_gate
        .check_tool_call(readonly.id, "write_file", "/tmp/out.txt", 5)
        .await;
    board.check(
        "capability/read-only write_file denied",
        matches!(r, Err(GateDenial::MissingCapability(_))),
        &format!("expected Err(MissingCapability), got {r:?}"),
    );

    let r = kernel
        .syscall_gate
        .check_tool_call(readonly.id, "run_command", "ls -la", 5)
        .await;
    board.check(
        "capability/read-only run_command denied",
        matches!(r, Err(GateDenial::MissingCapability(_))),
        &format!("expected Err(MissingCapability), got {r:?}"),
    );

    let r = kernel
        .syscall_gate
        .check_tool_call(readonly.id, "read_file", "/etc/hosts", 5)
        .await;
    board.check(
        "capability/read-only read_file allowed",
        r.is_ok(),
        &format!("expected Ok (read needs no cap), got {r:?}"),
    );
    println!();

    // ── 3. CGROUP CONCURRENCY ──────────────────────────────────────────────────
    // Provider tokens are enforced on actual LLM calls. Here the syscall gate
    // demonstrates the separate structural concurrent-tool ceiling.
    println!("[3] CGROUP CONCURRENCY: managed read-only leaf (one active tool call)");
    let held = kernel.syscall_gate.acquire_tool_call(readonly.id).unwrap();
    let r = kernel.syscall_gate.acquire_tool_call(readonly.id);
    board.check(
        "cgroup/second concurrent call denied",
        matches!(r, Err(GateDenial::CgroupToolLimit)),
        "expected Err(CgroupToolLimit)",
    );

    // Releasing the RAII guard restores headroom.
    drop(held);
    let r = kernel.syscall_gate.acquire_tool_call(readonly.id);
    board.check(
        "cgroup/after-release allowed",
        r.is_ok(),
        "expected Ok after release",
    );
    drop(r);
    println!();

    // ── 4. NAMESPACE ISOLATION ───────────────────────────────────────────────────
    // Register a tool exclusively in a foreign namespace id the agent never
    // joined. The gate denies with NotInNamespace (≈ ENOENT) — the agent cannot
    // even see the tool. Proven approach from
    // os_enforcement.rs::namespace_isolation_denies_foreign_tool.
    println!("[4] NAMESPACE: tool registered in a namespace the agent is NOT a member of");
    let foreign_ns: u64 = 9999; // not the default Agent/Tool ns the agent joined
    kernel
        .syscall_gate
        .register_tool_namespace("secret_admin_tool", foreign_ns);
    let secret_security =
        ToolSecurity::constant(SecurityAction::Read, "/db/users").caller_namespace();

    let r = kernel
        .syscall_gate
        .check_tool_call_declared(
            full.id,
            "secret_admin_tool",
            "/db/users",
            5,
            &secret_security,
        )
        .await;
    board.check(
        "namespace/foreign tool denied",
        matches!(
            r,
            Err(GateDenial::NotInNamespace { ref tool, namespace })
                if tool == "secret_admin_tool" && namespace == foreign_ns
        ),
        &format!("expected Err(NotInNamespace{{tool:secret_admin_tool, namespace:{foreign_ns}}}), got {r:?}"),
    );

    // Joining the namespace makes the tool resolvable without a restart.
    kernel.syscall_gate.add_agent_namespace(full.id, foreign_ns);
    let r = kernel
        .syscall_gate
        .check_tool_call_declared(
            full.id,
            "secret_admin_tool",
            "/db/users",
            5,
            &secret_security,
        )
        .await;
    board.check(
        "namespace/after-join tool resolves",
        r.is_ok(),
        &format!("expected Ok after joining ns {foreign_ns}, got {r:?}"),
    );
    println!();

    // ── 5. SCHEDULER / PROCFS ─────────────────────────────────────────────────────
    // The scheduler observer spawned by start_runtime ticks every 100ms and
    // publishes the CFS pick into procfs as /system/current_agent. After a short
    // sleep the entry must name one of the live agents' PIDs — proof the
    // background runtime is actually running.
    println!("[5] SCHEDULER/PROCFS: sleep 150ms, read /system/current_agent");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let entry = {
        let procfs = kernel.os.procfs.lock().await;
        procfs.read("/system/current_agent")
    };
    let current = match entry {
        Some(ProcEntry::File(ref s)) => Some(s.clone()),
        _ => None,
    };
    let valid_pids = [full_pid.to_string(), ro_pid.to_string()];
    println!(
        "    /system/current_agent = {:?}  (live pids: {:?})",
        current, valid_pids
    );
    board.check(
        "scheduler/current_agent published by observer",
        current
            .as_ref()
            .map(|c| valid_pids.contains(c))
            .unwrap_or(false),
        "scheduler observer (from start_runtime) wrote a live agent's PID into procfs",
    );

    let all_ok = board.report();

    kernel.shutdown().await.expect("shutdown");

    if !all_ok {
        std::process::exit(1);
    }
}
