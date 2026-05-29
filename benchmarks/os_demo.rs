//! os-demo — a keyless, LLM-free proof that the AI Agent OS enforcement layer
//! is load-bearing on the live runtime path.
//!
//! Every check below boots a real `AgentKernelImpl` via `kernel::boot_in_memory`
//! (which also spawns the scheduler observer + cgroup reset timer through
//! `start_runtime`), creates real agents through `create_agent_full`, and drives
//! the *same* `SyscallGate::check_tool_call` chokepoint that `AgentExecutor`
//! uses in production. No API keys, no network, no LLM provider — the
//! `llm_provider` is the inert `"stub"`. The denials are produced by the
//! capability, cgroup, and namespace layers, not by mocks.
//!
//! The proven denial patterns are adapted from `tests/src/os_enforcement.rs`.
//!
//! Run: `cargo run --package os-benchmark --bin os-demo`

use std::sync::Arc;

use kernel::cgroups::CgroupLimits;
use kernel::procfs::ProcEntry;
use kernel::syscall_gate::GateDenial;
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
    println!("[1] BOOT: kernel::boot_in_memory() (spawns scheduler observer + cgroup reset)");
    let kernel: Arc<AgentKernelImpl> = kernel::boot_in_memory().expect("boot kernel");

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
    println!("    booted; full-access agent uuid={} pid={}", full.id, full_pid);
    println!("    booted; read-only  agent uuid={} pid={}", readonly.id, ro_pid);
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

    // ── 3. CGROUP QUOTA ─────────────────────────────────────────────────────────
    // Attach the full-access agent to a tight cgroup (100 tokens/min), burn 90,
    // then a 30-token call breaches the 100-token cap → CgroupQuota (EAGAIN).
    // Proven approach from os_enforcement.rs::cgroup_quota_blocks_when_over_budget.
    println!("[3] CGROUP QUOTA: tight cgroup (tokens_per_min=100); burn 90, request 30");
    let tight = kernel.cgroups.create(
        "demo-tight".into(),
        kernel.cgroups.root(),
        CgroupLimits {
            tokens_per_min: 100,
            ..Default::default()
        },
    );
    kernel.syscall_gate.set_cgroup(full.id, tight);
    kernel.syscall_gate.record_tool_usage(full.id, 90);

    let r = kernel
        .syscall_gate
        .check_tool_call(full.id, "read_file", "/etc/hosts", 30)
        .await;
    board.check(
        "cgroup/over-budget denied",
        r == Err(GateDenial::CgroupQuota),
        &format!("expected Err(CgroupQuota) (90+30 > 100), got {r:?}"),
    );

    // Resetting the per-minute counter restores headroom.
    kernel.cgroups.reset_minute_counters();
    let r = kernel
        .syscall_gate
        .check_tool_call(full.id, "read_file", "/etc/hosts", 30)
        .await;
    board.check(
        "cgroup/after-reset allowed",
        r.is_ok(),
        &format!("expected Ok after reset, got {r:?}"),
    );
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

    let r = kernel
        .syscall_gate
        .check_tool_call(full.id, "secret_admin_tool", "/db/users", 5)
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
        .check_tool_call(full.id, "secret_admin_tool", "/db/users", 5)
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
