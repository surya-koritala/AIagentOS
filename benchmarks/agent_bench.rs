//! agent-bench — an offline, keyless agent-task benchmark + a tiny eval harness.
//!
//! This drives a real in-memory `AgentKernelImpl` through a realistic agent
//! workload and reports throughput + latency metrics, then runs a small set of
//! named eval "tasks" and prints a pass/fail table.
//!
//! Everything here runs **offline with no API keys and no LLM provider**: the
//! workload exercises the kernel paths that don't need a live model — agent
//! creation, tool calls through the `SyscallGate` chokepoint (the same gate
//! `AgentExecutor` uses in production), and shutdown. The `llm_provider` field
//! is the inert `"stub"`. There is no LLM-driven turn in this benchmark, so the
//! "tokens" reported are the *estimated* token counts passed into the gate's
//! cgroup accounting, NOT real model tokens — this is logged explicitly so the
//! numbers aren't misread.
//!
//! Run: `cargo run --package os-benchmark --bin agent-bench`
//! Smoke-tested in CI via the `#[tokio::test]` at the bottom of this file
//! (picked up by `cargo test --workspace`), so the benchmark can't silently rot.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kernel::agent::AgentKernel;
use kernel::{AgentConfig, AgentHandle, AgentKernelImpl, Priority};

/// Tunable workload shape. The CLI run uses [`BenchConfig::full`]; the smoke
/// test uses [`BenchConfig::smoke`] (tiny N, sub-second).
#[derive(Clone, Copy)]
struct BenchConfig {
    /// Number of agents to create through the live `create_agent_full` path.
    agents: usize,
    /// Tool calls driven through the syscall gate, spread round-robin over the
    /// created agents.
    tool_calls: usize,
    /// Estimated tokens charged per tool call (fed to the gate's cgroup
    /// accounting — NOT real model tokens).
    tokens_per_call: u64,
}

impl BenchConfig {
    fn full() -> Self {
        Self {
            agents: 50,
            tool_calls: 5_000,
            tokens_per_call: 8,
        }
    }

    /// Only used by the smoke test below; the bin's `main` uses [`full`].
    #[cfg_attr(not(test), allow(dead_code))]
    fn smoke() -> Self {
        Self {
            agents: 4,
            tool_calls: 40,
            tokens_per_call: 4,
        }
    }
}

/// Collected metrics from one benchmark run. All latencies are wall-clock for
/// the corresponding kernel call; throughput is derived from totals.
struct BenchReport {
    agents_created: usize,
    agent_create_elapsed: Duration,
    tool_calls_ok: usize,
    tool_calls_denied: usize,
    tool_call_elapsed: Duration,
    tool_latencies: Vec<Duration>,
    est_tokens_charged: u64,
}

impl BenchReport {
    fn agents_per_sec(&self) -> f64 {
        per_sec(self.agents_created as f64, self.agent_create_elapsed)
    }

    fn tool_calls_per_sec(&self) -> f64 {
        per_sec(
            (self.tool_calls_ok + self.tool_calls_denied) as f64,
            self.tool_call_elapsed,
        )
    }

    /// Percentile (0.0..=1.0) over the sorted tool-call latencies. Returns zero
    /// when no samples were collected.
    fn latency_pct(&self, pct: f64) -> Duration {
        if self.tool_latencies.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.tool_latencies.clone();
        sorted.sort();
        let idx = ((sorted.len() as f64 - 1.0) * pct).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn print(&self) {
        println!("── benchmark metrics ──────────────────────────────────────");
        println!(
            "  agents created      : {} in {:.2}ms  ({:.0} agents/sec)",
            self.agents_created,
            self.agent_create_elapsed.as_secs_f64() * 1e3,
            self.agents_per_sec(),
        );
        println!(
            "  tool calls (gate)   : {} ok / {} denied in {:.2}ms  ({:.0} calls/sec)",
            self.tool_calls_ok,
            self.tool_calls_denied,
            self.tool_call_elapsed.as_secs_f64() * 1e3,
            self.tool_calls_per_sec(),
        );
        println!(
            "  tool-call latency   : p50 {:.1}us  p95 {:.1}us  p99 {:.1}us",
            self.latency_pct(0.50).as_secs_f64() * 1e6,
            self.latency_pct(0.95).as_secs_f64() * 1e6,
            self.latency_pct(0.99).as_secs_f64() * 1e6,
        );
        println!(
            "  est. tokens charged : {} (cgroup accounting estimate, NOT real LLM tokens)",
            self.est_tokens_charged,
        );
    }
}

fn per_sec(count: f64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        0.0
    } else {
        count / secs
    }
}

fn agent_config(idx: usize) -> AgentConfig {
    AgentConfig {
        name: format!("bench-agent-{idx}"),
        task: "agent-task benchmark".into(),
        // Inert provider: no LLM, no network, no keys.
        llm_provider: "stub".into(),
        // full-access so the gate's capability layer admits every tool below;
        // we are measuring gate throughput, not denials, on the hot path.
        permission_profile: "full-access".into(),
        priority: Priority::new(((idx % 5) + 1) as u8).unwrap_or_default(),
        sandbox_config: None,
    }
}

/// Drives the workload against a freshly booted in-memory kernel and returns the
/// metrics. Pure measurement — printing is the caller's job.
async fn run_benchmark(kernel: &Arc<AgentKernelImpl>, cfg: BenchConfig) -> BenchReport {
    // ── Phase 1: agent creation through the live admission path ──────────────
    let start = Instant::now();
    let mut handles: Vec<AgentHandle> = Vec::with_capacity(cfg.agents);
    for i in 0..cfg.agents {
        let h = kernel
            .create_agent_full(agent_config(i))
            .await
            .expect("create_agent_full");
        handles.push(h);
    }
    let agent_create_elapsed = start.elapsed();

    // ── Phase 2: tool calls through the SyscallGate chokepoint ───────────────
    // Rotate over a small menu of read-class tools so every call is admitted by
    // the capability + MAC layers and stays under the (default) cgroup quota.
    let tools = ["read_file", "list_directory", "http_get"];
    let mut tool_latencies = Vec::with_capacity(cfg.tool_calls);
    let mut tool_calls_ok = 0usize;
    let mut tool_calls_denied = 0usize;
    let mut est_tokens_charged = 0u64;

    let tool_start = Instant::now();
    for i in 0..cfg.tool_calls {
        let agent = handles[i % handles.len()].id;
        let tool = tools[i % tools.len()];
        let call_start = Instant::now();
        let res = kernel
            .syscall_gate
            .check_tool_call(agent, tool, "/tmp/bench", cfg.tokens_per_call)
            .await;
        tool_latencies.push(call_start.elapsed());
        match res {
            Ok(_) => {
                tool_calls_ok += 1;
                est_tokens_charged += cfg.tokens_per_call;
            }
            Err(_) => tool_calls_denied += 1,
        }
    }
    let tool_call_elapsed = tool_start.elapsed();

    BenchReport {
        agents_created: handles.len(),
        agent_create_elapsed,
        tool_calls_ok,
        tool_calls_denied,
        tool_call_elapsed,
        tool_latencies,
        est_tokens_charged,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Eval harness
// ════════════════════════════════════════════════════════════════════════════

/// Outcome of a single named eval task.
struct EvalOutcome {
    name: &'static str,
    passed: bool,
    elapsed: Duration,
    detail: String,
}

/// A named eval task: an async closure that asserts something about the kernel
/// and returns `Ok(detail)` on pass or `Err(detail)` on fail. Kept Rust-native
/// and offline — no datasets, no network. This is the seam where SWE-bench-style
/// tasks would slot in, but every task here runs against the in-memory kernel.
type EvalFn = Box<
    dyn for<'a> Fn(
        &'a Arc<AgentKernelImpl>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, String>> + 'a>,
    >,
>;

struct EvalTask {
    name: &'static str,
    run: EvalFn,
}

/// Helper to build an [`EvalTask`] from an async block, hiding the pinning
/// boilerplate.
macro_rules! eval_task {
    ($name:literal, |$k:ident| $body:block) => {
        EvalTask {
            name: $name,
            run: Box::new(move |$k: &Arc<AgentKernelImpl>| Box::pin(async move { $body })),
        }
    };
}

/// The default offline eval suite. Each task exercises a distinct kernel path.
fn eval_suite() -> Vec<EvalTask> {
    vec![
        eval_task!("agent.create", |kernel| {
            let h = kernel
                .create_agent_full(agent_config(0))
                .await
                .map_err(|e| format!("create failed: {e:?}"))?;
            if kernel.agent_manager.get_agent_state(h.id).is_some() {
                Ok(format!("agent {} registered", h.id))
            } else {
                Err("agent not registered after create".into())
            }
        }),
        eval_task!("gate.capability_allows_read", |kernel| {
            let h = kernel
                .create_agent_full(agent_config(1))
                .await
                .map_err(|e| format!("create failed: {e:?}"))?;
            match kernel
                .syscall_gate
                .check_tool_call(h.id, "read_file", "/etc/hosts", 4)
                .await
            {
                Ok(_) => Ok("read_file admitted (needs no capability)".into()),
                Err(e) => Err(format!("read_file unexpectedly denied: {e:?}")),
            }
        }),
        eval_task!("gate.capability_denies_write_for_readonly", |kernel| {
            let cfg = AgentConfig {
                permission_profile: "read-only".into(),
                ..agent_config(2)
            };
            let h = kernel
                .create_agent_full(cfg)
                .await
                .map_err(|e| format!("create failed: {e:?}"))?;
            match kernel
                .syscall_gate
                .check_tool_call(h.id, "write_file", "/tmp/x", 4)
                .await
            {
                Err(_) => Ok("write_file denied for read-only agent".into()),
                Ok(_) => Err("write_file unexpectedly allowed for read-only agent".into()),
            }
        }),
        eval_task!("gate.distinct_pids", |kernel| {
            let a = kernel
                .create_agent_full(agent_config(3))
                .await
                .map_err(|e| format!("create a failed: {e:?}"))?;
            let b = kernel
                .create_agent_full(agent_config(4))
                .await
                .map_err(|e| format!("create b failed: {e:?}"))?;
            let pa = kernel.syscall_gate.pid_of(a.id);
            let pb = kernel.syscall_gate.pid_of(b.id);
            match (pa, pb) {
                (Some(pa), Some(pb)) if pa != pb => Ok(format!("distinct pids {pa} != {pb}")),
                other => Err(format!("expected two distinct pids, got {other:?}")),
            }
        }),
    ]
}

/// Runs the eval suite against fresh kernels (one per task, for isolation) and
/// returns the outcomes.
async fn run_eval_suite(tasks: Vec<EvalTask>) -> Vec<EvalOutcome> {
    let mut outcomes = Vec::with_capacity(tasks.len());
    for task in tasks {
        let kernel = AgentKernelImpl::new().expect("kernel new");
        let kernel = Arc::new(kernel);
        let start = Instant::now();
        let result = (task.run)(&kernel).await;
        let elapsed = start.elapsed();
        let (passed, detail) = match result {
            Ok(d) => (true, d),
            Err(d) => (false, d),
        };
        outcomes.push(EvalOutcome {
            name: task.name,
            passed,
            elapsed,
            detail,
        });
    }
    outcomes
}

fn print_eval_table(outcomes: &[EvalOutcome]) {
    let passed = outcomes.iter().filter(|o| o.passed).count();
    println!("── eval harness ───────────────────────────────────────────");
    println!("  {:<6} {:<44} {:>9}", "RESULT", "TASK", "TIME");
    for o in outcomes {
        println!(
            "  {:<6} {:<44} {:>7.2}ms   {}",
            if o.passed { "PASS" } else { "FAIL" },
            o.name,
            o.elapsed.as_secs_f64() * 1e3,
            o.detail,
        );
    }
    println!("  {}/{} tasks passed", passed, outcomes.len());
}

#[tokio::main]
async fn main() {
    println!("════════════════════════════════════════════════════════════");
    println!("  AI Agent OS — agent-task benchmark + eval harness");
    println!("  (offline / keyless: no LLM provider, no network, no API keys)");
    println!("════════════════════════════════════════════════════════════");
    println!();

    let cfg = BenchConfig::full();
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
    let report = run_benchmark(&kernel, cfg).await;
    report.print();
    kernel.shutdown().await.expect("shutdown");
    println!();

    let outcomes = run_eval_suite(eval_suite()).await;
    print_eval_table(&outcomes);

    let all_passed = report.agents_created == cfg.agents
        && report.tool_calls_ok > 0
        && outcomes.iter().all(|o| o.passed);

    println!();
    if all_passed {
        println!("✅ benchmark + eval complete");
    } else {
        println!("❌ benchmark or eval failed");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast CI smoke test: runs a tiny iteration of the benchmark and asserts it
    /// completes and produces sane metrics. Tiny N keeps this well under a second
    /// of real work so it can live in the default `cargo test --workspace` run.
    #[tokio::test]
    async fn smoke_benchmark_produces_sane_metrics() {
        let cfg = BenchConfig::smoke();
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let report = run_benchmark(&kernel, cfg).await;

        // All requested agents were created through the live path.
        assert_eq!(report.agents_created, cfg.agents, "agent count mismatch");
        // Every tool call was accounted for (ok + denied == total).
        assert_eq!(
            report.tool_calls_ok + report.tool_calls_denied,
            cfg.tool_calls,
            "tool calls unaccounted for",
        );
        // full-access read-class tools should be admitted on the hot path.
        assert!(report.tool_calls_ok > 0, "no tool calls were admitted");
        // Latency samples collected one-per-call.
        assert_eq!(
            report.tool_latencies.len(),
            cfg.tool_calls,
            "missing latency samples",
        );
        // Derived throughput must be finite and positive.
        assert!(
            report.agents_per_sec() > 0.0,
            "non-positive agent throughput"
        );
        assert!(
            report.tool_calls_per_sec() > 0.0,
            "non-positive tool throughput",
        );
        // Percentiles are ordered and non-zero given real samples.
        assert!(report.latency_pct(0.50) <= report.latency_pct(0.95));
        assert!(report.latency_pct(0.95) <= report.latency_pct(0.99));
        // Token accounting matches admitted calls.
        assert_eq!(
            report.est_tokens_charged,
            report.tool_calls_ok as u64 * cfg.tokens_per_call,
            "token accounting mismatch",
        );

        kernel.shutdown().await.expect("shutdown");
    }

    /// Fast CI smoke test for the eval harness: the offline suite must run and
    /// every task must pass.
    #[tokio::test]
    async fn smoke_eval_suite_all_pass() {
        let outcomes = run_eval_suite(eval_suite()).await;
        assert!(!outcomes.is_empty(), "eval suite was empty");
        for o in &outcomes {
            assert!(o.passed, "eval task `{}` failed: {}", o.name, o.detail);
        }
    }
}
