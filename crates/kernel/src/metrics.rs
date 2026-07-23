//! Prometheus-text metrics exposition — the operator-facing read-out of the
//! running kernel.
//!
//! This module is the `/proc`-style health export for an `agent-server` in
//! production: it hand-renders a `text/plain; version=0.0.4` Prometheus
//! exposition from counters that already exist elsewhere in the kernel — the
//! [syscall gate](crate::syscall_gate)'s enforcement counters, the
//! [observability engine](crate::observability)'s system token/api totals, and
//! the scheduler's live execution count and the agent manager's population.
//! No `prometheus`/`metrics` crate is
//! pulled in; the format is small, stable, and rendered deterministically so it
//! can be unit-tested by string assertion.
//!
//! Two consumers read it:
//!   * the [`Syscall::Metrics`](crate::syscall_server::Syscall::Metrics) op, so
//!     an SDK/client can pull metrics over the existing newline-JSON protocol;
//!     and
//!   * an optional raw-`tokio` HTTP `/metrics` endpoint (in `agent-server`) for
//!     a real Prometheus scraper.

use std::sync::OnceLock;
use std::time::Instant;

use crate::agent::AgentKernel;
use crate::observability::{MetricScope, ObservabilityEngine};
use crate::syscall_gate::GateStats;
use crate::AgentKernelImpl;

/// The Prometheus exposition content type, including the format version. Use
/// this for the `Content-Type` header of an HTTP `/metrics` response.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Process start instant, captured the first time metrics are rendered. Used to
/// derive `agentos_process_uptime_seconds` without threading a boot time through
/// the kernel struct.
fn process_start() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

/// A plain, serializable snapshot of the numbers that back the exposition.
/// Rendering is split from collection so both can be tested in isolation and so
/// the same snapshot can drive a non-Prometheus consumer later.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetricsSnapshot {
    /// Syscall-gate enforcement counters.
    pub gate: GateStats,
    /// Total agents the kernel hosts.
    pub agent_count: u64,
    /// Agents currently executing a turn.
    pub running_agents: u64,
    /// Agents available to the node (all lifecycle states except Stopped).
    pub live_agents: u64,
    /// Admitted agents waiting for a turn, excluding explicitly paused agents.
    pub queued_agents: u64,
    /// Agents explicitly paused by lifecycle control.
    pub paused_agents: u64,
    /// Agents in the terminal stopped lifecycle state.
    pub stopped_agents: u64,
    /// Turn-admission slots currently occupied and configured capacity.
    pub active_turns: u64,
    pub waiting_turns: u64,
    pub turn_capacity: u64,
    pub turn_admitted_total: u64,
    pub turn_cancelled_total: u64,
    pub turn_starvation_total: u64,
    pub turn_wait_ns_total: u64,
    pub turn_run_ns_total: u64,
    /// Provider requests holding an LLM core, waiting, and total core capacity.
    pub llm_requests_in_flight: u64,
    pub llm_requests_waiting: u64,
    pub llm_core_capacity: u64,
    pub llm_admitted_total: u64,
    pub llm_cancelled_total: u64,
    pub llm_wait_ns_total: u64,
    pub llm_run_ns_total: u64,
    /// System-wide tokens consumed (sum across agents).
    pub tokens_consumed: u64,
    /// System-wide LLM api calls made (sum across agents).
    pub api_calls_made: u64,
    /// Whole seconds the process has been up.
    pub uptime_seconds: u64,
}

impl MetricsSnapshot {
    /// Collect a live snapshot from the kernel's existing subsystems. Pure
    /// reads — no counter is mutated and the syscall gate is not consulted.
    pub fn collect(kernel: &AgentKernelImpl) -> Self {
        let gate = kernel.syscall_gate.stats();

        let agents = kernel.agent_manager.list_agents(None);
        // Agent-manager lifecycle state says whether an agent process is
        // available; it does not say whether a turn is executing right now.
        // The scheduler owns that runtime transition, so it is the canonical
        // source for this concurrency gauge.
        let running = crate::scheduler::AgentScheduler::get_queue_status(&*kernel.scheduler)
            .running_agents as u64;
        let scheduler_queued =
            crate::scheduler::AgentScheduler::get_queue_status(&*kernel.scheduler).queued_agents
                as u64;
        let agent_count = agents.len() as u64;
        let paused = agents
            .iter()
            .filter(|agent| matches!(agent.state, crate::AgentState::Paused))
            .count() as u64;
        let stopped = agents
            .iter()
            .filter(|agent| matches!(agent.state, crate::AgentState::Stopped))
            .count() as u64;

        let sys = kernel.observability.get_metrics(MetricScope::System);

        let turns = kernel.turn_admission.metrics();
        let llm = kernel.llm_scheduler.metrics();
        Self {
            gate,
            agent_count,
            running_agents: running,
            live_agents: agent_count.saturating_sub(stopped),
            queued_agents: scheduler_queued.saturating_sub(paused),
            paused_agents: paused,
            stopped_agents: stopped,
            active_turns: turns.running as u64,
            waiting_turns: turns.waiting as u64,
            turn_capacity: turns.capacity as u64,
            turn_admitted_total: turns.admitted_total,
            turn_cancelled_total: turns.cancelled_total,
            turn_starvation_total: turns.starvation_total,
            turn_wait_ns_total: turns.wait_ns_total,
            turn_run_ns_total: turns.run_ns_total,
            llm_requests_in_flight: llm.in_flight as u64,
            llm_requests_waiting: llm.waiting as u64,
            llm_core_capacity: llm.cores as u64,
            llm_admitted_total: llm.admitted_total,
            llm_cancelled_total: llm.cancelled_total,
            llm_wait_ns_total: llm.wait_ns_total,
            llm_run_ns_total: llm.run_ns_total,
            tokens_consumed: sys.tokens_consumed,
            api_calls_made: sys.api_calls_made,
            uptime_seconds: process_start().elapsed().as_secs(),
        }
    }

    /// Render this snapshot as a Prometheus text exposition (format version
    /// 0.0.4). Deterministic: metric families appear in a fixed order with
    /// `# HELP`/`# TYPE` headers, so the output is stable enough to assert on.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        // --- Syscall-gate enforcement: one counter family, labelled by result.
        out.push_str(
            "# HELP agentos_syscall_gate_total Tool-call decisions made by the syscall gate, by result.\n",
        );
        out.push_str("# TYPE agentos_syscall_gate_total counter\n");
        let g = &self.gate;
        out.push_str(&format!(
            "agentos_syscall_gate_total{{result=\"allowed\"}} {}\n",
            g.allowed
        ));
        out.push_str(&format!(
            "agentos_syscall_gate_total{{result=\"denied_capability\"}} {}\n",
            g.denied_capability
        ));
        out.push_str(&format!(
            "agentos_syscall_gate_total{{result=\"denied_mac\"}} {}\n",
            g.denied_mac
        ));
        out.push_str(&format!(
            "agentos_syscall_gate_total{{result=\"denied_approval\"}} {}\n",
            g.denied_approval
        ));
        out.push_str(&format!(
            "agentos_syscall_gate_total{{result=\"denied_cgroup\"}} {}\n",
            g.denied_cgroup
        ));
        out.push_str(&format!(
            "agentos_syscall_gate_total{{result=\"denied_namespace\"}} {}\n",
            g.denied_namespace
        ));
        out.push_str(&format!(
            "agentos_syscall_gate_total{{result=\"denied_unknown\"}} {}\n",
            g.denied_unknown
        ));

        // Audited allowances are a distinct family (a subset of `allowed`).
        out.push_str(
            "# HELP agentos_syscall_gate_audited_total Allowed tool calls that also matched a MAC audit rule.\n",
        );
        out.push_str("# TYPE agentos_syscall_gate_audited_total counter\n");
        out.push_str(&format!(
            "agentos_syscall_gate_audited_total {}\n",
            g.audited
        ));

        // --- Agent population.
        out.push_str("# HELP agentos_agents Total agents the kernel hosts.\n");
        out.push_str("# TYPE agentos_agents gauge\n");
        out.push_str(&format!("agentos_agents {}\n", self.agent_count));

        out.push_str("# HELP agentos_running_agents Agents currently executing a turn.\n");
        out.push_str("# TYPE agentos_running_agents gauge\n");
        out.push_str(&format!("agentos_running_agents {}\n", self.running_agents));
        for (name, help, value) in [
            ("live", "Agents available to the node.", self.live_agents),
            (
                "queued",
                "Agents waiting to execute a turn.",
                self.queued_agents,
            ),
            ("paused", "Agents explicitly paused.", self.paused_agents),
            (
                "stopped",
                "Agents in the stopped state.",
                self.stopped_agents,
            ),
        ] {
            out.push_str(&format!("# HELP agentos_{name}_agents {help}\n"));
            out.push_str(&format!("# TYPE agentos_{name}_agents gauge\n"));
            out.push_str(&format!("agentos_{name}_agents {value}\n"));
        }

        out.push_str("# HELP agentos_turn_admission Turn admission slots by state.\n");
        out.push_str("# TYPE agentos_turn_admission gauge\n");
        out.push_str(&format!(
            "agentos_turn_admission{{state=\"active\"}} {}\n",
            self.active_turns
        ));
        out.push_str(&format!(
            "agentos_turn_admission{{state=\"waiting\"}} {}\n",
            self.waiting_turns
        ));
        out.push_str(&format!(
            "agentos_turn_admission{{state=\"capacity\"}} {}\n",
            self.turn_capacity
        ));
        out.push_str("# HELP agentos_turn_admitted_total Agent turns admitted.\n");
        out.push_str("# TYPE agentos_turn_admitted_total counter\n");
        out.push_str(&format!(
            "agentos_turn_admitted_total {}\n",
            self.turn_admitted_total
        ));
        out.push_str(
            "# HELP agentos_turn_cancelled_total Turn waiters cancelled before admission.\n",
        );
        out.push_str("# TYPE agentos_turn_cancelled_total counter\n");
        out.push_str(&format!(
            "agentos_turn_cancelled_total {}\n",
            self.turn_cancelled_total
        ));
        out.push_str("# HELP agentos_turn_starvation_total Admitted turns whose wait exceeded the 30-second starvation threshold.\n");
        out.push_str("# TYPE agentos_turn_starvation_total counter\n");
        out.push_str(&format!(
            "agentos_turn_starvation_total {}\n",
            self.turn_starvation_total
        ));
        for (metric, help, value) in [
            (
                "wait",
                "Cumulative nanoseconds turns waited for admission.",
                self.turn_wait_ns_total,
            ),
            (
                "run",
                "Cumulative nanoseconds turns held admission.",
                self.turn_run_ns_total,
            ),
        ] {
            out.push_str(&format!(
                "# HELP agentos_turn_{metric}_nanoseconds_total {help}\n"
            ));
            out.push_str(&format!(
                "# TYPE agentos_turn_{metric}_nanoseconds_total counter\n"
            ));
            out.push_str(&format!(
                "agentos_turn_{metric}_nanoseconds_total {value}\n"
            ));
        }

        out.push_str("# HELP agentos_llm_cores LLM request scheduler cores by state.\n");
        out.push_str("# TYPE agentos_llm_cores gauge\n");
        out.push_str(&format!(
            "agentos_llm_cores{{state=\"in_flight\"}} {}\n",
            self.llm_requests_in_flight
        ));
        out.push_str(&format!(
            "agentos_llm_cores{{state=\"waiting\"}} {}\n",
            self.llm_requests_waiting
        ));
        out.push_str(&format!(
            "agentos_llm_cores{{state=\"capacity\"}} {}\n",
            self.llm_core_capacity
        ));
        for (metric, help, value) in [
            (
                "admitted",
                "LLM requests admitted.",
                self.llm_admitted_total,
            ),
            (
                "cancelled",
                "LLM request waiters cancelled before admission.",
                self.llm_cancelled_total,
            ),
        ] {
            out.push_str(&format!("# HELP agentos_llm_{metric}_total {help}\n"));
            out.push_str(&format!("# TYPE agentos_llm_{metric}_total counter\n"));
            out.push_str(&format!("agentos_llm_{metric}_total {value}\n"));
        }
        for (metric, help, value) in [
            (
                "wait",
                "Cumulative nanoseconds LLM requests waited for a core.",
                self.llm_wait_ns_total,
            ),
            (
                "run",
                "Cumulative nanoseconds LLM requests held a core.",
                self.llm_run_ns_total,
            ),
        ] {
            out.push_str(&format!(
                "# HELP agentos_llm_{metric}_nanoseconds_total {help}\n"
            ));
            out.push_str(&format!(
                "# TYPE agentos_llm_{metric}_nanoseconds_total counter\n"
            ));
            out.push_str(&format!("agentos_llm_{metric}_nanoseconds_total {value}\n"));
        }

        // --- LLM usage totals (system scope).
        out.push_str("# HELP agentos_tokens_consumed_total Tokens consumed across all agents.\n");
        out.push_str("# TYPE agentos_tokens_consumed_total counter\n");
        out.push_str(&format!(
            "agentos_tokens_consumed_total {}\n",
            self.tokens_consumed
        ));

        out.push_str("# HELP agentos_api_calls_total LLM API calls made across all agents.\n");
        out.push_str("# TYPE agentos_api_calls_total counter\n");
        out.push_str(&format!(
            "agentos_api_calls_total {}\n",
            self.api_calls_made
        ));

        // --- Process uptime.
        out.push_str(
            "# HELP agentos_process_uptime_seconds Seconds since this server process rendered its first metrics.\n",
        );
        out.push_str("# TYPE agentos_process_uptime_seconds gauge\n");
        out.push_str(&format!(
            "agentos_process_uptime_seconds {}\n",
            self.uptime_seconds
        ));

        out
    }
}

/// Render the kernel's current metrics as a Prometheus text exposition.
/// Convenience over `MetricsSnapshot::collect(kernel).render_prometheus()`.
pub fn render_prometheus(kernel: &AgentKernelImpl) -> String {
    MetricsSnapshot::collect(kernel).render_prometheus()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MetricsSnapshot {
        MetricsSnapshot {
            gate: GateStats {
                allowed: 5,
                denied_capability: 2,
                denied_mac: 1,
                denied_approval: 6,
                denied_cgroup: 0,
                denied_namespace: 3,
                denied_unknown: 4,
                audited: 1,
            },
            agent_count: 7,
            running_agents: 2,
            live_agents: 6,
            queued_agents: 3,
            paused_agents: 1,
            stopped_agents: 1,
            active_turns: 2,
            waiting_turns: 1,
            turn_capacity: 3,
            turn_admitted_total: 9,
            turn_cancelled_total: 2,
            turn_starvation_total: 1,
            turn_wait_ns_total: 100,
            turn_run_ns_total: 200,
            llm_requests_in_flight: 1,
            llm_requests_waiting: 2,
            llm_core_capacity: 4,
            llm_admitted_total: 8,
            llm_cancelled_total: 1,
            llm_wait_ns_total: 300,
            llm_run_ns_total: 400,
            tokens_consumed: 1234,
            api_calls_made: 12,
            uptime_seconds: 99,
        }
    }

    #[test]
    fn render_has_help_and_type_headers() {
        let text = sample().render_prometheus();
        // Each family carries a HELP + TYPE line.
        assert!(text.contains("# HELP agentos_syscall_gate_total"));
        assert!(text.contains("# TYPE agentos_syscall_gate_total counter"));
        assert!(text.contains("# TYPE agentos_agents gauge"));
        assert!(text.contains("# TYPE agentos_running_agents gauge"));
        assert!(text.contains("# TYPE agentos_live_agents gauge"));
        assert!(text.contains("# TYPE agentos_turn_admission gauge"));
        assert!(text.contains("# TYPE agentos_llm_cores gauge"));
        assert!(text.contains("# TYPE agentos_turn_wait_nanoseconds_total counter"));
        assert!(text.contains("# TYPE agentos_llm_wait_nanoseconds_total counter"));
        assert!(text.contains("# TYPE agentos_tokens_consumed_total counter"));
        assert!(text.contains("# TYPE agentos_api_calls_total counter"));
        assert!(text.contains("# TYPE agentos_process_uptime_seconds gauge"));
    }

    #[test]
    fn render_reflects_snapshot_values() {
        let text = sample().render_prometheus();
        assert!(text.contains("agentos_syscall_gate_total{result=\"allowed\"} 5"));
        assert!(text.contains("agentos_syscall_gate_total{result=\"denied_capability\"} 2"));
        assert!(text.contains("agentos_syscall_gate_total{result=\"denied_mac\"} 1"));
        assert!(text.contains("agentos_syscall_gate_total{result=\"denied_approval\"} 6"));
        assert!(text.contains("agentos_syscall_gate_total{result=\"denied_namespace\"} 3"));
        assert!(text.contains("agentos_syscall_gate_total{result=\"denied_unknown\"} 4"));
        assert!(text.contains("agentos_syscall_gate_audited_total 1"));
        assert!(text.contains("agentos_agents 7"));
        assert!(text.contains("agentos_running_agents 2"));
        assert!(text.contains("agentos_live_agents 6"));
        assert!(text.contains("agentos_queued_agents 3"));
        assert!(text.contains("agentos_paused_agents 1"));
        assert!(text.contains("agentos_stopped_agents 1"));
        assert!(text.contains("agentos_turn_admission{state=\"active\"} 2"));
        assert!(text.contains("agentos_llm_cores{state=\"in_flight\"} 1"));
        assert!(text.contains("agentos_tokens_consumed_total 1234"));
        assert!(text.contains("agentos_api_calls_total 12"));
        assert!(text.contains("agentos_process_uptime_seconds 99"));
    }

    #[test]
    fn render_is_deterministic() {
        let s = sample();
        assert_eq!(s.render_prometheus(), s.render_prometheus());
    }

    #[tokio::test]
    async fn collect_reflects_gate_counters_after_tool_calls() {
        use crate::agent_struct::CapabilitySet;

        let kernel = AgentKernelImpl::new().expect("kernel new");

        // Register an agent directly with the gate and drive real check_tool_call
        // decisions: an allowed read, and a denied write (no CAP_FILE_WRITE).
        let kid = uuid::Uuid::new_v4();
        let pid = kernel
            .syscall_gate
            .register_agent(kid, CapabilitySet::none(), None);
        kernel
            .syscall_gate
            .mac
            .lock()
            .await
            .label_agent(pid, "profile:read-only".into());

        // read_file requires no capability → allowed.
        let allowed = kernel
            .syscall_gate
            .check_tool_call(kid, "read_file", "/etc/hosts", 1)
            .await;
        assert!(allowed.is_ok());

        // write_file requires CAP_FILE_WRITE which the agent lacks → denied.
        let denied = kernel
            .syscall_gate
            .check_tool_call(kid, "write_file", "/tmp/x", 1)
            .await;
        assert!(denied.is_err());

        let snap = MetricsSnapshot::collect(&kernel);
        assert_eq!(snap.gate.allowed, 1);
        assert_eq!(snap.gate.denied_capability, 1);

        let text = snap.render_prometheus();
        assert!(text.contains("agentos_syscall_gate_total{result=\"allowed\"} 1"));
        assert!(text.contains("agentos_syscall_gate_total{result=\"denied_capability\"} 1"));
    }

    #[test]
    fn collect_uses_scheduler_for_current_execution_count() {
        let kernel = AgentKernelImpl::new().expect("kernel new");
        let kid = uuid::Uuid::new_v4();

        // No AgentManager lifecycle record exists for this id. The scheduler is
        // nevertheless executing it, which is the state the gauge promises.
        kernel.scheduler.set_running(kid);
        assert_eq!(MetricsSnapshot::collect(&kernel).running_agents, 1);

        kernel.scheduler.set_queued(kid);
        assert_eq!(MetricsSnapshot::collect(&kernel).running_agents, 0);
    }
}
