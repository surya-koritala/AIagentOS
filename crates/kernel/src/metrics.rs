//! Prometheus-text metrics exposition — the operator-facing read-out of the
//! running kernel.
//!
//! This module is the `/proc`-style health export for an `agent-server` in
//! production: it hand-renders a `text/plain; version=0.0.4` Prometheus
//! exposition from counters that already exist elsewhere in the kernel — the
//! [syscall gate](crate::syscall_gate)'s enforcement counters, the
//! [observability engine](crate::observability)'s system token/api totals, and
//! the agent manager's live agent counts. No `prometheus`/`metrics` crate is
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Syscall-gate enforcement counters.
    pub gate: GateStats,
    /// Total agents the kernel hosts.
    pub agent_count: u64,
    /// Agents currently executing a turn.
    pub running_agents: u64,
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
        let running = agents
            .iter()
            .filter(|a| matches!(a.state, crate::AgentState::Running))
            .count() as u64;
        let agent_count = agents.len() as u64;

        let sys = kernel.observability.get_metrics(MetricScope::System);

        Self {
            gate,
            agent_count,
            running_agents: running,
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
                denied_cgroup: 0,
                denied_namespace: 3,
                denied_unknown: 4,
                audited: 1,
            },
            agent_count: 7,
            running_agents: 2,
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
        assert!(text.contains("agentos_syscall_gate_total{result=\"denied_namespace\"} 3"));
        assert!(text.contains("agentos_syscall_gate_total{result=\"denied_unknown\"} 4"));
        assert!(text.contains("agentos_syscall_gate_audited_total 1"));
        assert!(text.contains("agentos_agents 7"));
        assert!(text.contains("agentos_running_agents 2"));
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
        kernel
            .syscall_gate
            .register_agent(kid, CapabilitySet::none(), None);

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
}
