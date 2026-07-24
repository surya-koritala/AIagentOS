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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use crate::agent::AgentKernel;
use crate::observability::{MetricScope, ObservabilityEngine};
use crate::syscall_gate::GateStats;
use crate::AgentKernelImpl;

/// Bounded lifecycle outcomes for one operation. These counters are
/// process-local and monotonic; no agent id appears as a metric label.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct LifecycleOperationMetrics {
    pub requested: u64,
    pub completed: u64,
    pub timed_out: u64,
    pub forced: u64,
    pub failed: u64,
    /// Cumulative wall-clock time for completed attempts, in microseconds.
    pub duration_microseconds_total: u64,
    /// Number of attempts represented by `duration_microseconds_total`.
    pub duration_samples: u64,
}

/// Lifecycle counters grouped by the fixed public operation set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct LifecycleMetricsSnapshot {
    pub pause: LifecycleOperationMetrics,
    pub resume: LifecycleOperationMetrics,
    pub stop: LifecycleOperationMetrics,
    pub kill: LifecycleOperationMetrics,
    pub wait: LifecycleOperationMetrics,
}

#[derive(Debug, Default)]
struct LifecycleOperationCounters {
    requested: AtomicU64,
    completed: AtomicU64,
    timed_out: AtomicU64,
    forced: AtomicU64,
    failed: AtomicU64,
    duration_microseconds_total: AtomicU64,
    duration_samples: AtomicU64,
}

impl LifecycleOperationCounters {
    fn record(&self, outcome: crate::LifecycleOutcome) {
        let counter = match outcome {
            crate::LifecycleOutcome::Requested => &self.requested,
            crate::LifecycleOutcome::Completed => &self.completed,
            crate::LifecycleOutcome::TimedOut => &self.timed_out,
            crate::LifecycleOutcome::Forced => &self.forced,
            crate::LifecycleOutcome::Failed => &self.failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_duration(&self, duration: std::time::Duration) {
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        let _ = self.duration_microseconds_total.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_add(micros)),
        );
        let _ =
            self.duration_samples
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(1))
                });
    }

    fn snapshot(&self) -> LifecycleOperationMetrics {
        LifecycleOperationMetrics {
            requested: self.requested.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            timed_out: self.timed_out.load(Ordering::Relaxed),
            forced: self.forced.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            duration_microseconds_total: self.duration_microseconds_total.load(Ordering::Relaxed),
            duration_samples: self.duration_samples.load(Ordering::Relaxed),
        }
    }
}

/// Process-local lifecycle telemetry shared by the kernel coordinator and
/// operator metrics exporter.
#[derive(Debug, Default)]
pub(crate) struct LifecycleCounters {
    pause: LifecycleOperationCounters,
    resume: LifecycleOperationCounters,
    stop: LifecycleOperationCounters,
    kill: LifecycleOperationCounters,
    wait: LifecycleOperationCounters,
}

impl LifecycleCounters {
    pub(crate) fn record(
        &self,
        operation: crate::LifecycleOperation,
        outcome: crate::LifecycleOutcome,
    ) {
        let counters = match operation {
            crate::LifecycleOperation::Pause => &self.pause,
            crate::LifecycleOperation::Resume => &self.resume,
            crate::LifecycleOperation::Stop => &self.stop,
            crate::LifecycleOperation::Kill => &self.kill,
            crate::LifecycleOperation::Wait => &self.wait,
        };
        counters.record(outcome);
    }

    pub(crate) fn record_duration(
        &self,
        operation: crate::LifecycleOperation,
        duration: std::time::Duration,
    ) {
        let counters = match operation {
            crate::LifecycleOperation::Pause => &self.pause,
            crate::LifecycleOperation::Resume => &self.resume,
            crate::LifecycleOperation::Stop => &self.stop,
            crate::LifecycleOperation::Kill => &self.kill,
            crate::LifecycleOperation::Wait => &self.wait,
        };
        counters.record_duration(duration);
    }

    pub(crate) fn snapshot(&self) -> LifecycleMetricsSnapshot {
        LifecycleMetricsSnapshot {
            pause: self.pause.snapshot(),
            resume: self.resume.snapshot(),
            stop: self.stop.snapshot(),
            kill: self.kill.snapshot(),
            wait: self.wait.snapshot(),
        }
    }
}

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
#[serde(default)]
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
    pub turn_admitted_realtime_total: u64,
    pub turn_admitted_normal_total: u64,
    pub turn_admitted_background_total: u64,
    pub turn_admitted_deadline_total: u64,
    pub turn_cancelled_total: u64,
    pub turn_cooperative_yields_total: u64,
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
    /// Durable provider/global quota state for the current effective fixed
    /// epoch. These fields use no tenant or agent labels, keeping cardinality
    /// bounded.
    pub quota_epoch: u64,
    pub quota_provider_requests: u64,
    pub quota_provider_tokens: u64,
    pub quota_rpm_limit: u64,
    pub quota_tpm_limit: u64,
    pub quota_reserved_receipts: u64,
    pub quota_in_flight_receipts: u64,
    pub quota_estimated_receipts: u64,
    pub quota_reconciled_receipts: u64,
    pub quota_denied_provider_requests: u64,
    pub quota_denied_provider_tokens: u64,
    pub quota_denied_cgroup_requests: u64,
    pub quota_denied_cgroup_tokens: u64,
    pub quota_denied_migration_fence: u64,
    pub quota_storage_healthy: bool,
    /// Lifecycle requests and bounded outcomes by operation.
    pub lifecycle: LifecycleMetricsSnapshot,
    /// Kernel-owned service-supervisor state and bounded counters.
    pub service_configured: u64,
    pub service_desired: u64,
    pub service_running: u64,
    pub service_ready: u64,
    pub service_healthy: u64,
    pub service_failed: u64,
    pub service_restarts_total: u64,
    pub service_dependency_blocks_total: u64,
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
        let quota = kernel.rate_limiter.stats();
        let services = kernel
            .os
            .init
            .try_lock()
            .map(|init| init.metrics())
            .unwrap_or_default();
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
            turn_admitted_realtime_total: turns.admitted_realtime_total,
            turn_admitted_normal_total: turns.admitted_normal_total,
            turn_admitted_background_total: turns.admitted_background_total,
            turn_admitted_deadline_total: turns.admitted_deadline_total,
            turn_cancelled_total: turns.cancelled_total,
            turn_cooperative_yields_total: turns.cooperative_yields_total,
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
            quota_epoch: quota.epoch,
            quota_provider_requests: quota.requests_this_minute,
            quota_provider_tokens: quota.tokens_this_minute,
            quota_rpm_limit: u64::from(quota.rpm_limit),
            quota_tpm_limit: quota.tpm_limit,
            quota_reserved_receipts: quota.reserved_receipts,
            quota_in_flight_receipts: quota.in_flight_receipts,
            quota_estimated_receipts: quota.estimated_receipts,
            quota_reconciled_receipts: quota.reconciled_receipts,
            quota_denied_provider_requests: quota.denied_provider_requests,
            quota_denied_provider_tokens: quota.denied_provider_tokens,
            quota_denied_cgroup_requests: quota.denied_cgroup_requests,
            quota_denied_cgroup_tokens: quota.denied_cgroup_tokens,
            quota_denied_migration_fence: quota.denied_migration_fence,
            quota_storage_healthy: quota.healthy,
            lifecycle: kernel.lifecycle_counters.snapshot(),
            service_configured: services.configured,
            service_desired: services.desired,
            service_running: services.running,
            service_ready: services.ready,
            service_healthy: services.healthy,
            service_failed: services.failed,
            service_restarts_total: services.restarts_total,
            service_dependency_blocks_total: services.dependency_blocks_total,
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

        out.push_str("# HELP agentos_services Service supervisor units by bounded state.\n");
        out.push_str("# TYPE agentos_services gauge\n");
        for (state, value) in [
            ("configured", self.service_configured),
            ("desired", self.service_desired),
            ("running", self.service_running),
            ("ready", self.service_ready),
            ("healthy", self.service_healthy),
            ("failed", self.service_failed),
        ] {
            out.push_str(&format!("agentos_services{{state=\"{state}\"}} {value}\n"));
        }
        out.push_str(
            "# HELP agentos_service_restarts_total Service restart attempts in durable runtime history.\n",
        );
        out.push_str("# TYPE agentos_service_restarts_total counter\n");
        out.push_str(&format!(
            "agentos_service_restarts_total {}\n",
            self.service_restarts_total
        ));
        out.push_str(
            "# HELP agentos_service_dependency_blocks_total Service starts or restarts blocked by required dependencies.\n",
        );
        out.push_str("# TYPE agentos_service_dependency_blocks_total counter\n");
        out.push_str(&format!(
            "agentos_service_dependency_blocks_total {}\n",
            self.service_dependency_blocks_total
        ));

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
            "# HELP agentos_turn_class_admitted_total Agent turns admitted by bounded scheduling class.\n",
        );
        out.push_str("# TYPE agentos_turn_class_admitted_total counter\n");
        for (class, value) in [
            ("realtime", self.turn_admitted_realtime_total),
            ("normal", self.turn_admitted_normal_total),
            ("background", self.turn_admitted_background_total),
            ("deadline", self.turn_admitted_deadline_total),
        ] {
            out.push_str(&format!(
                "agentos_turn_class_admitted_total{{class=\"{class}\"}} {value}\n"
            ));
        }
        out.push_str(
            "# HELP agentos_turn_cancelled_total Turn waiters cancelled before admission.\n",
        );
        out.push_str("# TYPE agentos_turn_cancelled_total counter\n");
        out.push_str(&format!(
            "agentos_turn_cancelled_total {}\n",
            self.turn_cancelled_total
        ));
        out.push_str("# HELP agentos_turn_cooperative_yields_total Completed turns that exhausted their token slice and yielded at the public turn boundary.\n");
        out.push_str("# TYPE agentos_turn_cooperative_yields_total counter\n");
        out.push_str(&format!(
            "agentos_turn_cooperative_yields_total {}\n",
            self.turn_cooperative_yields_total
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

        out.push_str(
            "# HELP agentos_quota_storage_healthy Whether durable quota accounting is healthy.\n",
        );
        out.push_str("# TYPE agentos_quota_storage_healthy gauge\n");
        out.push_str(&format!(
            "agentos_quota_storage_healthy {}\n",
            u8::from(self.quota_storage_healthy)
        ));
        out.push_str("# HELP agentos_quota_epoch Current effective fixed Unix-minute epoch.\n");
        out.push_str("# TYPE agentos_quota_epoch gauge\n");
        out.push_str(&format!("agentos_quota_epoch {}\n", self.quota_epoch));
        out.push_str(
            "# HELP agentos_provider_quota_usage Current provider/global quota usage by dimension.\n",
        );
        out.push_str("# TYPE agentos_provider_quota_usage gauge\n");
        out.push_str(&format!(
            "agentos_provider_quota_usage{{dimension=\"requests\"}} {}\n",
            self.quota_provider_requests
        ));
        out.push_str(&format!(
            "agentos_provider_quota_usage{{dimension=\"tokens\"}} {}\n",
            self.quota_provider_tokens
        ));
        out.push_str(
            "# HELP agentos_provider_quota_limit Configured provider/global quota limit by dimension; zero is unlimited.\n",
        );
        out.push_str("# TYPE agentos_provider_quota_limit gauge\n");
        out.push_str(&format!(
            "agentos_provider_quota_limit{{dimension=\"requests\"}} {}\n",
            self.quota_rpm_limit
        ));
        out.push_str(&format!(
            "agentos_provider_quota_limit{{dimension=\"tokens\"}} {}\n",
            self.quota_tpm_limit
        ));
        out.push_str(
            "# HELP agentos_quota_receipts Current-epoch durable receipts by bounded lifecycle state.\n",
        );
        out.push_str("# TYPE agentos_quota_receipts gauge\n");
        for (state, value) in [
            ("reserved", self.quota_reserved_receipts),
            ("in_flight", self.quota_in_flight_receipts),
            ("estimated", self.quota_estimated_receipts),
            ("reconciled", self.quota_reconciled_receipts),
        ] {
            out.push_str(&format!(
                "agentos_quota_receipts{{state=\"{state}\"}} {value}\n"
            ));
        }
        out.push_str(
            "# HELP agentos_quota_denied_total Quota admission denials by bounded scope and dimension.\n",
        );
        out.push_str("# TYPE agentos_quota_denied_total counter\n");
        for (scope, dimension, value) in [
            ("provider", "requests", self.quota_denied_provider_requests),
            ("provider", "tokens", self.quota_denied_provider_tokens),
            ("cgroup", "requests", self.quota_denied_cgroup_requests),
            ("cgroup", "tokens", self.quota_denied_cgroup_tokens),
            (
                "provider",
                "migration_fence",
                self.quota_denied_migration_fence,
            ),
        ] {
            out.push_str(&format!(
                "agentos_quota_denied_total{{scope=\"{scope}\",dimension=\"{dimension}\"}} {value}\n"
            ));
        }

        out.push_str(
            "# HELP agentos_lifecycle_operations_total Agent lifecycle operations by operation and bounded outcome.\n",
        );
        out.push_str("# TYPE agentos_lifecycle_operations_total counter\n");
        for (operation, counters) in [
            ("pause", self.lifecycle.pause),
            ("resume", self.lifecycle.resume),
            ("stop", self.lifecycle.stop),
            ("kill", self.lifecycle.kill),
            ("wait", self.lifecycle.wait),
        ] {
            for (outcome, value) in [
                ("requested", counters.requested),
                ("completed", counters.completed),
                ("timed_out", counters.timed_out),
                ("forced", counters.forced),
                ("failed", counters.failed),
            ] {
                out.push_str(&format!(
                    "agentos_lifecycle_operations_total{{operation=\"{operation}\",outcome=\"{outcome}\"}} {value}\n"
                ));
            }
        }
        out.push_str(
            "# HELP agentos_lifecycle_duration_seconds Wall-clock lifecycle operation latency.\n",
        );
        out.push_str("# TYPE agentos_lifecycle_duration_seconds summary\n");
        for (operation, counters) in [
            ("pause", self.lifecycle.pause),
            ("resume", self.lifecycle.resume),
            ("stop", self.lifecycle.stop),
            ("kill", self.lifecycle.kill),
            ("wait", self.lifecycle.wait),
        ] {
            out.push_str(&format!(
                "agentos_lifecycle_duration_seconds_sum{{operation=\"{operation}\"}} {:.6}\n",
                counters.duration_microseconds_total as f64 / 1_000_000.0
            ));
            out.push_str(&format!(
                "agentos_lifecycle_duration_seconds_count{{operation=\"{operation}\"}} {}\n",
                counters.duration_samples
            ));
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
            turn_admitted_realtime_total: 1,
            turn_admitted_normal_total: 6,
            turn_admitted_background_total: 1,
            turn_admitted_deadline_total: 1,
            turn_cancelled_total: 2,
            turn_cooperative_yields_total: 4,
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
            quota_epoch: 42,
            quota_provider_requests: 3,
            quota_provider_tokens: 456,
            quota_rpm_limit: 60,
            quota_tpm_limit: 100_000,
            quota_reserved_receipts: 1,
            quota_in_flight_receipts: 2,
            quota_estimated_receipts: 3,
            quota_reconciled_receipts: 4,
            quota_denied_provider_requests: 5,
            quota_denied_provider_tokens: 6,
            quota_denied_cgroup_requests: 7,
            quota_denied_cgroup_tokens: 8,
            quota_denied_migration_fence: 9,
            quota_storage_healthy: true,
            lifecycle: LifecycleMetricsSnapshot {
                pause: LifecycleOperationMetrics {
                    requested: 3,
                    completed: 2,
                    timed_out: 1,
                    forced: 0,
                    failed: 0,
                    duration_microseconds_total: 125_000,
                    duration_samples: 3,
                },
                kill: LifecycleOperationMetrics {
                    requested: 1,
                    completed: 0,
                    timed_out: 0,
                    forced: 1,
                    failed: 0,
                    duration_microseconds_total: 5_000,
                    duration_samples: 1,
                },
                ..Default::default()
            },
            service_configured: 4,
            service_desired: 3,
            service_running: 2,
            service_ready: 2,
            service_healthy: 2,
            service_failed: 1,
            service_restarts_total: 5,
            service_dependency_blocks_total: 2,
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
        assert!(text.contains("# TYPE agentos_services gauge"));
        assert!(text.contains("# TYPE agentos_service_restarts_total counter"));
        assert!(text.contains("# TYPE agentos_turn_admission gauge"));
        assert!(text.contains("# TYPE agentos_turn_class_admitted_total counter"));
        assert!(text.contains("# TYPE agentos_turn_cooperative_yields_total counter"));
        assert!(text.contains("# TYPE agentos_llm_cores gauge"));
        assert!(text.contains("# TYPE agentos_turn_wait_nanoseconds_total counter"));
        assert!(text.contains("# TYPE agentos_llm_wait_nanoseconds_total counter"));
        assert!(text.contains("# TYPE agentos_quota_storage_healthy gauge"));
        assert!(text.contains("# TYPE agentos_provider_quota_usage gauge"));
        assert!(text.contains("# TYPE agentos_quota_receipts gauge"));
        assert!(text.contains("# TYPE agentos_quota_denied_total counter"));
        assert!(text.contains("# TYPE agentos_lifecycle_operations_total counter"));
        assert!(text.contains("# TYPE agentos_lifecycle_duration_seconds summary"));
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
        assert!(text.contains("agentos_turn_class_admitted_total{class=\"normal\"} 6"));
        assert!(text.contains("agentos_turn_cooperative_yields_total 4"));
        assert!(text.contains("agentos_llm_cores{state=\"in_flight\"} 1"));
        assert!(text.contains("agentos_quota_storage_healthy 1"));
        assert!(text.contains("agentos_quota_epoch 42"));
        assert!(text.contains("agentos_provider_quota_usage{dimension=\"tokens\"} 456"));
        assert!(text.contains("agentos_quota_receipts{state=\"reconciled\"} 4"));
        assert!(
            text.contains("agentos_quota_denied_total{scope=\"cgroup\",dimension=\"tokens\"} 8")
        );
        assert!(text.contains(
            "agentos_lifecycle_operations_total{operation=\"pause\",outcome=\"timed_out\"} 1"
        ));
        assert!(text.contains(
            "agentos_lifecycle_operations_total{operation=\"kill\",outcome=\"forced\"} 1"
        ));
        assert!(
            text.contains("agentos_lifecycle_duration_seconds_sum{operation=\"pause\"} 0.125000")
        );
        assert!(text.contains("agentos_lifecycle_duration_seconds_count{operation=\"pause\"} 3"));
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
            .label_mac_agent(pid, "profile:read-only".into())
            .await;

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
