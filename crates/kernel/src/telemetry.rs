//! Stable, bounded-cardinality request telemetry.
//!
//! Request correlation belongs in traces and logs, never in metric labels.
//! This module deliberately exposes only a fixed subsystem and outcome matrix,
//! making the Prometheus series count independent of tenants, agents, request
//! IDs, tools, providers, paths, URLs, or prompt contents.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Version of the public metric-name, label, type, and unit contract.
pub const TELEMETRY_CONTRACT_VERSION: u32 = 2;

const SUBSYSTEM_COUNT: usize = 12;
const OUTCOME_COUNT: usize = 5;
/// Fixed latency histogram boundaries in microseconds.
pub const REQUEST_DURATION_BUCKETS_MICROSECONDS: [u64; 13] = [
    5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000,
    10_000_000, 30_000_000, 60_000_000,
];
const BUCKET_COUNT: usize = REQUEST_DURATION_BUCKETS_MICROSECONDS.len();

/// Fixed latency classes shared by the runtime and its SLO exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum RequestClass {
    Control = 0,
    Agent = 1,
}

impl RequestClass {
    pub const ALL: [Self; 2] = [Self::Control, Self::Agent];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Agent => "agent",
        }
    }
}

/// Fixed request subsystems allowed as the `subsystem` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum RequestSubsystem {
    Agent = 0,
    Auth = 1,
    Checkpoint = 2,
    Cluster = 3,
    Memory = 4,
    Operator = 5,
    Package = 6,
    Protocol = 7,
    Service = 8,
    Storage = 9,
    System = 10,
    Tool = 11,
}

impl RequestSubsystem {
    pub const ALL: [Self; SUBSYSTEM_COUNT] = [
        Self::Agent,
        Self::Auth,
        Self::Checkpoint,
        Self::Cluster,
        Self::Memory,
        Self::Operator,
        Self::Package,
        Self::Protocol,
        Self::Service,
        Self::Storage,
        Self::System,
        Self::Tool,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Auth => "auth",
            Self::Checkpoint => "checkpoint",
            Self::Cluster => "cluster",
            Self::Memory => "memory",
            Self::Operator => "operator",
            Self::Package => "package",
            Self::Protocol => "protocol",
            Self::Service => "service",
            Self::Storage => "storage",
            Self::System => "system",
            Self::Tool => "tool",
        }
    }

    /// Resource and execution traffic uses the agent latency class. Control
    /// includes authentication, membership, packages, protocol and supervision.
    pub const fn request_class(self) -> RequestClass {
        match self {
            Self::Agent | Self::Checkpoint | Self::Memory | Self::Storage | Self::Tool => RequestClass::Agent,
            Self::Auth | Self::Cluster | Self::Operator | Self::Package | Self::Protocol | Self::Service | Self::System => RequestClass::Control,
        }
    }

    /// Collapse the static authorization action into a bounded public label.
    pub fn from_action(action: &str) -> Self {
        if action == "agent.call_tool" {
            return Self::Tool;
        }
        match action.split_once('.').map_or(action, |(prefix, _)| prefix) {
            "agent" => Self::Agent,
            "auth" => Self::Auth,
            "checkpoint" => Self::Checkpoint,
            "cluster" => Self::Cluster,
            "context" | "memory" | "snapshot" => Self::Memory,
            "operator" => Self::Operator,
            "package" => Self::Package,
            "protocol" => Self::Protocol,
            "service" => Self::Service,
            "storage" => Self::Storage,
            "tool" => Self::Tool,
            // Node and other privileged kernel operations are intentionally
            // grouped into one stable system series.
            _ => Self::System,
        }
    }
}

/// Fixed request outcomes allowed as the `outcome` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum RequestOutcome {
    Success = 0,
    Rejected = 1,
    Failed = 2,
    TimedOut = 3,
    Cancelled = 4,
}

impl RequestOutcome {
    pub const ALL: [Self; OUTCOME_COUNT] = [
        Self::Success,
        Self::Rejected,
        Self::Failed,
        Self::TimedOut,
        Self::Cancelled,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

/// One stable subsystem/outcome cell in a request telemetry snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RequestTelemetrySample {
    pub subsystem: String,
    pub outcome: String,
    pub requests: u64,
    pub duration_microseconds_total: u64,
    /// Cumulative counts matching
    /// [`REQUEST_DURATION_BUCKETS_MICROSECONDS`].
    pub duration_bucket_counts: Vec<u64>,
}

/// Serializable process-local request telemetry.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RequestTelemetrySnapshot {
    pub in_flight: u64,
    pub samples: Vec<RequestTelemetrySample>,
}

/// One class projection, aggregating all outcomes without adding dynamic labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestClassTelemetrySample {
    pub class: RequestClass,
    pub requests: u64,
    pub duration_microseconds_total: u64,
    pub duration_bucket_counts: [u64; BUCKET_COUNT],
}

impl RequestTelemetrySnapshot {
    /// Sum the same completed observations used by subsystem metrics. These
    /// counts are not a second observation path and cannot double-count a call.
    pub fn request_classes(&self) -> [RequestClassTelemetrySample; 2] {
        let mut classes = RequestClass::ALL.map(|class| RequestClassTelemetrySample {
            class,
            requests: 0,
            duration_microseconds_total: 0,
            duration_bucket_counts: [0; BUCKET_COUNT],
        });
        for sample in &self.samples {
            let Some(subsystem) = RequestSubsystem::ALL.into_iter().find(|subsystem| subsystem.as_str() == sample.subsystem) else {
                continue;
            };
            let aggregate = &mut classes[subsystem.request_class() as usize];
            aggregate.requests = aggregate.requests.saturating_add(sample.requests);
            aggregate.duration_microseconds_total = aggregate.duration_microseconds_total.saturating_add(sample.duration_microseconds_total);
            for (total, count) in aggregate.duration_bucket_counts.iter_mut().zip(&sample.duration_bucket_counts) {
                *total = total.saturating_add(*count);
            }
        }
        classes
    }
}

/// Process-local request counters owned by one kernel instance.
pub(crate) struct RequestTelemetry {
    in_flight: AtomicU64,
    requests: [[AtomicU64; OUTCOME_COUNT]; SUBSYSTEM_COUNT],
    duration_microseconds_total: [[AtomicU64; OUTCOME_COUNT]; SUBSYSTEM_COUNT],
    duration_buckets: [[[AtomicU64; BUCKET_COUNT]; OUTCOME_COUNT]; SUBSYSTEM_COUNT],
}

impl Default for RequestTelemetry {
    fn default() -> Self {
        Self {
            in_flight: AtomicU64::new(0),
            requests: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            duration_microseconds_total: std::array::from_fn(|_| {
                std::array::from_fn(|_| AtomicU64::new(0))
            }),
            duration_buckets: std::array::from_fn(|_| {
                std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0)))
            }),
        }
    }
}

impl RequestTelemetry {
    pub(crate) fn start(&self, subsystem: RequestSubsystem) -> RequestObservation<'_> {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        RequestObservation {
            telemetry: self,
            subsystem,
            started: Instant::now(),
            outcome: None,
        }
    }

    pub(crate) fn snapshot(&self) -> RequestTelemetrySnapshot {
        let mut samples = Vec::with_capacity(SUBSYSTEM_COUNT * OUTCOME_COUNT);
        for subsystem in RequestSubsystem::ALL {
            for outcome in RequestOutcome::ALL {
                samples.push(RequestTelemetrySample {
                    subsystem: subsystem.as_str().to_string(),
                    outcome: outcome.as_str().to_string(),
                    requests: self.requests[subsystem as usize][outcome as usize]
                        .load(Ordering::Relaxed),
                    duration_microseconds_total: self.duration_microseconds_total
                        [subsystem as usize][outcome as usize]
                        .load(Ordering::Relaxed),
                    duration_bucket_counts: self.duration_buckets[subsystem as usize]
                        [outcome as usize]
                        .iter()
                        .map(|bucket| bucket.load(Ordering::Relaxed))
                        .collect(),
                });
            }
        }
        RequestTelemetrySnapshot {
            in_flight: self.in_flight.load(Ordering::Relaxed),
            samples,
        }
    }
}

/// Drop-safe observation. A cancelled dispatch future is still accounted.
pub(crate) struct RequestObservation<'a> {
    telemetry: &'a RequestTelemetry,
    subsystem: RequestSubsystem,
    started: Instant,
    outcome: Option<RequestOutcome>,
}

impl RequestObservation<'_> {
    pub(crate) fn finish(&mut self, outcome: RequestOutcome) {
        self.outcome = Some(outcome);
    }
}

impl Drop for RequestObservation<'_> {
    fn drop(&mut self) {
        let outcome = self.outcome.unwrap_or(RequestOutcome::Cancelled);
        let micros = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.telemetry.requests[self.subsystem as usize][outcome as usize]
            .fetch_add(1, Ordering::Relaxed);
        let _ = self.telemetry.duration_microseconds_total[self.subsystem as usize]
            [outcome as usize]
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(micros))
            });
        for (index, boundary) in REQUEST_DURATION_BUCKETS_MICROSECONDS.iter().enumerate() {
            if micros <= *boundary {
                self.telemetry.duration_buckets[self.subsystem as usize][outcome as usize][index]
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        self.telemetry.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ProviderOutcomeSnapshot {
    pub success: u64,
    pub failed: u64,
    pub timed_out: u64,
    pub cancelled: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum ProviderOutcome {
    Success = 0,
    Failed = 1,
    TimedOut = 2,
    Cancelled = 3,
}

#[derive(Default)]
pub(crate) struct ProviderOutcomeCounters {
    outcomes: [AtomicU64; 4],
}

impl ProviderOutcomeCounters {
    pub(crate) fn start(self: &std::sync::Arc<Self>) -> ProviderObservation {
        ProviderObservation { counters: self.clone(), outcome: None }
    }

    pub(crate) fn snapshot(&self) -> ProviderOutcomeSnapshot {
        ProviderOutcomeSnapshot {
            success: self.outcomes[0].load(Ordering::Relaxed),
            failed: self.outcomes[1].load(Ordering::Relaxed),
            timed_out: self.outcomes[2].load(Ordering::Relaxed),
            cancelled: self.outcomes[3].load(Ordering::Relaxed),
        }
    }
}

pub(crate) struct ProviderObservation {
    counters: std::sync::Arc<ProviderOutcomeCounters>,
    outcome: Option<ProviderOutcome>,
}

impl ProviderObservation {
    pub(crate) fn finish(&mut self, outcome: ProviderOutcome) {
        self.outcome = Some(outcome);
    }
}

impl Drop for ProviderObservation {
    fn drop(&mut self) {
        let outcome = self.outcome.unwrap_or(ProviderOutcome::Cancelled);
        let _ = self.counters.outcomes[outcome as usize].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| Some(value.saturating_add(1)));
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CheckpointRecoverySnapshot {
    pub attempted: u64,
    pub recovered: u64,
    pub safe_rejected: u64,
    pub cross_tenant_attempts: u64,
    pub cross_tenant_recoveries: u64,
}

#[derive(Default)]
pub(crate) struct CheckpointRecoveryCounters {
    completed: std::sync::Mutex<CheckpointRecoverySnapshot>,
}

impl CheckpointRecoveryCounters {
    pub(crate) fn start(self: &std::sync::Arc<Self>) -> CheckpointRecoveryObservation {
        CheckpointRecoveryObservation { counters: self.clone(), recovered: false, foreign: false }
    }

    pub(crate) fn snapshot(&self) -> CheckpointRecoverySnapshot {
        self.completed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

pub(crate) struct CheckpointRecoveryObservation {
    counters: std::sync::Arc<CheckpointRecoveryCounters>,
    recovered: bool,
    foreign: bool,
}

impl CheckpointRecoveryObservation {
    pub(crate) fn observed_foreign_tenant(&mut self, foreign: bool) { self.foreign |= foreign; }
    pub(crate) fn recovered(&mut self) { self.recovered = true; }
}

impl Drop for CheckpointRecoveryObservation {
    fn drop(&mut self) {
        let mut snapshot = self.counters.completed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if snapshot.attempted == u64::MAX { return; }
        snapshot.attempted += 1;
        if self.recovered { snapshot.recovered += 1; } else { snapshot.safe_rejected += 1; }
        if self.foreign {
            snapshot.cross_tenant_attempts += 1;
            if self.recovered { snapshot.cross_tenant_recoveries += 1; }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct DenialProbeSnapshot {
    pub adversarial_attempts: u64,
    pub unexpected_allows: u64,
    pub tenant_boundary_attempts: u64,
    pub confirmed_violations: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum DenialProbeKind { AuthorizationSandbox, TenantBoundary }

#[derive(Default)]
pub(crate) struct DenialProbeCounters {
    completed: std::sync::Mutex<DenialProbeSnapshot>,
}

impl DenialProbeCounters {
    pub(crate) fn record(&self, kind: DenialProbeKind, allowed: bool) {
        let mut snapshot = self.completed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match kind {
            DenialProbeKind::AuthorizationSandbox => {
                if snapshot.adversarial_attempts != u64::MAX {
                    snapshot.adversarial_attempts += 1;
                    snapshot.unexpected_allows += u64::from(allowed);
                }
            }
            DenialProbeKind::TenantBoundary => {
                if snapshot.tenant_boundary_attempts != u64::MAX {
                    snapshot.tenant_boundary_attempts += 1;
                    snapshot.confirmed_violations += u64::from(allowed);
                }
            }
        }
    }

    pub(crate) fn snapshot(&self) -> DenialProbeSnapshot {
        self.completed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_mapping_is_bounded() {
        assert_eq!(
            RequestSubsystem::from_action("agent.send_message"),
            RequestSubsystem::Agent
        );
        assert_eq!(
            RequestSubsystem::from_action("memory.store"),
            RequestSubsystem::Memory
        );
        assert_eq!(
            RequestSubsystem::from_action("snapshot.restore"),
            RequestSubsystem::Memory
        );
        assert_eq!(
            RequestSubsystem::from_action("agent.call_tool"),
            RequestSubsystem::Tool
        );
        assert_eq!(
            RequestSubsystem::from_action("unknown.dynamic.value"),
            RequestSubsystem::System
        );
    }

    #[test]
    fn completed_and_cancelled_observations_are_accounted() {
        let telemetry = RequestTelemetry::default();
        {
            let mut observation = telemetry.start(RequestSubsystem::Agent);
            observation.finish(RequestOutcome::Success);
        }
        {
            let _cancelled = telemetry.start(RequestSubsystem::Tool);
        }

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(snapshot.samples.len(), SUBSYSTEM_COUNT * OUTCOME_COUNT);
        assert_eq!(
            snapshot
                .samples
                .iter()
                .find(|sample| sample.subsystem == "agent" && sample.outcome == "success")
                .unwrap()
                .requests,
            1
        );
        assert_eq!(
            snapshot
                .samples
                .iter()
                .find(|sample| sample.subsystem == "tool" && sample.outcome == "cancelled")
                .unwrap()
                .requests,
            1
        );
    }

    #[test]
    fn mixed_request_outcomes_have_one_exact_bounded_class_projection() {
        let telemetry = RequestTelemetry::default();
        for (subsystem, outcome) in [
            (RequestSubsystem::Auth, RequestOutcome::Success),
            (RequestSubsystem::Operator, RequestOutcome::TimedOut),
            (RequestSubsystem::Checkpoint, RequestOutcome::Failed),
            (RequestSubsystem::Memory, RequestOutcome::Rejected),
        ] {
            let mut observation = telemetry.start(subsystem);
            observation.finish(outcome);
        }
        drop(telemetry.start(RequestSubsystem::Tool));
        let mut snapshot = telemetry.snapshot();
        let classes = snapshot.request_classes();
        assert_eq!(classes[0].class, RequestClass::Control);
        assert_eq!(classes[0].requests, 2);
        assert_eq!(classes[1].class, RequestClass::Agent);
        assert_eq!(classes[1].requests, 3);
        assert_eq!(classes.iter().map(|sample| sample.requests).sum::<u64>(), 5);
        assert_eq!(classes.iter().map(|sample| sample.duration_microseconds_total).sum::<u64>(), snapshot.samples.iter().map(|sample| sample.duration_microseconds_total).sum::<u64>());
        for index in 0..BUCKET_COUNT {
            assert_eq!(classes.iter().map(|sample| sample.duration_bucket_counts[index]).sum::<u64>(), snapshot.samples.iter().map(|sample| sample.duration_bucket_counts[index]).sum::<u64>());
        }
        snapshot.samples.push(RequestTelemetrySample {
            subsystem: "tenant/user/tool/dynamic".into(),
            outcome: "success".into(),
            requests: 999,
            duration_microseconds_total: u64::MAX,
            duration_bucket_counts: vec![999; BUCKET_COUNT],
        });
        assert_eq!(snapshot.request_classes(), classes, "dynamic labels changed the fixed class projection");
    }

    #[tokio::test]
    async fn dropping_a_provider_future_records_exactly_one_cancelled_invocation() {
        let counters = std::sync::Arc::new(ProviderOutcomeCounters::default());
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let counters = counters.clone();
            let entered = entered.clone();
            async move {
                let _observation = counters.start();
                entered.notify_one();
                std::future::pending::<()>().await;
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified()).await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        for outcome in [ProviderOutcome::Success, ProviderOutcome::Failed, ProviderOutcome::TimedOut] {
            let mut observation = counters.start();
            observation.finish(outcome);
        }
        assert_eq!(counters.snapshot(), ProviderOutcomeSnapshot { success: 1, failed: 1, timed_out: 1, cancelled: 1 });
    }
}
