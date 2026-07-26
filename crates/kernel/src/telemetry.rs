//! Stable, bounded-cardinality request telemetry.
//!
//! Request correlation belongs in traces and logs, never in metric labels.
//! This module deliberately exposes only a fixed subsystem and outcome matrix,
//! making the Prometheus series count independent of tenants, agents, request
//! IDs, tools, providers, paths, URLs, or prompt contents.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Version of the public metric-name, label, type, and unit contract.
pub const TELEMETRY_CONTRACT_VERSION: u32 = 1;

const SUBSYSTEM_COUNT: usize = 12;
const OUTCOME_COUNT: usize = 5;
/// Fixed latency histogram boundaries in microseconds.
pub const REQUEST_DURATION_BUCKETS_MICROSECONDS: [u64; 13] = [
    5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000,
    10_000_000, 30_000_000, 60_000_000,
];
const BUCKET_COUNT: usize = REQUEST_DURATION_BUCKETS_MICROSECONDS.len();

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
}
