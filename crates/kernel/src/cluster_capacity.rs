//! Signed node-origin capacity samples, admitted and aged by quorum time.

use crate::cluster_control::{
    ClusterControl, ClusterMember, ClusterMemberState, NodeControlStatus,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CAPACITY_DOMAIN: &[u8] = b"AIagentOS signed node capacity v1\0";
pub const CAPACITY_STALENESS_SECONDS: i64 = 15;
pub const CAPACITY_PUBLISH_INTERVAL_SECONDS: u64 = 5;
pub const MAX_CAPACITY_NODES: usize = 31;
const MAX_CAPACITY_REPORT_BYTES: usize = 72 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityCounters {
    pub agent_count: u64,
    pub running_agents: u64,
    pub live_agents: u64,
    pub queued_agents: u64,
    pub paused_agents: u64,
    pub stopped_agents: u64,
    pub active_turns: u64,
    pub waiting_turns: u64,
    pub turn_capacity: u64,
    pub llm_requests_in_flight: u64,
    pub llm_requests_waiting: u64,
    pub llm_core_capacity: u64,
}

impl CapacityCounters {
    pub fn collect(kernel: &crate::AgentKernelImpl) -> Self {
        let sample = crate::metrics::MetricsSnapshot::collect(kernel);
        Self {
            agent_count: sample.agent_count,
            running_agents: sample.running_agents,
            live_agents: sample.live_agents,
            queued_agents: sample.queued_agents,
            paused_agents: sample.paused_agents,
            stopped_agents: sample.stopped_agents,
            active_turns: sample.active_turns,
            waiting_turns: kernel.turn_admission.waiting() as u64,
            turn_capacity: sample.turn_capacity,
            llm_requests_in_flight: sample.llm_requests_in_flight,
            llm_requests_waiting: sample.llm_requests_waiting,
            llm_core_capacity: sample.llm_core_capacity,
        }
    }
}

/// A signature proves sample origin and freshness, not truthful hardware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNodeCapacity {
    pub version: u16,
    pub cluster_id: String,
    pub node_id: String,
    pub member_generation: u64,
    pub control: NodeControlStatus,
    pub observed_at: DateTime<Utc>,
    pub sequence: u64,
    pub counters: CapacityCounters,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum CapacityRejection {
    #[error("capacity report signature is invalid")]
    Forged,
    #[error("capacity report observation or sequence was already admitted")]
    Replay,
    #[error("capacity report is older than the replicated staleness horizon")]
    Stale,
    #[error("capacity report observation is ahead of replicated authority time")]
    Future,
    #[error("capacity report node is not currently enrolled and active")]
    Unenrolled,
    #[error("capacity report does not match current membership or control generation")]
    Generation,
    #[error("capacity report exceeds the bounded publishing cadence")]
    Cadence,
    #[error("capacity report is malformed or exceeds bounded storage")]
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumNodeCapacity {
    pub report: SignedNodeCapacity,
    pub committed_at: DateTime<Utc>,
    pub log_id: openraft::LogId<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterCapacitySnapshot {
    pub cluster_id: String,
    pub authority_time: DateTime<Utc>,
    pub staleness_seconds: i64,
    pub reports: Vec<QuorumNodeCapacity>,
    pub members: Vec<ClusterMember>,
}

impl SignedNodeCapacity {
    pub fn payload(&self) -> Result<Vec<u8>, CapacityRejection> {
        if self.version != 1
            || self.sequence == 0
            || self.member_generation == 0
            || !canonical_uuid(&self.cluster_id)
            || !canonical_uuid(&self.node_id)
            || self.node_id != self.control.identity.node_id
            || !canonical_hex(&self.control.identity.public_key, 32)
            || !canonical_hex(&self.control.identity.fingerprint, 32)
            || self.control.reason.len() > 1024
            || crate::cluster_control::validate_profile(&self.control.profile).is_err()
        {
            return Err(CapacityRejection::Invalid);
        }
        let mut unsigned = self.clone();
        unsigned.signature_hex.clear();
        let encoded = serde_json::to_vec(&unsigned).map_err(|_| CapacityRejection::Invalid)?;
        if encoded.len() > MAX_CAPACITY_REPORT_BYTES {
            return Err(CapacityRejection::Invalid);
        }
        let mut payload = CAPACITY_DOMAIN.to_vec();
        payload.extend_from_slice(&encoded);
        Ok(payload)
    }

    pub fn verify_origin(
        &self,
        member: &ClusterMember,
        cluster_id: &str,
    ) -> Result<(), CapacityRejection> {
        if self.cluster_id != cluster_id
            || self.node_id != member.node_id
            || self.control.identity.public_key != member.public_key
            || self.control.identity.fingerprint != member.fingerprint
        {
            return Err(CapacityRejection::Unenrolled);
        }
        if !canonical_hex(&self.signature_hex, 64) {
            return Err(CapacityRejection::Forged);
        }
        let signature = crate::cluster_control::hex_decode(&self.signature_hex)
            .filter(|signature| signature.len() == 64)
            .ok_or(CapacityRejection::Forged)?;
        if !ClusterControl::verify_challenge(&member.public_key, &self.payload()?, &signature) {
            return Err(CapacityRejection::Forged);
        }
        Ok(())
    }

    pub fn verify_current(
        &self,
        member: &ClusterMember,
        cluster_id: &str,
        at: DateTime<Utc>,
    ) -> Result<(), CapacityRejection> {
        self.verify_origin(member, cluster_id)?;
        if member.state != ClusterMemberState::Active {
            return Err(CapacityRejection::Unenrolled);
        }
        if self.member_generation != member.generation {
            return Err(CapacityRejection::Generation);
        }
        if member.updated_at > self.observed_at || self.control.updated_at > self.observed_at {
            return Err(CapacityRejection::Generation);
        }
        if self.control.identity.created_at > self.observed_at {
            return Err(CapacityRejection::Generation);
        }
        if self.observed_at > at {
            return Err(CapacityRejection::Future);
        }
        if at.signed_duration_since(self.observed_at)
            > chrono::Duration::seconds(CAPACITY_STALENESS_SECONDS)
        {
            return Err(CapacityRejection::Stale);
        }
        Ok(())
    }
}

pub(crate) fn validate_admission(
    report: &SignedNodeCapacity,
    members: &BTreeMap<String, ClusterMember>,
    cluster_id: &str,
    at: DateTime<Utc>,
    previous: Option<&QuorumNodeCapacity>,
) -> Result<(), CapacityRejection> {
    let member = members
        .get(&report.node_id)
        .ok_or(CapacityRejection::Unenrolled)?;
    report.verify_current(member, cluster_id, at)?;
    if let Some(previous) = previous {
        if report.sequence <= previous.report.sequence
            || report.observed_at <= previous.report.observed_at
        {
            return Err(CapacityRejection::Replay);
        }
        if report.control.generation < previous.report.control.generation
            || (report.control.generation == previous.report.control.generation
                && report.control != previous.report.control)
        {
            return Err(CapacityRejection::Generation);
        }
        if report
            .observed_at
            .signed_duration_since(previous.report.observed_at)
            < chrono::Duration::seconds(CAPACITY_PUBLISH_INTERVAL_SECONDS as i64)
        {
            return Err(CapacityRejection::Cadence);
        }
    }
    Ok(())
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub struct CapacityPublisher {
    stop: tokio::sync::watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl CapacityPublisher {
    pub(crate) fn start(
        authority: crate::cluster_runtime::ClusterAuthorityHandle,
        kernel: std::sync::Weak<crate::AgentKernelImpl>,
    ) -> Self {
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                CAPACITY_PUBLISH_INTERVAL_SECONDS,
            ));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    changed = stopped.changed() => if changed.is_err() || *stopped.borrow() { return; },
                    _ = tick.tick() => {
                        let Some(kernel) = kernel.upgrade() else { return; };
                        tokio::select! {
                            changed = stopped.changed() => if changed.is_err() || *stopped.borrow() { return; },
                            result = tokio::time::timeout(std::time::Duration::from_secs(10), authority.publish_kernel_capacity(&kernel)) => {
                                match result {
                                    Ok(Ok(crate::cluster_consensus::AuthorityResponse::NodeCapacityReported { .. })) => {}
                                    Ok(Ok(crate::cluster_consensus::AuthorityResponse::Rejected { reason, .. })) => tracing::warn!(?reason, "quorum denied node capacity sample"),
                                    _ => tracing::warn!("quorum capacity publishing unavailable; placement freshness will fail closed"),
                                }
                            }
                        }
                    }
                }
            }
        });
        Self {
            stop,
            task: Some(task),
        }
    }

    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for CapacityPublisher {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn member(control: &NodeControlStatus, at: DateTime<Utc>) -> ClusterMember {
        ClusterMember {
            node_id: control.identity.node_id.clone(),
            fingerprint: control.identity.fingerprint.clone(),
            public_key: control.identity.public_key.clone(),
            tls_server_certificate_fingerprint: None,
            endpoint: "127.0.0.1:1".into(),
            server_version: "capacity-fixture".into(),
            min_protocol_version: 1,
            protocol_version: 2,
            state: ClusterMemberState::Active,
            generation: 1,
            joined_at: at,
            updated_at: at,
            reason: "actual node-key fixture".into(),
        }
    }

    #[test]
    fn unsigned_or_forged_capacity_is_never_used_for_placement() {
        let root = tempfile::tempdir().unwrap();
        let kernel = Arc::new(
            crate::AgentKernelImpl::with_db_path(&root.path().join("capacity.db")).unwrap(),
        );
        let at = Utc::now();
        let cluster_id = uuid::Uuid::new_v4().to_string();
        let report = kernel
            .cluster_control
            .sample_capacity(&kernel, &cluster_id, 1, at)
            .unwrap();
        let current = member(&report.control, at);
        assert!(report.verify_current(&current, &cluster_id, at).is_ok());
        let mut forged = report.clone();
        forged.counters.turn_capacity = forged.counters.turn_capacity.saturating_add(1);
        assert_eq!(
            forged.verify_current(&current, &cluster_id, at),
            Err(CapacityRejection::Forged)
        );
        forged = report.clone();
        forged.signature_hex.clear();
        assert_eq!(
            forged.verify_current(&current, &cluster_id, at),
            Err(CapacityRejection::Forged)
        );
        assert!(
            kernel
                .cluster_control
                .prove_challenge_hex(&crate::cluster_control::hex_encode(
                    &report.payload().unwrap()
                ))
                .is_err(),
            "public nonce signer cannot manufacture capacity reports"
        );
        drop(kernel);
        root.close().unwrap();
    }

    #[test]
    fn replayed_capacity_report_is_rejected_by_observed_at() {
        let root = tempfile::tempdir().unwrap();
        let kernel = Arc::new(
            crate::AgentKernelImpl::with_db_path(&root.path().join("capacity.db")).unwrap(),
        );
        let at = Utc::now();
        let cluster_id = uuid::Uuid::new_v4().to_string();
        let report = kernel
            .cluster_control
            .sample_capacity(&kernel, &cluster_id, 1, at)
            .unwrap();
        let members = BTreeMap::from([(report.node_id.clone(), member(&report.control, at))]);
        let committed = QuorumNodeCapacity {
            report: report.clone(),
            committed_at: at,
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 3),
        };
        assert_eq!(
            validate_admission(&report, &members, &cluster_id, at, Some(&committed)),
            Err(CapacityRejection::Replay)
        );
        let next_same_time = kernel
            .cluster_control
            .sample_capacity(&kernel, &cluster_id, 1, at)
            .unwrap();
        assert!(next_same_time.sequence > report.sequence);
        assert_eq!(
            validate_admission(&next_same_time, &members, &cluster_id, at, Some(&committed)),
            Err(CapacityRejection::Replay)
        );
        let future = kernel
            .cluster_control
            .sample_capacity(&kernel, &cluster_id, 1, at + chrono::Duration::seconds(1))
            .unwrap();
        assert_eq!(
            validate_admission(&future, &members, &cluster_id, at, Some(&committed)),
            Err(CapacityRejection::Future)
        );
        assert_eq!(
            validate_admission(
                &report,
                &members,
                &cluster_id,
                at + chrono::Duration::seconds(16),
                None
            ),
            Err(CapacityRejection::Stale)
        );
        let too_soon = kernel
            .cluster_control
            .sample_capacity(&kernel, &cluster_id, 1, at + chrono::Duration::seconds(1))
            .unwrap();
        assert_eq!(
            validate_admission(
                &too_soon,
                &members,
                &cluster_id,
                at + chrono::Duration::seconds(1),
                Some(&committed)
            ),
            Err(CapacityRejection::Cadence)
        );
        drop(kernel);
        root.close().unwrap();
    }

    #[test]
    fn capacity_sequence_survives_restart_and_member_epochs_invalidate_samples() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("capacity.db");
        let kernel = Arc::new(crate::AgentKernelImpl::with_db_path(&database).unwrap());
        let at = Utc::now();
        let cluster_id = uuid::Uuid::new_v4().to_string();
        let report = kernel
            .cluster_control
            .sample_capacity(&kernel, &cluster_id, 1, at)
            .unwrap();
        let mut enrolled = member(&report.control, at);
        enrolled.generation = 2;
        assert_eq!(
            report.verify_current(&enrolled, &cluster_id, at),
            Err(CapacityRejection::Generation)
        );
        enrolled.generation = 1;
        enrolled.state = ClusterMemberState::Revoked;
        assert_eq!(
            report.verify_current(&enrolled, &cluster_id, at),
            Err(CapacityRejection::Unenrolled)
        );
        drop(kernel);
        let reopened = Arc::new(crate::AgentKernelImpl::with_db_path(&database).unwrap());
        let next = reopened
            .cluster_control
            .sample_capacity(&reopened, &cluster_id, 1, at + chrono::Duration::seconds(5))
            .unwrap();
        assert!(next.sequence > report.sequence);
        assert_eq!(next.node_id, report.node_id);
        drop(reopened);
        root.close().unwrap();
    }

    #[test]
    fn control_mutation_time_is_not_capacity_observation_and_changes_require_new_generation() {
        let root = tempfile::tempdir().unwrap();
        let kernel = Arc::new(
            crate::AgentKernelImpl::with_db_path(&root.path().join("capacity.db")).unwrap(),
        );
        let at = Utc::now();
        let cluster_id = uuid::Uuid::new_v4().to_string();
        let first = kernel
            .cluster_control
            .sample_capacity(&kernel, &cluster_id, 1, at)
            .unwrap();
        let current = member(&first.control, at);
        let second = kernel
            .cluster_control
            .sample_capacity(&kernel, &cluster_id, 1, at + chrono::Duration::seconds(5))
            .unwrap();
        assert_eq!(first.control.updated_at, second.control.updated_at);
        assert_eq!(first.control.generation, second.control.generation);
        assert_ne!(first.observed_at, second.observed_at);
        assert!(second.sequence > first.sequence);
        let committed = QuorumNodeCapacity {
            report: first.clone(),
            committed_at: at,
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 3),
        };
        let members = BTreeMap::from([(current.node_id.clone(), current)]);
        assert!(validate_admission(
            &second,
            &members,
            &cluster_id,
            second.observed_at,
            Some(&committed)
        )
        .is_ok());
        kernel
            .cluster_control
            .transition(
                crate::cluster_control::NodeAvailability::Draining,
                first.control.generation,
                "capacity-fixture",
                "actual drain changes control epoch",
            )
            .unwrap();
        let third = kernel
            .cluster_control
            .sample_capacity(&kernel, &cluster_id, 1, at + chrono::Duration::seconds(10))
            .unwrap();
        assert_eq!(third.control.generation, first.control.generation + 1);
        assert_eq!(
            third.control.availability,
            crate::cluster_control::NodeAvailability::Draining
        );
        let second_committed = QuorumNodeCapacity {
            report: second,
            committed_at: at + chrono::Duration::seconds(5),
            log_id: committed.log_id,
        };
        assert!(validate_admission(
            &third,
            &members,
            &cluster_id,
            third.observed_at,
            Some(&second_committed)
        )
        .is_ok());
        let third_committed = QuorumNodeCapacity {
            report: third.clone(),
            committed_at: third.observed_at,
            log_id: committed.log_id,
        };
        assert_eq!(
            validate_admission(
                &first,
                &members,
                &cluster_id,
                third.observed_at,
                Some(&third_committed)
            ),
            Err(CapacityRejection::Replay)
        );
        drop(kernel);
        root.close().unwrap();
    }

    #[test]
    fn capacity_cursor_requires_current_reader() {
        let context = crate::context::SqliteContextManager::in_memory().unwrap();
        let connection = context.conn.lock().unwrap();
        let before: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert!(crate::schema::preflight_for_reader(&connection, 15).is_err());
        let after: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(before, after);
        crate::schema::preflight_for_reader(&connection, crate::schema::CURRENT_SCHEMA_VERSION)
            .unwrap();
    }
}
