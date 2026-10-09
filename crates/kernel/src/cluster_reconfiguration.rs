//! Durable, independently authorized targets for live Raft reconfiguration.
//!
//! A proposal records an exact prior and target catalog. The running leader
//! consumes that target through the existing learner and joint-consensus path.
//! Operator configuration remains an explicit restart input.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use chrono::{DateTime, Utc};
use openraft::StoredMembership;
use serde::{Deserialize, Serialize};

use crate::cluster_consensus::{ClusterRaftNode, ClusterRaftNodeId};

/// Exact voter and transport metadata carried by a prepared proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterReconfigurationTarget {
    pub catalog: BTreeMap<ClusterRaftNodeId, ClusterRaftNode>,
    pub voter_ids: BTreeSet<ClusterRaftNodeId>,
    pub voter_generation: u64,
    pub voter_set_sha256: String,
    pub trust_generation: u64,
    pub catalog_sha256: String,
    pub overlap_not_after: Option<DateTime<Utc>>,
}

/// Bounded immutable proposal evidence; completion is derived from Raft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterReconfigurationPlan {
    pub operation_id: String,
    pub prior: ClusterReconfigurationTarget,
    pub target: ClusterReconfigurationTarget,
    pub actor: String,
    pub reason: String,
    pub proposed_at: DateTime<Utc>,
}

/// Current applied membership and the latest independently authorized target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterReconfigurationStatus {
    pub current: ClusterReconfigurationTarget,
    pub target: Option<ClusterReconfigurationTarget>,
    pub operation_id: Option<String>,
    pub settled: bool,
}

impl ClusterReconfigurationTarget {
    pub(crate) fn from_membership(
        membership: &StoredMembership<ClusterRaftNodeId, ClusterRaftNode>,
    ) -> io::Result<Self> {
        if membership.log_id().is_none() || membership.membership().get_joint_config().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Raft membership is not initialized",
            ));
        }
        let catalog = membership
            .nodes()
            .map(|(id, node)| (*id, node.clone()))
            .collect::<BTreeMap<_, _>>();
        let first = catalog.values().next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Raft membership has no catalog")
        })?;
        let target = Self {
            voter_ids: membership.voter_ids().collect(),
            voter_generation: first.voter_set_generation,
            voter_set_sha256: first.voter_set_sha256.clone(),
            trust_generation: first.transport_trust_generation,
            catalog_sha256: first.transport_catalog_sha256.clone(),
            overlap_not_after: first.transport_trust_overlap_not_after,
            catalog,
        };
        Ok(target)
    }

    pub(crate) fn validate(&self, at: DateTime<Utc>) -> io::Result<()> {
        crate::cluster_runtime::validate_reconfiguration_target(self, at)
    }

    pub(crate) fn is_settled(
        &self,
        membership: &StoredMembership<ClusterRaftNodeId, ClusterRaftNode>,
    ) -> bool {
        membership.membership().get_joint_config().len() == 1
            && Self::from_membership(membership).is_ok_and(|current| current == *self)
    }
}

pub(crate) fn prepare_voter_target(
    current: &ClusterReconfigurationTarget,
    target_voter_ids: &BTreeSet<ClusterRaftNodeId>,
    expected_generation: u64,
    target_generation: u64,
    at: DateTime<Utc>,
) -> io::Result<ClusterReconfigurationTarget> {
    check_generation(
        current.voter_generation,
        expected_generation,
        target_generation,
    )?;
    if target_voter_ids == &current.voter_ids {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "voter proposal has no voter-set change",
        ));
    }
    let mut target = current.clone();
    target.voter_ids = target_voter_ids.clone();
    target.voter_generation = target_generation;
    target.voter_set_sha256 =
        crate::cluster_runtime::configured_voter_set_sha256(target_generation, target_voter_ids);
    for node in target.catalog.values_mut() {
        node.voter_set_generation = target_generation;
        node.voter_set_sha256.clone_from(&target.voter_set_sha256);
    }
    target.validate(at)?;
    Ok(target)
}

pub(crate) fn prepare_trust_target(
    current: &ClusterReconfigurationTarget,
    target_catalog: &BTreeMap<ClusterRaftNodeId, ClusterRaftNode>,
    expected_generation: u64,
    target_generation: u64,
    overlap_not_after: Option<DateTime<Utc>>,
    at: DateTime<Utc>,
) -> io::Result<ClusterReconfigurationTarget> {
    check_generation(
        current.trust_generation,
        expected_generation,
        target_generation,
    )?;
    let target = ClusterReconfigurationTarget {
        catalog: target_catalog.clone(),
        voter_ids: current.voter_ids.clone(),
        voter_generation: current.voter_generation,
        voter_set_sha256: current.voter_set_sha256.clone(),
        trust_generation: target_generation,
        catalog_sha256: crate::cluster_runtime::configured_transport_catalog_sha256(target_catalog),
        overlap_not_after,
    };
    // The live API cannot install roots from fingerprints. Every node must
    // already have this exact CA set provisioned in its startup TLS config.
    let prior_roots = current
        .catalog
        .values()
        .next()
        .map(|node| &node.transport_peer_ca_sha256);
    if prior_roots.is_none_or(|roots| roots.is_empty())
        || target
            .catalog
            .values()
            .any(|node| Some(&node.transport_peer_ca_sha256) != prior_roots)
    {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "live trust changes require the unchanged preprovisioned CA fingerprint set and a versioned prior catalog"));
    }
    target.validate(at)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_runtime::{
        configured_transport_catalog_sha256, configured_voter_set_sha256,
    };

    fn current() -> ClusterReconfigurationTarget {
        let mut catalog = BTreeMap::new();
        for id in 1..=4 {
            catalog.insert(
                id,
                ClusterRaftNode {
                    endpoint: format!("127.0.0.1:{}", 8000 + id),
                    server_name: format!("node-{id}.example"),
                    tls_certificate_sha256: format!("{id:064x}"),
                    tls_client_certificate_sha256: format!("{:064x}", id + 4),
                    identity_public_key: format!("{:064x}", id + 8),
                    transport_trust_generation: 1,
                    transport_peer_ca_sha256: vec!["f".repeat(64)],
                    ..Default::default()
                },
            );
        }
        let catalog_sha256 = configured_transport_catalog_sha256(&catalog);
        for node in catalog.values_mut() {
            node.transport_catalog_sha256.clone_from(&catalog_sha256);
        }
        ClusterReconfigurationTarget {
            catalog,
            voter_ids: BTreeSet::from([1, 2, 3]),
            voter_generation: 0,
            voter_set_sha256: String::new(),
            trust_generation: 1,
            catalog_sha256,
            overlap_not_after: None,
        }
    }

    #[test]
    fn voter_target_separates_current_target_and_catalog_generations() {
        let current = current();
        current.validate(Utc::now()).unwrap();
        let target =
            prepare_voter_target(&current, &BTreeSet::from([1, 2, 4]), 0, 1, Utc::now()).unwrap();
        assert_eq!(target.catalog_sha256, current.catalog_sha256);
        assert_eq!(target.trust_generation, current.trust_generation);
        assert_eq!(
            target.voter_set_sha256,
            configured_voter_set_sha256(1, &target.voter_ids)
        );
        for (expected, generation, message) in [
            (9, 1, "expected generation"),
            (0, 0, "reuses"),
            (0, 2, "skips"),
        ] {
            let error = prepare_voter_target(
                &current,
                &BTreeSet::from([1, 2, 4]),
                expected,
                generation,
                Utc::now(),
            )
            .unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
        }
        assert!(prepare_voter_target(&current, &BTreeSet::new(), 0, 1, Utc::now()).is_err());
        assert!(prepare_voter_target(&current, &BTreeSet::from([9]), 0, 1, Utc::now()).is_err());
    }

    #[test]
    fn trust_target_requires_complete_consistent_preprovisioned_roots() {
        let current = current();
        let at = Utc::now();
        let expiry = at + chrono::Duration::hours(1);
        let mut catalog = current.catalog.clone();
        for (id, node) in &mut catalog {
            node.transport_trust_generation = 2;
            node.transport_trust_overlap_not_after = Some(expiry);
            node.tls_certificate_sha256_overlap = vec![format!("{:064x}", id + 12)];
        }
        let digest = configured_transport_catalog_sha256(&catalog);
        for node in catalog.values_mut() {
            node.transport_catalog_sha256.clone_from(&digest);
        }
        let target = prepare_trust_target(&current, &catalog, 1, 2, Some(expiry), at).unwrap();
        assert_eq!(target.voter_ids, current.voter_ids);
        assert_eq!(target.voter_generation, current.voter_generation);
        assert_ne!(target.catalog_sha256, current.catalog_sha256);
        let mut absent_root = catalog.clone();
        absent_root.get_mut(&1).unwrap().transport_peer_ca_sha256 = vec!["e".repeat(64)];
        assert_eq!(
            prepare_trust_target(&current, &absent_root, 1, 2, Some(expiry), at)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let mut simultaneous = catalog.clone();
        simultaneous.get_mut(&1).unwrap().voter_set_generation = 1;
        assert!(prepare_trust_target(&current, &simultaneous, 1, 2, Some(expiry), at).is_err());
        assert!(prepare_trust_target(&current, &catalog, 1, 2, Some(expiry), expiry).is_err());
    }
}

fn check_generation(current: u64, expected: u64, target: u64) -> io::Result<()> {
    if expected != current {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reconfiguration expected generation does not match current generation",
        ));
    }
    if target <= current {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reconfiguration target generation reuses a committed generation",
        ));
    }
    if current.checked_add(1) != Some(target) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reconfiguration target generation skips a generation",
        ));
    }
    Ok(())
}

pub(crate) fn status(
    membership: &StoredMembership<ClusterRaftNodeId, ClusterRaftNode>,
    plan: Option<&ClusterReconfigurationPlan>,
) -> io::Result<ClusterReconfigurationStatus> {
    let current = ClusterReconfigurationTarget::from_membership(membership)?;
    let settled = plan.map_or_else(
        || current.is_settled(membership),
        |plan| plan.target.is_settled(membership),
    );
    Ok(ClusterReconfigurationStatus {
        current,
        target: plan.map(|plan| plan.target.clone()),
        operation_id: plan.map(|plan| plan.operation_id.clone()),
        settled,
    })
}
