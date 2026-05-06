//! Cgroups — hierarchical resource control for agents.
//!
//! Like Linux cgroups. Organize agents into groups with enforced resource limits.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use crate::agent_struct::AgentId;

static NEXT_CGROUP_ID: AtomicU64 = AtomicU64::new(1);

pub type CgroupId = u64;

/// Resource limits for a cgroup.
#[derive(Debug, Clone)]
pub struct CgroupLimits {
    /// Max tokens per minute (0 = unlimited).
    pub tokens_per_min: u64,
    /// Max concurrent tool calls (0 = unlimited).
    pub max_tool_calls: u32,
    /// Max context size in tokens (0 = unlimited).
    pub max_context_tokens: u64,
    /// Max agents in this group (0 = unlimited).
    pub max_agents: u32,
}

impl Default for CgroupLimits {
    fn default() -> Self {
        Self { tokens_per_min: 0, max_tool_calls: 0, max_context_tokens: 0, max_agents: 0 }
    }
}

/// Current resource usage for a cgroup.
#[derive(Debug, Clone, Default)]
pub struct CgroupUsage {
    pub tokens_this_min: u64,
    pub active_tool_calls: u32,
    pub context_tokens: u64,
    pub agent_count: u32,
}

/// A cgroup node in the hierarchy.
#[derive(Debug, Clone)]
pub struct Cgroup {
    pub id: CgroupId,
    pub name: String,
    pub parent: Option<CgroupId>,
    pub children: Vec<CgroupId>,
    pub limits: CgroupLimits,
    pub usage: CgroupUsage,
    pub members: Vec<AgentId>,
}

/// The cgroup hierarchy manager.
pub struct CgroupManager {
    groups: DashMap<CgroupId, Cgroup>,
    root: CgroupId,
}

impl CgroupManager {
    pub fn new() -> Self {
        let root_id = NEXT_CGROUP_ID.fetch_add(1, Ordering::SeqCst);
        let root = Cgroup {
            id: root_id,
            name: "/".into(),
            parent: None,
            children: Vec::new(),
            limits: CgroupLimits::default(), // root has no limits
            usage: CgroupUsage::default(),
            members: Vec::new(),
        };
        let mgr = Self { groups: DashMap::new(), root: root_id };
        mgr.groups.insert(root_id, root);
        mgr
    }

    /// Create a child cgroup.
    pub fn create(&self, name: String, parent: CgroupId, limits: CgroupLimits) -> CgroupId {
        let id = NEXT_CGROUP_ID.fetch_add(1, Ordering::SeqCst);
        let cg = Cgroup {
            id, name, parent: Some(parent), children: Vec::new(),
            limits, usage: CgroupUsage::default(), members: Vec::new(),
        };
        self.groups.insert(id, cg);
        if let Some(mut parent_cg) = self.groups.get_mut(&parent) {
            parent_cg.children.push(id);
        }
        id
    }

    /// Add an agent to a cgroup.
    pub fn add_agent(&self, cgroup_id: CgroupId, agent_id: AgentId) -> Result<(), &'static str> {
        let mut cg = self.groups.get_mut(&cgroup_id).ok_or("cgroup not found")?;
        if cg.limits.max_agents > 0 && cg.usage.agent_count >= cg.limits.max_agents {
            return Err("max agents reached");
        }
        cg.members.push(agent_id);
        cg.usage.agent_count += 1;
        Ok(())
    }

    /// Remove an agent from a cgroup.
    pub fn remove_agent(&self, cgroup_id: CgroupId, agent_id: AgentId) {
        if let Some(mut cg) = self.groups.get_mut(&cgroup_id) {
            cg.members.retain(|&id| id != agent_id);
            cg.usage.agent_count = cg.usage.agent_count.saturating_sub(1);
        }
    }

    /// Check if a token usage is within limits (checks entire hierarchy).
    pub fn check_token_limit(&self, cgroup_id: CgroupId, tokens: u64) -> bool {
        let mut current = Some(cgroup_id);
        while let Some(id) = current {
            if let Some(cg) = self.groups.get(&id) {
                if cg.limits.tokens_per_min > 0 && cg.usage.tokens_this_min + tokens > cg.limits.tokens_per_min {
                    return false; // would exceed limit
                }
                current = cg.parent;
            } else {
                break;
            }
        }
        true
    }

    /// Record token usage (propagates up hierarchy).
    pub fn record_tokens(&self, cgroup_id: CgroupId, tokens: u64) {
        let mut current = Some(cgroup_id);
        while let Some(id) = current {
            if let Some(mut cg) = self.groups.get_mut(&id) {
                cg.usage.tokens_this_min += tokens;
                current = cg.parent;
            } else {
                break;
            }
        }
    }

    /// Reset per-minute counters (called by timer).
    pub fn reset_minute_counters(&self) {
        for mut entry in self.groups.iter_mut() {
            entry.usage.tokens_this_min = 0;
        }
    }

    /// Get cgroup info.
    pub fn get(&self, id: CgroupId) -> Option<Cgroup> {
        self.groups.get(&id).map(|cg| cg.clone())
    }

    /// Get root cgroup ID.
    pub fn root(&self) -> CgroupId { self.root }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_hierarchy() {
        let mgr = CgroupManager::new();
        let child = mgr.create("team-a".into(), mgr.root(), CgroupLimits { tokens_per_min: 1000, ..Default::default() });
        let grandchild = mgr.create("agent-1".into(), child, CgroupLimits { tokens_per_min: 500, ..Default::default() });
        let gc = mgr.get(grandchild).unwrap();
        assert_eq!(gc.parent, Some(child));
    }

    #[test]
    fn token_limit_enforcement() {
        let mgr = CgroupManager::new();
        let cg = mgr.create("limited".into(), mgr.root(), CgroupLimits { tokens_per_min: 100, ..Default::default() });
        assert!(mgr.check_token_limit(cg, 50));
        mgr.record_tokens(cg, 80);
        assert!(!mgr.check_token_limit(cg, 30)); // 80 + 30 > 100
    }

    #[test]
    fn hierarchical_limit() {
        let mgr = CgroupManager::new();
        let parent = mgr.create("parent".into(), mgr.root(), CgroupLimits { tokens_per_min: 100, ..Default::default() });
        let child = mgr.create("child".into(), parent, CgroupLimits { tokens_per_min: 200, ..Default::default() });
        // Child has 200 limit but parent has 100 — parent limit should block
        mgr.record_tokens(child, 90); // propagates to parent too
        assert!(!mgr.check_token_limit(child, 20)); // parent at 90, 90+20 > 100
    }

    #[test]
    fn max_agents_enforcement() {
        let mgr = CgroupManager::new();
        let cg = mgr.create("small".into(), mgr.root(), CgroupLimits { max_agents: 2, ..Default::default() });
        assert!(mgr.add_agent(cg, 1).is_ok());
        assert!(mgr.add_agent(cg, 2).is_ok());
        assert!(mgr.add_agent(cg, 3).is_err()); // max reached
    }

    #[test]
    fn reset_counters() {
        let mgr = CgroupManager::new();
        let cg = mgr.create("test".into(), mgr.root(), CgroupLimits { tokens_per_min: 100, ..Default::default() });
        mgr.record_tokens(cg, 80);
        mgr.reset_minute_counters();
        assert!(mgr.check_token_limit(cg, 80)); // reset, so 80 is fine again
    }
}

// ─── Cgroup enforcement in execution ─────────────────────────────────────────

/// Check if an agent can proceed with a token-consuming operation.
/// Returns Err with reason if blocked.
pub fn enforce_limits(mgr: &CgroupManager, cgroup_id: CgroupId, tokens: u64) -> Result<(), &'static str> {
    if !mgr.check_token_limit(cgroup_id, tokens) {
        return Err("cgroup token limit exceeded");
    }
    Ok(())
}

#[cfg(test)]
mod enforce_tests {
    use super::*;

    #[test]
    fn enforce_allows_within_limit() {
        let mgr = CgroupManager::new();
        let cg = mgr.create("test".into(), mgr.root(), CgroupLimits { tokens_per_min: 100, ..Default::default() });
        assert!(enforce_limits(&mgr, cg, 50).is_ok());
    }

    #[test]
    fn enforce_blocks_over_limit() {
        let mgr = CgroupManager::new();
        let cg = mgr.create("test".into(), mgr.root(), CgroupLimits { tokens_per_min: 100, ..Default::default() });
        mgr.record_tokens(cg, 90);
        assert!(enforce_limits(&mgr, cg, 20).is_err());
    }
}
