//! Cgroups — hierarchical resource control for agents.
//!
//! Numeric cgroup IDs are process-local handles. Every cgroup also has an
//! immutable stable quota scope (for example `/profile/standard`) used by the
//! durable provider-accounting store across restarts. Live agent-count and
//! concurrent-tool-call limits remain in memory; token accounting does not.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use crate::agent_struct::AgentId;
use crate::context::CgroupQuotaConstraint;

static NEXT_CGROUP_ID: AtomicU64 = AtomicU64::new(1);

pub type CgroupId = u64;

/// Resource limits for a cgroup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupLimits {
    /// Durable provider tokens per fixed Unix-minute epoch (0 = unlimited).
    pub tokens_per_min: u64,
    /// Max concurrent tool calls (0 = unlimited).
    pub max_concurrent_tool_calls: u32,
    /// Max context size in tokens (0 = unlimited).
    pub max_context_tokens: u64,
    /// Max directly assigned agents in this group (0 = unlimited).
    pub max_agents: u32,
}

/// Current process-local resource usage for a cgroup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupUsage {
    /// Retained for API compatibility. Durable token usage lives in SQLite and
    /// is intentionally never mirrored into a resettable process-local counter.
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
    /// Immutable durable quota identity. Numeric `id` must never be persisted.
    pub quota_scope: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CgroupError {
    #[error("cgroup {0} does not exist")]
    GroupNotFound(CgroupId),

    #[error("invalid cgroup quota scope {scope:?}: {reason}")]
    InvalidScope { scope: String, reason: &'static str },

    #[error("cgroup quota scope {0:?} already exists")]
    DuplicateScope(String),

    #[error("cgroup hierarchy contains a cycle at cgroup {0}")]
    HierarchyCycle(CgroupId),

    #[error("cgroup hierarchy contains duplicate quota scope {0:?}")]
    DuplicateHierarchyScope(String),

    #[error("cgroup hierarchy for {0} does not terminate at the manager root")]
    HierarchyDoesNotReachRoot(CgroupId),

    #[error("cgroup hierarchy lock is poisoned")]
    HierarchyLockPoisoned,

    #[error("the root cgroup cannot be removed")]
    RootRemoval,

    #[error("cgroup {0} is not an empty leaf")]
    GroupNotEmpty(CgroupId),

    #[error("cgroup {cgroup_id} is missing from parent {parent_id}'s child list")]
    ParentChildMismatch {
        cgroup_id: CgroupId,
        parent_id: CgroupId,
    },

    #[error("cgroup {cgroup_id} quota scope {scope:?} is missing or points elsewhere")]
    ScopeIndexMismatch { cgroup_id: CgroupId, scope: String },

    #[error("agent {agent_id} is already a member of cgroup {cgroup_id}")]
    AgentAlreadyMember {
        cgroup_id: CgroupId,
        agent_id: AgentId,
    },

    #[error("agent {agent_id} is not a member of cgroup {cgroup_id}")]
    AgentNotMember {
        cgroup_id: CgroupId,
        agent_id: AgentId,
    },

    #[error("cgroup {0} has reached its max-agent limit")]
    MaxAgentsReached(CgroupId),

    #[error("cgroup {cgroup_id} ({scope}) has reached its concurrent tool-call limit")]
    ToolCallLimit { cgroup_id: CgroupId, scope: String },

    #[error("cgroup {0} has active tool-call reservations")]
    ActiveToolReservations(CgroupId),
}

/// The cgroup hierarchy manager.
pub struct CgroupManager {
    groups: DashMap<CgroupId, Cgroup>,
    scope_index: DashMap<String, CgroupId>,
    /// Active membership-aware reservations keyed by agent. Production gate
    /// moves/unregistration consult this exact map instead of inferring
    /// ownership from aggregate ancestor counters.
    active_tool_calls_by_agent: DashMap<AgentId, u32>,
    tool_calls_changed: tokio::sync::Notify,
    root: CgroupId,
    /// Serializes structural publication/removal. Membership and tool-slot
    /// operations take this before touching a leaf so an empty leaf cannot be
    /// reclaimed between validation and mutation.
    tree_lock: Mutex<()>,
}

impl Default for CgroupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupManager {
    pub fn new() -> Self {
        let root_id = NEXT_CGROUP_ID.fetch_add(1, Ordering::SeqCst);
        let root = Cgroup {
            id: root_id,
            name: "/".into(),
            parent: None,
            children: Vec::new(),
            limits: CgroupLimits::default(),
            usage: CgroupUsage::default(),
            members: Vec::new(),
            quota_scope: "/".into(),
        };
        let manager = Self {
            groups: DashMap::new(),
            scope_index: DashMap::new(),
            active_tool_calls_by_agent: DashMap::new(),
            tool_calls_changed: tokio::sync::Notify::new(),
            root: root_id,
            tree_lock: Mutex::new(()),
        };
        manager.scope_index.insert("/".into(), root_id);
        manager.groups.insert(root_id, root);
        manager
    }

    fn validate_scope(scope: &str) -> Result<(), CgroupError> {
        let reason = if scope.is_empty() {
            Some("scope must not be empty")
        } else if scope.len() > 1024 {
            Some("scope must not exceed 1024 bytes")
        } else if scope.contains('\0') {
            Some("scope must not contain NUL")
        } else if !scope.starts_with('/') {
            Some("scope must start with '/'")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(CgroupError::InvalidScope {
                scope: scope.to_string(),
                reason,
            }),
            None => Ok(()),
        }
    }

    fn escape_scope_segment(name: &str) -> Result<String, CgroupError> {
        if name.is_empty() {
            return Err(CgroupError::InvalidScope {
                scope: name.to_string(),
                reason: "derived scope segment must not be empty",
            });
        }
        Ok(name.replace('~', "~0").replace('/', "~1"))
    }

    /// Create a child with an explicitly stable durable quota scope.
    pub fn create_scoped(
        &self,
        name: String,
        parent: CgroupId,
        quota_scope: String,
        limits: CgroupLimits,
    ) -> Result<CgroupId, CgroupError> {
        let _tree = self.lock_tree()?;
        Self::validate_scope(&quota_scope)?;
        // Validate the complete parent chain before publishing a child.
        let _ = self.hierarchy_unlocked(parent)?;

        let id = NEXT_CGROUP_ID.fetch_add(1, Ordering::SeqCst);
        match self.scope_index.entry(quota_scope.clone()) {
            Entry::Occupied(_) => return Err(CgroupError::DuplicateScope(quota_scope)),
            Entry::Vacant(entry) => {
                entry.insert(id);
            }
        }

        let cgroup = Cgroup {
            id,
            name,
            parent: Some(parent),
            children: Vec::new(),
            limits,
            usage: CgroupUsage::default(),
            members: Vec::new(),
            quota_scope: quota_scope.clone(),
        };
        self.groups.insert(id, cgroup);
        let Some(mut parent_group) = self.groups.get_mut(&parent) else {
            self.groups.remove(&id);
            self.scope_index.remove(&quota_scope);
            return Err(CgroupError::GroupNotFound(parent));
        };
        parent_group.children.push(id);
        Ok(id)
    }

    /// Fallible derived-scope creation. Names are escaped as JSON Pointer path
    /// segments so the resulting identity is unambiguous and restart-stable.
    pub fn try_create(
        &self,
        name: String,
        parent: CgroupId,
        limits: CgroupLimits,
    ) -> Result<CgroupId, CgroupError> {
        let parent_scope = self
            .groups
            .get(&parent)
            .map(|group| group.quota_scope.clone())
            .ok_or(CgroupError::GroupNotFound(parent))?;
        let segment = Self::escape_scope_segment(&name)?;
        let quota_scope = if parent_scope == "/" {
            format!("/{segment}")
        } else {
            format!("{parent_scope}/{segment}")
        };
        self.create_scoped(name, parent, quota_scope, limits)
    }

    /// Backwards-compatible derived-scope creation.
    pub fn create(&self, name: String, parent: CgroupId, limits: CgroupLimits) -> CgroupId {
        self.try_create(name, parent, limits)
            .expect("invalid cgroup hierarchy or duplicate derived quota scope")
    }

    fn lock_tree(&self) -> Result<MutexGuard<'_, ()>, CgroupError> {
        self.tree_lock
            .lock()
            .map_err(|_| CgroupError::HierarchyLockPoisoned)
    }

    fn hierarchy_unlocked(&self, cgroup_id: CgroupId) -> Result<Vec<Cgroup>, CgroupError> {
        let mut leaf_to_root = Vec::new();
        let mut group_ids = HashSet::new();
        let mut scope_ids = HashSet::new();
        let mut current = Some(cgroup_id);

        while let Some(id) = current {
            if !group_ids.insert(id) {
                return Err(CgroupError::HierarchyCycle(id));
            }
            let group = self
                .groups
                .get(&id)
                .map(|group| group.clone())
                .ok_or(CgroupError::GroupNotFound(id))?;
            Self::validate_scope(&group.quota_scope)?;
            if !scope_ids.insert(group.quota_scope.clone()) {
                return Err(CgroupError::DuplicateHierarchyScope(group.quota_scope));
            }
            current = group.parent;
            leaf_to_root.push(group);
        }

        if leaf_to_root.last().map(|group| group.id) != Some(self.root) {
            return Err(CgroupError::HierarchyDoesNotReachRoot(cgroup_id));
        }
        leaf_to_root.reverse();
        Ok(leaf_to_root)
    }

    #[cfg(test)]
    fn hierarchy(&self, cgroup_id: CgroupId) -> Result<Vec<Cgroup>, CgroupError> {
        let _tree = self.lock_tree()?;
        self.hierarchy_unlocked(cgroup_id)
    }

    /// Stable root-to-leaf constraints for durable provider admission.
    #[cfg(test)]
    pub(crate) fn quota_constraints(
        &self,
        cgroup_id: CgroupId,
    ) -> Result<Vec<CgroupQuotaConstraint>, CgroupError> {
        self.hierarchy(cgroup_id).map(|groups| {
            groups
                .into_iter()
                .map(|group| CgroupQuotaConstraint {
                    scope_id: group.quota_scope,
                    token_limit: group.limits.tokens_per_min,
                })
                .collect()
        })
    }

    /// Stable constraints plus fail-closed direct-membership validation.
    pub(crate) fn quota_constraints_for_agent(
        &self,
        cgroup_id: CgroupId,
        agent_id: AgentId,
    ) -> Result<Vec<CgroupQuotaConstraint>, CgroupError> {
        let _tree = self.lock_tree()?;
        let groups = self.hierarchy_unlocked(cgroup_id)?;
        let leaf = groups
            .last()
            .ok_or(CgroupError::HierarchyDoesNotReachRoot(cgroup_id))?;
        if !leaf.members.contains(&agent_id) {
            return Err(CgroupError::AgentNotMember {
                cgroup_id,
                agent_id,
            });
        }
        Ok(groups
            .into_iter()
            .map(|group| CgroupQuotaConstraint {
                scope_id: group.quota_scope,
                token_limit: group.limits.tokens_per_min,
            })
            .collect())
    }

    /// Add an agent to a cgroup.
    pub fn add_agent(&self, cgroup_id: CgroupId, agent_id: AgentId) -> Result<(), CgroupError> {
        let _tree = self.lock_tree()?;
        let _ = self.hierarchy_unlocked(cgroup_id)?;
        let mut group = self
            .groups
            .get_mut(&cgroup_id)
            .ok_or(CgroupError::GroupNotFound(cgroup_id))?;
        if group.members.contains(&agent_id) {
            return Err(CgroupError::AgentAlreadyMember {
                cgroup_id,
                agent_id,
            });
        }
        if group.limits.max_agents > 0 && group.usage.agent_count >= group.limits.max_agents {
            return Err(CgroupError::MaxAgentsReached(cgroup_id));
        }
        group.members.push(agent_id);
        group.usage.agent_count = group.members.len().min(u32::MAX as usize) as u32;
        Ok(())
    }

    pub fn try_remove_agent(
        &self,
        cgroup_id: CgroupId,
        agent_id: AgentId,
    ) -> Result<(), CgroupError> {
        let _tree = self.lock_tree()?;
        let _ = self.hierarchy_unlocked(cgroup_id)?;
        if self
            .active_tool_calls_by_agent
            .get(&agent_id)
            .is_some_and(|active| *active > 0)
        {
            return Err(CgroupError::ActiveToolReservations(cgroup_id));
        }
        let mut group = self
            .groups
            .get_mut(&cgroup_id)
            .ok_or(CgroupError::GroupNotFound(cgroup_id))?;
        let Some(index) = group.members.iter().position(|member| *member == agent_id) else {
            return Err(CgroupError::AgentNotMember {
                cgroup_id,
                agent_id,
            });
        };
        group.members.swap_remove(index);
        group.usage.agent_count = group.members.len().min(u32::MAX as usize) as u32;
        Ok(())
    }

    /// Atomically move one direct member between cgroups.
    ///
    /// A move is rejected while any node in the source hierarchy has an active
    /// tool-call reservation. Otherwise an in-flight guard could later release
    /// old counters while the agent starts calls in the destination hierarchy,
    /// bypassing both groups' concurrency limits.
    pub fn try_move_agent(
        &self,
        source: CgroupId,
        destination: CgroupId,
        agent_id: AgentId,
    ) -> Result<(), CgroupError> {
        let _tree = self.lock_tree()?;
        let source_hierarchy = self.hierarchy_unlocked(source)?;
        if source == destination {
            let leaf = source_hierarchy
                .last()
                .ok_or(CgroupError::HierarchyDoesNotReachRoot(source))?;
            return if leaf.members.contains(&agent_id) {
                Ok(())
            } else {
                Err(CgroupError::AgentNotMember {
                    cgroup_id: source,
                    agent_id,
                })
            };
        }
        let destination_hierarchy = self.hierarchy_unlocked(destination)?;
        let source_leaf = source_hierarchy
            .last()
            .ok_or(CgroupError::HierarchyDoesNotReachRoot(source))?;
        if !source_leaf.members.contains(&agent_id) {
            return Err(CgroupError::AgentNotMember {
                cgroup_id: source,
                agent_id,
            });
        }
        if self
            .active_tool_calls_by_agent
            .get(&agent_id)
            .is_some_and(|active| *active > 0)
        {
            return Err(CgroupError::ActiveToolReservations(source));
        }
        let destination_leaf = destination_hierarchy
            .last()
            .ok_or(CgroupError::HierarchyDoesNotReachRoot(destination))?;
        if destination_leaf.members.contains(&agent_id) {
            return Err(CgroupError::AgentAlreadyMember {
                cgroup_id: destination,
                agent_id,
            });
        }
        if destination_leaf.limits.max_agents > 0
            && destination_leaf.usage.agent_count >= destination_leaf.limits.max_agents
        {
            return Err(CgroupError::MaxAgentsReached(destination));
        }

        // All fallible checks completed under the structural lock. Mutate each
        // DashMap entry separately to avoid holding two shard write guards.
        {
            let mut destination_group = self
                .groups
                .get_mut(&destination)
                .expect("validated destination remains present under tree lock");
            destination_group.members.push(agent_id);
            destination_group.usage.agent_count =
                destination_group.members.len().min(u32::MAX as usize) as u32;
        }
        {
            let mut source_group = self
                .groups
                .get_mut(&source)
                .expect("validated source remains present under tree lock");
            let index = source_group
                .members
                .iter()
                .position(|member| *member == agent_id)
                .expect("validated source membership remains present under tree lock");
            source_group.members.swap_remove(index);
            source_group.usage.agent_count =
                source_group.members.len().min(u32::MAX as usize) as u32;
        }
        Ok(())
    }

    /// Deprecated process-local token precheck retained for source
    /// compatibility.
    ///
    /// Token usage is now enforced atomically in the durable provider ledger,
    /// which this standalone manager cannot query. To preserve fail-closed
    /// behavior for old callers, this returns `true` only when the complete
    /// hierarchy is valid and every token limit is unlimited (`0`).
    #[deprecated(
        since = "0.3.0",
        note = "non-authoritative compatibility shim; use kernel provider admission"
    )]
    pub fn check_token_limit(&self, cgroup_id: CgroupId, _tokens: u64) -> bool {
        let Ok(_tree) = self.lock_tree() else {
            return false;
        };
        self.hierarchy_unlocked(cgroup_id)
            .is_ok_and(|groups| groups.iter().all(|group| group.limits.tokens_per_min == 0))
    }

    /// Deprecated no-op retained for source compatibility. Provider token
    /// usage is written through the durable rate limiter, never this manager.
    #[deprecated(
        since = "0.3.0",
        note = "no-op compatibility shim; use kernel provider accounting"
    )]
    pub fn record_tokens(&self, _cgroup_id: CgroupId, _tokens: u64) {}

    /// Deprecated no-op reservation retained for source compatibility.
    ///
    /// `true` means only that the hierarchy is structurally valid and entirely
    /// unlimited. Any bounded hierarchy returns `false`, because admitting it
    /// without the durable ledger would fail open.
    #[deprecated(
        since = "0.3.0",
        note = "non-authoritative compatibility shim; use kernel provider admission"
    )]
    pub fn try_record_tokens(&self, cgroup_id: CgroupId, _tokens: u64) -> bool {
        let Ok(_tree) = self.lock_tree() else {
            return false;
        };
        self.hierarchy_unlocked(cgroup_id)
            .is_ok_and(|groups| groups.iter().all(|group| group.limits.tokens_per_min == 0))
    }

    /// Deprecated no-op retained for source compatibility. Durable fixed
    /// epochs roll over by timestamp and have no resettable process counter.
    #[deprecated(
        since = "0.3.0",
        note = "no-op compatibility shim; durable fixed epochs need no reset timer"
    )]
    pub fn reset_minute_counters(&self) {}

    /// Remove a non-root cgroup only when it is an entirely idle leaf.
    ///
    /// Structural validation happens before mutation while `tree_lock` is
    /// held. The parent child list, stable-scope index, and group table are
    /// then updated as one manager-level transaction, so failed validation
    /// cannot publish a partial removal.
    pub fn try_remove_empty_leaf(&self, cgroup_id: CgroupId) -> Result<(), CgroupError> {
        let _tree = self.lock_tree()?;
        if cgroup_id == self.root {
            return Err(CgroupError::RootRemoval);
        }
        let group = self
            .groups
            .get(&cgroup_id)
            .map(|group| group.clone())
            .ok_or(CgroupError::GroupNotFound(cgroup_id))?;
        if !group.children.is_empty()
            || !group.members.is_empty()
            || group.usage.agent_count != 0
            || group.usage.active_tool_calls != 0
            || group.usage.context_tokens != 0
        {
            return Err(CgroupError::GroupNotEmpty(cgroup_id));
        }
        let parent_id = group
            .parent
            .ok_or(CgroupError::HierarchyDoesNotReachRoot(cgroup_id))?;
        {
            let parent = self
                .groups
                .get(&parent_id)
                .ok_or(CgroupError::GroupNotFound(parent_id))?;
            if parent
                .children
                .iter()
                .filter(|child| **child == cgroup_id)
                .count()
                != 1
            {
                return Err(CgroupError::ParentChildMismatch {
                    cgroup_id,
                    parent_id,
                });
            }
        }
        if self
            .scope_index
            .get(&group.quota_scope)
            .map(|indexed| *indexed)
            != Some(cgroup_id)
        {
            return Err(CgroupError::ScopeIndexMismatch {
                cgroup_id,
                scope: group.quota_scope,
            });
        }

        // All fallible validation is complete. The manager lock prevents a
        // structural observer or mutator from seeing the intermediate state.
        self.groups
            .get_mut(&parent_id)
            .expect("validated parent remains present while tree lock is held")
            .children
            .retain(|child| *child != cgroup_id);
        self.scope_index.remove(&group.quota_scope);
        self.groups.remove(&cgroup_id);
        Ok(())
    }

    /// Backwards-compatible best-effort removal. Enforcement-critical paths
    /// use [`try_remove_agent`](Self::try_remove_agent) and propagate errors.
    pub fn remove_agent(&self, cgroup_id: CgroupId, agent_id: AgentId) {
        let _ = self.try_remove_agent(cgroup_id, agent_id);
    }

    fn rollback_tool_calls(&self, cgroups: &[CgroupId]) {
        for id in cgroups {
            if let Some(mut group) = self.groups.get_mut(id) {
                group.usage.active_tool_calls = group.usage.active_tool_calls.saturating_sub(1);
            }
        }
    }

    fn release_tool_call(&self, cgroups: &[CgroupId], agent_id: Option<AgentId>) {
        self.rollback_tool_calls(cgroups);
        let Some(agent_id) = agent_id else {
            return;
        };
        if let Entry::Occupied(mut active) = self.active_tool_calls_by_agent.entry(agent_id) {
            let remaining = active.get().saturating_sub(1);
            if remaining == 0 {
                active.remove();
            } else {
                *active.get_mut() = remaining;
            }
        }
        self.tool_calls_changed.notify_waiters();
    }

    pub(crate) async fn wait_for_agent_tool_calls(&self, agent_id: AgentId) {
        loop {
            // Register before checking so the final guard drop cannot be lost
            // between the observation and await.
            let changed = self.tool_calls_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self
                .active_tool_calls_by_agent
                .get(&agent_id)
                .is_some_and(|active| *active > 0)
            {
                return;
            }
            changed.as_mut().await;
        }
    }

    fn acquire_tool_call_for_hierarchy(
        self: &Arc<Self>,
        hierarchy: Vec<Cgroup>,
        agent_id: Option<AgentId>,
    ) -> Result<ToolCallGuard, CgroupError> {
        let mut acquired = Vec::with_capacity(hierarchy.len());
        for snapshot in hierarchy {
            let Some(mut group) = self.groups.get_mut(&snapshot.id) else {
                self.rollback_tool_calls(&acquired);
                return Err(CgroupError::GroupNotFound(snapshot.id));
            };
            if group.limits.max_concurrent_tool_calls > 0
                && group.usage.active_tool_calls >= group.limits.max_concurrent_tool_calls
            {
                let error = CgroupError::ToolCallLimit {
                    cgroup_id: group.id,
                    scope: group.quota_scope.clone(),
                };
                drop(group);
                self.rollback_tool_calls(&acquired);
                return Err(error);
            }
            group.usage.active_tool_calls = group.usage.active_tool_calls.saturating_add(1);
            acquired.push(group.id);
        }
        if let Some(agent_id) = agent_id {
            self.active_tool_calls_by_agent
                .entry(agent_id)
                .and_modify(|active| *active = active.saturating_add(1))
                .or_insert(1);
        }
        Ok(ToolCallGuard {
            manager: self.clone(),
            cgroups: acquired,
            agent_id,
        })
    }

    /// Fallible structural concurrent-tool-call reservation.
    pub fn acquire_tool_call_checked(
        self: &Arc<Self>,
        cgroup_id: CgroupId,
    ) -> Result<ToolCallGuard, CgroupError> {
        let _tree = self.lock_tree()?;
        let hierarchy = self.hierarchy_unlocked(cgroup_id)?;
        self.acquire_tool_call_for_hierarchy(hierarchy, None)
    }

    /// Membership-aware reservation used by the syscall gate.
    pub fn acquire_tool_call_for_agent(
        self: &Arc<Self>,
        cgroup_id: CgroupId,
        agent_id: AgentId,
    ) -> Result<ToolCallGuard, CgroupError> {
        let _tree = self.lock_tree()?;
        let hierarchy = self.hierarchy_unlocked(cgroup_id)?;
        let leaf = hierarchy
            .last()
            .ok_or(CgroupError::HierarchyDoesNotReachRoot(cgroup_id))?;
        if !leaf.members.contains(&agent_id) {
            return Err(CgroupError::AgentNotMember {
                cgroup_id,
                agent_id,
            });
        }
        self.acquire_tool_call_for_hierarchy(hierarchy, Some(agent_id))
    }

    /// Backwards-compatible structural reservation.
    pub fn try_acquire_tool_call(self: &Arc<Self>, cgroup_id: CgroupId) -> Option<ToolCallGuard> {
        self.acquire_tool_call_checked(cgroup_id).ok()
    }

    pub fn get(&self, id: CgroupId) -> Option<Cgroup> {
        let _tree = self.lock_tree().ok()?;
        self.groups.get(&id).map(|group| group.clone())
    }

    #[cfg(test)]
    pub(crate) fn structural_counts(&self) -> (usize, usize) {
        let _tree = self
            .lock_tree()
            .expect("cgroup hierarchy lock must remain healthy in tests");
        (self.groups.len(), self.scope_index.len())
    }

    pub fn root(&self) -> CgroupId {
        self.root
    }
}

/// Deprecated process-local compatibility precheck.
///
/// This succeeds only when `cgroup_id` belongs to a well-formed, entirely
/// unlimited hierarchy. Bounded hierarchies fail closed because durable RPM/TPM
/// admission requires the kernel's provider rate limiter and cannot be
/// performed by a standalone `CgroupManager`.
#[deprecated(
    since = "0.3.0",
    note = "non-authoritative compatibility shim; use kernel provider admission"
)]
pub fn enforce_limits(
    manager: &CgroupManager,
    cgroup_id: CgroupId,
    tokens: u64,
) -> Result<(), &'static str> {
    #[allow(deprecated)]
    if manager.check_token_limit(cgroup_id, tokens) {
        Ok(())
    } else {
        Err("cgroup hierarchy unavailable or requires durable provider admission")
    }
}

/// RAII reservation for one active tool call. Dropping releases every
/// cgroup/ancestor counter even when execution errors or is cancelled.
pub struct ToolCallGuard {
    manager: Arc<CgroupManager>,
    cgroups: Vec<CgroupId>,
    agent_id: Option<AgentId>,
}

impl Drop for ToolCallGuard {
    fn drop(&mut self) {
        self.manager.release_tool_call(&self.cgroups, self.agent_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_derived_scopes_are_stable_and_escaped() {
        let manager = CgroupManager::new();
        assert_eq!(manager.get(manager.root()).unwrap().quota_scope, "/");
        let tenant = manager.create("tenant/a~b".into(), manager.root(), CgroupLimits::default());
        assert_eq!(manager.get(tenant).unwrap().quota_scope, "/tenant~1a~0b");
        let child = manager.create("worker".into(), tenant, CgroupLimits::default());
        assert_eq!(
            manager.get(child).unwrap().quota_scope,
            "/tenant~1a~0b/worker"
        );
    }

    #[test]
    fn explicit_scopes_are_validated_and_unique() {
        let manager = CgroupManager::new();
        let profile = manager
            .create_scoped(
                "standard".into(),
                manager.root(),
                "/profile/standard".into(),
                CgroupLimits::default(),
            )
            .unwrap();
        assert_eq!(
            manager.get(profile).unwrap().quota_scope,
            "/profile/standard"
        );
        assert!(matches!(
            manager.create_scoped(
                "duplicate".into(),
                manager.root(),
                "/profile/standard".into(),
                CgroupLimits::default()
            ),
            Err(CgroupError::DuplicateScope(_))
        ));
        for invalid in ["", "relative", "/bad\0scope"] {
            assert!(matches!(
                manager.create_scoped(
                    "bad".into(),
                    manager.root(),
                    invalid.into(),
                    CgroupLimits::default()
                ),
                Err(CgroupError::InvalidScope { .. })
            ));
        }
    }

    #[test]
    fn quota_constraints_are_root_to_leaf_and_exact() {
        let manager = CgroupManager::new();
        let parent = manager.create(
            "tenant".into(),
            manager.root(),
            CgroupLimits {
                tokens_per_min: 100,
                ..Default::default()
            },
        );
        let child = manager.create(
            "agent".into(),
            parent,
            CgroupLimits {
                tokens_per_min: 25,
                ..Default::default()
            },
        );
        assert_eq!(
            manager.quota_constraints(child).unwrap(),
            vec![
                CgroupQuotaConstraint {
                    scope_id: "/".into(),
                    token_limit: 0,
                },
                CgroupQuotaConstraint {
                    scope_id: "/tenant".into(),
                    token_limit: 100,
                },
                CgroupQuotaConstraint {
                    scope_id: "/tenant/agent".into(),
                    token_limit: 25,
                },
            ]
        );
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_token_shims_fail_closed_for_any_bounded_hierarchy() {
        let manager = CgroupManager::new();
        let unlimited = manager.create("unlimited".into(), manager.root(), CgroupLimits::default());
        let bounded = manager.create(
            "bounded".into(),
            unlimited,
            CgroupLimits {
                tokens_per_min: 100,
                ..Default::default()
            },
        );

        assert!(manager.check_token_limit(unlimited, u64::MAX));
        assert!(manager.try_record_tokens(unlimited, u64::MAX));
        assert!(enforce_limits(&manager, unlimited, u64::MAX).is_ok());

        assert!(!manager.check_token_limit(bounded, 0));
        assert!(!manager.try_record_tokens(bounded, 0));
        assert!(enforce_limits(&manager, bounded, 0).is_err());
    }

    #[test]
    fn corrupt_missing_cycle_and_duplicate_scope_hierarchies_fail_closed() {
        let manager = CgroupManager::new();
        let parent = manager.create("parent".into(), manager.root(), CgroupLimits::default());
        let child = manager.create("child".into(), parent, CgroupLimits::default());

        manager.groups.get_mut(&parent).unwrap().parent = Some(child);
        assert!(matches!(
            manager.quota_constraints(child),
            Err(CgroupError::HierarchyCycle(_))
        ));
        manager.groups.get_mut(&parent).unwrap().parent = Some(manager.root());
        manager.groups.get_mut(&child).unwrap().quota_scope = "/parent".into();
        assert!(matches!(
            manager.quota_constraints(child),
            Err(CgroupError::DuplicateHierarchyScope(_))
        ));
        manager.groups.get_mut(&child).unwrap().quota_scope = "/parent/child".into();
        manager.groups.remove(&parent);
        assert_eq!(
            manager.quota_constraints(child),
            Err(CgroupError::GroupNotFound(parent))
        );
    }

    #[test]
    fn membership_and_max_agents_fail_closed() {
        let manager = CgroupManager::new();
        let group = manager.create(
            "small".into(),
            manager.root(),
            CgroupLimits {
                max_agents: 1,
                ..Default::default()
            },
        );
        manager.add_agent(group, 7).unwrap();
        assert!(matches!(
            manager.add_agent(group, 7),
            Err(CgroupError::AgentAlreadyMember { .. })
        ));
        assert_eq!(
            manager.add_agent(group, 8),
            Err(CgroupError::MaxAgentsReached(group))
        );
        assert!(manager.quota_constraints_for_agent(group, 7).is_ok());
        assert!(matches!(
            manager.quota_constraints_for_agent(group, 8),
            Err(CgroupError::AgentNotMember { .. })
        ));
        assert!(matches!(
            manager.try_remove_agent(group, 8),
            Err(CgroupError::AgentNotMember { .. })
        ));
    }

    #[test]
    fn empty_leaf_removal_updates_parent_scope_index_and_group_table_together() {
        let manager = Arc::new(CgroupManager::new());
        let parent = manager.create("parent".into(), manager.root(), CgroupLimits::default());
        let leaf = manager.create("leaf".into(), parent, CgroupLimits::default());
        assert_eq!(manager.structural_counts(), (3, 3));

        assert_eq!(
            manager.try_remove_empty_leaf(manager.root()),
            Err(CgroupError::RootRemoval)
        );
        assert_eq!(
            manager.try_remove_empty_leaf(parent),
            Err(CgroupError::GroupNotEmpty(parent))
        );

        manager.add_agent(leaf, 7).unwrap();
        assert_eq!(
            manager.try_remove_empty_leaf(leaf),
            Err(CgroupError::GroupNotEmpty(leaf))
        );
        manager.try_remove_agent(leaf, 7).unwrap();

        let guard = manager.acquire_tool_call_checked(leaf).unwrap();
        assert_eq!(
            manager.try_remove_empty_leaf(leaf),
            Err(CgroupError::GroupNotEmpty(leaf))
        );
        drop(guard);

        manager.try_remove_empty_leaf(leaf).unwrap();
        assert_eq!(manager.structural_counts(), (2, 2));
        assert!(manager.get(leaf).is_none());
        assert!(!manager.get(parent).unwrap().children.contains(&leaf));
        assert!(!manager.scope_index.contains_key("/parent/leaf"));
    }

    #[test]
    fn concurrent_tool_call_limit_is_hierarchical_and_released_on_drop() {
        let manager = Arc::new(CgroupManager::new());
        let parent = manager.create(
            "tools".into(),
            manager.root(),
            CgroupLimits {
                max_concurrent_tool_calls: 1,
                ..Default::default()
            },
        );
        let child = manager.create("child".into(), parent, CgroupLimits::default());
        let first = manager
            .acquire_tool_call_checked(child)
            .expect("first call admitted");
        assert!(matches!(
            manager.acquire_tool_call_checked(child),
            Err(CgroupError::ToolCallLimit { .. })
        ));
        assert_eq!(manager.get(parent).unwrap().usage.active_tool_calls, 1);
        assert_eq!(manager.get(child).unwrap().usage.active_tool_calls, 1);
        drop(first);
        assert_eq!(manager.get(parent).unwrap().usage.active_tool_calls, 0);
        assert_eq!(manager.get(child).unwrap().usage.active_tool_calls, 0);
    }

    #[test]
    fn active_tool_guard_prevents_membership_move_without_changing_limits() {
        let manager = Arc::new(CgroupManager::new());
        let source = manager.create(
            "source".into(),
            manager.root(),
            CgroupLimits {
                max_concurrent_tool_calls: 1,
                ..Default::default()
            },
        );
        let destination = manager.create(
            "destination".into(),
            manager.root(),
            CgroupLimits::default(),
        );
        manager.add_agent(source, 42).unwrap();

        let guard = manager.acquire_tool_call_for_agent(source, 42).unwrap();
        assert!(matches!(
            manager.try_move_agent(source, destination, 42),
            Err(CgroupError::ActiveToolReservations(_))
        ));
        assert!(manager.get(source).unwrap().members.contains(&42));
        assert!(!manager.get(destination).unwrap().members.contains(&42));
        assert!(matches!(
            manager.acquire_tool_call_for_agent(source, 42),
            Err(CgroupError::ToolCallLimit { .. })
        ));

        drop(guard);
        manager.try_move_agent(source, destination, 42).unwrap();
        assert!(!manager.get(source).unwrap().members.contains(&42));
        assert!(manager.get(destination).unwrap().members.contains(&42));
    }

    #[test]
    fn active_agent_guard_blocks_ancestor_to_descendant_move() {
        let manager = Arc::new(CgroupManager::new());
        let source = manager.create("source".into(), manager.root(), CgroupLimits::default());
        let destination = manager.create(
            "destination".into(),
            source,
            CgroupLimits {
                max_concurrent_tool_calls: 1,
                ..Default::default()
            },
        );
        manager.add_agent(source, 7).unwrap();
        let guard = manager.acquire_tool_call_for_agent(source, 7).unwrap();
        assert!(matches!(
            manager.try_move_agent(source, destination, 7),
            Err(CgroupError::ActiveToolReservations(_))
        ));
        drop(guard);
        manager.try_move_agent(source, destination, 7).unwrap();
    }

    #[test]
    fn unrelated_shared_ancestor_activity_does_not_block_membership_move() {
        let manager = Arc::new(CgroupManager::new());
        let source = manager.create("source".into(), manager.root(), CgroupLimits::default());
        let destination = manager.create(
            "destination".into(),
            manager.root(),
            CgroupLimits::default(),
        );
        let unrelated = manager.create("unrelated".into(), manager.root(), CgroupLimits::default());
        manager.add_agent(source, 1).unwrap();
        manager.add_agent(unrelated, 2).unwrap();
        let unrelated_guard = manager.acquire_tool_call_for_agent(unrelated, 2).unwrap();

        manager.try_move_agent(source, destination, 1).unwrap();
        assert!(manager.get(destination).unwrap().members.contains(&1));
        drop(unrelated_guard);
    }

    #[test]
    fn membership_aware_tool_slot_rejects_unassigned_agent_without_bumps() {
        let manager = Arc::new(CgroupManager::new());
        let group = manager.create("tools".into(), manager.root(), CgroupLimits::default());
        assert!(matches!(
            manager.acquire_tool_call_for_agent(group, 99),
            Err(CgroupError::AgentNotMember { .. })
        ));
        assert_eq!(manager.get(group).unwrap().usage.active_tool_calls, 0);
        manager.add_agent(group, 99).unwrap();
        let guard = manager.acquire_tool_call_for_agent(group, 99).unwrap();
        assert_eq!(manager.get(group).unwrap().usage.active_tool_calls, 1);
        drop(guard);
        assert_eq!(manager.get(group).unwrap().usage.active_tool_calls, 0);
    }

    #[tokio::test]
    async fn final_agent_guard_drop_cannot_be_lost_by_idle_waiter() {
        let manager = Arc::new(CgroupManager::new());
        let group = manager.create("waiters".into(), manager.root(), CgroupLimits::default());
        for agent_id in 1..=64 {
            manager.add_agent(group, agent_id).unwrap();
            let guard = manager
                .acquire_tool_call_for_agent(group, agent_id)
                .unwrap();
            let waiting = manager.clone();
            let waiter =
                tokio::spawn(async move { waiting.wait_for_agent_tool_calls(agent_id).await });
            if agent_id % 2 == 0 {
                tokio::task::yield_now().await;
            }
            drop(guard);
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .expect("idle waiter lost the final guard notification")
                .unwrap();
            manager.try_remove_agent(group, agent_id).unwrap();
        }
    }
}
