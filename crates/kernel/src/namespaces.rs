//! Agent Namespaces — isolated resource views.
//!
//! Like Linux namespaces (PID, mount, net, user), each namespace type
//! gives agents an isolated view of a specific resource.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use crate::agent_struct::AgentId;

static NEXT_NS_ID: AtomicU64 = AtomicU64::new(1);

/// Namespace ID.
pub type NamespaceId = u64;

/// Types of namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceType {
    /// Tool namespace — which tools are visible.
    Tool,
    /// Context namespace — isolated memory/context.
    Context,
    /// Agent namespace — which agents are visible (like PID namespace).
    Agent,
    /// Network namespace — isolated communication.
    Network,
    /// User namespace — UID/GID mapping.
    User,
    /// Mount namespace — isolated tool mount table.
    Mount,
}

/// A namespace instance.
#[derive(Debug, Clone)]
pub struct Namespace {
    pub id: NamespaceId,
    pub ns_type: NamespaceType,
    pub parent: Option<NamespaceId>,
    pub members: HashSet<AgentId>,
}

impl Namespace {
    pub fn new(ns_type: NamespaceType, parent: Option<NamespaceId>) -> Self {
        Self {
            id: NEXT_NS_ID.fetch_add(1, Ordering::SeqCst),
            ns_type,
            parent,
            members: HashSet::new(),
        }
    }
}

/// Global namespace registry.
pub struct NamespaceRegistry {
    namespaces: DashMap<NamespaceId, Namespace>,
    /// Default namespace per type (all agents start here).
    defaults: DashMap<NamespaceType, NamespaceId>,
}

impl NamespaceRegistry {
    pub fn new() -> Self {
        let registry = Self {
            namespaces: DashMap::new(),
            defaults: DashMap::new(),
        };
        // Create default namespaces
        for ns_type in [NamespaceType::Tool, NamespaceType::Context, NamespaceType::Agent,
                        NamespaceType::Network, NamespaceType::User, NamespaceType::Mount] {
            let ns = Namespace::new(ns_type, None);
            let id = ns.id;
            registry.namespaces.insert(id, ns);
            registry.defaults.insert(ns_type, id);
        }
        registry
    }

    /// Create a new namespace (like unshare()).
    pub fn create(&self, ns_type: NamespaceType, parent: Option<NamespaceId>) -> NamespaceId {
        let ns = Namespace::new(ns_type, parent);
        let id = ns.id;
        self.namespaces.insert(id, ns);
        id
    }

    /// Add an agent to a namespace.
    pub fn join(&self, ns_id: NamespaceId, agent_id: AgentId) -> bool {
        if let Some(mut ns) = self.namespaces.get_mut(&ns_id) {
            ns.members.insert(agent_id);
            true
        } else {
            false
        }
    }

    /// Remove an agent from a namespace.
    pub fn leave(&self, ns_id: NamespaceId, agent_id: AgentId) -> bool {
        if let Some(mut ns) = self.namespaces.get_mut(&ns_id) {
            ns.members.remove(&agent_id);
            true
        } else {
            false
        }
    }

    /// Check if two agents are in the same namespace of a given type.
    pub fn same_namespace(&self, agent_a: AgentId, agent_b: AgentId, ns_type: NamespaceType) -> bool {
        for entry in self.namespaces.iter() {
            if entry.ns_type == ns_type && entry.members.contains(&agent_a) && entry.members.contains(&agent_b) {
                return true;
            }
        }
        false
    }

    /// Check if an agent can see another agent (agent namespace check).
    pub fn can_see(&self, viewer: AgentId, target: AgentId) -> bool {
        // Agents in the same agent namespace can see each other
        self.same_namespace(viewer, target, NamespaceType::Agent)
    }

    /// Get the default namespace ID for a type.
    pub fn default_ns(&self, ns_type: NamespaceType) -> Option<NamespaceId> {
        self.defaults.get(&ns_type).map(|r| *r.value())
    }

    /// Get members of a namespace.
    pub fn members(&self, ns_id: NamespaceId) -> Vec<AgentId> {
        self.namespaces.get(&ns_id)
            .map(|ns| ns.members.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get namespace info.
    pub fn get(&self, ns_id: NamespaceId) -> Option<Namespace> {
        self.namespaces.get(&ns_id).map(|ns| ns.clone())
    }

    /// Count namespaces.
    pub fn count(&self) -> usize {
        self.namespaces.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_namespaces_created() {
        let reg = NamespaceRegistry::new();
        assert_eq!(reg.count(), 6); // one per type
        assert!(reg.default_ns(NamespaceType::Tool).is_some());
        assert!(reg.default_ns(NamespaceType::Agent).is_some());
    }

    #[test]
    fn create_and_join_namespace() {
        let reg = NamespaceRegistry::new();
        let ns = reg.create(NamespaceType::Agent, None);
        reg.join(ns, 100);
        reg.join(ns, 200);
        assert_eq!(reg.members(ns).len(), 2);
    }

    #[test]
    fn leave_namespace() {
        let reg = NamespaceRegistry::new();
        let ns = reg.create(NamespaceType::Agent, None);
        reg.join(ns, 100);
        reg.join(ns, 200);
        reg.leave(ns, 100);
        assert_eq!(reg.members(ns).len(), 1);
    }

    #[test]
    fn same_namespace_check() {
        let reg = NamespaceRegistry::new();
        let ns = reg.create(NamespaceType::Agent, None);
        reg.join(ns, 100);
        reg.join(ns, 200);
        assert!(reg.same_namespace(100, 200, NamespaceType::Agent));
    }

    #[test]
    fn different_namespace_isolation() {
        let reg = NamespaceRegistry::new();
        let ns1 = reg.create(NamespaceType::Agent, None);
        let ns2 = reg.create(NamespaceType::Agent, None);
        reg.join(ns1, 100);
        reg.join(ns2, 200);
        assert!(!reg.same_namespace(100, 200, NamespaceType::Agent));
        assert!(!reg.can_see(100, 200));
    }

    #[test]
    fn nested_namespace() {
        let reg = NamespaceRegistry::new();
        let parent = reg.create(NamespaceType::Tool, None);
        let child = reg.create(NamespaceType::Tool, Some(parent));
        let ns = reg.get(child).unwrap();
        assert_eq!(ns.parent, Some(parent));
    }
}
