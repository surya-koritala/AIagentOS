//! Service Discovery — agents register and find services by capability.
//!
//! Like DNS-SD / mDNS. Agents register what they can do, others find them.

use std::collections::HashMap;

use crate::agent_sockets::SocketAddr;
use crate::agent_struct::AgentId;

/// A registered service.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    pub name: String,
    pub agent_id: AgentId,
    pub address: SocketAddr,
    pub capabilities: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub healthy: bool,
}

/// Service discovery registry.
pub struct ServiceRegistry {
    services: HashMap<String, Vec<ServiceEntry>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Register a service.
    pub fn register(
        &mut self,
        name: String,
        agent_id: AgentId,
        address: SocketAddr,
        capabilities: Vec<String>,
    ) {
        let entry = ServiceEntry {
            name: name.clone(),
            agent_id,
            address,
            capabilities,
            metadata: HashMap::new(),
            healthy: true,
        };
        self.services.entry(name).or_default().push(entry);
    }

    /// Deregister all services for an agent.
    pub fn deregister(&mut self, agent_id: AgentId) {
        for entries in self.services.values_mut() {
            entries.retain(|e| e.agent_id != agent_id);
        }
    }

    /// Find services by name.
    pub fn lookup(&self, name: &str) -> Vec<&ServiceEntry> {
        self.services
            .get(name)
            .map(|v| v.iter().filter(|e| e.healthy).collect())
            .unwrap_or_default()
    }

    /// Find services by capability.
    pub fn find_by_capability(&self, cap: &str) -> Vec<&ServiceEntry> {
        self.services
            .values()
            .flatten()
            .filter(|e| e.healthy && e.capabilities.contains(&cap.to_string()))
            .collect()
    }

    /// Mark a service as unhealthy.
    pub fn mark_unhealthy(&mut self, agent_id: AgentId) {
        for entries in self.services.values_mut() {
            for entry in entries.iter_mut() {
                if entry.agent_id == agent_id {
                    entry.healthy = false;
                }
            }
        }
    }

    /// Mark a service as healthy.
    pub fn mark_healthy(&mut self, agent_id: AgentId) {
        for entries in self.services.values_mut() {
            for entry in entries.iter_mut() {
                if entry.agent_id == agent_id {
                    entry.healthy = true;
                }
            }
        }
    }

    /// Get total registered services.
    pub fn count(&self) -> usize {
        self.services.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_lookup() {
        let mut reg = ServiceRegistry::new();
        reg.register(
            "researcher".into(),
            1,
            SocketAddr::new(1, 8080),
            vec!["search".into(), "summarize".into()],
        );
        let results = reg.lookup("researcher");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, 1);
    }

    #[test]
    fn find_by_capability() {
        let mut reg = ServiceRegistry::new();
        reg.register(
            "agent-a".into(),
            1,
            SocketAddr::new(1, 80),
            vec!["code".into()],
        );
        reg.register(
            "agent-b".into(),
            2,
            SocketAddr::new(2, 80),
            vec!["code".into(), "review".into()],
        );
        reg.register(
            "agent-c".into(),
            3,
            SocketAddr::new(3, 80),
            vec!["research".into()],
        );
        let coders = reg.find_by_capability("code");
        assert_eq!(coders.len(), 2);
    }

    #[test]
    fn unhealthy_excluded() {
        let mut reg = ServiceRegistry::new();
        reg.register("svc".into(), 1, SocketAddr::new(1, 80), vec![]);
        reg.register("svc".into(), 2, SocketAddr::new(2, 80), vec![]);
        reg.mark_unhealthy(1);
        let results = reg.lookup("svc");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, 2);
    }

    #[test]
    fn deregister() {
        let mut reg = ServiceRegistry::new();
        reg.register("svc".into(), 1, SocketAddr::new(1, 80), vec![]);
        reg.deregister(1);
        assert_eq!(reg.count(), 0);
    }
}
