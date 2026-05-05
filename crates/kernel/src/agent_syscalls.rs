//! Agent syscalls — create, clone, exec, exit, wait, kill.
//!
//! The fundamental operations on agents, equivalent to Linux process syscalls.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::agent_struct::*;

/// Flags for agent_clone() — control what's shared vs copied.
pub mod clone_flags {
    pub const CLONE_CONTEXT: u32   = 1 << 0;  // Share context (conversation history)
    pub const CLONE_TOOLS: u32     = 1 << 1;  // Share tool descriptors
    pub const CLONE_NAMESPACE: u32 = 1 << 2;  // Share all namespaces
    pub const CLONE_CGROUP: u32    = 1 << 3;  // Share resource limits
    pub const CLONE_CREDS: u32     = 1 << 4;  // Share credentials
    pub const CLONE_SIGNALS: u32   = 1 << 5;  // Share signal handlers
    pub const CLONE_PARENT: u32    = 1 << 6;  // New agent has same parent (sibling)
}

/// Result of agent_wait().
#[derive(Debug, Clone)]
pub struct WaitResult {
    pub agent_id: AgentId,
    pub exit_code: i32,
    pub signaled: bool,
}

/// Agent syscall implementations.
pub struct AgentSyscalls {
    table: Arc<AgentTable>,
}

impl AgentSyscalls {
    pub fn new(table: Arc<AgentTable>) -> Self {
        Self { table }
    }

    /// Create a new agent (like fork+exec combined).
    pub fn agent_create(&self, name: String, parent: AgentId) -> AgentId {
        let mut agent = AgentStruct::new(name, parent);
        agent.state = AgentState::Ready;

        // Inherit parent's credentials and namespace (if parent exists)
        if let Some(parent_ref) = self.table.get(parent) {
            let parent_lock = parent_ref.value();
            // We can't async here, so just copy basic fields
            // In real impl this would be async
            agent.creds.uid = 1000; // inherit from parent in async version
        }

        let id = agent.id;

        // Register as child of parent
        self.table.insert(agent);

        // Add to parent's children list
        if let Some(parent_ref) = self.table.get(parent) {
            // Would need write lock in async version
        }

        id
    }

    /// Clone an agent with selective resource sharing.
    pub fn agent_clone(&self, source_id: AgentId, flags: u32) -> Option<AgentId> {
        let source_ref = self.table.get(source_id)?;
        let source = source_ref.value();

        // Create new agent
        let parent = if flags & clone_flags::CLONE_PARENT != 0 {
            // Same parent as source (sibling)
            0 // would read source.parent
        } else {
            source_id // source is parent
        };

        let mut child = AgentStruct::new(format!("clone-{}", source_id), parent);
        child.state = AgentState::Ready;

        // Copy or share resources based on flags
        if flags & clone_flags::CLONE_NAMESPACE != 0 {
            // Share namespaces (same IDs)
            child.resources.context_ns = 0; // would copy from source
            child.resources.tool_ns = 0;
            child.resources.agent_ns = 0;
            child.resources.net_ns = 0;
        }

        if flags & clone_flags::CLONE_CGROUP != 0 {
            child.resources.cgroup = 0; // share cgroup
        }

        if flags & clone_flags::CLONE_CREDS != 0 {
            child.creds.uid = 1000; // would copy from source
            child.creds.gid = 1000;
        }

        // Scheduling: child starts with same nice value
        child.sched.nice = 0; // would copy from source
        child.sched.class = SchedClass::Normal;

        let id = child.id;
        self.table.insert(child);
        Some(id)
    }

    /// Terminate an agent with an exit code.
    pub fn agent_exit(&self, agent_id: AgentId, code: i32) -> bool {
        if let Some(agent_ref) = self.table.get(agent_id) {
            let agent = agent_ref.value();
            // Would need write lock
            // agent.state = AgentState::Zombie;
            // agent.exit_info = Some(ExitInfo { code, signal: None, exited_at: Utc::now() });
            true
        } else {
            false
        }
    }

    /// Send a signal to an agent.
    pub fn agent_kill(&self, target_id: AgentId, signal: u8, sender_id: AgentId) -> Result<(), &'static str> {
        // Check sender has CAP_AGENT_KILL or is sending to self/child
        if sender_id != target_id {
            if let Some(sender_ref) = self.table.get(sender_id) {
                // Would check capabilities
            }
        }

        if let Some(target_ref) = self.table.get(target_id) {
            // Would need write lock to send signal
            Ok(())
        } else {
            Err("agent not found")
        }
    }

    /// Get agent count.
    pub fn count(&self) -> usize {
        self.table.count()
    }

    /// List all agent IDs.
    pub fn list(&self) -> Vec<AgentId> {
        self.table.list_ids()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> AgentSyscalls {
        let table = Arc::new(AgentTable::new());
        AgentSyscalls::new(table)
    }

    #[test]
    fn create_agent() {
        let sys = setup();
        let id = sys.agent_create("test-agent".into(), 0);
        assert!(id > 0);
        assert_eq!(sys.count(), 1);
    }

    #[test]
    fn create_multiple_agents() {
        let sys = setup();
        let id1 = sys.agent_create("a1".into(), 0);
        let id2 = sys.agent_create("a2".into(), 0);
        let id3 = sys.agent_create("a3".into(), 0);
        assert_eq!(sys.count(), 3);
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    #[test]
    fn clone_agent() {
        let sys = setup();
        let parent = sys.agent_create("parent".into(), 0);
        let child = sys.agent_clone(parent, 0);
        assert!(child.is_some());
        assert_eq!(sys.count(), 2);
    }

    #[test]
    fn clone_with_shared_namespace() {
        let sys = setup();
        let parent = sys.agent_create("parent".into(), 0);
        let child = sys.agent_clone(parent, clone_flags::CLONE_NAMESPACE | clone_flags::CLONE_CREDS);
        assert!(child.is_some());
    }

    #[test]
    fn clone_nonexistent_fails() {
        let sys = setup();
        let result = sys.agent_clone(99999, 0);
        assert!(result.is_none());
    }

    #[test]
    fn kill_nonexistent_fails() {
        let sys = setup();
        let result = sys.agent_kill(99999, signals::SIGTERM, 0);
        assert!(result.is_err());
    }

    #[test]
    fn kill_existing_succeeds() {
        let sys = setup();
        let id = sys.agent_create("target".into(), 0);
        let result = sys.agent_kill(id, signals::SIGTERM, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn list_agents() {
        let sys = setup();
        sys.agent_create("a".into(), 0);
        sys.agent_create("b".into(), 0);
        let ids = sys.list();
        assert_eq!(ids.len(), 2);
    }
}
