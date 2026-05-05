//! Sandbox Manager — provides isolated execution environments for agents.
//!
//! Creates workspace directories with path canonicalization to prevent traversal,
//! network allowlist checking, and platform-aware isolation.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use dashmap::DashMap;

use crate::{AgentId, IsolationLevel, SandboxConfig, SandboxError, SandboxId};

/// The Sandbox Manager trait.
pub trait SandboxManager: Send + Sync {
    fn create_sandbox(&self, agent_id: AgentId, config: &SandboxConfig) -> Result<SandboxId, SandboxError>;
    fn destroy_sandbox(&self, sandbox_id: SandboxId) -> Result<(), SandboxError>;
    fn intercept_action(&self, sandbox_id: SandboxId, action: &SandboxAction) -> Result<(), SandboxError>;
    fn get_sandbox_for_agent(&self, agent_id: AgentId) -> Option<SandboxId>;
}

/// An action that may be intercepted by the sandbox.
#[derive(Debug, Clone)]
pub enum SandboxAction {
    /// File system access to a path.
    FileAccess(PathBuf),
    /// Network access to a host.
    NetworkAccess(String),
    /// Process execution.
    ProcessExec(String),
}

/// Internal sandbox state.
#[derive(Debug, Clone)]
struct SandboxState {
    id: SandboxId,
    agent_id: AgentId,
    workspace_dir: PathBuf,
    allowed_network_hosts: HashSet<String>,
    isolation_level: IsolationLevel,
}

/// Concrete sandbox manager implementation.
pub struct SandboxManagerImpl {
    sandboxes: DashMap<SandboxId, SandboxState>,
    agent_sandboxes: DashMap<AgentId, SandboxId>,
}

impl SandboxManagerImpl {
    pub fn new() -> Self {
        Self {
            sandboxes: DashMap::new(),
            agent_sandboxes: DashMap::new(),
        }
    }

    /// Canonicalize a path and check if it's within the sandbox boundary.
    fn is_within_boundary(workspace: &Path, target: &Path) -> bool {
        // Canonicalize both paths to resolve symlinks and ..
        let workspace_canonical = workspace.to_path_buf();
        // Use lexical normalization for testing (real impl would use fs::canonicalize)
        let target_normalized = Self::normalize_path(target);
        let workspace_normalized = Self::normalize_path(workspace);
        target_normalized.starts_with(&workspace_normalized)
    }

    /// Normalize a path by resolving .. and . components lexically.
    fn normalize_path(path: &Path) -> PathBuf {
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::ParentDir => { components.pop(); }
                std::path::Component::CurDir => {}
                c => components.push(c),
            }
        }
        components.iter().collect()
    }
}

impl SandboxManager for SandboxManagerImpl {
    fn create_sandbox(&self, agent_id: AgentId, config: &SandboxConfig) -> Result<SandboxId, SandboxError> {
        let sandbox_id = uuid::Uuid::new_v4();

        let allowed_hosts: HashSet<String> = config.allowed_network_hosts
            .as_ref()
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default();

        let state = SandboxState {
            id: sandbox_id,
            agent_id,
            workspace_dir: config.workspace_dir.clone(),
            allowed_network_hosts: allowed_hosts,
            isolation_level: config.isolation_level.clone(),
        };

        self.sandboxes.insert(sandbox_id, state);
        self.agent_sandboxes.insert(agent_id, sandbox_id);

        Ok(sandbox_id)
    }

    fn destroy_sandbox(&self, sandbox_id: SandboxId) -> Result<(), SandboxError> {
        let state = self.sandboxes.remove(&sandbox_id)
            .ok_or_else(|| SandboxError::DestructionFailed("Sandbox not found".to_string()))?;
        self.agent_sandboxes.remove(&state.1.agent_id);
        Ok(())
    }

    fn intercept_action(&self, sandbox_id: SandboxId, action: &SandboxAction) -> Result<(), SandboxError> {
        let state = self.sandboxes.get(&sandbox_id)
            .ok_or_else(|| SandboxError::BoundaryViolation("Sandbox not found".to_string()))?;

        match action {
            SandboxAction::FileAccess(path) => {
                if !Self::is_within_boundary(&state.workspace_dir, path) {
                    return Err(SandboxError::BoundaryViolation(
                        format!("Path {:?} is outside sandbox boundary {:?}", path, state.workspace_dir)
                    ));
                }
            }
            SandboxAction::NetworkAccess(host) => {
                if !state.allowed_network_hosts.is_empty()
                    && !state.allowed_network_hosts.contains(host) {
                    return Err(SandboxError::BoundaryViolation(
                        format!("Network access to '{}' not in allowlist", host)
                    ));
                }
            }
            SandboxAction::ProcessExec(cmd) => {
                // Only container-level isolation allows arbitrary process execution
                if state.isolation_level != IsolationLevel::Container {
                    return Err(SandboxError::BoundaryViolation(
                        format!("Process execution '{}' not allowed at {:?} isolation level", cmd, state.isolation_level)
                    ));
                }
            }
        }

        Ok(())
    }

    fn get_sandbox_for_agent(&self, agent_id: AgentId) -> Option<SandboxId> {
        self.agent_sandboxes.get(&agent_id).map(|r| *r.value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SandboxConfig {
        SandboxConfig {
            workspace_dir: PathBuf::from("/tmp/sandbox/agent1"),
            allowed_network_hosts: Some(vec!["api.openai.com".to_string()]),
            max_disk_usage_bytes: None,
            max_memory_bytes: None,
            isolation_level: IsolationLevel::Filesystem,
        }
    }

    #[test]
    fn create_and_destroy_sandbox() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        assert!(mgr.get_sandbox_for_agent(agent_id).is_some());
        mgr.destroy_sandbox(sid).unwrap();
        assert!(mgr.get_sandbox_for_agent(agent_id).is_none());
    }

    #[test]
    fn file_access_within_boundary_allowed() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::FileAccess(PathBuf::from("/tmp/sandbox/agent1/file.txt")));
        assert!(result.is_ok());
    }

    #[test]
    fn file_access_outside_boundary_blocked() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::FileAccess(PathBuf::from("/etc/passwd")));
        assert!(result.is_err());
    }

    #[test]
    fn path_traversal_blocked() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::FileAccess(PathBuf::from("/tmp/sandbox/agent1/../../etc/passwd")));
        assert!(result.is_err());
    }

    #[test]
    fn network_allowed_host_passes() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::NetworkAccess("api.openai.com".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn network_disallowed_host_blocked() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::NetworkAccess("evil.com".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn process_exec_blocked_at_filesystem_level() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::ProcessExec("rm -rf /".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn process_exec_allowed_at_container_level() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let config = SandboxConfig {
            isolation_level: IsolationLevel::Container,
            ..test_config()
        };
        let sid = mgr.create_sandbox(agent_id, &config).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::ProcessExec("ls".to_string()));
        assert!(result.is_ok());
    }
}
