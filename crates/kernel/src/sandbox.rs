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
    fn create_sandbox(
        &self,
        agent_id: AgentId,
        config: &SandboxConfig,
    ) -> Result<SandboxId, SandboxError>;
    fn destroy_sandbox(&self, sandbox_id: SandboxId) -> Result<(), SandboxError>;
    fn intercept_action(
        &self,
        sandbox_id: SandboxId,
        action: &SandboxAction,
    ) -> Result<(), SandboxError>;
    /// Resolve the exact filesystem target that a provider may use. Relative
    /// paths are rooted in the sandbox workspace and the returned target has
    /// passed the same traversal/symlink boundary check as `intercept_action`.
    fn resolve_file_path(
        &self,
        sandbox_id: SandboxId,
        path: &Path,
    ) -> Result<PathBuf, SandboxError>;
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
    /// Browser navigation/download target.
    BrowserAccess(String),
    /// Peripheral operation name.
    PeripheralAccess(String),
    /// Namespace-governed inter-agent communication.
    Ipc,
}

/// Internal sandbox state.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SandboxState {
    id: SandboxId,
    agent_id: AgentId,
    workspace_dir: PathBuf,
    allowed_network_hosts: HashSet<String>,
    isolation_level: IsolationLevel,
    managed_workspace: bool,
}

/// Concrete sandbox manager implementation.
pub struct SandboxManagerImpl {
    sandboxes: DashMap<SandboxId, SandboxState>,
    agent_sandboxes: DashMap<AgentId, SandboxId>,
}

impl Default for SandboxManagerImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxManagerImpl {
    pub fn new() -> Self {
        Self {
            sandboxes: DashMap::new(),
            agent_sandboxes: DashMap::new(),
        }
    }

    /// Secure default used by all production agent-creation paths that do not
    /// carry an explicit operator sandbox. Network and host process access are
    /// denied; the workspace is unique and owned by the sandbox manager.
    pub fn default_config() -> SandboxConfig {
        SandboxConfig {
            workspace_dir: std::env::temp_dir()
                .join("aiagentos-workspaces")
                .join(uuid::Uuid::new_v4().to_string()),
            allowed_network_hosts: Some(Vec::new()),
            max_disk_usage_bytes: Some(100 * 1024 * 1024),
            max_memory_bytes: Some(256 * 1024 * 1024),
            isolation_level: IsolationLevel::Filesystem,
        }
    }

    pub fn is_managed_config(config: &SandboxConfig) -> bool {
        config
            .workspace_dir
            .starts_with(std::env::temp_dir().join("aiagentos-workspaces"))
            && config.isolation_level == IsolationLevel::Filesystem
    }

    pub fn create_managed_sandbox(
        &self,
        agent_id: AgentId,
        config: &SandboxConfig,
    ) -> Result<SandboxId, SandboxError> {
        self.create_sandbox_inner(agent_id, config, true)
    }

    fn create_sandbox_inner(
        &self,
        agent_id: AgentId,
        config: &SandboxConfig,
        managed_workspace: bool,
    ) -> Result<SandboxId, SandboxError> {
        if self.agent_sandboxes.contains_key(&agent_id) {
            return Err(SandboxError::CreationFailed(
                "agent already has a sandbox".into(),
            ));
        }
        let workspace_dir = if config.isolation_level == IsolationLevel::Trusted {
            config.workspace_dir.clone()
        } else {
            if !config.workspace_dir.is_absolute() {
                return Err(SandboxError::CreationFailed(
                    "sandbox workspace must be an absolute path".into(),
                ));
            }
            std::fs::create_dir_all(&config.workspace_dir)
                .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
            std::fs::canonicalize(&config.workspace_dir)
                .map_err(|error| SandboxError::CreationFailed(error.to_string()))?
        };
        let sandbox_id = uuid::Uuid::new_v4();
        let allowed_hosts = config
            .allowed_network_hosts
            .as_ref()
            .map(|hosts| hosts.iter().map(|host| host.to_ascii_lowercase()).collect())
            .unwrap_or_default();
        let state = SandboxState {
            id: sandbox_id,
            agent_id,
            workspace_dir,
            allowed_network_hosts: allowed_hosts,
            isolation_level: config.isolation_level.clone(),
            managed_workspace,
        };
        self.sandboxes.insert(sandbox_id, state);
        self.agent_sandboxes.insert(agent_id, sandbox_id);
        Ok(sandbox_id)
    }

    /// Resolve the target or its nearest existing ancestor and ensure it stays
    /// beneath the already-canonical workspace. This rejects existing symlink
    /// escapes and safely handles a not-yet-created final path.
    fn is_within_boundary(workspace: &Path, target: &Path) -> bool {
        if !target.is_absolute() {
            return false;
        }
        let workspace = match std::fs::canonicalize(workspace) {
            Ok(path) => path,
            Err(_) => return false,
        };
        let mut existing = target;
        while !existing.exists() {
            let Some(parent) = existing.parent() else {
                return false;
            };
            if parent == existing {
                return false;
            }
            existing = parent;
        }
        std::fs::canonicalize(existing)
            .map(|path| path.starts_with(&workspace))
            .unwrap_or(false)
    }

    fn resolve_against_state(state: &SandboxState, path: &Path) -> Result<PathBuf, SandboxError> {
        let target = if path.is_absolute() {
            path.to_path_buf()
        } else {
            state.workspace_dir.join(path)
        };
        if state.isolation_level != IsolationLevel::Trusted
            && !Self::is_within_boundary(&state.workspace_dir, &target)
        {
            return Err(SandboxError::BoundaryViolation(format!(
                "Path {:?} is outside sandbox boundary {:?}",
                path, state.workspace_dir
            )));
        }
        Ok(target)
    }
}

impl SandboxManager for SandboxManagerImpl {
    fn create_sandbox(
        &self,
        agent_id: AgentId,
        config: &SandboxConfig,
    ) -> Result<SandboxId, SandboxError> {
        self.create_sandbox_inner(agent_id, config, false)
    }

    fn destroy_sandbox(&self, sandbox_id: SandboxId) -> Result<(), SandboxError> {
        let state = self
            .sandboxes
            .remove(&sandbox_id)
            .ok_or_else(|| SandboxError::DestructionFailed("Sandbox not found".to_string()))?;
        self.agent_sandboxes.remove(&state.1.agent_id);
        if state.1.managed_workspace {
            std::fs::remove_dir_all(&state.1.workspace_dir)
                .map_err(|error| SandboxError::DestructionFailed(error.to_string()))?;
        }
        Ok(())
    }

    fn intercept_action(
        &self,
        sandbox_id: SandboxId,
        action: &SandboxAction,
    ) -> Result<(), SandboxError> {
        let state = self
            .sandboxes
            .get(&sandbox_id)
            .ok_or_else(|| SandboxError::BoundaryViolation("Sandbox not found".to_string()))?;

        match action {
            SandboxAction::FileAccess(path) => {
                Self::resolve_against_state(&state, path)?;
            }
            SandboxAction::NetworkAccess(target) | SandboxAction::BrowserAccess(target) => {
                if state.isolation_level == IsolationLevel::Trusted {
                    return Ok(());
                }
                let url = reqwest::Url::parse(target).map_err(|_| {
                    SandboxError::BoundaryViolation("invalid network target".into())
                })?;
                if !matches!(url.scheme(), "http" | "https") {
                    return Err(SandboxError::BoundaryViolation(
                        "only http/https network targets are allowed".into(),
                    ));
                }
                let host = url
                    .host_str()
                    .ok_or_else(|| SandboxError::BoundaryViolation("missing network host".into()))?
                    .to_ascii_lowercase();
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    if !is_public_ip(ip) {
                        return Err(SandboxError::BoundaryViolation(
                            "private or local network targets are denied".into(),
                        ));
                    }
                }
                if !state.allowed_network_hosts.contains(&host) {
                    return Err(SandboxError::BoundaryViolation(
                        "network host is not in the sandbox allowlist".into(),
                    ));
                }
            }
            SandboxAction::ProcessExec(_) => {
                if state.isolation_level == IsolationLevel::Trusted {
                    return Ok(());
                }
                return Err(SandboxError::BoundaryViolation(
                    "host process execution is unavailable for untrusted sandboxes".into(),
                ));
            }
            SandboxAction::PeripheralAccess(_) => {
                if state.isolation_level == IsolationLevel::Trusted {
                    return Ok(());
                }
                return Err(SandboxError::BoundaryViolation(
                    "peripheral access requires an explicit trusted operator grant".into(),
                ));
            }
            SandboxAction::Ipc => {}
        }

        Ok(())
    }

    fn resolve_file_path(
        &self,
        sandbox_id: SandboxId,
        path: &Path,
    ) -> Result<PathBuf, SandboxError> {
        let state = self
            .sandboxes
            .get(&sandbox_id)
            .ok_or_else(|| SandboxError::BoundaryViolation("Sandbox not found".to_string()))?;
        Self::resolve_against_state(&state, path)
    }

    fn get_sandbox_for_agent(&self, agent_id: AgentId) -> Option<SandboxId> {
        self.agent_sandboxes.get(&agent_id).map(|r| *r.value())
    }
}

fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.octets()[0] == 0)
        }
        std::net::IpAddr::V6(ip) => {
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SandboxConfig {
        SandboxConfig {
            workspace_dir: std::env::temp_dir()
                .join("aiagentos-sandbox-tests")
                .join(uuid::Uuid::new_v4().to_string()),
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
        let config = test_config();
        let sid = mgr.create_sandbox(agent_id, &config).unwrap();
        let result = mgr.intercept_action(
            sid,
            &SandboxAction::FileAccess(config.workspace_dir.join("file.txt")),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn relative_file_access_resolves_inside_workspace() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        assert!(mgr
            .intercept_action(
                sid,
                &SandboxAction::FileAccess(PathBuf::from("nested/file.txt"))
            )
            .is_ok());
        assert!(mgr
            .intercept_action(
                sid,
                &SandboxAction::FileAccess(PathBuf::from("../../etc/passwd"))
            )
            .is_err());
    }

    #[test]
    fn file_access_outside_boundary_blocked() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let config = test_config();
        let outside = config.workspace_dir.parent().unwrap().join("outside.txt");
        let sid = mgr.create_sandbox(agent_id, &config).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::FileAccess(outside));
        assert!(result.is_err());
    }

    #[test]
    fn path_traversal_blocked() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let config = test_config();
        let traversal = config.workspace_dir.join("../../outside.txt");
        let sid = mgr.create_sandbox(agent_id, &config).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::FileAccess(traversal));
        assert!(result.is_err());
    }

    #[test]
    fn network_allowed_host_passes() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        let result = mgr.intercept_action(
            sid,
            &SandboxAction::NetworkAccess("https://api.openai.com/v1".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn network_disallowed_host_blocked() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let sid = mgr.create_sandbox(agent_id, &test_config()).unwrap();
        let result = mgr.intercept_action(
            sid,
            &SandboxAction::NetworkAccess("https://evil.com/".to_string()),
        );
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
    fn container_declaration_does_not_fall_back_to_host_execution() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let config = SandboxConfig {
            isolation_level: IsolationLevel::Container,
            ..test_config()
        };
        let sid = mgr.create_sandbox(agent_id, &config).unwrap();
        let result = mgr.intercept_action(sid, &SandboxAction::ProcessExec("ls".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn private_ip_literal_is_denied_even_if_allowlisted() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let config = SandboxConfig {
            allowed_network_hosts: Some(vec!["127.0.0.1".into()]),
            ..test_config()
        };
        let sid = mgr.create_sandbox(agent_id, &config).unwrap();
        assert!(mgr
            .intercept_action(
                sid,
                &SandboxAction::NetworkAccess("http://127.0.0.1/admin".into())
            )
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_escape_is_denied() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("agentos-symlink-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        symlink("/etc", root.join("escape")).unwrap();
        let mgr = SandboxManagerImpl::new();
        let sid = mgr
            .create_sandbox(
                uuid::Uuid::new_v4(),
                &SandboxConfig {
                    workspace_dir: root.clone(),
                    allowed_network_hosts: Some(Vec::new()),
                    max_disk_usage_bytes: None,
                    max_memory_bytes: None,
                    isolation_level: IsolationLevel::Filesystem,
                },
            )
            .unwrap();
        assert!(mgr
            .intercept_action(sid, &SandboxAction::FileAccess(root.join("escape/passwd")))
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
