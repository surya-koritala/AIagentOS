//! Sandbox Manager — provides isolated execution environments for agents.
//!
//! Creates workspace directories with path canonicalization to prevent traversal,
//! network allowlist checking, and platform-aware isolation.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use dashmap::DashMap;

use crate::{AgentId, IsolationLevel, SandboxConfig, SandboxError, SandboxId};

/// The Sandbox Manager trait.
#[async_trait::async_trait]
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
    /// Execute a filesystem operation through the sandbox's directory
    /// capability. Providers never reopen an authorized host pathname for
    /// non-trusted agents.
    fn execute_filesystem(
        &self,
        sandbox_id: SandboxId,
        operation: &str,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError>;
    /// Execute HTTP through a client bound to the policy-validated DNS answers.
    /// Redirects and ambient proxy configuration are disabled.
    async fn execute_network(
        &self,
        sandbox_id: SandboxId,
        operation: &str,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError>;
    /// Execute an application command in the configured host-isolation
    /// backend. `Process` is rejected until a native backend is qualified;
    /// `Container` uses the hardened rootless OCI backend on Linux.
    async fn execute_process(
        &self,
        sandbox_id: SandboxId,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError>;
    fn isolation_level(&self, sandbox_id: SandboxId) -> Result<IsolationLevel, SandboxError>;
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
    workspace_alias: PathBuf,
    workspace_dir: PathBuf,
    allowed_network_hosts: HashSet<String>,
    isolation_level: IsolationLevel,
    managed_workspace: bool,
    workspace: Arc<Mutex<Option<Dir>>>,
    max_disk_usage_bytes: Option<u64>,
    max_memory_bytes: Option<u64>,
    container_image: Option<String>,
    operation_lock: Arc<Mutex<()>>,
    process_lock: Arc<tokio::sync::Semaphore>,
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
    const MANAGED_MARKER: &'static str = ".aiagentos-managed";

    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            static ORPHAN_CLEANUP: std::sync::Once = std::sync::Once::new();
            ORPHAN_CLEANUP.call_once(crate::docker_sandbox::cleanup_orphans_best_effort);
        }
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
            workspace_dir: Self::managed_root().join(uuid::Uuid::new_v4().to_string()),
            allowed_network_hosts: Some(Vec::new()),
            max_disk_usage_bytes: Some(100 * 1024 * 1024),
            max_memory_bytes: Some(256 * 1024 * 1024),
            isolation_level: IsolationLevel::Filesystem,
            container_image: None,
        }
    }

    pub fn managed_root() -> PathBuf {
        std::env::temp_dir().join("aiagentos-workspaces")
    }

    fn live_managed_workspaces() -> &'static Mutex<HashSet<PathBuf>> {
        static LIVE: std::sync::OnceLock<Mutex<HashSet<PathBuf>>> = std::sync::OnceLock::new();
        LIVE.get_or_init(|| Mutex::new(HashSet::new()))
    }

    pub fn is_managed_config(config: &SandboxConfig) -> bool {
        if !config.workspace_dir.starts_with(Self::managed_root())
            || config.isolation_level != IsolationLevel::Filesystem
            || !config
                .workspace_dir
                .file_name()
                .and_then(|leaf| leaf.to_str())
                .is_some_and(|leaf| uuid::Uuid::parse_str(leaf).is_ok())
        {
            return false;
        }
        if config.workspace_dir.join(Self::MANAGED_MARKER).is_file() {
            return true;
        }
        // Compatibility for managed workspaces created before the durable
        // marker existed. The internal root is reserved, the leaf is a UUID,
        // and strict ownership/mode must still prove it was service-managed.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            std::fs::metadata(&config.workspace_dir).is_ok_and(|metadata| {
                metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.permissions().mode() & 0o077 == 0
            })
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    fn ensure_managed_root() -> Result<PathBuf, SandboxError> {
        let root = Self::managed_root();
        std::fs::create_dir_all(&root)
            .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
            let metadata = std::fs::metadata(&root)
                .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(SandboxError::CreationFailed(
                    "managed workspace root must be private to the service user".into(),
                ));
            }
        }
        std::fs::canonicalize(root).map_err(|error| SandboxError::CreationFailed(error.to_string()))
    }

    /// Remove UUID-scoped managed workspaces that have no live persisted
    /// agent. A crash may occur before the marker is written, so ownership by
    /// the private managed root plus a UUID leaf is the cleanup authority.
    pub fn reconcile_managed_workspaces(
        &self,
        active_workspaces: &HashSet<PathBuf>,
    ) -> Result<usize, SandboxError> {
        // Keep discovery and deletion atomic with managed-workspace creation
        // and destruction. Without this guard, reconciliation can observe a
        // newly created directory before its live registration is published.
        let live = Self::live_managed_workspaces().lock().map_err(|_| {
            SandboxError::DestructionFailed("managed workspace registry unavailable".into())
        })?;
        let root = Self::ensure_managed_root()?;
        let mut active = active_workspaces
            .iter()
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .collect::<HashSet<_>>();
        active.extend(live.iter().cloned());
        let mut removed = 0;
        for entry in std::fs::read_dir(&root)
            .map_err(|error| SandboxError::DestructionFailed(error.to_string()))?
        {
            let entry =
                entry.map_err(|error| SandboxError::DestructionFailed(error.to_string()))?;
            let file_type = entry
                .file_type()
                .map_err(|error| SandboxError::DestructionFailed(error.to_string()))?;
            if !file_type.is_dir()
                || uuid::Uuid::parse_str(&entry.file_name().to_string_lossy()).is_err()
            {
                continue;
            }
            let path = entry.path();
            let canonical = std::fs::canonicalize(&path)
                .map_err(|error| SandboxError::DestructionFailed(error.to_string()))?;
            if canonical.parent() != Some(root.as_path()) || active.contains(&canonical) {
                continue;
            }
            std::fs::remove_dir_all(&canonical)
                .map_err(|error| SandboxError::DestructionFailed(error.to_string()))?;
            removed += 1;
        }
        Ok(removed)
    }

    #[cfg(test)]
    pub(crate) fn structural_counts(&self) -> (usize, usize) {
        (self.sandboxes.len(), self.agent_sandboxes.len())
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
        if config.isolation_level == IsolationLevel::Process {
            return Err(SandboxError::CreationFailed(
                "native process isolation is not supported; use a qualified container backend"
                    .into(),
            ));
        }
        if config.isolation_level == IsolationLevel::Container {
            #[cfg(not(target_os = "linux"))]
            {
                return Err(SandboxError::CreationFailed(
                    "container isolation is unsupported on this platform".into(),
                ));
            }
            #[cfg(target_os = "linux")]
            {
                let image = config.container_image.as_deref().ok_or_else(|| {
                    SandboxError::CreationFailed(
                        "container isolation requires a digest-pinned image".into(),
                    )
                })?;
                crate::docker_sandbox::validate_digest_image(image)
                    .map_err(SandboxError::CreationFailed)?;
            }
        }
        // Hold the registry guard before touching a managed directory so
        // reconciliation cannot mistake an in-progress creation for an
        // orphan. The guard stays held until the path is published below.
        let mut managed_registry = if managed_workspace {
            Some(Self::live_managed_workspaces().lock().map_err(|_| {
                SandboxError::CreationFailed("managed workspace registry unavailable".into())
            })?)
        } else {
            None
        };
        let managed_root = if managed_workspace {
            let root = Self::ensure_managed_root()?;
            let parent = config.workspace_dir.parent().ok_or_else(|| {
                SandboxError::CreationFailed("managed workspace path is invalid".into())
            })?;
            let parent = std::fs::canonicalize(parent)
                .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
            let valid_leaf = config
                .workspace_dir
                .file_name()
                .and_then(|leaf| leaf.to_str())
                .is_some_and(|leaf| uuid::Uuid::parse_str(leaf).is_ok());
            if parent != root || !valid_leaf {
                return Err(SandboxError::CreationFailed(
                    "managed workspace must be a UUID leaf of the private managed root".into(),
                ));
            }
            Some(root)
        } else {
            None
        };
        let workspace_dir = if config.isolation_level == IsolationLevel::Trusted {
            config.workspace_dir.clone()
        } else {
            if !config.workspace_dir.is_absolute() {
                return Err(SandboxError::CreationFailed(
                    "sandbox workspace must be an absolute path".into(),
                ));
            }
            #[cfg(unix)]
            let existed = config.workspace_dir.exists();
            if managed_workspace
                && std::fs::symlink_metadata(&config.workspace_dir)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err(SandboxError::CreationFailed(
                    "managed workspace cannot be a symbolic link".into(),
                ));
            }
            std::fs::create_dir_all(&config.workspace_dir)
                .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};

                let metadata = std::fs::metadata(&config.workspace_dir)
                    .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
                if metadata.uid() != unsafe { libc::geteuid() } {
                    return Err(SandboxError::CreationFailed(
                        "untrusted sandbox workspace must be owned by the service user".into(),
                    ));
                }
                if !existed || metadata.mode() & 0o077 != 0 {
                    std::fs::set_permissions(
                        &config.workspace_dir,
                        std::fs::Permissions::from_mode(0o700),
                    )
                    .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
                }
            }
            let workspace = std::fs::canonicalize(&config.workspace_dir)
                .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
            if managed_root
                .as_ref()
                .is_some_and(|root| workspace.parent() != Some(root.as_path()))
            {
                return Err(SandboxError::CreationFailed(
                    "managed workspace escaped the private managed root".into(),
                ));
            }
            workspace
        };
        if managed_root.is_some() {
            let marker = workspace_dir.join(Self::MANAGED_MARKER);
            std::fs::write(&marker, [])
                .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600))
                    .map_err(|error| SandboxError::CreationFailed(error.to_string()))?;
            }
        }
        let workspace = if config.isolation_level == IsolationLevel::Trusted {
            None
        } else {
            Some(
                Dir::open_ambient_dir(&workspace_dir, ambient_authority())
                    .map_err(|error| SandboxError::CreationFailed(error.to_string()))?,
            )
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
            workspace_alias: config.workspace_dir.clone(),
            workspace_dir: workspace_dir.clone(),
            allowed_network_hosts: allowed_hosts,
            isolation_level: config.isolation_level.clone(),
            managed_workspace,
            workspace: Arc::new(Mutex::new(workspace)),
            max_disk_usage_bytes: config.max_disk_usage_bytes,
            max_memory_bytes: config.max_memory_bytes,
            container_image: config.container_image.clone(),
            operation_lock: Arc::new(Mutex::new(())),
            process_lock: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        if managed_workspace {
            managed_registry
                .as_mut()
                .ok_or_else(|| {
                    SandboxError::CreationFailed("managed workspace registry unavailable".into())
                })?
                .insert(workspace_dir.clone());
        }
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

    fn relative_capability_path(
        state: &SandboxState,
        path: &Path,
    ) -> Result<PathBuf, SandboxError> {
        let relative = if path.is_absolute() {
            path.strip_prefix(&state.workspace_dir)
                .or_else(|_| path.strip_prefix(&state.workspace_alias))
                .map_err(|_| SandboxError::BoundaryViolation("filesystem target denied".into()))?
                .to_path_buf()
        } else {
            path.to_path_buf()
        };
        if relative.as_os_str().is_empty() {
            return Ok(PathBuf::from("."));
        }
        if relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        }) {
            return Err(SandboxError::BoundaryViolation(
                "filesystem target denied".into(),
            ));
        }
        Ok(relative)
    }

    fn filesystem_error(operation: &str, error: std::io::Error) -> SandboxError {
        SandboxError::BoundaryViolation(format!(
            "sandbox filesystem {operation} failed ({:?})",
            error.kind()
        ))
    }

    fn directory_usage(dir: &Dir) -> Result<u64, SandboxError> {
        let mut usage = 0_u64;
        let entries = dir
            .entries()
            .map_err(|error| Self::filesystem_error("quota scan", error))?;
        for entry in entries {
            let entry = entry.map_err(|error| Self::filesystem_error("quota scan", error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| Self::filesystem_error("quota scan", error))?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                let child = dir
                    .open_dir(entry.file_name())
                    .map_err(|error| Self::filesystem_error("quota scan", error))?;
                usage = usage.saturating_add(Self::directory_usage(&child)?);
            } else if file_type.is_file() {
                usage = usage.saturating_add(
                    entry
                        .metadata()
                        .map_err(|error| Self::filesystem_error("quota scan", error))?
                        .len(),
                );
            }
        }
        Ok(usage)
    }

    fn enforce_write_quota(
        state: &SandboxState,
        workspace: &Dir,
        relative: &Path,
        new_len: u64,
    ) -> Result<(), SandboxError> {
        let Some(limit) = state.max_disk_usage_bytes else {
            return Ok(());
        };
        let current = Self::directory_usage(workspace)?;
        let replaced_len = workspace
            .metadata(relative)
            .ok()
            .filter(|metadata| metadata.is_file())
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if current.saturating_sub(replaced_len).saturating_add(new_len) > limit {
            return Err(SandboxError::BoundaryViolation(
                "sandbox disk quota exceeded".into(),
            ));
        }
        Ok(())
    }

    fn execute_filesystem_inner(
        state: &SandboxState,
        operation: &str,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        if state.isolation_level == IsolationLevel::Trusted {
            return Err(SandboxError::BoundaryViolation(
                "trusted filesystem requests must use an operator provider".into(),
            ));
        }
        let _operation = state.operation_lock.lock().map_err(|_| {
            SandboxError::BoundaryViolation("sandbox filesystem unavailable".into())
        })?;
        let workspace = state.workspace.lock().map_err(|_| {
            SandboxError::BoundaryViolation("sandbox filesystem unavailable".into())
        })?;
        let workspace = workspace.as_ref().ok_or_else(|| {
            SandboxError::BoundaryViolation("sandbox filesystem unavailable".into())
        })?;
        let supplied = parameters
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SandboxError::BoundaryViolation("sandbox filesystem target denied".into())
            })?;
        let relative = Self::relative_capability_path(state, Path::new(supplied))?;
        match operation {
            "read" => {
                let content = workspace
                    .read_to_string(&relative)
                    .map_err(|error| Self::filesystem_error("read", error))?;
                Ok(serde_json::json!({"content": content}))
            }
            "write" | "create" => {
                let content = parameters
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                Self::enforce_write_quota(state, workspace, &relative, content.len() as u64)?;
                workspace
                    .write(&relative, content)
                    .map_err(|error| Self::filesystem_error("write", error))?;
                Ok(serde_json::json!({"written": true}))
            }
            "create_dir" => {
                workspace
                    .create_dir_all(&relative)
                    .map_err(|error| Self::filesystem_error("create directory", error))?;
                Ok(serde_json::json!({"created": true}))
            }
            "edit" => {
                let search = parameters
                    .get("search")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        SandboxError::BoundaryViolation(
                            "sandbox edit search value is required".into(),
                        )
                    })?;
                let replace = parameters
                    .get("replace")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let content = workspace
                    .read_to_string(&relative)
                    .map_err(|error| Self::filesystem_error("edit read", error))?;
                if !content.contains(search) {
                    return Err(SandboxError::BoundaryViolation(
                        "sandbox edit search text was not found".into(),
                    ));
                }
                let updated = content.replacen(search, replace, 1);
                Self::enforce_write_quota(state, workspace, &relative, updated.len() as u64)?;

                let parent = relative.parent().unwrap_or_else(|| Path::new(""));
                let temporary = parent.join(format!(".aiagentos-edit-{}", uuid::Uuid::new_v4()));
                workspace
                    .write(&temporary, &updated)
                    .map_err(|error| Self::filesystem_error("edit write", error))?;
                if let Err(error) = workspace.rename(&temporary, workspace, &relative) {
                    let _ = workspace.remove_file(&temporary);
                    return Err(Self::filesystem_error("edit commit", error));
                }
                Ok(serde_json::json!({"edited": true}))
            }
            "delete" => {
                workspace
                    .remove_file(&relative)
                    .map_err(|error| Self::filesystem_error("delete", error))?;
                Ok(serde_json::json!({"deleted": true}))
            }
            "list" => {
                let entries = workspace
                    .read_dir(&relative)
                    .map_err(|error| Self::filesystem_error("list", error))?
                    .map(|entry| {
                        entry
                            .map(|entry| entry.file_name().to_string_lossy().to_string())
                            .map_err(|error| Self::filesystem_error("list", error))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(serde_json::json!({"entries": entries}))
            }
            _ => Err(SandboxError::BoundaryViolation(
                "unsupported sandbox filesystem operation".into(),
            )),
        }
    }

    fn network_target(
        state: &SandboxState,
        target: &str,
    ) -> Result<(reqwest::Url, String, u16), SandboxError> {
        let url = reqwest::Url::parse(target)
            .map_err(|_| SandboxError::BoundaryViolation("invalid network target".into()))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(SandboxError::BoundaryViolation(
                "network target scheme or credentials denied".into(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| SandboxError::BoundaryViolation("missing network host".into()))?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| SandboxError::BoundaryViolation("network port denied".into()))?;
        let required_port = if url.scheme() == "https" { 443 } else { 80 };
        if port != required_port {
            return Err(SandboxError::BoundaryViolation(
                "network port denied".into(),
            ));
        }
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
        Ok((url, host, port))
    }

    async fn execute_network_inner(
        state: &SandboxState,
        operation: &str,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        if state.isolation_level == IsolationLevel::Trusted {
            return Err(SandboxError::BoundaryViolation(
                "trusted network requests must use an operator provider".into(),
            ));
        }
        let target = parameters
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SandboxError::BoundaryViolation("network target denied".into()))?;
        let (url, host, port) = Self::network_target(state, target)?;

        let mut addresses = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            vec![std::net::SocketAddr::new(ip, port)]
        } else {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| {
                    SandboxError::BoundaryViolation("network name resolution denied".into())
                })?
                .collect::<Vec<_>>()
        };
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
            return Err(SandboxError::BoundaryViolation(
                "network name resolved to a denied address".into(),
            ));
        }

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if host.parse::<std::net::IpAddr>().is_err() {
            builder = builder.resolve_to_addrs(&host, &addresses);
        }
        let client = builder
            .build()
            .map_err(|_| SandboxError::BoundaryViolation("network client unavailable".into()))?;

        let request = match operation {
            "get" | "browse" => client.get(url),
            "post" => client.post(url).json(
                &parameters
                    .get("body")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            ),
            "put" => client.put(url).json(
                &parameters
                    .get("body")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            ),
            "delete" => client.delete(url),
            _ => {
                return Err(SandboxError::BoundaryViolation(
                    "unsupported sandbox network operation".into(),
                ))
            }
        };
        let mut response = request
            .send()
            .await
            .map_err(|_| SandboxError::BoundaryViolation("network request failed".into()))?;
        let status = response.status().as_u16();
        const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| SandboxError::BoundaryViolation("network response failed".into()))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(SandboxError::BoundaryViolation(
                    "network response exceeded sandbox limit".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8_lossy(&body).to_string();
        if operation == "browse" {
            let mut in_tag = false;
            let mut visible = String::new();
            for character in text.chars() {
                match character {
                    '<' => in_tag = true,
                    '>' => in_tag = false,
                    _ if !in_tag => visible.push(character),
                    _ => {}
                }
            }
            let clean = visible.split_whitespace().collect::<Vec<_>>().join(" ");
            let content = clean
                .chars()
                .take(crate::MAX_BROWSE_CHARS.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<String>();
            Ok(serde_json::json!({"status": status, "content": content}))
        } else {
            Ok(serde_json::json!({"status": status, "body": text}))
        }
    }

    async fn execute_process_inner(
        state: &SandboxState,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        if state.isolation_level != IsolationLevel::Container {
            return Err(SandboxError::BoundaryViolation(
                "isolated process backend unavailable".into(),
            ));
        }
        let program = parameters
            .get("command")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SandboxError::BoundaryViolation("process command denied".into()))?;
        let arguments = parameters
            .get("args")
            .and_then(serde_json::Value::as_array)
            .map(|arguments| {
                arguments
                    .iter()
                    .map(|argument| {
                        argument.as_str().map(str::to_string).ok_or_else(|| {
                            SandboxError::BoundaryViolation(
                                "process arguments must be strings".into(),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let image = state
            .container_image
            .as_deref()
            .ok_or_else(|| SandboxError::BoundaryViolation("container image unavailable".into()))?;
        let _permit = state
            .process_lock
            .acquire()
            .await
            .map_err(|_| SandboxError::BoundaryViolation("process sandbox closed".into()))?;

        #[cfg(target_os = "linux")]
        {
            crate::docker_sandbox::execute_hardened(
                state.agent_id,
                &state.workspace_dir,
                image,
                state.max_memory_bytes,
                program,
                &arguments,
            )
            .await
            .map_err(SandboxError::BoundaryViolation)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (image, program, arguments);
            Err(SandboxError::BoundaryViolation(
                "container isolation is unsupported on this platform".into(),
            ))
        }
    }
}

#[async_trait::async_trait]
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
            .get(&sandbox_id)
            .map(|state| state.clone())
            .ok_or_else(|| SandboxError::DestructionFailed("Sandbox not found".to_string()))?;
        let mut managed_registry = if state.managed_workspace {
            Some(Self::live_managed_workspaces().lock().map_err(|_| {
                SandboxError::DestructionFailed("managed workspace registry unavailable".into())
            })?)
        } else {
            None
        };
        #[cfg(target_os = "linux")]
        if state.isolation_level == IsolationLevel::Container {
            crate::docker_sandbox::cleanup_agent_best_effort(state.agent_id);
        }
        if state.managed_workspace {
            let _operation = state.operation_lock.lock().map_err(|_| {
                SandboxError::DestructionFailed("sandbox filesystem unavailable".into())
            })?;
            let workspace = state
                .workspace
                .lock()
                .map_err(|_| {
                    SandboxError::DestructionFailed("sandbox filesystem unavailable".into())
                })?
                .take();
            drop(workspace);
            if let Err(error) = std::fs::remove_dir_all(&state.workspace_dir) {
                let reopened = Dir::open_ambient_dir(&state.workspace_dir, ambient_authority())
                    .map_err(|reopen_error| {
                        SandboxError::DestructionFailed(format!(
                            "{error}; sandbox capability could not be restored: {reopen_error}"
                        ))
                    })?;
                *state.workspace.lock().map_err(|_| {
                    SandboxError::DestructionFailed(
                        "sandbox capability could not be restored".into(),
                    )
                })? = Some(reopened);
                return Err(SandboxError::DestructionFailed(error.to_string()));
            }
            managed_registry
                .as_mut()
                .ok_or_else(|| {
                    SandboxError::DestructionFailed("managed workspace registry unavailable".into())
                })?
                .remove(&state.workspace_dir);
        }
        self.sandboxes.remove(&sandbox_id);
        self.agent_sandboxes.remove(&state.agent_id);
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
                Self::network_target(&state, target)?;
            }
            SandboxAction::ProcessExec(_) => {
                if state.isolation_level == IsolationLevel::Trusted {
                    return Ok(());
                }
                if state.isolation_level != IsolationLevel::Container {
                    return Err(SandboxError::BoundaryViolation(
                        "host process execution is unavailable for untrusted sandboxes".into(),
                    ));
                }
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

    fn execute_filesystem(
        &self,
        sandbox_id: SandboxId,
        operation: &str,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        let state = self
            .sandboxes
            .get(&sandbox_id)
            .ok_or_else(|| SandboxError::BoundaryViolation("Sandbox not found".to_string()))?;
        Self::execute_filesystem_inner(&state, operation, parameters)
    }

    async fn execute_network(
        &self,
        sandbox_id: SandboxId,
        operation: &str,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        let state = self
            .sandboxes
            .get(&sandbox_id)
            .map(|state| state.clone())
            .ok_or_else(|| SandboxError::BoundaryViolation("Sandbox not found".to_string()))?;
        Self::execute_network_inner(&state, operation, parameters).await
    }

    async fn execute_process(
        &self,
        sandbox_id: SandboxId,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        let state = self
            .sandboxes
            .get(&sandbox_id)
            .map(|state| state.clone())
            .ok_or_else(|| SandboxError::BoundaryViolation("Sandbox not found".to_string()))?;
        Self::execute_process_inner(&state, parameters).await
    }

    fn isolation_level(&self, sandbox_id: SandboxId) -> Result<IsolationLevel, SandboxError> {
        self.sandboxes
            .get(&sandbox_id)
            .map(|state| state.isolation_level.clone())
            .ok_or_else(|| SandboxError::BoundaryViolation("Sandbox not found".to_string()))
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
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ip(std::net::IpAddr::V4(mapped));
            }
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
            container_image: None,
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
    fn unavailable_isolation_levels_fail_at_creation_instead_of_falling_back() {
        let mgr = SandboxManagerImpl::new();
        let process = SandboxConfig {
            isolation_level: IsolationLevel::Process,
            ..test_config()
        };
        assert!(mgr.create_sandbox(uuid::Uuid::new_v4(), &process).is_err());

        let container_without_image = SandboxConfig {
            isolation_level: IsolationLevel::Container,
            ..test_config()
        };
        assert!(mgr
            .create_sandbox(uuid::Uuid::new_v4(), &container_without_image)
            .is_err());
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

    #[test]
    fn mapped_private_ip_credentials_and_nonstandard_ports_are_denied() {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let config = SandboxConfig {
            allowed_network_hosts: Some(vec!["::ffff:127.0.0.1".into(), "api.openai.com".into()]),
            ..test_config()
        };
        let sid = mgr.create_sandbox(agent_id, &config).unwrap();

        for target in [
            "http://[::ffff:127.0.0.1]/",
            "https://user:secret@api.openai.com/",
            "https://api.openai.com:8443/",
            "http://api.openai.com:443/",
        ] {
            assert!(
                mgr.intercept_action(sid, &SandboxAction::NetworkAccess(target.into()))
                    .is_err(),
                "{target} must be denied"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_escape_is_denied() {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("agentos-symlink-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
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
                    container_image: None,
                },
            )
            .unwrap();
        assert!(mgr
            .intercept_action(sid, &SandboxAction::FileAccess(root.join("escape/passwd")))
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn capability_io_blocks_a_symlink_swap_after_authorization() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = std::env::temp_dir().join(format!("agentos-cap-race-{}", uuid::Uuid::new_v4()));
        let outside =
            std::env::temp_dir().join(format!("agentos-cap-outside-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("slot")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(outside.join("target.txt"), "outside sentinel").unwrap();

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
                    container_image: None,
                },
            )
            .unwrap();

        let authorized = mgr
            .resolve_file_path(sid, Path::new("slot/target.txt"))
            .unwrap();
        std::fs::rename(root.join("slot"), root.join("original")).unwrap();
        symlink(&outside, root.join("slot")).unwrap();

        let result = mgr.execute_filesystem(
            sid,
            "write",
            &serde_json::json!({
                "path": authorized.to_str().unwrap(),
                "content": "must stay inside"
            }),
        );
        assert!(result.is_err());
        assert_eq!(
            std::fs::read_to_string(outside.join("target.txt")).unwrap(),
            "outside sentinel"
        );

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn capability_io_enforces_disk_quota_before_mutation() {
        let mgr = SandboxManagerImpl::new();
        let config = SandboxConfig {
            max_disk_usage_bytes: Some(4),
            ..test_config()
        };
        let root = config.workspace_dir.clone();
        let sid = mgr.create_sandbox(uuid::Uuid::new_v4(), &config).unwrap();

        assert!(mgr
            .execute_filesystem(
                sid,
                "write",
                &serde_json::json!({"path": "too-large.txt", "content": "12345"}),
            )
            .is_err());
        assert!(!root.join("too-large.txt").exists());
        assert!(mgr
            .execute_filesystem(
                sid,
                "write",
                &serde_json::json!({"path": "fits.txt", "content": "1234"}),
            )
            .is_ok());
        assert_eq!(
            std::fs::read_to_string(root.join("fits.txt")).unwrap(),
            "1234"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capability_io_rejects_cross_agent_workspace_access() {
        let mgr = SandboxManagerImpl::new();
        let first = test_config();
        let second = test_config();
        let first_root = first.workspace_dir.clone();
        let second_root = second.workspace_dir.clone();
        let first_id = mgr.create_sandbox(uuid::Uuid::new_v4(), &first).unwrap();
        mgr.create_sandbox(uuid::Uuid::new_v4(), &second).unwrap();
        std::fs::write(second_root.join("secret.txt"), "other agent").unwrap();

        let result = mgr.execute_filesystem(
            first_id,
            "read",
            &serde_json::json!({"path": second_root.join("secret.txt")}),
        );
        assert!(result.is_err());

        std::fs::remove_dir_all(first_root).unwrap();
        std::fs::remove_dir_all(second_root).unwrap();
    }

    #[test]
    fn capability_filesystem_operations_and_denials_are_complete() {
        let mgr = SandboxManagerImpl::new();
        let config = SandboxConfig {
            max_disk_usage_bytes: Some(1024),
            ..test_config()
        };
        let root = config.workspace_dir.clone();
        let sid = mgr.create_sandbox(uuid::Uuid::new_v4(), &config).unwrap();

        assert_eq!(
            mgr.execute_filesystem(sid, "create_dir", &serde_json::json!({"path": "nested"}),)
                .unwrap(),
            serde_json::json!({"created": true})
        );
        assert_eq!(
            mgr.execute_filesystem(
                sid,
                "create",
                &serde_json::json!({"path": "nested/note.txt", "content": "hello world"}),
            )
            .unwrap(),
            serde_json::json!({"written": true})
        );
        #[cfg(unix)]
        std::os::unix::fs::symlink("nested/note.txt", root.join("note-link")).unwrap();
        assert_eq!(
            mgr.execute_filesystem(
                sid,
                "edit",
                &serde_json::json!({
                    "path": "nested/note.txt",
                    "search": "world",
                    "replace": "sandbox"
                }),
            )
            .unwrap(),
            serde_json::json!({"edited": true})
        );
        assert_eq!(
            std::fs::read_to_string(root.join("nested/note.txt")).unwrap(),
            "hello sandbox"
        );

        let listing = mgr
            .execute_filesystem(sid, "list", &serde_json::json!({"path": "nested"}))
            .unwrap();
        assert_eq!(
            listing["entries"],
            serde_json::json!(["note.txt"]),
            "directory listing must stay capability-relative"
        );
        assert!(mgr
            .execute_filesystem(
                sid,
                "edit",
                &serde_json::json!({"path": "nested/note.txt", "replace": "missing search"}),
            )
            .is_err());
        assert!(mgr
            .execute_filesystem(
                sid,
                "edit",
                &serde_json::json!({
                    "path": "nested/note.txt",
                    "search": "not present",
                    "replace": "x"
                }),
            )
            .is_err());
        assert!(mgr
            .execute_filesystem(sid, "read", &serde_json::json!({}))
            .is_err());
        assert!(mgr
            .execute_filesystem(
                sid,
                "chmod",
                &serde_json::json!({"path": "nested/note.txt"})
            )
            .is_err());
        assert_eq!(
            mgr.execute_filesystem(
                sid,
                "delete",
                &serde_json::json!({"path": "nested/note.txt"}),
            )
            .unwrap(),
            serde_json::json!({"deleted": true})
        );
        assert!(!root.join("nested/note.txt").exists());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn non_io_and_trusted_execution_paths_fail_closed() {
        let mgr = SandboxManagerImpl::new();
        let config = SandboxConfig {
            allowed_network_hosts: Some(vec!["93.184.216.34".into()]),
            ..test_config()
        };
        let root = config.workspace_dir.clone();
        let sid = mgr.create_sandbox(uuid::Uuid::new_v4(), &config).unwrap();

        assert!(mgr
            .execute_network(
                sid,
                "patch",
                &serde_json::json!({"url": "http://93.184.216.34"}),
            )
            .await
            .is_err());
        assert!(mgr
            .execute_network(sid, "get", &serde_json::json!({}))
            .await
            .is_err());
        assert!(mgr
            .execute_process(sid, &serde_json::json!({"command": "echo"}))
            .await
            .is_err());

        let missing = uuid::Uuid::new_v4();
        assert!(mgr
            .execute_network(
                missing,
                "get",
                &serde_json::json!({"url": "http://93.184.216.34"}),
            )
            .await
            .is_err());
        assert!(mgr
            .execute_process(missing, &serde_json::json!({"command": "echo"}))
            .await
            .is_err());
        assert!(mgr
            .execute_filesystem(missing, "read", &serde_json::json!({"path": "x"}))
            .is_err());
        assert!(mgr.isolation_level(missing).is_err());

        let trusted = SandboxConfig {
            workspace_dir: root.join("trusted"),
            isolation_level: IsolationLevel::Trusted,
            ..test_config()
        };
        let trusted_id = mgr.create_sandbox(uuid::Uuid::new_v4(), &trusted).unwrap();
        assert!(mgr
            .execute_filesystem(trusted_id, "read", &serde_json::json!({"path": "anything"}),)
            .is_err());
        assert!(mgr
            .execute_network(
                trusted_id,
                "get",
                &serde_json::json!({"url": "https://example.com"}),
            )
            .await
            .is_err());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_workspace_marker_and_orphan_reconciliation_are_durable() {
        let mgr = SandboxManagerImpl::new();
        let config = SandboxManagerImpl::default_config();
        let workspace = config.workspace_dir.clone();
        let sid = mgr
            .create_managed_sandbox(uuid::Uuid::new_v4(), &config)
            .unwrap();
        assert!(SandboxManagerImpl::is_managed_config(&config));

        let orphan = SandboxManagerImpl::managed_root().join(uuid::Uuid::new_v4().to_string());
        let unrelated = SandboxManagerImpl::managed_root().join("operator-owned");
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::create_dir_all(&unrelated).unwrap();
        let active = HashSet::from([workspace.clone()]);
        assert!(
            mgr.reconcile_managed_workspaces(&active).unwrap() >= 1,
            "the injected orphan and any older crash leftovers must be removed"
        );
        assert!(workspace.exists());
        assert!(!orphan.exists());
        assert!(unrelated.exists());

        mgr.destroy_sandbox(sid).unwrap();
        assert!(!workspace.exists());
        std::fs::remove_dir_all(unrelated).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_owned_workspace_is_hardened_before_use() {
        use std::os::unix::fs::PermissionsExt;

        let mgr = SandboxManagerImpl::new();
        let config = test_config();
        std::fs::create_dir_all(&config.workspace_dir).unwrap();
        std::fs::set_permissions(
            &config.workspace_dir,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let sid = mgr.create_sandbox(uuid::Uuid::new_v4(), &config).unwrap();
        let mode = std::fs::metadata(&config.workspace_dir)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);

        mgr.destroy_sandbox(sid).unwrap();
        std::fs::remove_dir_all(config.workspace_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn managed_workspace_symlink_is_rejected() {
        let mgr = SandboxManagerImpl::new();
        let config = SandboxManagerImpl::default_config();
        let target =
            std::env::temp_dir().join(format!("aiagentos-symlink-target-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&target).unwrap();
        SandboxManagerImpl::ensure_managed_root().unwrap();
        std::os::unix::fs::symlink(&target, &config.workspace_dir).unwrap();

        let result = mgr.create_managed_sandbox(uuid::Uuid::new_v4(), &config);
        assert!(matches!(result, Err(SandboxError::CreationFailed(_))));
        assert!(!target.join(SandboxManagerImpl::MANAGED_MARKER).exists());

        std::fs::remove_file(config.workspace_dir).unwrap();
        std::fs::remove_dir_all(target).unwrap();
    }
}
