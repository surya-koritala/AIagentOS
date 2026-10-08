//! Opaque capabilities for workspace entries, rooted in a live sandbox.

use crate::{AgentId, SandboxError, SandboxId};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
};
use uuid::Uuid;

pub const MAX_WORKSPACE_TRANSFER_BYTES: usize = 1024 * 1024;
pub(crate) const CONTEXT_PARAMETER: &str = "_agentos_workspace_context";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRight {
    Read,
    Write,
    List,
    Stat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceHandle {
    pub id: String,
    pub path: String,
    pub kind: WorkspaceKind,
    pub rights: Vec<WorkspaceRight>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceStat {
    pub kind: WorkspaceKind,
    pub size: u64,
    pub readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceRead {
    pub data_base64: String,
    pub offset: u64,
    pub eof: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceOpenRequest {
    pub path: String,
    pub kind: WorkspaceKind,
    pub rights: Vec<WorkspaceRight>,
    #[serde(default)]
    pub allow_missing: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error(transparent)]
    Vfs(#[from] super::VfsError),
    #[error("workspace argument invalid: {0}")]
    Invalid(String),
    #[error("workspace handle rights denied")]
    PermissionDenied,
    #[error("workspace tool denied: {0}")]
    Tool(crate::tools::ToolAuthorizationError),
    #[error("workspace backing operation failed: {0}")]
    Backing(String),
}

pub(crate) fn operation_for_right(right: WorkspaceRight) -> (&'static str, &'static str) {
    match right {
        WorkspaceRight::Read => ("read_file_bytes", "read_bytes"),
        WorkspaceRight::Write => ("write_file_bytes", "write_bytes"),
        WorkspaceRight::List => ("list_directory", "list"),
        WorkspaceRight::Stat => ("stat_path", "stat"),
    }
}

pub(crate) fn validated_rights(
    rights: &[WorkspaceRight],
    kind: WorkspaceKind,
) -> Result<BTreeSet<WorkspaceRight>, SandboxError> {
    let set = rights.iter().copied().collect::<BTreeSet<_>>();
    if set.is_empty()
        || set.len() != rights.len()
        || (kind == WorkspaceKind::File && set.contains(&WorkspaceRight::List))
    {
        return Err(denied("invalid workspace rights"));
    }
    Ok(set)
}

pub(crate) fn canonical_relative(path: &str, allow_root: bool) -> Result<String, SandboxError> {
    if allow_root && path.is_empty() {
        return Ok(".".into());
    }
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || part.contains(':')
                || part.ends_with([' ', '.'])
                || part
                    .chars()
                    .any(|character| matches!(character, '<' | '>' | '"' | '|' | '?' | '*'))
                || portable_device_name(part)
        })
    {
        return Err(denied("invalid workspace path"));
    }
    Ok(path.to_string())
}

fn portable_device_name(component: &str) -> bool {
    let name = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    matches!(
        name.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

pub(crate) fn workspace_path(path: &str) -> Result<String, SandboxError> {
    if path == "/workspace" {
        return Ok(".".into());
    }
    canonical_relative(
        path.strip_prefix("/workspace/")
            .ok_or_else(|| denied("invalid workspace path"))?,
        false,
    )
}

pub(crate) fn public_path(relative: &str) -> String {
    if relative == "." {
        "/workspace".into()
    } else {
        format!("/workspace/{relative}")
    }
}

pub(crate) fn denied(message: &str) -> SandboxError {
    SandboxError::BoundaryViolation(message.into())
}

struct WorkspaceObject {
    owner: AgentId,
    sandbox: SandboxId,
    path: String,
    directory_path: PathBuf,
    directory: Arc<WorkspaceDirectory>,
    entry: PathBuf,
    kind: WorkspaceKind,
}

/// Shared native reference whose retirement does not depend on async callers
/// releasing their opaque capability clones.
#[derive(Debug)]
pub(crate) struct WorkspaceDirectory {
    directory: Mutex<Option<Dir>>,
}

impl WorkspaceDirectory {
    pub(crate) fn revoke(&self) {
        self.directory
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }

    fn with<T>(
        &self,
        apply: impl FnOnce(&Dir) -> Result<T, SandboxError>,
    ) -> Result<T, SandboxError> {
        let directory = self
            .directory
            .lock()
            .map_err(|_| denied("workspace directory unavailable"))?;
        let directory = directory
            .as_ref()
            .ok_or_else(|| denied("workspace directory revoked"))?;
        apply(directory)
    }
}

pub(crate) struct WorkspaceBinding {
    pub owner: AgentId,
    pub sandbox: SandboxId,
    pub path: String,
    pub directory_path: PathBuf,
    pub directory: Dir,
    pub entry: PathBuf,
    pub kind: WorkspaceKind,
}

pub(crate) struct WorkspaceOpenOptions {
    pub identity: Uuid,
    pub owner: AgentId,
    pub sandbox: SandboxId,
    pub relative: String,
    pub parent: Option<WorkspaceCapability>,
    pub kind: WorkspaceKind,
    pub rights: Vec<WorkspaceRight>,
    pub allow_missing: bool,
}

/// A kernel-owned capability. Its directory and identity are never serialized.
#[derive(Clone)]
pub struct WorkspaceCapability {
    identity: Uuid,
    object: Arc<WorkspaceObject>,
    rights: BTreeSet<WorkspaceRight>,
}

impl std::fmt::Debug for WorkspaceCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceCapability")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl WorkspaceCapability {
    pub(crate) fn new(
        identity: Uuid,
        binding: WorkspaceBinding,
        rights: BTreeSet<WorkspaceRight>,
    ) -> Self {
        let WorkspaceBinding {
            owner,
            sandbox,
            path,
            directory_path,
            directory,
            entry,
            kind,
        } = binding;
        Self {
            identity,
            object: Arc::new(WorkspaceObject {
                owner,
                sandbox,
                path,
                directory_path,
                directory: Arc::new(WorkspaceDirectory {
                    directory: Mutex::new(Some(directory)),
                }),
                entry,
                kind,
            }),
            rights,
        }
    }
    pub(crate) fn identity(&self) -> Uuid {
        self.identity
    }
    pub(crate) fn owner(&self) -> AgentId {
        self.object.owner
    }
    pub(crate) fn sandbox(&self) -> SandboxId {
        self.object.sandbox
    }
    pub(crate) fn path(&self) -> &str {
        &self.object.path
    }
    pub(crate) fn kind(&self) -> WorkspaceKind {
        self.object.kind
    }
    pub(crate) fn directory_path(&self) -> &Path {
        &self.object.directory_path
    }
    pub(crate) fn with_directory<T>(
        &self,
        apply: impl FnOnce(&Dir) -> Result<T, SandboxError>,
    ) -> Result<T, SandboxError> {
        self.object.directory.with(apply)
    }
    pub(crate) fn directory_reference(&self) -> Weak<WorkspaceDirectory> {
        Arc::downgrade(&self.object.directory)
    }
    pub(crate) fn entry(&self) -> &Path {
        &self.object.entry
    }
    pub(crate) fn rights(&self) -> Vec<WorkspaceRight> {
        self.rights.iter().copied().collect()
    }
    pub(crate) fn require(&self, right: WorkspaceRight) -> Result<(), SandboxError> {
        if self.rights.contains(&right) {
            Ok(())
        } else {
            Err(denied("workspace handle rights denied"))
        }
    }
    pub(crate) fn attenuate(
        &self,
        identity: Uuid,
        rights: &[WorkspaceRight],
    ) -> Result<Self, SandboxError> {
        let rights = validated_rights(rights, self.kind())?;
        if !rights.is_subset(&self.rights) {
            return Err(denied("workspace handle rights cannot broaden"));
        }
        Ok(Self {
            identity,
            object: self.object.clone(),
            rights,
        })
    }
    pub(crate) fn handle(&self) -> WorkspaceHandle {
        WorkspaceHandle {
            id: self.identity.to_string(),
            path: public_path(self.path()),
            kind: self.kind(),
            rights: self.rights(),
        }
    }
}

/// An opaque request carried separately from untrusted JSON. The JSON witness
/// is part of the normal gate request identity, so it cannot be changed later.
#[derive(Clone, Debug)]
pub enum WorkspaceRequest {
    Open {
        identity: Uuid,
        owner: AgentId,
        sandbox: SandboxId,
        path: String,
        relative: String,
        parent: Option<WorkspaceCapability>,
        kind: WorkspaceKind,
        rights: BTreeSet<WorkspaceRight>,
        allow_missing: bool,
    },
    Use {
        capability: WorkspaceCapability,
    },
}

impl WorkspaceRequest {
    pub(crate) fn open(options: WorkspaceOpenOptions) -> Result<Self, SandboxError> {
        let WorkspaceOpenOptions {
            identity,
            owner,
            sandbox,
            relative,
            parent,
            kind,
            rights,
            allow_missing,
        } = options;
        let rights = validated_rights(&rights, kind)?;
        if allow_missing
            && (kind != WorkspaceKind::File || !rights.contains(&WorkspaceRight::Write))
        {
            return Err(denied(
                "missing workspace entries require file-write rights",
            ));
        }
        let path = match &parent {
            Some(parent) => {
                if parent.owner() != owner
                    || parent.sandbox() != sandbox
                    || parent.kind() != WorkspaceKind::Directory
                    || !rights.is_subset(&parent.rights)
                {
                    return Err(denied("workspace child rights denied"));
                }
                let child = canonical_relative(&relative, false)?;
                if parent.path() == "." {
                    child
                } else {
                    format!("{}/{child}", parent.path())
                }
            }
            None => {
                if relative == "." {
                    relative.clone()
                } else {
                    canonical_relative(&relative, false)?
                }
            }
        };
        if path.len() > 4096 {
            return Err(denied("workspace path too long"));
        }
        Ok(Self::Open {
            identity,
            owner,
            sandbox,
            path,
            relative,
            parent,
            kind,
            rights,
            allow_missing,
        })
    }
    pub(crate) fn validate_open(&self) -> Result<(), SandboxError> {
        let Self::Open {
            identity,
            owner,
            sandbox,
            path,
            relative,
            parent,
            kind,
            rights,
            allow_missing,
        } = self
        else {
            return Err(denied("workspace request is not an open"));
        };
        let expected = Self::open(WorkspaceOpenOptions {
            identity: *identity,
            owner: *owner,
            sandbox: *sandbox,
            relative: relative.clone(),
            parent: parent.clone(),
            kind: *kind,
            rights: rights.iter().copied().collect(),
            allow_missing: *allow_missing,
        })?;
        if expected.path() != path {
            return Err(denied("workspace target does not match its capability"));
        }
        Ok(())
    }
    pub(crate) fn path(&self) -> &str {
        match self {
            Self::Open { path, .. } => path,
            Self::Use { capability } => capability.path(),
        }
    }
    pub(crate) fn owner(&self) -> AgentId {
        match self {
            Self::Open { owner, .. } => *owner,
            Self::Use { capability } => capability.owner(),
        }
    }
    pub(crate) fn sandbox(&self) -> SandboxId {
        match self {
            Self::Open { sandbox, .. } => *sandbox,
            Self::Use { capability } => capability.sandbox(),
        }
    }
    pub(crate) fn witness(&self) -> Value {
        match self {
            Self::Open {
                identity,
                owner,
                sandbox,
                path,
                relative,
                parent,
                kind,
                rights,
                allow_missing,
            } => {
                json!({"version":1,"mode":"open","identity":identity,"owner":owner,"sandbox":sandbox,"path":path,"relative":relative,"parent":parent.as_ref().map(WorkspaceCapability::identity),"kind":kind,"rights":rights,"allow_missing":allow_missing})
            }
            Self::Use { capability } => {
                json!({"version":1,"mode":"use","identity":capability.identity(),"owner":capability.owner(),"sandbox":capability.sandbox(),"path":capability.path(),"kind":capability.kind(),"rights":capability.rights()})
            }
        }
    }
    pub(crate) fn parameters(&self) -> Value {
        json!({"path":self.path(),CONTEXT_PARAMETER:self.witness()})
    }
}

#[derive(Debug)]
pub struct WorkspaceExecution {
    pub data: Value,
    pub opened: Option<WorkspaceCapability>,
}

pub(crate) fn directory_identity(directory: &Dir) -> Result<(u64, u64), SandboxError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|_| denied("workspace directory unavailable"))?;
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        use cap_primitives::fs::_WindowsByHandle;
        Ok((
            metadata
                .volume_serial_number()
                .ok_or_else(|| denied("workspace directory identity unavailable"))?
                as u64,
            metadata
                .file_index()
                .ok_or_else(|| denied("workspace directory identity unavailable"))?,
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        Err(denied("workspace directory identity unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentConfig, AgentKernelImpl, IsolationLevel, Priority, SandboxConfig};
    use proptest::prelude::*;
    use std::sync::atomic::Ordering;

    proptest! {
        #[test]
        fn canonical_workspace_names_do_not_normalize_aliases(name in "file_[a-z0-9_.-]{0,70}[a-z0-9_-]") {
            prop_assert_eq!(workspace_path(&format!("/workspace/{name}")).unwrap(), name.clone());
            for alias in [format!("/workspace//{name}"), format!("/workspace/{name}/"), format!("/workspace/./{name}"), format!("/workspace/a/../{name}"), format!("/workspace/{name}\\x")] {
                prop_assert!(workspace_path(&alias).is_err());
            }
        }
    }

    #[test]
    fn portable_paths_reject_device_and_trailing_name_aliases() {
        for name in [
            "CON",
            "nul.txt",
            "CoM1.log",
            "COM¹",
            "LPT9",
            "CONIN$",
            "file.",
            "file ",
            "file:stream",
            "file*",
            "file?",
            "file|",
            "file\"",
            "<file>",
        ] {
            assert!(
                workspace_path(&format!("/workspace/{name}")).is_err(),
                "{name}"
            );
        }
        assert_eq!(
            workspace_path("/workspace/résumé.txt").unwrap(),
            "résumé.txt"
        );
    }

    async fn setup() -> (
        tempfile::TempDir,
        Arc<AgentKernelImpl>,
        AgentId,
        WorkspaceHandle,
    ) {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.bin"), b"original").unwrap();
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let agent = kernel
            .create_agent_full(AgentConfig {
                name: "controlled-workspace".into(),
                task: "workspace cancellation".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: Some(SandboxConfig {
                    workspace_dir: root.path().to_path_buf(),
                    isolation_level: IsolationLevel::Filesystem,
                    allowed_network_hosts: Some(Vec::new()),
                    max_disk_usage_bytes: Some(100000),
                    max_memory_bytes: None,
                    container_image: None,
                }),
            })
            .await
            .unwrap()
            .id;
        let handle = kernel
            .vfs_open_workspace(
                agent,
                WorkspaceOpenRequest {
                    path: "/workspace/file.bin".into(),
                    kind: WorkspaceKind::File,
                    rights: vec![WorkspaceRight::Read, WorkspaceRight::Write],
                    allow_missing: false,
                },
            )
            .await
            .unwrap();
        (root, kernel, agent, handle)
    }

    async fn observed(flag: &std::sync::atomic::AtomicBool) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !flag.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("controlled filesystem checkpoint reached");
    }

    #[tokio::test]
    async fn managed_teardown_releases_a_retained_native_workspace_reference() {
        use crate::syscall_server::{Syscall, SyscallClient, SyscallReply, SyscallServer};
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let agent = kernel
            .create_agent_full(AgentConfig {
                name: "managed-capability-retirement".into(),
                task: "managed VFS lifecycle".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            })
            .await
            .unwrap()
            .id;
        let handle = kernel
            .vfs_open_workspace(
                agent,
                WorkspaceOpenRequest {
                    path: "/workspace".into(),
                    kind: WorkspaceKind::Directory,
                    rights: vec![WorkspaceRight::List],
                    allow_missing: false,
                },
            )
            .await
            .unwrap();
        let scope = kernel
            .tool_vfs
            .acquire(agent, &handle.id)
            .unwrap()
            .workspace()
            .unwrap();
        assert!(scope.with_directory(directory_identity).is_ok());
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let server = tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(address).await.unwrap();
        assert!(matches!(
            client
                .call(Syscall::StopAgent {
                    agent_id: agent.to_string()
                })
                .await
                .unwrap(),
            SyscallReply::AgentStatus { .. }
        ));
        assert!(scope.with_directory(directory_identity).is_err());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn managed_stop_can_finish_before_a_native_open_publishes_its_handle() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let agent = kernel
            .create_agent_full(AgentConfig {
                name: "managed-publication-race".into(),
                task: "managed VFS publication".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            })
            .await
            .unwrap()
            .id;
        let row = kernel
            .context_manager
            .load_all_agents()
            .unwrap()
            .into_iter()
            .find(|row| row.id == agent)
            .unwrap();
        let config: SandboxConfig =
            serde_json::from_str(row.sandbox_config_json.as_ref().unwrap()).unwrap();
        let (entered, release, _) = kernel.sandbox_manager.pause_next_filesystem_for_test();
        let opening = tokio::spawn({
            let kernel = kernel.clone();
            async move {
                kernel
                    .vfs_open_workspace(
                        agent,
                        WorkspaceOpenRequest {
                            path: "/workspace".into(),
                            kind: WorkspaceKind::Directory,
                            rights: vec![WorkspaceRight::List],
                            allow_missing: false,
                        },
                    )
                    .await
            }
        });
        observed(&entered).await;
        let lifecycle = kernel.lifecycle_lock(agent);
        let held = lifecycle.lock().await;
        let mut stopping = std::pin::pin!(kernel.stop_agent(agent));
        // Poll stop into the fair lifecycle queue before native open resumes.
        tokio::select! {
            biased;
            result = &mut stopping => panic!("stop crossed a held lifecycle lock: {result:?}"),
            () = tokio::task::yield_now() => {},
        }
        release.store(true, Ordering::Release);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while kernel
                .cgroups
                .get(kernel.cgroups.root())
                .unwrap()
                .usage
                .active_tool_calls
                != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("native open completed and released tool admission");
        assert!(!opening.is_finished(), "publication waits behind stop");
        drop(held);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(3), stopping)
                .await
                .unwrap()
                .unwrap(),
            crate::AgentState::Stopped
        );
        assert!(matches!(
            opening.await.unwrap(),
            Err(WorkspaceError::Vfs(super::super::VfsError::NotFound))
        ));
        assert!(!config.workspace_dir.exists());
    }

    #[tokio::test]
    async fn canceled_workspace_write_keeps_original_bytes_and_worker_ownership() {
        use base64::Engine;
        let (root, kernel, agent, handle) = setup().await;
        let (entered, release, canceled) = kernel.sandbox_manager.pause_next_filesystem_for_test();
        let worker = tokio::spawn({
            let kernel = kernel.clone();
            let id = handle.id.clone();
            async move {
                kernel
                    .vfs_write_workspace(
                        agent,
                        &id,
                        base64::engine::general_purpose::STANDARD.encode(b"never commit"),
                    )
                    .await
            }
        });
        observed(&entered).await;
        worker.abort();
        let _ = worker.await;
        observed(&canceled).await;
        assert!(!release.load(Ordering::Acquire));
        assert_eq!(
            std::fs::read(root.path().join("file.bin")).unwrap(),
            b"original"
        );
        release.store(true, Ordering::Release);
        let chunk = kernel
            .vfs_read_workspace(agent, &handle.id, 0, 64)
            .await
            .unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(chunk.data_base64)
                .unwrap(),
            b"original"
        );
    }

    #[tokio::test]
    async fn canceled_workspace_open_reclaims_its_reserved_handle_slot() {
        let (_root, kernel, agent, _handle) = setup().await;
        let before = kernel.vfs_workspace_mounts(agent).unwrap().open_handles;
        let (entered, release, canceled) = kernel.sandbox_manager.pause_next_filesystem_for_test();
        let worker = tokio::spawn({
            let kernel = kernel.clone();
            async move {
                kernel
                    .vfs_open_workspace(
                        agent,
                        WorkspaceOpenRequest {
                            path: "/workspace/file.bin".into(),
                            kind: WorkspaceKind::File,
                            rights: vec![WorkspaceRight::Read],
                            allow_missing: false,
                        },
                    )
                    .await
            }
        });
        observed(&entered).await;
        assert_eq!(
            kernel.vfs_workspace_mounts(agent).unwrap().open_handles,
            before + 1
        );
        worker.abort();
        let _ = worker.await;
        observed(&canceled).await;
        assert_eq!(
            kernel.vfs_workspace_mounts(agent).unwrap().open_handles,
            before
        );
        release.store(true, Ordering::Release);
    }

    #[tokio::test]
    async fn broker_rejects_changed_or_absent_opaque_workspace_context() {
        use crate::resources::ResourceBroker;
        let (_root, kernel, agent, handle) = setup().await;
        let scope = kernel
            .tool_vfs
            .acquire(agent, &handle.id)
            .unwrap()
            .workspace()
            .unwrap();
        let context = WorkspaceRequest::Use { capability: scope };
        let mut parameters = context.parameters();
        parameters["max_bytes"] = json!(64);
        let (prepared, _guard) = kernel
            .tool_registry
            .authorize_and_acquire_call(&kernel.syscall_gate, agent, "read_file_bytes", &parameters)
            .await
            .unwrap();
        let changed = WorkspaceRequest::Use {
            capability: match &context {
                WorkspaceRequest::Use { capability } => capability
                    .attenuate(Uuid::new_v4(), &[WorkspaceRight::Read])
                    .unwrap(),
                _ => unreachable!(),
            },
        };
        assert!(kernel
            .resource_broker
            .execute_workspace(prepared.request, changed)
            .await
            .is_err());
        let (prepared, _guard2) = kernel
            .tool_registry
            .authorize_and_acquire_call(&kernel.syscall_gate, agent, "read_file_bytes", &parameters)
            .await
            .unwrap();
        assert!(kernel
            .resource_broker
            .execute(prepared.request)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn public_wire_kill_revokes_a_paused_workspace_write_before_commit() {
        use crate::syscall_server::{Syscall, SyscallClient, SyscallReply, SyscallServer};
        use base64::Engine;
        let (root, kernel, agent, handle) = setup().await;
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let server = tokio::spawn(server.serve());
        let mut writer = SyscallClient::connect(addr).await.unwrap();
        let mut killer = SyscallClient::connect(addr).await.unwrap();
        let (entered, release, _) = kernel.sandbox_manager.pause_next_filesystem_for_test();
        writer
            .send(&Syscall::VfsWriteWorkspace {
                agent_id: agent.to_string(),
                handle: handle.id,
                data_base64: base64::engine::general_purpose::STANDARD.encode(b"never commit"),
            })
            .await
            .unwrap();
        observed(&entered).await;
        let killed = killer
            .call(Syscall::KillAgent {
                agent_id: agent.to_string(),
            })
            .await
            .unwrap();
        assert!(matches!(killed, SyscallReply::AgentStatus { .. }));
        release.store(true, Ordering::Release);
        assert!(matches!(
            writer.read_reply().await.unwrap(),
            SyscallReply::TypedError { .. } | SyscallReply::Error { .. }
        ));
        assert_eq!(
            std::fs::read(root.path().join("file.bin")).unwrap(),
            b"original"
        );
        server.abort();
        let _ = server.await;
    }
}
