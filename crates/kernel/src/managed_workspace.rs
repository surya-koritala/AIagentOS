//! Private control-plane ownership for one leased datastore namespace.

#[cfg(not(windows))]
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AgentId, SandboxError};

const VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024;
const MAX_CONTROL_ENTRIES: usize = 4096;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoreOwner {
    version: u32,
    store: Uuid,
    database: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceOwner {
    version: u32,
    store: Uuid,
    agent: AgentId,
    workspace: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyResolution {
    version: u32,
    store: Uuid,
    agent: AgentId,
    path: PathBuf,
}

pub(crate) struct ManagedWorkspaceNamespace {
    root: PathBuf,
    control: PathBuf,
    data: PathBuf,
    store: Uuid,
    _lease: NamespaceLease,
}

struct NamespaceLease(std::fs::File);
impl Drop for NamespaceLease {
    fn drop(&mut self) {
        // Close-on-exec alone does not release a shared Unix file description
        // inherited by a concurrent fork before exec completes.
        let _ = self.0.unlock();
    }
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn sandbox(error: impl ToString) -> SandboxError {
    SandboxError::BoundaryViolation(error.to_string())
}
fn no_symlink_ancestors(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        if std::fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            return Err(denied("workspace ownership rejects symlink ancestors"));
        }
    }
    Ok(())
}

fn private_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        match crate::windows_private_fs::create_directory(path) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                crate::windows_private_fs::verify_path(path, true)?;
            }
            Err(error) => return Err(error),
        }
        crate::windows_private_fs::verify_path(path, true)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => return Err(error),
        }
        check_private_directory(path)
    }
    #[cfg(not(any(unix, windows)))]
    { let _ = path; Err(denied("private workspace namespaces are unsupported")) }
}

fn check_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)] { crate::windows_private_fs::verify_path(path, true) }
    #[cfg(unix)] {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        no_symlink_ancestors(path)?;
        let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(denied("workspace control directory must be current-owner-only"));
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))] { let _ = path; Err(denied("workspace ownership verification is unsupported")) }
}

fn read_private(path: &Path) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    let file = crate::windows_private_fs::open_read(path, true)?;
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        no_symlink_ancestors(path.parent().ok_or_else(|| denied("ownership manifest has no parent"))?)?;
        let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(denied("ownership manifest must be current-owner-only"));
        }
        file
    };
    #[cfg(not(any(unix, windows)))]
    let file: File = { let _ = path; return Err(denied("ownership manifests are unsupported")); };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(denied("ownership manifest must be a bounded regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES { return Err(denied("ownership manifest exceeds its bound")); }
    Ok(bytes)
}

impl ManagedWorkspaceNamespace {
    pub(crate) fn new(database: Option<(&Path, Uuid)>) -> Result<Self, SandboxError> {
        let (base, store, binding) = match database {
            Some((database, store)) => {
                let database = std::fs::canonicalize(database).map_err(sandbox)?;
                let base = database.parent().ok_or_else(|| sandbox("managed datastore has no parent"))?.to_path_buf();
                let binding = ring::digest::digest(&ring::digest::SHA256, database.as_os_str().as_encoded_bytes());
                let binding = binding.as_ref().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
                (base, store, Some(binding))
            }
            None => (std::fs::canonicalize(std::env::temp_dir()).map_err(sandbox)?, Uuid::new_v4(), None),
        };
        let prefix = base.join(".aiagentos-workspace-stores");
        private_directory(&prefix).map_err(sandbox)?;
        let name = match &binding { Some(binding) => format!("{store}-{binding}"), None => format!("instance-{store}") };
        let root = prefix.join(name);
        private_directory(&root).map_err(sandbox)?;
        let control = root.join("control");
        let data = root.join("data");
        private_directory(&control).map_err(sandbox)?;
        private_directory(&data).map_err(sandbox)?;
        let lease_path = control.join("namespace.lock");
        #[cfg(windows)]
        let lease = crate::windows_private_fs::open_private_rw(&lease_path).map_err(sandbox)?;
        #[cfg(unix)]
        let lease = {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let lease = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&lease_path).map_err(sandbox)?;
            let metadata = lease.metadata().map_err(sandbox)?;
            if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(sandbox("workspace namespace lease is not a current-owner-only regular file"));
            }
            lease
        };
        #[cfg(not(any(unix, windows)))]
        let lease: std::fs::File = return Err(sandbox("workspace namespace leases are unsupported"));
        lease.try_lock().map_err(|_| sandbox("workspace namespace is already owned by another runtime"))?;
        let expected = StoreOwner { version: VERSION, store, database: binding };
        let manifest = control.join("store.json");
        match read_private(&manifest) {
            Ok(bytes) => {
                let owner: StoreOwner = serde_json::from_slice(&bytes).map_err(sandbox)?;
                if owner != expected { return Err(sandbox("workspace namespace owner does not match the leased datastore")); }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                crate::config::write_owner_only_atomic(&manifest, &serde_json::to_vec(&expected).map_err(sandbox)?).map_err(sandbox)?;
            }
            Err(error) => return Err(sandbox(error)),
        }
        Ok(Self { root, control, data, store, _lease: NamespaceLease(lease) })
    }

    pub(crate) fn data(&self) -> &Path { &self.data }

    pub(crate) fn reconcile(&self, active: &std::collections::HashSet<PathBuf>, protected_agents: &std::collections::HashSet<AgentId>) -> Result<usize, SandboxError> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&self.control).map_err(sandbox)? {
            if entries.len() == MAX_CONTROL_ENTRIES { return Err(sandbox("workspace ownership reconciliation exceeds its bounded control inventory")); }
            entries.push(entry.map_err(sandbox)?);
        }
        // Collect before deleting: close the native enumeration reference and
        // fail before any mutation if the control inventory exceeds its bound.
        let mut removed = 0;
        for entry in entries {
            let name = entry.file_name();
            let Some(stem) = Path::new(&name).file_stem().and_then(|stem| stem.to_str()) else { continue; };
            if Path::new(&name).extension().and_then(|extension| extension.to_str()) != Some("json") { continue; }
            let Ok(workspace) = Uuid::parse_str(stem) else { continue; };
            let path = self.data.join(workspace.to_string());
            if active.contains(&path) || self.verify(&path, None).is_err() { continue; }
            let owner: WorkspaceOwner = serde_json::from_slice(&read_private(&self.owner_path(workspace)).map_err(sandbox)?).map_err(sandbox)?;
            if protected_agents.contains(&owner.agent) { continue; }
            // A verified control-only orphan is safe to retire, including a
            // crash after manifest publication but before directory creation.
            self.retire(&path, None)?;
            removed += 1;
        }
        Ok(removed)
    }

    fn workspace_id(&self, path: &Path) -> Result<Uuid, SandboxError> {
        if path.parent() != Some(self.data.as_path()) { return Err(sandbox("workspace belongs to another datastore namespace; explicit ownership resolution is required")); }
        let leaf = path.file_name().and_then(|leaf| leaf.to_str()).ok_or_else(|| sandbox("workspace leaf is invalid"))?;
        Uuid::parse_str(leaf).map_err(sandbox)
    }
    fn owner_path(&self, workspace: Uuid) -> PathBuf { self.control.join(format!("{workspace}.json")) }

    pub(crate) fn verify(&self, path: &Path, agent: Option<AgentId>) -> Result<Uuid, SandboxError> {
        check_private_directory(&self.root).map_err(sandbox)?;
        check_private_directory(&self.control).map_err(sandbox)?;
        check_private_directory(&self.data).map_err(sandbox)?;
        let workspace = self.workspace_id(path)?;
        let owner: WorkspaceOwner = serde_json::from_slice(&read_private(&self.owner_path(workspace)).map_err(sandbox)?).map_err(sandbox)?;
        if owner.version != VERSION || owner.store != self.store || owner.workspace != workspace || agent.is_some_and(|agent| owner.agent != agent) {
            return Err(sandbox("workspace control manifest does not attest this store, agent and workspace"));
        }
        Ok(workspace)
    }

    pub(crate) fn publish(&self, path: &Path, agent: AgentId) -> Result<(), SandboxError> {
        let workspace = self.workspace_id(path)?;
        let owner_path = self.owner_path(workspace);
        match read_private(&owner_path) {
            Ok(_) => { self.verify(path, Some(agent))?; }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let owner = WorkspaceOwner { version: VERSION, store: self.store, agent, workspace };
                crate::config::write_owner_only_atomic(&owner_path, &serde_json::to_vec(&owner).map_err(sandbox)?).map_err(sandbox)?;
                allocation_cutpoint("manifest_published");
            }
            Err(error) => return Err(sandbox(error)),
        }
        Ok(())
    }

    pub(crate) fn retire(&self, path: &Path, agent: Option<AgentId>) -> Result<(), SandboxError> {
        let workspace = self.verify(path, agent)?;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                #[cfg(windows)] crate::windows_private_fs::check_directory(path).map_err(sandbox)?;
                no_symlink_ancestors(path).map_err(sandbox)?;
                if std::fs::canonicalize(path).map_err(sandbox)?.parent() != Some(self.data.as_path()) { return Err(sandbox("workspace directory escaped its attested namespace")); }
                std::fs::remove_dir_all(path).map_err(sandbox)?;
            }
            Ok(_) => return Err(sandbox("owned workspace is not a regular directory")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(sandbox(error)),
        }
        std::fs::remove_file(self.owner_path(workspace)).map_err(sandbox)?;
        #[cfg(windows)] crate::windows_private_fs::sync_directory(&self.control).map_err(sandbox)?;
        #[cfg(unix)] File::open(&self.control).and_then(|directory| directory.sync_all()).map_err(sandbox)?;
        Ok(())
    }

    /// Trusted local resolution preserves an unverified legacy path as an
    /// operator workspace. It never grants automatic deletion ownership.
    pub(crate) fn retain_legacy(&self, path: &Path, agent: AgentId) -> Result<(), SandboxError> {
        #[cfg(windows)] crate::windows_private_fs::check_directory(path).map_err(sandbox)?;
        no_symlink_ancestors(path).map_err(sandbox)?;
        let path = std::fs::canonicalize(path).map_err(sandbox)?;
        let value = LegacyResolution { version: VERSION, store: self.store, agent, path };
        crate::config::write_owner_only_atomic(&self.control.join(format!("legacy-{agent}.json")), &serde_json::to_vec(&value).map_err(sandbox)?).map_err(sandbox)
    }

    pub(crate) fn legacy_retained(&self, path: &Path, agent: AgentId) -> Result<bool, SandboxError> {
        let bytes = match read_private(&self.control.join(format!("legacy-{agent}.json"))) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(sandbox(error)),
        };
        let resolution: LegacyResolution = serde_json::from_slice(&bytes).map_err(sandbox)?;
        if resolution.version != VERSION || resolution.store != self.store || resolution.agent != agent || resolution.path != std::fs::canonicalize(path).map_err(sandbox)? {
            return Err(sandbox("legacy workspace resolution does not match the current store record"));
        }
        Ok(true)
    }
}

pub(crate) fn allocation_cutpoint(_step: &str) {
    #[cfg(any(test, feature = "qualification"))]
    if std::env::var("AIAGENTOS_TEST_WORKSPACE_ALLOCATION_EXIT").ok().as_deref() == Some(_step) {
        std::process::exit(89);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> (ManagedWorkspaceNamespace, PathBuf, AgentId) {
        let namespace = ManagedWorkspaceNamespace::new(None).unwrap();
        let path = namespace.data().join(Uuid::new_v4().to_string());
        let agent = Uuid::new_v4();
        namespace.publish(&path, agent).unwrap();
        std::fs::create_dir(&path).unwrap();
        (namespace, path, agent)
    }
    #[cfg(unix)]
    fn directory_link(source: &Path, destination: &Path) { std::os::unix::fs::symlink(source, destination).unwrap(); }
    #[cfg(windows)]
    fn directory_link(source: &Path, destination: &Path) { std::os::windows::fs::symlink_dir(source, destination).unwrap(); }
    #[cfg(unix)]
    fn file_link(source: &Path, destination: &Path) { std::os::unix::fs::symlink(source, destination).unwrap(); }
    #[cfg(windows)]
    fn file_link(source: &Path, destination: &Path) { std::os::windows::fs::symlink_file(source, destination).unwrap(); }

    #[test]
    fn control_manifests_and_control_directory_never_follow_reparse_or_symlink_replacements() {
        let (namespace, path, agent) = owner();
        let workspace = Uuid::parse_str(path.file_name().unwrap().to_str().unwrap()).unwrap();
        let manifest = namespace.owner_path(workspace);
        let outside = tempfile::tempdir().unwrap();
        let copied = outside.path().join("copied.json");
        crate::config::write_owner_only_atomic(&copied, &std::fs::read(&manifest).unwrap()).unwrap();
        std::fs::remove_file(&manifest).unwrap();
        file_link(&copied, &manifest);
        assert!(namespace.verify(&path, Some(agent)).is_err());
        assert!(namespace.retire(&path, Some(agent)).is_err());
        assert!(path.exists(), "unverified reparse ownership triggered data deletion");
        std::fs::remove_file(&manifest).unwrap();
        namespace.publish(&path, agent).unwrap();
        let moved = namespace.root.join("preserved-control");
        std::fs::rename(&namespace.control, &moved).unwrap();
        directory_link(&moved, &namespace.control);
        assert!(namespace.verify(&path, Some(agent)).is_err());
        assert!(namespace.retire(&path, Some(agent)).is_err());
        assert!(path.exists());
        #[cfg(windows)] std::fs::remove_dir(&namespace.control).unwrap();
        #[cfg(unix)] std::fs::remove_file(&namespace.control).unwrap();
        std::fs::rename(moved, &namespace.control).unwrap();
        namespace.retire(&path, Some(agent)).unwrap();
        let root = namespace.root.clone();
        drop(namespace);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_store_or_agent_manifest_never_authorizes_cleanup() {
        let (namespace, path, agent) = owner();
        let workspace = namespace.workspace_id(&path).unwrap();
        std::fs::write(path.join("sentinel"), "owned data").unwrap();
        let manifest = namespace.owner_path(workspace);
        let original = std::fs::read(&manifest).unwrap();
        let foreign = WorkspaceOwner { version:VERSION,store:Uuid::new_v4(),agent,workspace };
        crate::config::write_owner_only_atomic(&manifest, &serde_json::to_vec(&foreign).unwrap()).unwrap();
        assert!(namespace.retire(&path, Some(agent)).is_err());
        assert_eq!(std::fs::read_to_string(path.join("sentinel")).unwrap(), "owned data");
        crate::config::write_owner_only_atomic(&manifest, &original).unwrap();
        assert!(namespace.retire(&path, Some(Uuid::new_v4())).is_err());
        namespace.retire(&path, Some(agent)).unwrap();
        let root = namespace.root.clone();
        drop(namespace);
        std::fs::remove_dir_all(root).unwrap();
    }
}
