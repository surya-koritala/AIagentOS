//! Agent-owned, ephemeral handles to the live governed tool mount.
//!
//! Handles identify one registration, never grant authorization, and are not
//! inherited, persisted, or reopened after a kernel restart.

use crate::{AgentId, AgentKernelImpl};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use uuid::Uuid;

pub const MAX_HANDLES_PER_AGENT: usize = 64;
pub const MAX_HANDLES_TOTAL: usize = 4096;
pub const MAX_MOUNT_ENTRIES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VfsHandle {
    pub id: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VfsMountView {
    pub mount: String,
    pub entries: Vec<String>,
    pub truncated: bool,
    pub open_handles: usize,
    pub handle_limit: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum VfsError {
    #[error("invalid VFS path; expected canonical /tools/<name>")]
    InvalidPath,
    #[error("VFS object not found")]
    NotFound,
    #[error("VFS handle capacity exhausted")]
    Capacity,
    #[error("VFS unavailable")]
    Unavailable,
}

pub(crate) struct ToolHandleLease {
    pub name: String,
    pub binding_id: Uuid,
    closed: AtomicBool,
}

impl ToolHandleLease {
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
pub struct ToolVfs {
    handles: Mutex<HashMap<AgentId, HashMap<Uuid, Arc<ToolHandleLease>>>>,
}

pub fn tool_name(path: &str) -> Result<&str, VfsError> {
    let name = path.strip_prefix("/tools/").ok_or(VfsError::InvalidPath)?;
    if name.is_empty()
        || name.len() > 128
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
    {
        return Err(VfsError::InvalidPath);
    }
    Ok(name)
}

impl ToolVfs {
    fn open(&self, agent: AgentId, path: &str, binding_id: Uuid) -> Result<VfsHandle, VfsError> {
        let name = tool_name(path)?.to_string();
        let mut handles = self.handles.lock().map_err(|_| VfsError::Unavailable)?;
        if handles.values().map(HashMap::len).sum::<usize>() >= MAX_HANDLES_TOTAL
            || handles
                .get(&agent)
                .is_some_and(|owned| owned.len() >= MAX_HANDLES_PER_AGENT)
        {
            return Err(VfsError::Capacity);
        }
        let id = Uuid::new_v4();
        handles.entry(agent).or_default().insert(
            id,
            Arc::new(ToolHandleLease {
                name,
                binding_id,
                closed: AtomicBool::new(false),
            }),
        );
        Ok(VfsHandle {
            id: id.to_string(),
            path: path.to_string(),
        })
    }

    pub(crate) fn acquire(
        &self,
        agent: AgentId,
        handle: &str,
    ) -> Result<Arc<ToolHandleLease>, VfsError> {
        let id = Uuid::parse_str(handle).map_err(|_| VfsError::NotFound)?;
        let handles = self.handles.lock().map_err(|_| VfsError::Unavailable)?;
        handles
            .get(&agent)
            .and_then(|owned| owned.get(&id))
            .cloned()
            .ok_or(VfsError::NotFound)
    }

    pub fn close(&self, agent: AgentId, handle: &str) -> Result<(), VfsError> {
        let id = Uuid::parse_str(handle).map_err(|_| VfsError::NotFound)?;
        let mut handles = self.handles.lock().map_err(|_| VfsError::Unavailable)?;
        let owned = handles.get_mut(&agent).ok_or(VfsError::NotFound)?;
        let lease = owned.remove(&id).ok_or(VfsError::NotFound)?;
        lease.closed.store(true, Ordering::SeqCst);
        if owned.is_empty() {
            handles.remove(&agent);
        }
        Ok(())
    }

    pub(crate) fn revoke_agent(&self, agent: AgentId) {
        // A poisoned table cannot retain usable handles after lifecycle cleanup.
        let mut handles = self
            .handles
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(owned) = handles.remove(&agent) {
            for lease in owned.into_values() {
                lease.closed.store(true, Ordering::SeqCst);
            }
        }
    }

    fn count(&self, agent: AgentId) -> Result<usize, VfsError> {
        let handles = self.handles.lock().map_err(|_| VfsError::Unavailable)?;
        Ok(handles.get(&agent).map_or(0, HashMap::len))
    }
}

impl AgentKernelImpl {
    pub async fn vfs_open(&self, agent: AgentId, path: &str) -> Result<VfsHandle, VfsError> {
        let name = tool_name(path)?;
        let lock = self.lifecycle_lock(agent);
        let _lifecycle = lock.lock().await;
        let binding_id = self
            .tool_registry
            .binding_id_for_agent(&self.syscall_gate, agent, name)
            .ok_or(VfsError::NotFound)?;
        self.tool_vfs.open(agent, path, binding_id)
    }

    pub fn vfs_mounts(&self, agent: AgentId) -> Result<VfsMountView, VfsError> {
        if self.syscall_gate.pid_of(agent).is_none() {
            return Err(VfsError::NotFound);
        }
        let mut entries = self
            .tool_registry
            .definitions_for_agent(&self.syscall_gate, agent)
            .into_iter()
            .map(|tool| format!("/tools/{}", tool.name))
            .filter(|path| tool_name(path).is_ok())
            .collect::<Vec<_>>();
        entries.sort();
        let truncated = entries.len() > MAX_MOUNT_ENTRIES;
        entries.truncate(MAX_MOUNT_ENTRIES);
        Ok(VfsMountView {
            mount: "/tools".into(),
            entries,
            truncated,
            open_handles: self.tool_vfs.count(agent)?,
            handle_limit: MAX_HANDLES_PER_AGENT,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn canonical_paths_round_trip(name in "[a-z][a-z0-9_.-]{0,100}") {
            let path = format!("/tools/{name}");
            prop_assert_eq!(tool_name(&path).unwrap(), name);
        }
        #[test]
        fn traversal_and_aliases_are_never_normalized(name in "[a-z]{1,30}") {
            for path in [format!("/tools/../{name}"), format!("/tools//{name}"),
                format!("/tools/{name}/"), format!("/tools/%2e%2e/{name}"), format!("tools/{name}")] {
                prop_assert!(tool_name(&path).is_err());
            }
        }
    }

    #[test]
    fn global_and_agent_capacity_reclaim_on_close_and_teardown() {
        let vfs = ToolVfs::default();
        let agent = Uuid::new_v4();
        let binding = Uuid::new_v4();
        let first = vfs.open(agent, "/tools/read_file", binding).unwrap();
        for _ in 1..MAX_HANDLES_PER_AGENT {
            vfs.open(agent, "/tools/read_file", binding).unwrap();
        }
        assert!(matches!(
            vfs.open(agent, "/tools/read_file", binding),
            Err(VfsError::Capacity)
        ));
        let lease = vfs.acquire(agent, &first.id).unwrap();
        assert!(vfs.acquire(Uuid::new_v4(), &first.id).is_err());
        vfs.close(agent, &first.id).unwrap();
        assert!(lease.is_closed());
        vfs.open(agent, "/tools/read_file", binding).unwrap();
        for _ in 1..MAX_HANDLES_TOTAL / MAX_HANDLES_PER_AGENT {
            let other = Uuid::new_v4();
            for _ in 0..MAX_HANDLES_PER_AGENT {
                vfs.open(other, "/tools/read_file", binding).unwrap();
            }
        }
        assert!(matches!(
            vfs.open(Uuid::new_v4(), "/tools/read_file", binding),
            Err(VfsError::Capacity)
        ));
        vfs.revoke_agent(agent);
        vfs.open(agent, "/tools/read_file", binding).unwrap();
    }
}
