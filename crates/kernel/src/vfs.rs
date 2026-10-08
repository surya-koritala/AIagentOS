//! Agent-owned, ephemeral handles to the live governed tool mount.
//!
//! Handles identify one registration, never grant authorization, and are not
//! inherited, persisted, or reopened after a kernel restart.

pub mod workspace;

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
    pub is_workspace: bool,
    workspace: Mutex<Option<workspace::WorkspaceCapability>>,
    workspace_bindings: Mutex<HashMap<String, Uuid>>,
}

impl ToolHandleLease {
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
    pub(crate) fn workspace(&self) -> Result<workspace::WorkspaceCapability, VfsError> {
        if self.is_closed() || !self.is_workspace {
            return Err(VfsError::NotFound);
        }
        self.workspace
            .lock()
            .map_err(|_| VfsError::Unavailable)?
            .clone()
            .ok_or(VfsError::NotFound)
    }
    pub(crate) fn workspace_binding(&self, name: &str) -> Result<Uuid, VfsError> {
        self.workspace_bindings
            .lock()
            .map_err(|_| VfsError::Unavailable)?
            .get(name)
            .copied()
            .ok_or(VfsError::NotFound)
    }
}

struct WorkspaceReservation<'a> {
    table: &'a ToolVfs,
    agent: AgentId,
    id: Uuid,
    lease: Arc<ToolHandleLease>,
    committed: bool,
}

impl WorkspaceReservation<'_> {
    fn publish(
        mut self,
        scope: workspace::WorkspaceCapability,
        bindings: HashMap<String, Uuid>,
    ) -> Result<workspace::WorkspaceHandle, VfsError> {
        let handles = self
            .table
            .handles
            .lock()
            .map_err(|_| VfsError::Unavailable)?;
        if scope.owner() != self.agent
            || scope.identity() != self.id
            || self.lease.is_closed()
            || !handles
                .get(&self.agent)
                .and_then(|owned| owned.get(&self.id))
                .is_some_and(|stored| Arc::ptr_eq(stored, &self.lease))
        {
            return Err(VfsError::NotFound);
        }
        let handle = scope.handle();
        *self
            .lease
            .workspace
            .lock()
            .map_err(|_| VfsError::Unavailable)? = Some(scope);
        *self
            .lease
            .workspace_bindings
            .lock()
            .map_err(|_| VfsError::Unavailable)? = bindings;
        self.committed = true;
        Ok(handle)
    }
}

impl Drop for WorkspaceReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.table.close(self.agent, &self.id.to_string());
        }
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
                is_workspace: false,
                workspace: Mutex::new(None),
                workspace_bindings: Mutex::new(HashMap::new()),
            }),
        );
        Ok(VfsHandle {
            id: id.to_string(),
            path: path.to_string(),
        })
    }

    fn reserve_workspace(&self, agent: AgentId) -> Result<WorkspaceReservation<'_>, VfsError> {
        let mut handles = self.handles.lock().map_err(|_| VfsError::Unavailable)?;
        if handles.values().map(HashMap::len).sum::<usize>() >= MAX_HANDLES_TOTAL
            || handles
                .get(&agent)
                .is_some_and(|owned| owned.len() >= MAX_HANDLES_PER_AGENT)
        {
            return Err(VfsError::Capacity);
        }
        let id = Uuid::new_v4();
        let lease = Arc::new(ToolHandleLease {
            name: String::new(),
            binding_id: Uuid::nil(),
            closed: AtomicBool::new(false),
            is_workspace: true,
            workspace: Mutex::new(None),
            workspace_bindings: Mutex::new(HashMap::new()),
        });
        handles.entry(agent).or_default().insert(id, lease.clone());
        Ok(WorkspaceReservation {
            table: self,
            agent,
            id,
            lease,
            committed: false,
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
    pub fn vfs_workspace_mounts(&self, agent: AgentId) -> Result<VfsMountView, VfsError> {
        use crate::sandbox::SandboxManager;
        if self.syscall_gate.pid_of(agent).is_none()
            || self.sandbox_manager.get_sandbox_for_agent(agent).is_none()
        {
            return Err(VfsError::NotFound);
        }
        Ok(VfsMountView {
            mount: "/workspace".into(),
            entries: vec!["/workspace".into()],
            truncated: false,
            open_handles: self.tool_vfs.count(agent)?,
            handle_limit: MAX_HANDLES_PER_AGENT,
        })
    }
    pub async fn vfs_open_workspace(
        &self,
        agent: AgentId,
        request: workspace::WorkspaceOpenRequest,
    ) -> Result<workspace::WorkspaceHandle, workspace::WorkspaceError> {
        self.open_workspace_entry(agent, request, None).await
    }

    pub async fn vfs_open_at(
        &self,
        agent: AgentId,
        parent: &str,
        request: workspace::WorkspaceOpenRequest,
    ) -> Result<workspace::WorkspaceHandle, workspace::WorkspaceError> {
        let lease = self.tool_vfs.acquire(agent, parent)?;
        let scope = lease.workspace()?;
        self.open_workspace_entry(agent, request, Some((lease, scope)))
            .await
    }

    async fn open_workspace_entry(
        &self,
        agent: AgentId,
        request: workspace::WorkspaceOpenRequest,
        parent: Option<(Arc<ToolHandleLease>, workspace::WorkspaceCapability)>,
    ) -> Result<workspace::WorkspaceHandle, workspace::WorkspaceError> {
        use crate::sandbox::SandboxManager;
        use workspace::{WorkspaceError, WorkspaceOpenOptions, WorkspaceRequest, WorkspaceRight};
        let rights = workspace::validated_rights(&request.rights, request.kind)
            .map_err(|error| WorkspaceError::Invalid(error.to_string()))?;
        let relative = if parent.is_some() {
            workspace::canonical_relative(&request.path, false)
        } else {
            workspace::workspace_path(&request.path)
        }
        .map_err(|error| WorkspaceError::Invalid(error.to_string()))?;
        let lock = self.lifecycle_lock(agent);
        let (reservation, sandbox) = {
            let _lifecycle = lock.lock().await;
            if self.syscall_gate.pid_of(agent).is_none() {
                return Err(VfsError::NotFound.into());
            }
            let sandbox = self
                .sandbox_manager
                .get_sandbox_for_agent(agent)
                .ok_or(VfsError::NotFound)?;
            (self.tool_vfs.reserve_workspace(agent)?, sandbox)
        };
        let context = WorkspaceRequest::open(WorkspaceOpenOptions {
            identity: reservation.id,
            owner: agent,
            sandbox,
            relative,
            parent: parent.as_ref().map(|(_, scope)| scope.clone()),
            kind: request.kind,
            rights: request.rights,
            allow_missing: request.allow_missing,
        })
        .map_err(|_| WorkspaceError::PermissionDenied)?;
        let open_right = if rights.len() == 1 && rights.contains(&WorkspaceRight::Write) {
            WorkspaceRight::Write
        } else if rights.len() == 1 && rights.contains(&WorkspaceRight::List) {
            WorkspaceRight::List
        } else {
            WorkspaceRight::Stat
        };
        let (name, operation) = workspace::operation_for_right(open_right);
        let mut bindings = HashMap::new();
        for right in rights.iter().copied().chain(std::iter::once(open_right)) {
            let (name, operation) = workspace::operation_for_right(right);
            let identity = self
                .tool_registry
                .workspace_binding_id(&self.syscall_gate, agent, name, operation)
                .ok_or(VfsError::NotFound)?;
            bindings.insert(name.to_string(), identity);
        }
        let mut parameters = context.parameters();
        if open_right == WorkspaceRight::Write {
            parameters["data_base64"] = serde_json::json!("");
        }
        let (prepared, guard) = self
            .tool_registry
            .authorize_and_acquire_bound_call(
                &self.syscall_gate,
                agent,
                name,
                &parameters,
                bindings.get(name).copied(),
            )
            .await
            .map_err(WorkspaceError::Tool)?;
        if reservation.lease.is_closed()
            || parent.as_ref().is_some_and(|(lease, _)| lease.is_closed())
        {
            return Err(VfsError::NotFound.into());
        }
        let result = self
            .resource_broker
            .execute_workspace(prepared.request, context)
            .await;
        drop(guard);
        let result = result.map_err(|error| WorkspaceError::Backing(error.to_string()))?;
        if !result.response.success {
            return Err(WorkspaceError::Backing(
                result.response.error.unwrap_or_default(),
            ));
        }
        let scope = result.opened.ok_or_else(|| {
            WorkspaceError::Backing("workspace open returned no capability".into())
        })?;
        let _lifecycle = lock.lock().await;
        if self.syscall_gate.pid_of(agent).is_none()
            || self.sandbox_manager.get_sandbox_for_agent(agent) != Some(sandbox)
            || parent.as_ref().is_some_and(|(lease, _)| lease.is_closed())
        {
            return Err(VfsError::NotFound.into());
        }
        if self
            .tool_registry
            .workspace_binding_id(&self.syscall_gate, agent, name, operation)
            != bindings.get(name).copied()
        {
            return Err(VfsError::NotFound.into());
        }
        reservation
            .publish(scope, bindings)
            .map_err(WorkspaceError::Vfs)
    }

    pub async fn vfs_dup_workspace(
        &self,
        agent: AgentId,
        handle: &str,
        rights: Vec<workspace::WorkspaceRight>,
    ) -> Result<workspace::WorkspaceHandle, workspace::WorkspaceError> {
        use crate::sandbox::SandboxManager;
        let lock = self.lifecycle_lock(agent);
        let _lifecycle = lock.lock().await;
        let lease = self.tool_vfs.acquire(agent, handle)?;
        let original = lease.workspace()?;
        if self.syscall_gate.pid_of(agent).is_none()
            || self.sandbox_manager.get_sandbox_for_agent(agent) != Some(original.sandbox())
        {
            return Err(VfsError::NotFound.into());
        }
        let reservation = self.tool_vfs.reserve_workspace(agent)?;
        let scope = original
            .attenuate(reservation.id, &rights)
            .map_err(|_| workspace::WorkspaceError::PermissionDenied)?;
        let bindings = lease
            .workspace_bindings
            .lock()
            .map_err(|_| VfsError::Unavailable)?
            .clone();
        if lease.is_closed() {
            return Err(VfsError::NotFound.into());
        }
        reservation
            .publish(scope, bindings)
            .map_err(workspace::WorkspaceError::Vfs)
    }

    async fn workspace_call(
        &self,
        agent: AgentId,
        handle: &str,
        right: workspace::WorkspaceRight,
        extra: serde_json::Value,
    ) -> Result<serde_json::Value, workspace::WorkspaceError> {
        use crate::sandbox::SandboxManager;
        use workspace::{WorkspaceError, WorkspaceRequest};
        let lease = self.tool_vfs.acquire(agent, handle)?;
        let scope = lease.workspace()?;
        scope
            .require(right)
            .map_err(|_| WorkspaceError::PermissionDenied)?;
        if self.sandbox_manager.get_sandbox_for_agent(agent) != Some(scope.sandbox()) {
            return Err(VfsError::NotFound.into());
        }
        let (name, operation) = workspace::operation_for_right(right);
        let identity = lease.workspace_binding(name)?;
        if self
            .tool_registry
            .workspace_binding_id(&self.syscall_gate, agent, name, operation)
            != Some(identity)
        {
            return Err(VfsError::NotFound.into());
        }
        let context = WorkspaceRequest::Use { capability: scope };
        let mut parameters = context.parameters();
        let parameters_object = parameters
            .as_object_mut()
            .expect("workspace parameters are an object");
        if let Some(extra) = extra.as_object() {
            parameters_object.extend(
                extra
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
        let (prepared, _guard) = self
            .tool_registry
            .authorize_and_acquire_bound_call(
                &self.syscall_gate,
                agent,
                name,
                &parameters,
                Some(identity),
            )
            .await
            .map_err(WorkspaceError::Tool)?;
        if lease.is_closed()
            || self
                .tool_registry
                .workspace_binding_id(&self.syscall_gate, agent, name, operation)
                != Some(identity)
        {
            return Err(VfsError::NotFound.into());
        }
        let result = self
            .resource_broker
            .execute_workspace(prepared.request, context)
            .await
            .map_err(|error| WorkspaceError::Backing(error.to_string()))?;
        if result.response.success {
            Ok(result.response.data)
        } else {
            Err(WorkspaceError::Backing(
                result.response.error.unwrap_or_default(),
            ))
        }
    }

    pub async fn vfs_read_workspace(
        &self,
        agent: AgentId,
        handle: &str,
        offset: u64,
        max_bytes: u32,
    ) -> Result<workspace::WorkspaceRead, workspace::WorkspaceError> {
        if max_bytes == 0 || max_bytes as usize > workspace::MAX_WORKSPACE_TRANSFER_BYTES {
            return Err(workspace::WorkspaceError::Invalid(
                "read limit out of range".into(),
            ));
        }
        let data = self
            .workspace_call(
                agent,
                handle,
                workspace::WorkspaceRight::Read,
                serde_json::json!({"offset":offset,"max_bytes":max_bytes}),
            )
            .await?;
        serde_json::from_value(data)
            .map_err(|_| workspace::WorkspaceError::Backing("invalid read response".into()))
    }

    pub async fn vfs_write_workspace(
        &self,
        agent: AgentId,
        handle: &str,
        data_base64: String,
    ) -> Result<u64, workspace::WorkspaceError> {
        let data = self
            .workspace_call(
                agent,
                handle,
                workspace::WorkspaceRight::Write,
                serde_json::json!({"data_base64":data_base64}),
            )
            .await?;
        data.get("written_bytes")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| workspace::WorkspaceError::Backing("invalid write response".into()))
    }

    pub async fn vfs_list_workspace(
        &self,
        agent: AgentId,
        handle: &str,
    ) -> Result<serde_json::Value, workspace::WorkspaceError> {
        self.workspace_call(
            agent,
            handle,
            workspace::WorkspaceRight::List,
            serde_json::json!({}),
        )
        .await
    }

    pub async fn vfs_stat_workspace(
        &self,
        agent: AgentId,
        handle: &str,
    ) -> Result<workspace::WorkspaceStat, workspace::WorkspaceError> {
        let data = self
            .workspace_call(
                agent,
                handle,
                workspace::WorkspaceRight::Stat,
                serde_json::json!({}),
            )
            .await?;
        serde_json::from_value(data)
            .map_err(|_| workspace::WorkspaceError::Backing("invalid metadata response".into()))
    }

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
