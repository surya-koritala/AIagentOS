//! Governed persistent agent data and local IPC mounts.

use crate::context::{
    ContextManager, Fact, FactCategory, SqliteContextManager, MAX_KV_KEY_BYTES, MAX_KV_VALUE_BYTES,
};
use crate::resources::{ResourceBroker, ResourceProvider, ResourceType};
use crate::ResourceError;
use serde_json::{json, Value};
use std::sync::Arc;

pub const MAX_DATA_ENTRIES: usize = 256;
pub const MAX_FACT_BYTES: usize = 64 * 1024;
pub const MAX_MEMORY_QUERY_BYTES: usize = 4096;

pub(crate) struct MemoryResourceProvider {
    pub context: Arc<SqliteContextManager>,
}
fn failed(message: &str) -> ResourceError {
    ResourceError::OperationFailed(message.into())
}
fn text<'a>(parameters: &'a Value, name: &str, limit: usize) -> Result<&'a str, ResourceError> {
    parameters
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| value.len() <= limit)
        .ok_or_else(|| failed("invalid or oversized memory parameter"))
}
pub(crate) fn validated_key(key: &str) -> Result<(), ResourceError> {
    if key.is_empty() || key.len() > MAX_KV_KEY_BYTES || key.starts_with("context_spill:") {
        return Err(failed("invalid or reserved KV key"));
    }
    Ok(())
}
#[async_trait::async_trait]
impl ResourceProvider for MemoryResourceProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Memory
    }
    fn supported_operations(&self) -> Vec<String> {
        [
            "store",
            "query",
            "stat",
            "kv_get",
            "kv_put",
            "kv_list",
            "kv_dir_stat",
            "kv_stat",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }
    async fn execute(&self, operation: &str, parameters: &Value) -> Result<Value, ResourceError> {
        let agent = text(parameters, "agent", 36)?
            .parse::<uuid::Uuid>()
            .map_err(|_| failed("invalid memory owner"))?;
        if self
            .context
            .agent_tenant(agent)
            .map_err(|error| failed(&error.to_string()))?
            .is_none()
        {
            return Err(failed("agent not found"));
        }
        let allowed: &[&str] = match operation {
            "store" => &["agent", "content", "category"],
            "query" => &["agent", "query"],
            "kv_get" | "kv_stat" => &["agent", "key"],
            "kv_put" => &["agent", "key", "value"],
            "stat" | "kv_list" | "kv_dir_stat" => &["agent"],
            _ => return Err(failed("unsupported memory operation")),
        };
        if parameters
            .as_object()
            .is_none_or(|object| object.keys().any(|key| !allowed.contains(&key.as_str())))
        {
            return Err(failed("unexpected memory parameter"));
        }
        let key = if operation.starts_with("kv_") && !matches!(operation, "kv_list" | "kv_dir_stat")
        {
            let key = text(parameters, "key", MAX_KV_KEY_BYTES)?;
            validated_key(key)?;
            Some(key)
        } else {
            None
        };
        let storage_error = |error: crate::ContextError| failed(&error.to_string());
        match operation {
            "store" => {
                let content = text(parameters, "content", MAX_FACT_BYTES)?;
                let category = parameters
                    .get("category")
                    .map(|category| serde_json::from_value::<FactCategory>(category.clone()))
                    .transpose()
                    .map_err(|_| failed("invalid fact category"))?
                    .unwrap_or(FactCategory::Fact);
                let id = uuid::Uuid::new_v4();
                let now = chrono::Utc::now();
                self.context
                    .store_fact(
                        agent,
                        Fact {
                            id,
                            content: content.into(),
                            category,
                            created_at: now,
                            last_accessed_at: now,
                            embedding: None,
                        },
                    )
                    .await
                    .map_err(storage_error)?;
                Ok(json!({"id":id}))
            }
            "query" => {
                let query = text(parameters, "query", MAX_MEMORY_QUERY_BYTES)?;
                Ok(
                    json!({"facts":self.context.query_memory(agent, query).await.map_err(storage_error)?}),
                )
            }
            "stat" => Ok(
                json!({"facts":self.context.fact_count(agent).map_err(storage_error)?,"max_fact_bytes":MAX_FACT_BYTES}),
            ),
            "kv_get" => Ok(
                json!({"value":self.context.kv_get_bounded(agent, key.expect("validated key"), MAX_KV_VALUE_BYTES).map_err(storage_error)?}),
            ),
            "kv_put" => {
                let value = text(parameters, "value", MAX_KV_VALUE_BYTES)?;
                self.context
                    .kv_put(agent, key.expect("validated key"), value)
                    .map_err(storage_error)?;
                Ok(json!({"stored":true,"bytes":value.len()}))
            }
            "kv_stat" => match self
                .context
                .kv_stat(agent, key.expect("validated key"))
                .map_err(storage_error)?
            {
                Some((bytes, updated_at)) => {
                    Ok(json!({"exists":true,"bytes":bytes,"updated_at":updated_at}))
                }
                None => Ok(json!({"exists":false,"bytes":0,"updated_at":null})),
            },
            "kv_dir_stat" => Ok(
                json!({"keys":self.context.kv_count(agent).map_err(storage_error)?,"list_limit":MAX_DATA_ENTRIES}),
            ),
            "kv_list" => {
                let mut keys = self
                    .context
                    .kv_list_bounded(agent, MAX_DATA_ENTRIES + 1)
                    .map_err(storage_error)?;
                let truncated = keys.len() > MAX_DATA_ENTRIES;
                keys.truncate(MAX_DATA_ENTRIES);
                Ok(json!({"keys":keys,"truncated":truncated}))
            }
            _ => Err(failed("unsupported memory operation")),
        }
    }
}

use super::workspace::WorkspaceRight;
use super::{
    mounts::{MountBinding, MountKind},
    ToolHandleLease, VfsError, MAX_HANDLES_PER_AGENT, MAX_HANDLES_TOTAL,
};
use crate::sandbox::SandboxManager;
use crate::{AgentId, AgentKernelImpl, SandboxId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{atomic::AtomicBool, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataKind {
    Memory,
    KvDirectory,
    KvEntry,
    Ipc,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataHandle {
    pub id: String,
    pub path: String,
    pub kind: DataKind,
    pub rights: Vec<WorkspaceRight>,
}
#[derive(Clone)]
pub(crate) struct DataCapability {
    owner: AgentId,
    sandbox: SandboxId,
    path: String,
    kind: DataKind,
    key: Option<String>,
    rights: BTreeSet<WorkspaceRight>,
    bindings: BTreeMap<WorkspaceRight, Uuid>,
}
#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error(transparent)]
    Vfs(#[from] VfsError),
    #[error("invalid data VFS argument: {0}")]
    Invalid(String),
    #[error("data VFS rights denied")]
    PermissionDenied,
    #[error("data VFS tool denied: {0}")]
    Tool(#[from] crate::tools::ToolAuthorizationError),
    #[error("data VFS operation failed: {0}")]
    Backing(String),
}
fn operation(
    kind: DataKind,
    right: WorkspaceRight,
) -> Option<(&'static str, &'static str, ResourceType)> {
    use WorkspaceRight::*;
    match (kind, right) {
        (DataKind::Memory, Read) => Some(("memory_query", "query", ResourceType::Memory)),
        (DataKind::Memory, Write) => Some(("memory_store", "store", ResourceType::Memory)),
        (DataKind::Memory, Stat) => Some(("memory_stat", "stat", ResourceType::Memory)),
        (DataKind::KvEntry, Read) => Some(("kv_get", "kv_get", ResourceType::Memory)),
        (DataKind::KvEntry, Write) => Some(("kv_put", "kv_put", ResourceType::Memory)),
        (DataKind::KvEntry, Stat) => Some(("kv_stat", "kv_stat", ResourceType::Memory)),
        (DataKind::KvDirectory, List) => Some(("kv_list", "kv_list", ResourceType::Memory)),
        (DataKind::KvDirectory, Stat) => {
            Some(("kv_directory_stat", "kv_dir_stat", ResourceType::Memory))
        }
        (DataKind::Ipc, Read) => Some(("check_inbox", "receive", ResourceType::Ipc)),
        (DataKind::Ipc, Write) => Some(("send_agent_message", "send", ResourceType::Ipc)),
        (DataKind::Ipc, List) => Some(("discover_agents", "discover", ResourceType::Ipc)),
        (DataKind::Ipc, Stat) => Some(("ipc_stat", "stat", ResourceType::Ipc)),
        _ => None,
    }
}
fn rights_for(
    kind: DataKind,
    rights: &[WorkspaceRight],
) -> Result<BTreeSet<WorkspaceRight>, DataError> {
    let set = rights.iter().copied().collect::<BTreeSet<_>>();
    if set.is_empty()
        || set.len() != rights.len()
        || set.iter().any(|right| operation(kind, *right).is_none())
    {
        return Err(DataError::Invalid("unsupported or duplicate rights".into()));
    }
    Ok(set)
}
pub fn kv_component(key: &str) -> Result<String, DataError> {
    validated_key(key).map_err(|error| DataError::Invalid(error.to_string()))?;
    Ok(key
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
fn decode_key(component: &str) -> Result<String, DataError> {
    if component.is_empty()
        || !component.len().is_multiple_of(2)
        || component.len() > MAX_KV_KEY_BYTES * 2
        || !component
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DataError::Invalid("noncanonical KV component".into()));
    }
    let bytes = component
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect::<Vec<_>>();
    let key =
        String::from_utf8(bytes).map_err(|_| DataError::Invalid("KV key must be UTF-8".into()))?;
    validated_key(&key).map_err(|error| DataError::Invalid(error.to_string()))?;
    Ok(key)
}
impl DataCapability {
    fn handle(&self, id: Uuid) -> DataHandle {
        DataHandle {
            id: id.to_string(),
            path: self.path.clone(),
            kind: self.kind,
            rights: self.rights.iter().copied().collect(),
        }
    }
}
impl AgentKernelImpl {
    fn data_scope(
        &self,
        agent: AgentId,
        handle: &str,
    ) -> Result<(Arc<ToolHandleLease>, DataCapability), DataError> {
        let lease = self.vfs_acquire(agent, handle)?;
        let scope = lease
            .data
            .lock()
            .map_err(|_| VfsError::Unavailable)?
            .clone()
            .ok_or(VfsError::NotFound)?;
        if scope.owner != agent
            || self.sandbox_manager.get_sandbox_for_agent(agent) != Some(scope.sandbox)
        {
            return Err(VfsError::NotFound.into());
        }
        Ok((lease, scope))
    }
    fn store_data_handle(
        &self,
        agent: AgentId,
        scope: DataCapability,
        mount: MountBinding,
    ) -> Result<DataHandle, DataError> {
        let mut handles = self
            .tool_vfs
            .handles
            .lock()
            .map_err(|_| VfsError::Unavailable)?;
        if !mount.entry.is_active() {
            return Err(VfsError::NotFound.into());
        }
        if handles.values().map(HashMap::len).sum::<usize>() >= MAX_HANDLES_TOTAL
            || handles
                .get(&agent)
                .is_some_and(|owned| owned.len() >= MAX_HANDLES_PER_AGENT)
        {
            return Err(VfsError::Capacity.into());
        }
        let id = Uuid::new_v4();
        let handle = scope.handle(id);
        handles.entry(agent).or_default().insert(
            id,
            Arc::new(ToolHandleLease {
                name: String::new(),
                binding_id: Uuid::nil(),
                closed: AtomicBool::new(false),
                is_workspace: false,
                is_data: true,
                workspace: Mutex::new(None),
                workspace_bindings: Mutex::new(HashMap::new()),
                data: Mutex::new(Some(scope)),
                mount,
            }),
        );
        Ok(handle)
    }
    pub async fn vfs_open_data(
        &self,
        agent: AgentId,
        path: &str,
        rights: Vec<WorkspaceRight>,
    ) -> Result<DataHandle, DataError> {
        let lifecycle = self.lifecycle_lock(agent);
        let _held = lifecycle.lock().await;
        let view = self.vfs_namespace_mounts(agent)?;
        let entry = view
            .mounts
            .iter()
            .find(|entry| {
                path == entry.path
                    || path
                        .strip_prefix(&entry.path)
                        .is_some_and(|tail| tail.starts_with('/'))
            })
            .ok_or(VfsError::NotFound)?;
        let mount = self.vfs_resolve_mount(agent, path, entry.kind)?;
        let suffix = mount.entry.relative(path)?;
        let (kind, key) = match (entry.kind, suffix.is_empty()) {
            (MountKind::Memory, true) => (DataKind::Memory, None),
            (MountKind::Kv, true) => (DataKind::KvDirectory, None),
            (MountKind::Kv, false) => (DataKind::KvEntry, Some(decode_key(suffix)?)),
            (MountKind::Ipc, true) => (DataKind::Ipc, None),
            _ => return Err(DataError::Invalid("unsupported data mount path".into())),
        };
        let rights = rights_for(kind, &rights)?;
        let mut bindings = BTreeMap::new();
        for right in &rights {
            let (name, op, resource) = operation(kind, *right).expect("validated data right");
            let id = self
                .tool_registry
                .data_binding_id(&self.syscall_gate, agent, name, &resource, op)
                .ok_or(VfsError::NotFound)?;
            bindings.insert(*right, id);
        }
        let sandbox = self
            .sandbox_manager
            .get_sandbox_for_agent(agent)
            .ok_or(VfsError::NotFound)?;
        self.store_data_handle(
            agent,
            DataCapability {
                owner: agent,
                sandbox,
                path: path.into(),
                kind,
                key,
                rights,
                bindings,
            },
            mount,
        )
    }
    pub async fn vfs_dup_data(
        &self,
        agent: AgentId,
        handle: &str,
        rights: Vec<WorkspaceRight>,
    ) -> Result<DataHandle, DataError> {
        let lifecycle = self.lifecycle_lock(agent);
        let _held = lifecycle.lock().await;
        let (lease, mut scope) = self.data_scope(agent, handle)?;
        let rights = rights_for(scope.kind, &rights)?;
        if !rights.is_subset(&scope.rights) {
            return Err(DataError::PermissionDenied);
        }
        scope.rights = rights;
        if !self.vfs_lease_live(agent, &lease) {
            return Err(VfsError::NotFound.into());
        }
        self.store_data_handle(agent, scope, lease.mount.clone())
    }
    pub async fn vfs_data_call(
        &self,
        agent: AgentId,
        handle: &str,
        right: WorkspaceRight,
        args: Value,
    ) -> Result<Value, DataError> {
        let (lease, scope) = self.data_scope(agent, handle)?;
        if !scope.rights.contains(&right) {
            return Err(DataError::PermissionDenied);
        }
        let (name, op, resource) =
            operation(scope.kind, right).ok_or(DataError::PermissionDenied)?;
        let identity = *scope.bindings.get(&right).ok_or(VfsError::NotFound)?;
        if self
            .tool_registry
            .data_binding_id(&self.syscall_gate, agent, name, &resource, op)
            != Some(identity)
        {
            return Err(VfsError::NotFound.into());
        }
        let object = args
            .as_object()
            .ok_or_else(|| DataError::Invalid("data arguments must be an object".into()))?;
        let allowed: &[&str] = match (scope.kind, right) {
            (DataKind::Memory, WorkspaceRight::Read) => &["query"],
            (DataKind::Memory, WorkspaceRight::Write) => &["content", "category"],
            (DataKind::KvEntry, WorkspaceRight::Write) => &["value"],
            (DataKind::Ipc, WorkspaceRight::Write) => &["to", "payload"],
            _ => &[],
        };
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(DataError::Invalid("unexpected data argument".into()));
        }
        let mut parameters = object.clone();
        if let Some(key) = &scope.key {
            parameters.insert("key".into(), Value::String(key.clone()));
        }
        if scope.kind == DataKind::Memory && right == WorkspaceRight::Read {
            parameters
                .entry("query")
                .or_insert_with(|| Value::String(String::new()));
        }
        let (mut prepared, _guard) = self
            .tool_registry
            .authorize_and_acquire_bound_call(
                &self.syscall_gate,
                agent,
                name,
                &Value::Object(parameters),
                Some(identity),
            )
            .await?;
        if !self.vfs_lease_live(agent, &lease)
            || self
                .tool_registry
                .data_binding_id(&self.syscall_gate, agent, name, &resource, op)
                != Some(identity)
        {
            return Err(VfsError::NotFound.into());
        }
        prepared.request.sandbox_context = Some(scope.sandbox);
        let result = self
            .resource_broker
            .execute(prepared.request)
            .await
            .map_err(|error| DataError::Backing(error.to_string()))?;
        if !result.success {
            return Err(DataError::Backing(result.error.unwrap_or_default()));
        }
        Ok(result.data)
    }
}

#[cfg(test)]
#[path = "data_deadline.rs"]
mod deadline_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn kv_components_roundtrip_opaque_utf8_keys(
            characters in prop::collection::vec(any::<char>(), 1..128)
        ) {
            let key = characters.into_iter().collect::<String>();
            prop_assume!(validated_key(&key).is_ok());
            let component = kv_component(&key).unwrap();
            prop_assert_eq!(component.len(), key.len() * 2);
            prop_assert_eq!(decode_key(&component).unwrap(), key);
            let traversal = format!("{component}/..");
            prop_assert!(decode_key(&traversal).is_err());
            if component.to_uppercase() != component {
                prop_assert!(decode_key(&component.to_uppercase()).is_err());
            }
        }

        #[test]
        fn accepted_components_have_one_canonical_encoding(component in any::<String>()) {
            if let Ok(key) = decode_key(&component) {
                prop_assert_eq!(kv_component(&key).unwrap(), component);
                prop_assert!(validated_key(&key).is_ok());
            }
        }
    }
}
