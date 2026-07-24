//! Resource Broker — mediates all agent access to host system resources.
//!
//! Routes resource requests to appropriate providers after permission validation.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::permissions::{AccessDecision, ActionOutcome, PermissionSystem};
use crate::sandbox::{SandboxAction, SandboxManager};
use crate::{AgentId, IsolationLevel, ResourceError, SandboxId};

/// Resource types available to agents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Filesystem,
    Application,
    Browser,
    Peripheral,
    Network,
    /// Inter-agent communication (mailboxes) routed to `IpcManager`.
    Ipc,
}

/// A request from an agent to access a resource.
#[derive(Debug)]
pub struct ResourceRequest {
    pub agent_id: AgentId,
    pub resource_type: ResourceType,
    pub operation: String,
    pub parameters: serde_json::Value,
    pub sandbox_context: Option<SandboxId>,
    /// Single-use proof issued only after the syscall gate admitted this
    /// immutable agent request. A trusted broker may subsequently resolve a
    /// lexically-normalized path inside the agent's sandbox; the proof does not
    /// claim symlink-safe host-path identity. Production brokers reject `None`;
    /// external callers cannot construct or clone a valid proof.
    pub gate_admission: Option<GateAdmissionProof>,
}

/// Provider target encoded by a validated resource type/operation pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderTargetSpec {
    /// The provider consumes a caller-controlled string parameter.
    Argument(&'static str),
    /// The provider target is fixed or injected by the kernel.
    Constant(&'static str),
}

/// Return the authoritative provider target for every supported operation.
/// Tool declaration validation and broker permission checks share this table.
pub(crate) fn provider_target_spec(
    resource_type: &ResourceType,
    operation: &str,
) -> Option<ProviderTargetSpec> {
    match (resource_type, operation) {
        (
            ResourceType::Filesystem,
            "read" | "write" | "create" | "create_dir" | "edit" | "delete" | "list",
        ) => Some(ProviderTargetSpec::Argument("path")),
        (ResourceType::Network, "get" | "post" | "put" | "delete" | "browse") => {
            Some(ProviderTargetSpec::Argument("url"))
        }
        (ResourceType::Browser, "navigate" | "click" | "type" | "read") => {
            Some(ProviderTargetSpec::Argument("url"))
        }
        (ResourceType::Application, "launch") => Some(ProviderTargetSpec::Argument("command")),
        (ResourceType::Application, "close" | "send_input" | "read_output") => {
            Some(ProviderTargetSpec::Argument("application"))
        }
        (ResourceType::Application, "install" | "uninstall") => {
            Some(ProviderTargetSpec::Argument("package"))
        }
        (ResourceType::Application, "credential" | "credential_access" | "read_credential") => {
            Some(ProviderTargetSpec::Argument("credential"))
        }
        (ResourceType::Ipc, "send" | "delegate") => Some(ProviderTargetSpec::Argument("to")),
        (ResourceType::Ipc, "delegation_status" | "complete_delegation") => {
            Some(ProviderTargetSpec::Argument("task_id"))
        }
        (ResourceType::Ipc, "receive") => Some(ProviderTargetSpec::Constant("ipc:self")),
        (ResourceType::Ipc, "discover") => Some(ProviderTargetSpec::Constant("ipc:namespace")),
        (ResourceType::Peripheral, "capture_image") => {
            Some(ProviderTargetSpec::Constant("peripheral:capture_image"))
        }
        (ResourceType::Peripheral, "record_audio") => {
            Some(ProviderTargetSpec::Constant("peripheral:record_audio"))
        }
        (ResourceType::Peripheral, "play_audio") => {
            Some(ProviderTargetSpec::Constant("peripheral:play_audio"))
        }
        (ResourceType::Peripheral, "print") => {
            Some(ProviderTargetSpec::Constant("peripheral:print"))
        }
        (ResourceType::Peripheral, "credential" | "credential_access" | "read_credential") => {
            Some(ProviderTargetSpec::Argument("credential"))
        }
        _ => None,
    }
}

pub(crate) fn provider_target(
    resource_type: &ResourceType,
    operation: &str,
    parameters: &serde_json::Value,
) -> Result<String, ResourceError> {
    match provider_target_spec(resource_type, operation) {
        Some(ProviderTargetSpec::Argument(argument)) => parameters
            .get(argument)
            .and_then(serde_json::Value::as_str)
            .filter(|target| !target.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                ResourceError::OperationFailed(format!(
                    "invalid or missing provider target '{argument}'"
                ))
            }),
        Some(ProviderTargetSpec::Constant(target)) => Ok(target.to_string()),
        None => Err(ResourceError::OperationFailed(format!(
            "unsupported provider operation {resource_type:?}/{operation}"
        ))),
    }
}

/// Return one lexical representation for a caller-supplied filesystem target.
///
/// This runs before MAC, approval-contract hashing, and gate-proof creation so
/// those decisions cannot authorize `allowed/../denied` while the provider
/// reaches a different path. Parent traversal is rejected instead of folded;
/// `.` and duplicate separators are collapsed. Both slash forms are converted
/// to `/` so MAC globs, approval identities, and provider parameters have the
/// same meaning on every supported host. Ambiguous UNC/device and drive-relative
/// forms are rejected instead of being interpreted differently by each OS.
/// This is deliberately not a symlink/no-follow isolation primitive — the
/// sandbox owns host resolution.
pub(crate) fn normalize_filesystem_target(target: &str) -> Result<String, ResourceError> {
    if target.trim().is_empty() || target.contains('\0') {
        return Err(ResourceError::OperationFailed(
            "invalid filesystem target".into(),
        ));
    }

    let portable = target.replace('\\', "/");
    if portable.starts_with("//") {
        return Err(ResourceError::OperationFailed(
            "UNC and device filesystem targets are not supported".into(),
        ));
    }
    let portable_bytes = portable.as_bytes();
    if portable_bytes.len() >= 2
        && portable_bytes[0].is_ascii_alphabetic()
        && portable_bytes[1] == b':'
        && portable_bytes.get(2) != Some(&b'/')
    {
        return Err(ResourceError::OperationFailed(
            "drive-relative filesystem targets are not supported".into(),
        ));
    }
    let rooted = portable.starts_with('/');
    let mut segments = Vec::new();
    for segment in portable.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                return Err(ResourceError::OperationFailed(
                    "filesystem parent traversal is not allowed".into(),
                ));
            }
            segment => segments.push(segment),
        }
    }

    let body = segments.join("/");
    match (rooted, body.is_empty()) {
        (true, true) => Ok("/".into()),
        (true, false) => Ok(format!("/{body}")),
        (false, true) => Ok(".".into()),
        (false, false) => Ok(body),
    }
}

pub(crate) fn opaque_identity(value: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, value);
    let mut identity = String::with_capacity(7 + digest.as_ref().len() * 2);
    identity.push_str("sha256:");
    use std::fmt::Write as _;
    for byte in digest.as_ref() {
        write!(&mut identity, "{byte:02x}").expect("writing a digest into a String cannot fail");
    }
    identity
}

pub(crate) fn request_identity(
    agent_id: AgentId,
    resource_type: &ResourceType,
    operation: &str,
    parameters: &serde_json::Value,
) -> Result<String, String> {
    let serialized = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "agent_id": agent_id,
        "resource_type": resource_type,
        "operation": operation,
        "parameters": parameters,
    }))
    .map_err(|error| format!("provider request serialization failed: {error}"))?;
    Ok(opaque_identity(&serialized))
}

/// Non-cloneable, request-bound evidence of a successful syscall-gate verdict.
#[derive(Debug)]
pub struct GateAdmissionProof {
    agent_id: AgentId,
    request_identity: String,
    approval_satisfied: bool,
}

impl GateAdmissionProof {
    pub(crate) fn new(
        agent_id: AgentId,
        request_identity: String,
        approval_satisfied: bool,
    ) -> Self {
        Self {
            agent_id,
            request_identity,
            approval_satisfied,
        }
    }

    fn verify(self, request: &ResourceRequest) -> Result<bool, ResourceError> {
        let actual = request_identity(
            request.agent_id,
            &request.resource_type,
            &request.operation,
            &request.parameters,
        )
        .map_err(ResourceError::OperationFailed)?;
        if self.agent_id != request.agent_id || self.request_identity != actual {
            return Err(ResourceError::OperationFailed(
                "gate admission proof does not match immutable agent request".into(),
            ));
        }
        Ok(self.approval_satisfied)
    }
}

/// Response from a resource operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceResponse {
    pub success: bool,
    pub data: serde_json::Value,
    pub error: Option<String>,
}

/// Describes a capability provided by a resource provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceCapability {
    pub resource_type: ResourceType,
    pub operations: Vec<String>,
    pub description: String,
}

/// A pluggable resource provider.
#[async_trait::async_trait]
pub trait ResourceProvider: Send + Sync {
    fn resource_type(&self) -> ResourceType;
    fn supported_operations(&self) -> Vec<String>;
    async fn execute(
        &self,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError>;
}

/// The Resource Broker trait.
#[async_trait::async_trait]
pub trait ResourceBroker: Send + Sync {
    async fn execute(&self, request: ResourceRequest) -> Result<ResourceResponse, ResourceError>;
    fn list_capabilities(&self) -> Vec<ResourceCapability>;
    fn register_provider(&self, provider: Box<dyn ResourceProvider>);
}

/// Concrete resource broker implementation with permission validation.
pub struct ResourceBrokerImpl {
    providers: DashMap<ResourceType, Box<dyn ResourceProvider>>,
    permission_system: Arc<dyn PermissionSystem>,
    sandbox_manager: Option<Arc<dyn SandboxManager>>,
    admission: DashMap<ResourceType, Arc<tokio::sync::Semaphore>>,
    waiting: AtomicUsize,
    max_waiters: usize,
    require_gate_admission: bool,
}

impl ResourceBrokerImpl {
    pub fn new(
        permission_system: Arc<dyn PermissionSystem>,
        sandbox_manager: Arc<dyn SandboxManager>,
    ) -> Self {
        Self::build(permission_system, Some(sandbox_manager), true)
    }

    fn build(
        permission_system: Arc<dyn PermissionSystem>,
        sandbox_manager: Option<Arc<dyn SandboxManager>>,
        require_gate_admission: bool,
    ) -> Self {
        let admission = DashMap::new();
        for (resource, permits) in [
            (ResourceType::Filesystem, 64),
            (ResourceType::Application, 8),
            (ResourceType::Browser, 16),
            (ResourceType::Peripheral, 8),
            (ResourceType::Network, 64),
            (ResourceType::Ipc, 256),
        ] {
            admission.insert(resource, Arc::new(tokio::sync::Semaphore::new(permits)));
        }
        Self {
            providers: DashMap::new(),
            permission_system,
            sandbox_manager,
            admission,
            waiting: AtomicUsize::new(0),
            max_waiters: 1024,
            require_gate_admission,
        }
    }

    #[cfg(test)]
    pub fn new_unconfined(permission_system: Arc<dyn PermissionSystem>) -> Self {
        Self::build(permission_system, None, false)
    }

    fn sandbox_action(request: &ResourceRequest) -> Result<SandboxAction, ResourceError> {
        let target = provider_target(
            &request.resource_type,
            &request.operation,
            &request.parameters,
        )?;
        match request.resource_type {
            ResourceType::Filesystem => Ok(SandboxAction::FileAccess(target.into())),
            ResourceType::Network => Ok(SandboxAction::NetworkAccess(target)),
            ResourceType::Browser => Ok(SandboxAction::BrowserAccess(target)),
            ResourceType::Application => Ok(SandboxAction::ProcessExec(target)),
            ResourceType::Peripheral => Ok(SandboxAction::PeripheralAccess(target)),
            ResourceType::Ipc => Ok(SandboxAction::Ipc),
        }
    }

    fn enforce_sandbox(
        &self,
        request: &mut ResourceRequest,
    ) -> Result<Option<(SandboxId, IsolationLevel)>, ResourceError> {
        let Some(manager) = &self.sandbox_manager else {
            return Ok(None);
        };
        let actual = manager
            .get_sandbox_for_agent(request.agent_id)
            .ok_or_else(|| ResourceError::OperationFailed("Sandbox denied".into()))?;
        if request
            .sandbox_context
            .is_some_and(|supplied| supplied != actual)
        {
            return Err(ResourceError::OperationFailed("Sandbox denied".into()));
        }
        if request.resource_type == ResourceType::Filesystem {
            let supplied_path = request
                .parameters
                .get("path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    ResourceError::OperationFailed(
                        "sandbox classification requires string parameter 'path'".into(),
                    )
                })?;
            let resolved = manager
                .resolve_file_path(actual, std::path::Path::new(supplied_path))
                .map_err(|_| ResourceError::OperationFailed("Sandbox denied".into()))?;
            let resolved = resolved.to_str().ok_or_else(|| {
                ResourceError::OperationFailed("sandbox path is not valid UTF-8".into())
            })?;
            let parameters = request.parameters.as_object_mut().ok_or_else(|| {
                ResourceError::OperationFailed("filesystem parameters must be an object".into())
            })?;
            parameters.insert(
                "path".into(),
                serde_json::Value::String(resolved.to_string()),
            );
            let isolation = manager
                .isolation_level(actual)
                .map_err(|_| ResourceError::OperationFailed("Sandbox denied".into()))?;
            Ok(Some((actual, isolation)))
        } else {
            let action = Self::sandbox_action(request)?;
            manager
                .intercept_action(actual, &action)
                .map_err(|_| ResourceError::OperationFailed("Sandbox denied".into()))?;
            let isolation = manager
                .isolation_level(actual)
                .map_err(|_| ResourceError::OperationFailed("Sandbox denied".into()))?;
            Ok(Some((actual, isolation)))
        }
    }
}

#[async_trait::async_trait]
impl ResourceBroker for ResourceBrokerImpl {
    async fn execute(
        &self,
        mut request: ResourceRequest,
    ) -> Result<ResourceResponse, ResourceError> {
        let admission_approved = match request.gate_admission.take() {
            Some(proof) => Some(proof.verify(&request)?),
            None if !self.require_gate_admission => None,
            None => {
                return Err(ResourceError::OperationFailed(
                    "syscall gate admission proof required".into(),
                ));
            }
        };
        let target = provider_target(
            &request.resource_type,
            &request.operation,
            &request.parameters,
        )?;

        // Validate permissions before execution
        let decision = self.permission_system.check_access(
            request.agent_id,
            &request.resource_type,
            &request.operation,
            Some(&target),
        );

        match decision {
            AccessDecision::Denied => {
                self.permission_system.log_action(
                    request.agent_id,
                    &request.operation,
                    &format!("{:?}", request.resource_type),
                    AccessDecision::Denied,
                    ActionOutcome::Failure,
                );
                return Err(ResourceError::OperationFailed(
                    "Permission denied".to_string(),
                ));
            }
            AccessDecision::RequiresApproval => {
                if admission_approved != Some(true) {
                    self.permission_system.log_action(
                        request.agent_id,
                        &request.operation,
                        &format!("{:?}", request.resource_type),
                        AccessDecision::RequiresApproval,
                        ActionOutcome::Pending,
                    );
                    return Err(ResourceError::OperationFailed(
                        "Requires user approval".to_string(),
                    ));
                }
            }
            AccessDecision::Allowed => {}
        }

        let sandbox = match self.enforce_sandbox(&mut request) {
            Ok(sandbox) => sandbox,
            Err(error) => {
                self.permission_system.log_action(
                    request.agent_id,
                    &request.operation,
                    &format!("{:?}", request.resource_type),
                    AccessDecision::Denied,
                    ActionOutcome::Failure,
                );
                return Err(error);
            }
        };
        if matches!(
            sandbox,
            Some((_, ref isolation))
                if request.resource_type == ResourceType::Browser
                    && *isolation != IsolationLevel::Trusted
        ) {
            self.permission_system.log_action(
                request.agent_id,
                &request.operation,
                &format!("{:?}", request.resource_type),
                AccessDecision::Denied,
                ActionOutcome::Failure,
            );
            return Err(ResourceError::OperationFailed(
                "isolated browser backend unavailable".into(),
            ));
        }

        // Dispatch to provider
        let provider = self.providers.get(&request.resource_type).ok_or_else(|| {
            ResourceError::ProviderNotFound(format!("{:?}", request.resource_type))
        })?;
        if !provider
            .supported_operations()
            .iter()
            .any(|operation| operation == &request.operation)
        {
            return Err(ResourceError::OperationFailed(format!(
                "provider does not advertise operation '{}'",
                request.operation
            )));
        }

        let registered = self
            .waiting
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |waiting| {
                (waiting < self.max_waiters).then_some(waiting + 1)
            })
            .is_ok();
        if !registered {
            return Err(ResourceError::OperationFailed(format!(
                "resource admission queue is full (capacity {}); retry with backoff",
                self.max_waiters
            )));
        }
        let waiting = ResourceWaitGuard(&self.waiting);
        let semaphore = self
            .admission
            .get(&request.resource_type)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or_else(|| ResourceError::ProviderNotFound("resource admission class".into()))?;
        let permit = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            semaphore.acquire_owned(),
        )
        .await
        .map_err(|_| {
            ResourceError::OperationFailed(
                "resource admission timed out after 30s; retry with backoff".into(),
            )
        })?
        .map_err(|_| ResourceError::OperationFailed("resource admission closed".into()))?;
        drop(waiting);

        // Transactional filesystem edits run on a blocking worker internally.
        // Dropping that worker future on the generic timeout does not stop the
        // underlying file mutation, which could let lifecycle cleanup release
        // its tool guard while a side effect still runs. Keep ownership until
        // the edit transaction finishes. Other provider operations retain the
        // bounded 30-second execution contract.
        let capability_filesystem = match sandbox {
            Some((sandbox_id, ref isolation))
                if request.resource_type == ResourceType::Filesystem
                    && *isolation != IsolationLevel::Trusted =>
            {
                Some(sandbox_id)
            }
            _ => None,
        };
        let capability_network = match sandbox {
            Some((sandbox_id, ref isolation))
                if request.resource_type == ResourceType::Network
                    && *isolation != IsolationLevel::Trusted =>
            {
                Some(sandbox_id)
            }
            _ => None,
        };
        let result = if let Some(sandbox_id) = capability_filesystem {
            let manager = Arc::clone(
                self.sandbox_manager
                    .as_ref()
                    .expect("sandbox identity came from a sandbox manager"),
            );
            let operation = request.operation.clone();
            let parameters = request.parameters.clone();
            tokio::task::spawn_blocking(move || {
                manager
                    .execute_filesystem(sandbox_id, &operation, &parameters)
                    .map_err(|error| ResourceError::OperationFailed(error.to_string()))
            })
            .await
            .map_err(|error| ResourceError::OperationFailed(error.to_string()))?
        } else if let Some(sandbox_id) = capability_network {
            let manager = Arc::clone(
                self.sandbox_manager
                    .as_ref()
                    .expect("sandbox identity came from a sandbox manager"),
            );
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                manager.execute_network(sandbox_id, &request.operation, &request.parameters),
            )
            .await
            .unwrap_or(Err(crate::SandboxError::BoundaryViolation(
                "network request timed out".into(),
            )))
            .map_err(|error| ResourceError::OperationFailed(error.to_string()))
        } else if request.resource_type == ResourceType::Filesystem && request.operation == "edit" {
            provider
                .execute(&request.operation, &request.parameters)
                .await
        } else {
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                provider.execute(&request.operation, &request.parameters),
            )
            .await
            .unwrap_or(Err(ResourceError::Timeout))
        };
        drop(permit);

        match result {
            Ok(data) => {
                self.permission_system.log_action(
                    request.agent_id,
                    &request.operation,
                    &format!("{:?}", request.resource_type),
                    AccessDecision::Allowed,
                    ActionOutcome::Success,
                );
                Ok(ResourceResponse {
                    success: true,
                    data,
                    error: None,
                })
            }
            Err(e) => {
                self.permission_system.log_action(
                    request.agent_id,
                    &request.operation,
                    &format!("{:?}", request.resource_type),
                    AccessDecision::Allowed,
                    ActionOutcome::Failure,
                );
                Ok(ResourceResponse {
                    success: false,
                    data: serde_json::Value::Null,
                    error: Some(e.to_string()),
                })
            }
        }
    }

    fn list_capabilities(&self) -> Vec<ResourceCapability> {
        self.providers
            .iter()
            .map(|entry| ResourceCapability {
                resource_type: entry.value().resource_type(),
                operations: entry.value().supported_operations(),
                description: format!("{:?} provider", entry.value().resource_type()),
            })
            .collect()
    }

    fn register_provider(&self, provider: Box<dyn ResourceProvider>) {
        let rt = provider.resource_type();
        self.providers.insert(rt, provider);
    }
}

struct ResourceWaitGuard<'a>(&'a AtomicUsize);

impl Drop for ResourceWaitGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::PermissionManager;
    use crate::sandbox::SandboxManagerImpl;
    use crate::{IsolationLevel, SandboxConfig};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn filesystem_normalization_is_platform_independent_and_fail_closed() {
        assert_eq!(
            normalize_filesystem_target(r"\workspace\\allowed\.\note.txt").unwrap(),
            "/workspace/allowed/note.txt"
        );
        assert_eq!(
            normalize_filesystem_target("/workspace//allowed/./note.txt").unwrap(),
            "/workspace/allowed/note.txt"
        );
        assert_eq!(
            normalize_filesystem_target(r"nested\\allowed\file.txt").unwrap(),
            "nested/allowed/file.txt"
        );
        assert!(normalize_filesystem_target(r"allowed\..\denied").is_err());
        assert!(normalize_filesystem_target(r"\\server\share\secret").is_err());
        assert!(normalize_filesystem_target("C:relative.txt").is_err());
        assert!(normalize_filesystem_target("C:").is_err());
        assert_eq!(
            normalize_filesystem_target(r"C:\workspace\file.txt").unwrap(),
            "C:/workspace/file.txt"
        );
    }

    struct MockProvider;

    #[async_trait::async_trait]
    impl ResourceProvider for MockProvider {
        fn resource_type(&self) -> ResourceType {
            ResourceType::Filesystem
        }
        fn supported_operations(&self) -> Vec<String> {
            vec!["read".to_string(), "write".to_string()]
        }
        async fn execute(
            &self,
            operation: &str,
            params: &serde_json::Value,
        ) -> Result<serde_json::Value, ResourceError> {
            Ok(serde_json::json!({"op": operation, "params": params, "result": "ok"}))
        }
    }

    struct CountingProvider(Arc<AtomicUsize>);

    struct DeleteProvider(Arc<AtomicUsize>);

    struct BlindProvider {
        resource_type: ResourceType,
        advertised: Vec<String>,
        calls: Arc<AtomicUsize>,
    }

    fn with_test_gate_proof(
        mut request: ResourceRequest,
        approval_satisfied: bool,
    ) -> ResourceRequest {
        let identity = request_identity(
            request.agent_id,
            &request.resource_type,
            &request.operation,
            &request.parameters,
        )
        .unwrap();
        request.gate_admission = Some(GateAdmissionProof::new(
            request.agent_id,
            identity,
            approval_satisfied,
        ));
        request
    }

    struct SlowApplicationProvider {
        current: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ResourceProvider for SlowApplicationProvider {
        fn resource_type(&self) -> ResourceType {
            ResourceType::Application
        }

        fn supported_operations(&self) -> Vec<String> {
            vec!["launch".into()]
        }

        async fn execute(
            &self,
            _operation: &str,
            _params: &serde_json::Value,
        ) -> Result<serde_json::Value, ResourceError> {
            let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(current, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.current.fetch_sub(1, Ordering::SeqCst);
            Ok(serde_json::json!({"ok": true}))
        }
    }

    #[async_trait::async_trait]
    impl ResourceProvider for CountingProvider {
        fn resource_type(&self) -> ResourceType {
            ResourceType::Filesystem
        }

        fn supported_operations(&self) -> Vec<String> {
            vec!["read".into()]
        }

        async fn execute(
            &self,
            _operation: &str,
            _params: &serde_json::Value,
        ) -> Result<serde_json::Value, ResourceError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({"unexpected": true}))
        }
    }

    #[async_trait::async_trait]
    impl ResourceProvider for DeleteProvider {
        fn resource_type(&self) -> ResourceType {
            ResourceType::Filesystem
        }

        fn supported_operations(&self) -> Vec<String> {
            vec!["delete".into()]
        }

        async fn execute(
            &self,
            operation: &str,
            params: &serde_json::Value,
        ) -> Result<serde_json::Value, ResourceError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({"operation": operation, "path": params["path"]}))
        }
    }

    #[async_trait::async_trait]
    impl ResourceProvider for BlindProvider {
        fn resource_type(&self) -> ResourceType {
            self.resource_type.clone()
        }

        fn supported_operations(&self) -> Vec<String> {
            self.advertised.clone()
        }

        async fn execute(
            &self,
            operation: &str,
            _params: &serde_json::Value,
        ) -> Result<serde_json::Value, ResourceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({"operation": operation}))
        }
    }

    #[tokio::test]
    async fn execute_with_permission() {
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(perms.clone());
        broker.register_provider(Box::new(MockProvider));

        let agent_id = uuid::Uuid::new_v4();
        perms.assign_profile(agent_id, &"standard".to_string());

        let req = ResourceRequest {
            agent_id,
            resource_type: ResourceType::Filesystem,
            operation: "read".to_string(),
            parameters: serde_json::json!({"path": "/tmp/test"}),
            sandbox_context: None,
            gate_admission: None,
        };

        let resp = broker.execute(req).await.unwrap();
        assert!(resp.success);
    }

    #[tokio::test]
    async fn execute_denied_by_permission() {
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(perms.clone());
        broker.register_provider(Box::new(MockProvider));

        let agent_id = uuid::Uuid::new_v4();
        perms.assign_profile(agent_id, &"read-only".to_string());

        let req = ResourceRequest {
            agent_id,
            resource_type: ResourceType::Filesystem,
            operation: "write".to_string(),
            parameters: serde_json::json!({"path": "/tmp/test"}),
            sandbox_context: None,
            gate_admission: None,
        };

        let result = broker.execute(req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_capabilities_after_register() {
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(perms);
        broker.register_provider(Box::new(MockProvider));
        let caps = broker.list_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].resource_type, ResourceType::Filesystem);
    }

    #[tokio::test]
    async fn execute_no_provider_fails() {
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(perms.clone());

        let agent_id = uuid::Uuid::new_v4();
        perms.assign_profile(agent_id, &"full-access".to_string());

        let req = ResourceRequest {
            agent_id,
            resource_type: ResourceType::Browser,
            operation: "navigate".to_string(),
            parameters: serde_json::json!({"url": "https://example.invalid"}),
            sandbox_context: None,
            gate_admission: None,
        };

        let result = broker.execute(req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn broker_resolves_unforgeable_sandbox_and_denies_before_provider() {
        let perms = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(perms.clone(), sandboxes.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        broker.register_provider(Box::new(CountingProvider(calls.clone())));
        let agent = uuid::Uuid::new_v4();
        perms.assign_profile(agent, &"full-access".to_string());
        let root = std::env::temp_dir().join(format!("agentos-broker-{}", uuid::Uuid::new_v4()));
        sandboxes
            .create_sandbox(
                agent,
                &SandboxConfig {
                    workspace_dir: root.clone(),
                    allowed_network_hosts: Some(Vec::new()),
                    max_disk_usage_bytes: None,
                    max_memory_bytes: None,
                    isolation_level: IsolationLevel::Filesystem,
                },
            )
            .unwrap();

        let result = broker
            .execute(with_test_gate_proof(
                ResourceRequest {
                    agent_id: agent,
                    resource_type: ResourceType::Filesystem,
                    operation: "read".into(),
                    parameters: serde_json::json!({"path": "/etc/passwd"}),
                    sandbox_context: Some(uuid::Uuid::new_v4()),
                    gate_admission: None,
                },
                false,
            ))
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn broker_executes_relative_file_through_workspace_capability() {
        let perms = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(perms.clone(), sandboxes.clone());
        let provider_calls = Arc::new(AtomicUsize::new(0));
        broker.register_provider(Box::new(CountingProvider(provider_calls.clone())));
        let agent = uuid::Uuid::new_v4();
        perms.assign_profile(agent, &"full-access".to_string());
        let root =
            std::env::temp_dir().join(format!("agentos-broker-relative-{}", uuid::Uuid::new_v4()));
        let sandbox = sandboxes
            .create_sandbox(
                agent,
                &SandboxConfig {
                    workspace_dir: root.clone(),
                    allowed_network_hosts: Some(Vec::new()),
                    max_disk_usage_bytes: None,
                    max_memory_bytes: None,
                    isolation_level: IsolationLevel::Filesystem,
                },
            )
            .unwrap();
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/file.txt"), "capability content").unwrap();

        let response = broker
            .execute(with_test_gate_proof(
                ResourceRequest {
                    agent_id: agent,
                    resource_type: ResourceType::Filesystem,
                    operation: "read".into(),
                    parameters: serde_json::json!({"path": "nested/file.txt"}),
                    sandbox_context: Some(sandbox),
                    gate_admission: None,
                },
                false,
            ))
            .await
            .unwrap();

        assert!(response.success);
        assert_eq!(response.data["content"], "capability content");
        assert_eq!(
            provider_calls.load(Ordering::SeqCst),
            0,
            "untrusted filesystem I/O must not reopen a host path in a provider"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn broker_denies_agent_without_registered_sandbox() {
        let perms = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(perms.clone(), sandboxes);
        broker.register_provider(Box::new(MockProvider));
        let agent = uuid::Uuid::new_v4();
        perms.assign_profile(agent, &"full-access".to_string());
        let result = broker
            .execute(with_test_gate_proof(
                ResourceRequest {
                    agent_id: agent,
                    resource_type: ResourceType::Filesystem,
                    operation: "read".into(),
                    parameters: serde_json::json!({"path": "/tmp/file"}),
                    sandbox_context: None,
                    gate_admission: None,
                },
                false,
            ))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn broker_rejects_private_dns_answers_before_provider_invocation() {
        let permissions = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(permissions.clone(), sandboxes.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        broker.register_provider(Box::new(BlindProvider {
            resource_type: ResourceType::Network,
            advertised: vec!["get".into()],
            calls: calls.clone(),
        }));

        let agent = uuid::Uuid::new_v4();
        permissions.assign_profile(agent, &"full-access".into());
        let root =
            std::env::temp_dir().join(format!("agentos-private-dns-{}", uuid::Uuid::new_v4()));
        sandboxes
            .create_sandbox(
                agent,
                &SandboxConfig {
                    workspace_dir: root.clone(),
                    allowed_network_hosts: Some(vec!["localhost".into()]),
                    max_disk_usage_bytes: None,
                    max_memory_bytes: None,
                    isolation_level: IsolationLevel::Filesystem,
                },
            )
            .unwrap();

        let response = broker
            .execute(with_test_gate_proof(
                ResourceRequest {
                    agent_id: agent,
                    resource_type: ResourceType::Network,
                    operation: "get".into(),
                    parameters: serde_json::json!({"url": "http://localhost/"}),
                    sandbox_context: None,
                    gate_admission: None,
                },
                false,
            ))
            .await
            .unwrap();
        assert!(!response.success);
        assert!(response
            .error
            .as_deref()
            .is_some_and(|error| error.contains("denied address")));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a provider must never see a target whose DNS answer is private"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn production_broker_rejects_proofless_launch_and_forged_ipc() {
        let permissions = Arc::new(PermissionManager::new());
        let broker =
            ResourceBrokerImpl::new(permissions.clone(), Arc::new(SandboxManagerImpl::new()));
        let application_calls = Arc::new(AtomicUsize::new(0));
        let ipc_calls = Arc::new(AtomicUsize::new(0));
        broker.register_provider(Box::new(BlindProvider {
            resource_type: ResourceType::Application,
            advertised: vec!["launch".into()],
            calls: application_calls.clone(),
        }));
        broker.register_provider(Box::new(BlindProvider {
            resource_type: ResourceType::Ipc,
            advertised: vec!["send".into()],
            calls: ipc_calls.clone(),
        }));
        let attacker = uuid::Uuid::new_v4();
        let victim = uuid::Uuid::new_v4();
        permissions.assign_profile(attacker, &"full-access".into());

        let launch = broker
            .execute(ResourceRequest {
                agent_id: attacker,
                resource_type: ResourceType::Application,
                operation: "launch".into(),
                parameters: serde_json::json!({"command": "echo"}),
                sandbox_context: None,
                gate_admission: None,
            })
            .await
            .unwrap_err();
        assert!(launch.to_string().contains("gate admission proof"));

        let forged_ipc = broker
            .execute(ResourceRequest {
                agent_id: attacker,
                resource_type: ResourceType::Ipc,
                operation: "send".into(),
                parameters: serde_json::json!({
                    "from": victim.to_string(),
                    "to": attacker.to_string(),
                    "payload": {"forged": true}
                }),
                sandbox_context: None,
                gate_admission: None,
            })
            .await
            .unwrap_err();
        assert!(forged_ipc.to_string().contains("gate admission proof"));
        assert_eq!(application_calls.load(Ordering::SeqCst), 0);
        assert_eq!(ipc_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn shared_application_alias_cannot_reach_launch_provider() {
        use crate::connector::ToolCall;
        use crate::tool_registry_share::{SharedToolDef, SharedToolRegistry};
        use crate::tools::{SecurityAction, ToolRegistry, ToolSecurity};

        let permissions = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(permissions.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        broker.register_provider(Box::new(BlindProvider {
            resource_type: ResourceType::Application,
            advertised: vec!["launch".into()],
            calls: calls.clone(),
        }));
        let agent = uuid::Uuid::new_v4();
        permissions.assign_profile(agent, &"full-access".into());

        let mut shared = SharedToolRegistry::new();
        shared
            .publish(
                SharedToolDef::new(
                    "remote_close",
                    "MCP-like application alias",
                    ResourceType::Application,
                    "close",
                    ToolSecurity::argument(SecurityAction::Execute, "application").sandboxed(),
                )
                .with_parameters(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "application": {"type": "string"},
                        "command": {"type": "string"}
                    },
                    "required": ["application", "command"]
                })),
            )
            .unwrap();
        let registry = ToolRegistry::new();
        assert!(shared.install_into("remote_close", &registry));
        let request = registry
            .resolve(
                agent,
                &ToolCall {
                    id: "remote".into(),
                    name: "remote_close".into(),
                    arguments: serde_json::json!({
                        "application": "benign-session",
                        "command": "must-not-execute"
                    }),
                },
            )
            .unwrap();

        let error = broker.execute(request).await.unwrap_err();
        assert!(error.to_string().contains("does not advertise operation"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn consumed_gate_approval_executes_exact_elevated_delete() {
        use crate::agent_struct::CapabilitySet;
        use crate::tools::{
            ApprovalPolicy, SandboxRequirement, SecurityAction, ToolBinding, ToolRegistry,
            ToolSecurity,
        };

        let permissions = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(permissions.clone(), sandboxes.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        broker.register_provider(Box::new(DeleteProvider(calls.clone())));

        let agent = uuid::Uuid::new_v4();
        permissions.assign_profile(agent, &"standard".into());
        let root =
            std::env::temp_dir().join(format!("agentos-approved-delete-{}", uuid::Uuid::new_v4()));
        sandboxes
            .create_sandbox(
                agent,
                &SandboxConfig {
                    workspace_dir: root.clone(),
                    allowed_network_hosts: Some(Vec::new()),
                    max_disk_usage_bytes: None,
                    max_memory_bytes: None,
                    isolation_level: IsolationLevel::Filesystem,
                },
            )
            .unwrap();
        std::fs::write(root.join("victim.txt"), "delete me").unwrap();

        let registry = ToolRegistry::new();
        registry
            .register(ToolBinding {
                name: "approved_delete".into(),
                description: "Delete one sandboxed path after approval".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }),
                resource_type: ResourceType::Filesystem,
                operation: "delete".into(),
                security: ToolSecurity::argument(SecurityAction::Delete, "path")
                    .with_approval(ApprovalPolicy::User)
                    .sandboxed(),
            })
            .unwrap();
        assert_eq!(
            registry
                .security("approved_delete")
                .unwrap()
                .sandbox_requirement,
            SandboxRequirement::Required
        );

        let gate = crate::syscall_gate::SyscallGate::with_mac(
            Arc::new(crate::cgroups::CgroupManager::new()),
            false,
            Vec::new(),
        );
        let mut capabilities = CapabilitySet::none();
        capabilities.grant(CapabilitySet::CAP_FILE_DELETE);
        gate.register_agent(agent, capabilities, None);
        let arguments = serde_json::json!({"path": "victim.txt"});
        let prepared = registry
            .prepare_execution(agent, "approved_delete", &arguments)
            .unwrap();
        let approval_resource = prepared.authorization.resource.clone();
        let approval_contract = prepared.approval_contract_digest.clone();

        assert!(
            broker
                .execute(ResourceRequest {
                    agent_id: agent,
                    resource_type: ResourceType::Filesystem,
                    operation: "delete".into(),
                    parameters: arguments.clone(),
                    sandbox_context: None,
                    gate_admission: None,
                })
                .await
                .is_err(),
            "the broker must not treat elevated permission as already approved"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        assert!(gate.grant_tool_approval_contract(
            agent,
            "approved_delete",
            approval_resource.clone(),
            &approval_contract,
            ApprovalPolicy::User,
        ));
        let (mut tampered, tampered_guard) = registry
            .authorize_and_acquire_call(&gate, agent, "approved_delete", &arguments)
            .await
            .unwrap();
        tampered.request.parameters["path"] = serde_json::json!("another-victim.txt");
        assert!(
            broker.execute(tampered.request).await.is_err(),
            "a consumed proof must not authorize a mutated provider request"
        );
        drop(tampered_guard);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        assert!(gate.grant_tool_approval_contract(
            agent,
            "approved_delete",
            approval_resource,
            &approval_contract,
            ApprovalPolicy::User,
        ));
        let (prepared, _guard) = registry
            .authorize_and_acquire_call(&gate, agent, "approved_delete", &arguments)
            .await
            .unwrap();
        let response = broker.execute(prepared.request).await.unwrap();
        assert!(response.success);
        assert_eq!(response.data["deleted"], true);
        assert!(!root.join("victim.txt").exists());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "untrusted delete must be capability-mediated, not provider-mediated"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn application_resource_admission_never_exceeds_class_limit() {
        let permissions = Arc::new(PermissionManager::new());
        let broker = Arc::new(ResourceBrokerImpl::new_unconfined(permissions.clone()));
        let current = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        broker.register_provider(Box::new(SlowApplicationProvider {
            current,
            maximum: maximum.clone(),
        }));

        let mut tasks = Vec::new();
        for _ in 0..24 {
            let agent = uuid::Uuid::new_v4();
            permissions.assign_profile(agent, &"full-access".into());
            let broker = broker.clone();
            tasks.push(tokio::spawn(async move {
                broker
                    .execute(ResourceRequest {
                        agent_id: agent,
                        resource_type: ResourceType::Application,
                        operation: "launch".into(),
                        parameters: serde_json::json!({"command": "test"}),
                        sandbox_context: None,
                        gate_admission: None,
                    })
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert!(maximum.load(Ordering::SeqCst) <= 8);
    }
}
