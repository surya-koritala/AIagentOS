//! Resource Broker — mediates all agent access to host system resources.
//!
//! Routes resource requests to appropriate providers after permission validation.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

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
        None => Err(ResourceError::UnsupportedOperation {
            resource: format!("{resource_type:?}"),
            operation: operation.to_string(),
        }),
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
///
/// Provider futures are a kernel security boundary. Implementations must not
/// detach side effects from the returned future, and dropping the future must
/// stop or synchronously own cleanup for any operation that can mutate external
/// state. The broker supplies cancellation through `execute_controlled`, waits
/// for a bounded drain, and then aborts a non-cooperative future. Providers that
/// need asynchronous cleanup should override `execute_controlled`, observe the
/// token, and return only after that cleanup is complete.
#[async_trait::async_trait]
pub trait ResourceProvider: Send + Sync {
    fn resource_type(&self) -> ResourceType;
    fn supported_operations(&self) -> Vec<String>;
    async fn execute(
        &self,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError>;

    async fn execute_controlled(
        &self,
        operation: &str,
        params: &serde_json::Value,
        cancellation: &CancellationToken,
    ) -> Result<serde_json::Value, ResourceError> {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                Err(ResourceError::OperationFailed(
                    "resource provider execution cancelled".into(),
                ))
            }
            result = self.execute(operation, params) => result,
        }
    }
}

/// The Resource Broker trait.
#[async_trait::async_trait]
pub trait ResourceBroker: Send + Sync {
    async fn execute(&self, request: ResourceRequest) -> Result<ResourceResponse, ResourceError>;
    fn list_capabilities(&self) -> Vec<ResourceCapability>;
    fn register_provider(&self, provider: Box<dyn ResourceProvider>) -> Result<(), ResourceError>;
}

/// Concrete resource broker implementation with permission validation.
pub struct ResourceBrokerImpl {
    providers: DashMap<ResourceType, Arc<dyn ResourceProvider>>,
    permission_system: Arc<dyn PermissionSystem>,
    sandbox_manager: Option<Arc<dyn SandboxManager>>,
    admission: DashMap<ResourceType, Arc<tokio::sync::Semaphore>>,
    waiting: AtomicUsize,
    max_waiters: usize,
    require_gate_admission: bool,
}

const PROVIDER_EXECUTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const PROVIDER_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

type ProviderJoinResult = Result<Result<serde_json::Value, ResourceError>, tokio::task::JoinError>;

/// Owns the isolated provider task until it has completed or a bounded drain
/// reaper has taken responsibility for it. This makes cancellation of the
/// broker future cancellation of the provider operation as well; Tokio's
/// default detached-on-`JoinHandle`-drop behavior is never used here.
struct ProviderTaskGuard {
    cancellation: CancellationToken,
    handle: Option<tokio::task::JoinHandle<Result<serde_json::Value, ResourceError>>>,
}

impl ProviderTaskGuard {
    fn new(
        provider: Arc<dyn ResourceProvider>,
        operation: String,
        parameters: serde_json::Value,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        let cancellation = CancellationToken::new();
        let provider_cancellation = cancellation.clone();
        let handle = tokio::spawn(async move {
            let _permit = permit;
            provider
                .execute_controlled(&operation, &parameters, &provider_cancellation)
                .await
        });
        Self {
            cancellation,
            handle: Some(handle),
        }
    }

    async fn join(&mut self) -> ProviderJoinResult {
        self.handle
            .as_mut()
            .expect("provider task handle is present until guard drop")
            .await
    }

    async fn cancel_and_drain(&mut self) {
        self.cancellation.cancel();
        let drained = tokio::time::timeout(PROVIDER_DRAIN_TIMEOUT, self.join()).await;
        if drained.is_err() {
            if let Some(handle) = self.handle.as_mut() {
                handle.abort();
                let _ = handle.await;
            }
        }
        self.handle.take();
    }
}

impl Drop for ProviderTaskGuard {
    fn drop(&mut self) {
        let Some(mut handle) = self.handle.take() else {
            return;
        };
        self.cancellation.cancel();
        if handle.is_finished() {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if tokio::time::timeout(PROVIDER_DRAIN_TIMEOUT, &mut handle)
                    .await
                    .is_err()
                {
                    handle.abort();
                    let _ = handle.await;
                }
            });
        } else {
            handle.abort();
        }
    }
}

fn provider_join_result(result: ProviderJoinResult) -> Result<serde_json::Value, ResourceError> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_panic() => Err(ResourceError::OperationFailed(
            "resource provider panicked; operation was isolated".into(),
        )),
        Err(_) => Err(ResourceError::OperationFailed(
            "resource provider task was cancelled".into(),
        )),
    }
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
        let provider = self
            .providers
            .get(&request.resource_type)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or_else(|| {
                ResourceError::ProviderNotFound(format!("{:?}", request.resource_type))
            })?;
        let supported_operations = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            provider.supported_operations()
        }))
        .map_err(|_| {
            ResourceError::OperationFailed(
                "resource provider panicked while reporting operations".into(),
            )
        })?;
        if !supported_operations
            .iter()
            .any(|operation| operation == &request.operation)
        {
            return Err(ResourceError::UnsupportedOperation {
                resource: format!("{:?}", request.resource_type),
                operation: request.operation.clone(),
            });
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

        // Filesystem operations run synchronously under the sandbox's
        // operation lock on a blocking worker. Dropping that worker future
        // does not stop an in-flight mutation, so keep ownership until the
        // capability operation finishes. Other providers retain the bounded
        // execution contract below.
        let mut permit = Some(permit);
        let capability_filesystem = match sandbox {
            Some((sandbox_id, _)) if request.resource_type == ResourceType::Filesystem => {
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
        let isolated_process = match sandbox {
            Some((sandbox_id, IsolationLevel::Container))
                if request.resource_type == ResourceType::Application =>
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
        } else if let Some(sandbox_id) = isolated_process {
            let manager = Arc::clone(
                self.sandbox_manager
                    .as_ref()
                    .expect("sandbox identity came from a sandbox manager"),
            );
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                manager.execute_process(sandbox_id, &request.parameters),
            )
            .await
            .unwrap_or(Err(crate::SandboxError::BoundaryViolation(
                "container execution timed out".into(),
            )))
            .map_err(|error| ResourceError::OperationFailed(error.to_string()))
        } else {
            let mut task = ProviderTaskGuard::new(
                provider,
                request.operation.clone(),
                request.parameters.clone(),
                permit
                    .take()
                    .expect("generic provider execution owns its admission permit"),
            );
            match tokio::time::timeout(PROVIDER_EXECUTION_TIMEOUT, task.join()).await {
                Ok(result) => {
                    task.handle.take();
                    provider_join_result(result)
                }
                Err(_) => {
                    task.cancel_and_drain().await;
                    Err(ResourceError::Timeout)
                }
            }
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
            .filter_map(|entry| {
                let provider = Arc::clone(entry.value());
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let resource_type = provider.resource_type();
                    let operations = provider.supported_operations();
                    (!operations.is_empty()).then(|| ResourceCapability {
                        operations,
                        description: format!("{resource_type:?} provider"),
                        resource_type,
                    })
                }))
                .ok()
                .flatten()
            })
            .collect()
    }

    fn register_provider(&self, provider: Box<dyn ResourceProvider>) -> Result<(), ResourceError> {
        let rt =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| provider.resource_type()))
                .map_err(|_| {
                    ResourceError::OperationFailed(
                        "resource provider panicked while reporting its type".into(),
                    )
                })?;
        match self.providers.entry(rt) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(ResourceError::OperationFailed(
                    "resource provider replacement is disabled; restart with an audited configuration change"
                        .into(),
                ))
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Arc::from(provider));
                Ok(())
            }
        }
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

    struct EmptyPeripheralProvider(Arc<AtomicUsize>);

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

    struct PanickingApplicationProvider;

    #[async_trait::async_trait]
    impl ResourceProvider for PanickingApplicationProvider {
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
            panic!("provider-controlled secret must not escape the isolation boundary")
        }
    }

    struct ProviderFutureDrop(Arc<AtomicUsize>);

    impl Drop for ProviderFutureDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct NeverEndingApplicationProvider {
        entered: Arc<tokio::sync::Notify>,
        dropped: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ResourceProvider for NeverEndingApplicationProvider {
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
            let _drop = ProviderFutureDrop(self.dropped.clone());
            self.entered.notify_one();
            std::future::pending().await
        }
    }

    struct PanickingMetadataProvider;

    #[async_trait::async_trait]
    impl ResourceProvider for PanickingMetadataProvider {
        fn resource_type(&self) -> ResourceType {
            panic!("metadata panic")
        }

        fn supported_operations(&self) -> Vec<String> {
            vec![]
        }

        async fn execute(
            &self,
            _operation: &str,
            _params: &serde_json::Value,
        ) -> Result<serde_json::Value, ResourceError> {
            unreachable!("metadata panic must prevent registration")
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

    #[async_trait::async_trait]
    impl ResourceProvider for EmptyPeripheralProvider {
        fn resource_type(&self) -> ResourceType {
            ResourceType::Peripheral
        }

        fn supported_operations(&self) -> Vec<String> {
            Vec::new()
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

    #[tokio::test]
    async fn execute_with_permission() {
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(perms.clone());
        broker.register_provider(Box::new(MockProvider)).unwrap();

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
    async fn provider_panic_is_redacted_and_releases_admission_permit() {
        let permissions = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(permissions.clone());
        broker
            .register_provider(Box::new(PanickingApplicationProvider))
            .unwrap();
        let agent = uuid::Uuid::new_v4();
        permissions.assign_profile(agent, &"full-access".into());

        let response = broker
            .execute(ResourceRequest {
                agent_id: agent,
                resource_type: ResourceType::Application,
                operation: "launch".into(),
                parameters: serde_json::json!({"command": "fixture"}),
                sandbox_context: None,
                gate_admission: None,
            })
            .await
            .unwrap();

        assert!(!response.success);
        let error = response.error.unwrap();
        assert!(error.contains("provider panicked"));
        assert!(!error.contains("provider-controlled secret"));
        assert_eq!(
            broker
                .admission
                .get(&ResourceType::Application)
                .unwrap()
                .available_permits(),
            8,
            "provider panic must not strand an application permit"
        );
    }

    #[tokio::test]
    async fn cancelling_broker_future_drains_provider_and_releases_permit() {
        let permissions = Arc::new(PermissionManager::new());
        let broker = Arc::new(ResourceBrokerImpl::new_unconfined(permissions.clone()));
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        broker
            .register_provider(Box::new(NeverEndingApplicationProvider {
                entered: entered.clone(),
                dropped: dropped.clone(),
            }))
            .unwrap();
        let agent = uuid::Uuid::new_v4();
        permissions.assign_profile(agent, &"full-access".into());
        let broker_task = broker.clone();

        let request = tokio::spawn(async move {
            broker_task
                .execute(ResourceRequest {
                    agent_id: agent,
                    resource_type: ResourceType::Application,
                    operation: "launch".into(),
                    parameters: serde_json::json!({"command": "fixture"}),
                    sandbox_context: None,
                    gate_admission: None,
                })
                .await
        });
        entered.notified().await;
        request.abort();
        let _ = request.await;

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while dropped.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
            while broker
                .admission
                .get(&ResourceType::Application)
                .unwrap()
                .available_permits()
                != 8
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("provider cancellation must drain before the bounded deadline");
    }

    #[test]
    fn registration_rejects_panicking_metadata_and_runtime_replacement() {
        let permissions = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(permissions);
        assert!(broker
            .register_provider(Box::new(PanickingMetadataProvider))
            .unwrap_err()
            .to_string()
            .contains("panicked while reporting its type"));

        let original_calls = Arc::new(AtomicUsize::new(0));
        broker
            .register_provider(Box::new(CountingProvider(original_calls)))
            .unwrap();
        let replacement_calls = Arc::new(AtomicUsize::new(0));
        let error = broker
            .register_provider(Box::new(DeleteProvider(replacement_calls.clone())))
            .unwrap_err();
        assert!(error.to_string().contains("replacement is disabled"));
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn execute_denied_by_permission() {
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(perms.clone());
        broker.register_provider(Box::new(MockProvider)).unwrap();

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
        broker.register_provider(Box::new(MockProvider)).unwrap();
        let caps = broker.list_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].resource_type, ResourceType::Filesystem);
    }

    #[tokio::test]
    async fn empty_provider_is_not_advertised_and_stub_dispatch_is_typed_unsupported() {
        let permissions = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(permissions.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        broker
            .register_provider(Box::new(EmptyPeripheralProvider(calls.clone())))
            .unwrap();
        assert!(
            broker.list_capabilities().is_empty(),
            "a provider with no real operations must not appear available"
        );

        let agent = uuid::Uuid::new_v4();
        permissions.assign_profile(agent, &"full-access".into());
        let error = broker
            .execute(ResourceRequest {
                agent_id: agent,
                resource_type: ResourceType::Peripheral,
                operation: "capture_image".into(),
                parameters: serde_json::json!({}),
                sandbox_context: None,
                gate_admission: None,
            })
            .await
            .expect_err("placeholder operation must fail before provider dispatch");
        assert_eq!(
            error,
            ResourceError::UnsupportedOperation {
                resource: "Peripheral".into(),
                operation: "capture_image".into(),
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
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
        broker
            .register_provider(Box::new(CountingProvider(calls.clone())))
            .unwrap();
        let agent = uuid::Uuid::new_v4();
        perms.assign_profile(agent, &"full-access".to_string());
        let root = std::env::temp_dir().join(format!("agentos-broker-{}", uuid::Uuid::new_v4()));
        let sandbox = sandboxes
            .create_sandbox(
                agent,
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
        sandboxes.destroy_sandbox(sandbox).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn broker_executes_relative_file_through_workspace_capability() {
        let perms = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(perms.clone(), sandboxes.clone());
        let provider_calls = Arc::new(AtomicUsize::new(0));
        broker
            .register_provider(Box::new(CountingProvider(provider_calls.clone())))
            .unwrap();
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
                    container_image: None,
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
        sandboxes.destroy_sandbox(sandbox).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn trusted_agent_filesystem_is_still_confined_to_workspace_capability() {
        let perms = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(perms.clone(), sandboxes.clone());
        let provider_calls = Arc::new(AtomicUsize::new(0));
        broker
            .register_provider(Box::new(CountingProvider(provider_calls.clone())))
            .unwrap();
        let agent = uuid::Uuid::new_v4();
        perms.assign_profile(agent, &"full-access".to_string());
        let root =
            std::env::temp_dir().join(format!("agentos-broker-trusted-{}", uuid::Uuid::new_v4()));
        let outside = std::env::temp_dir().join(format!(
            "agentos-broker-trusted-outside-{}",
            uuid::Uuid::new_v4()
        ));
        let sandbox = sandboxes
            .create_sandbox(
                agent,
                &SandboxConfig {
                    workspace_dir: root.clone(),
                    allowed_network_hosts: None,
                    max_disk_usage_bytes: None,
                    max_memory_bytes: None,
                    isolation_level: IsolationLevel::Trusted,
                    container_image: None,
                },
            )
            .unwrap();
        std::fs::write(root.join("inside.txt"), "trusted capability content").unwrap();
        std::fs::write(&outside, "ambient secret").unwrap();

        let inside = broker
            .execute(with_test_gate_proof(
                ResourceRequest {
                    agent_id: agent,
                    resource_type: ResourceType::Filesystem,
                    operation: "read".into(),
                    parameters: serde_json::json!({"path": root.join("inside.txt")}),
                    sandbox_context: Some(sandbox),
                    gate_admission: None,
                },
                false,
            ))
            .await
            .unwrap();
        assert!(inside.success);
        assert_eq!(inside.data["content"], "trusted capability content");

        let escaped = broker
            .execute(with_test_gate_proof(
                ResourceRequest {
                    agent_id: agent,
                    resource_type: ResourceType::Filesystem,
                    operation: "read".into(),
                    parameters: serde_json::json!({"path": outside}),
                    sandbox_context: Some(sandbox),
                    gate_admission: None,
                },
                false,
            ))
            .await;
        assert!(escaped.is_err());
        assert_eq!(
            provider_calls.load(Ordering::SeqCst),
            0,
            "trusted agents must not reach an ambient filesystem provider"
        );

        sandboxes.destroy_sandbox(sandbox).unwrap();
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_file(outside).unwrap();
    }

    #[tokio::test]
    async fn broker_denies_agent_without_registered_sandbox() {
        let perms = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(perms.clone(), sandboxes);
        broker.register_provider(Box::new(MockProvider)).unwrap();
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
        broker
            .register_provider(Box::new(BlindProvider {
                resource_type: ResourceType::Network,
                advertised: vec!["get".into()],
                calls: calls.clone(),
            }))
            .unwrap();

        let agent = uuid::Uuid::new_v4();
        permissions.assign_profile(agent, &"full-access".into());
        let root =
            std::env::temp_dir().join(format!("agentos-private-dns-{}", uuid::Uuid::new_v4()));
        let sandbox = sandboxes
            .create_sandbox(
                agent,
                &SandboxConfig {
                    workspace_dir: root.clone(),
                    allowed_network_hosts: Some(vec!["localhost".into()]),
                    max_disk_usage_bytes: None,
                    max_memory_bytes: None,
                    isolation_level: IsolationLevel::Filesystem,
                    container_image: None,
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
        sandboxes.destroy_sandbox(sandbox).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn host_authority_surfaces_are_fail_closed_unless_explicitly_trusted() {
        let permissions = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(permissions.clone(), sandboxes.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        for (resource_type, operation) in [
            (ResourceType::Application, "launch"),
            (ResourceType::Browser, "navigate"),
        ] {
            broker
                .register_provider(Box::new(BlindProvider {
                    resource_type,
                    advertised: vec![operation.into()],
                    calls: calls.clone(),
                }))
                .unwrap();
        }

        let untrusted = uuid::Uuid::new_v4();
        permissions.assign_profile(untrusted, &"full-access".into());
        let untrusted_root = std::env::temp_dir().join(format!(
            "agentos-untrusted-surfaces-{}",
            uuid::Uuid::new_v4()
        ));
        let untrusted_sandbox = sandboxes
            .create_sandbox(
                untrusted,
                &SandboxConfig {
                    workspace_dir: untrusted_root.clone(),
                    allowed_network_hosts: Some(vec!["example.com".into()]),
                    max_disk_usage_bytes: None,
                    max_memory_bytes: None,
                    isolation_level: IsolationLevel::Filesystem,
                    container_image: None,
                },
            )
            .unwrap();
        for (resource_type, operation, parameters) in [
            (
                ResourceType::Application,
                "launch",
                serde_json::json!({"command": "echo"}),
            ),
            (
                ResourceType::Browser,
                "navigate",
                serde_json::json!({"url": "https://example.com"}),
            ),
        ] {
            let denied = broker
                .execute(with_test_gate_proof(
                    ResourceRequest {
                        agent_id: untrusted,
                        resource_type,
                        operation: operation.into(),
                        parameters,
                        sandbox_context: None,
                        gate_admission: None,
                    },
                    false,
                ))
                .await;
            assert!(denied.is_err(), "{operation} must fail closed");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "untrusted application and browser requests must not reach providers"
        );
        let audit = permissions.get_audit_log(None);
        assert_eq!(audit.len(), 2);
        assert!(audit.iter().all(|entry| {
            entry.agent_id == untrusted
                && entry.decision == AccessDecision::Denied
                && entry.outcome == ActionOutcome::Failure
                && matches!(entry.resource.as_str(), "Application" | "Browser")
                && !entry.resource.contains("example.com")
                && !entry.resource.contains("echo")
        }));

        let trusted = uuid::Uuid::new_v4();
        permissions.assign_profile(trusted, &"full-access".into());
        let trusted_root =
            std::env::temp_dir().join(format!("agentos-trusted-surfaces-{}", uuid::Uuid::new_v4()));
        let trusted_sandbox = sandboxes
            .create_sandbox(
                trusted,
                &SandboxConfig {
                    workspace_dir: trusted_root.clone(),
                    allowed_network_hosts: Some(Vec::new()),
                    max_disk_usage_bytes: None,
                    max_memory_bytes: None,
                    isolation_level: IsolationLevel::Trusted,
                    container_image: None,
                },
            )
            .unwrap();
        for (resource_type, operation, parameters) in [
            (
                ResourceType::Application,
                "launch",
                serde_json::json!({"command": "operator-approved"}),
            ),
            (
                ResourceType::Browser,
                "navigate",
                serde_json::json!({"url": "https://operator.example"}),
            ),
        ] {
            let response = broker
                .execute(with_test_gate_proof(
                    ResourceRequest {
                        agent_id: trusted,
                        resource_type,
                        operation: operation.into(),
                        parameters,
                        sandbox_context: Some(trusted_sandbox),
                        gate_admission: None,
                    },
                    false,
                ))
                .await
                .unwrap();
            assert!(response.success, "{operation} trusted operator call");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        sandboxes.destroy_sandbox(untrusted_sandbox).unwrap();
        sandboxes.destroy_sandbox(trusted_sandbox).unwrap();
        std::fs::remove_dir_all(untrusted_root).ok();
        std::fs::remove_dir_all(trusted_root).ok();
    }

    #[tokio::test]
    async fn production_broker_rejects_proofless_launch_and_forged_ipc() {
        let permissions = Arc::new(PermissionManager::new());
        let broker =
            ResourceBrokerImpl::new(permissions.clone(), Arc::new(SandboxManagerImpl::new()));
        let application_calls = Arc::new(AtomicUsize::new(0));
        let ipc_calls = Arc::new(AtomicUsize::new(0));
        broker
            .register_provider(Box::new(BlindProvider {
                resource_type: ResourceType::Application,
                advertised: vec!["launch".into()],
                calls: application_calls.clone(),
            }))
            .unwrap();
        broker
            .register_provider(Box::new(BlindProvider {
                resource_type: ResourceType::Ipc,
                advertised: vec!["send".into()],
                calls: ipc_calls.clone(),
            }))
            .unwrap();
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

    #[test]
    fn shared_application_alias_cannot_be_published() {
        use crate::tool_registry_share::{ShareError, SharedToolDef, SharedToolRegistry};
        use crate::tools::{SecurityAction, ToolSecurity};

        let mut shared = SharedToolRegistry::new();
        let error = shared
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
            .expect_err("unsupported application aliases must fail before publication");
        assert!(
            matches!(error, ShareError::Invalid(message) if message.contains("operation 'close' is not supported"))
        );
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
        broker
            .register_provider(Box::new(DeleteProvider(calls.clone())))
            .unwrap();

        let agent = uuid::Uuid::new_v4();
        permissions.assign_profile(agent, &"standard".into());
        let root =
            std::env::temp_dir().join(format!("agentos-approved-delete-{}", uuid::Uuid::new_v4()));
        let sandbox = sandboxes
            .create_sandbox(
                agent,
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
        sandboxes.destroy_sandbox(sandbox).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn application_resource_admission_never_exceeds_class_limit() {
        let permissions = Arc::new(PermissionManager::new());
        let broker = Arc::new(ResourceBrokerImpl::new_unconfined(permissions.clone()));
        let current = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        broker
            .register_provider(Box::new(SlowApplicationProvider {
                current,
                maximum: maximum.clone(),
            }))
            .unwrap();

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
