//! Resource Broker — mediates all agent access to host system resources.
//!
//! Routes resource requests to appropriate providers after permission validation.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::permissions::{AccessDecision, ActionOutcome, PermissionSystem};
use crate::sandbox::{SandboxAction, SandboxManager};
use crate::{AgentId, ResourceError, SandboxId};

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
#[derive(Debug, Clone)]
pub struct ResourceRequest {
    pub agent_id: AgentId,
    pub resource_type: ResourceType,
    pub operation: String,
    pub parameters: serde_json::Value,
    pub sandbox_context: Option<SandboxId>,
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
}

impl ResourceBrokerImpl {
    pub fn new(
        permission_system: Arc<dyn PermissionSystem>,
        sandbox_manager: Arc<dyn SandboxManager>,
    ) -> Self {
        Self::build(permission_system, Some(sandbox_manager))
    }

    fn build(
        permission_system: Arc<dyn PermissionSystem>,
        sandbox_manager: Option<Arc<dyn SandboxManager>>,
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
        }
    }

    #[cfg(test)]
    pub fn new_unconfined(permission_system: Arc<dyn PermissionSystem>) -> Self {
        Self::build(permission_system, None)
    }

    fn sandbox_action(request: &ResourceRequest) -> Result<SandboxAction, ResourceError> {
        let string_parameter = |key: &str| {
            request
                .parameters
                .get(key)
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    ResourceError::OperationFailed(format!(
                        "sandbox classification requires string parameter '{key}'"
                    ))
                })
        };
        match request.resource_type {
            ResourceType::Filesystem => {
                Ok(SandboxAction::FileAccess(string_parameter("path")?.into()))
            }
            ResourceType::Network => Ok(SandboxAction::NetworkAccess(string_parameter("url")?)),
            ResourceType::Browser => Ok(SandboxAction::BrowserAccess(string_parameter("url")?)),
            ResourceType::Application => {
                Ok(SandboxAction::ProcessExec(string_parameter("command")?))
            }
            ResourceType::Peripheral => {
                Ok(SandboxAction::PeripheralAccess(request.operation.clone()))
            }
            ResourceType::Ipc => Ok(SandboxAction::Ipc),
        }
    }

    fn enforce_sandbox(&self, request: &mut ResourceRequest) -> Result<(), ResourceError> {
        let Some(manager) = &self.sandbox_manager else {
            return Ok(());
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
            Ok(())
        } else {
            let action = Self::sandbox_action(request)?;
            manager
                .intercept_action(actual, &action)
                .map_err(|_| ResourceError::OperationFailed("Sandbox denied".into()))
        }
    }
}

#[async_trait::async_trait]
impl ResourceBroker for ResourceBrokerImpl {
    async fn execute(
        &self,
        mut request: ResourceRequest,
    ) -> Result<ResourceResponse, ResourceError> {
        // Validate permissions before execution
        let decision = self.permission_system.check_access(
            request.agent_id,
            &request.resource_type,
            &request.operation,
            None,
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
            AccessDecision::Allowed => {}
        }

        if let Err(error) = self.enforce_sandbox(&mut request) {
            self.permission_system.log_action(
                request.agent_id,
                &request.operation,
                &format!("{:?}", request.resource_type),
                AccessDecision::Denied,
                ActionOutcome::Failure,
            );
            return Err(error);
        }

        // Dispatch to provider
        let provider = self.providers.get(&request.resource_type).ok_or_else(|| {
            ResourceError::ProviderNotFound(format!("{:?}", request.resource_type))
        })?;

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

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            provider.execute(&request.operation, &request.parameters),
        )
        .await
        .unwrap_or(Err(ResourceError::Timeout));
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
            parameters: serde_json::json!({}),
            sandbox_context: None,
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
            parameters: serde_json::json!({}),
            sandbox_context: None,
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
            parameters: serde_json::json!({}),
            sandbox_context: None,
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
            .execute(ResourceRequest {
                agent_id: agent,
                resource_type: ResourceType::Filesystem,
                operation: "read".into(),
                parameters: serde_json::json!({"path": "/etc/passwd"}),
                sandbox_context: Some(uuid::Uuid::new_v4()),
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn broker_rewrites_relative_file_path_to_validated_workspace_target() {
        let perms = Arc::new(PermissionManager::new());
        let sandboxes = Arc::new(SandboxManagerImpl::new());
        let broker = ResourceBrokerImpl::new(perms.clone(), sandboxes.clone());
        broker.register_provider(Box::new(MockProvider));
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

        let response = broker
            .execute(ResourceRequest {
                agent_id: agent,
                resource_type: ResourceType::Filesystem,
                operation: "read".into(),
                parameters: serde_json::json!({"path": "nested/file.txt"}),
                sandbox_context: Some(sandbox),
            })
            .await
            .unwrap();

        assert_eq!(
            response.data["params"]["path"],
            serde_json::json!(std::fs::canonicalize(&root)
                .unwrap()
                .join("nested/file.txt")
                .to_str()
                .unwrap())
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
            .execute(ResourceRequest {
                agent_id: agent,
                resource_type: ResourceType::Filesystem,
                operation: "read".into(),
                parameters: serde_json::json!({"path": "/tmp/file"}),
                sandbox_context: None,
            })
            .await;
        assert!(result.is_err());
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
                        parameters: serde_json::json!({}),
                        sandbox_context: None,
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
