//! Resource Broker — mediates all agent access to host system resources.
//!
//! Routes resource requests to appropriate providers after permission validation.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::permissions::{AccessDecision, ActionOutcome, PermissionSystem};
use crate::{AgentId, ResourceError, SandboxId};

/// Resource types available to agents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Filesystem,
    Application,
    Browser,
    Peripheral,
    Network,
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
}

impl ResourceBrokerImpl {
    pub fn new(permission_system: Arc<dyn PermissionSystem>) -> Self {
        Self {
            providers: DashMap::new(),
            permission_system,
        }
    }
}

#[async_trait::async_trait]
impl ResourceBroker for ResourceBrokerImpl {
    async fn execute(&self, request: ResourceRequest) -> Result<ResourceResponse, ResourceError> {
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

        // Dispatch to provider
        let provider = self.providers.get(&request.resource_type).ok_or_else(|| {
            ResourceError::ProviderNotFound(format!("{:?}", request.resource_type))
        })?;

        let result = provider
            .execute(&request.operation, &request.parameters)
            .await;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::PermissionManager;

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
            _params: &serde_json::Value,
        ) -> Result<serde_json::Value, ResourceError> {
            Ok(serde_json::json!({"op": operation, "result": "ok"}))
        }
    }

    #[tokio::test]
    async fn execute_with_permission() {
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new(perms.clone());
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
        let broker = ResourceBrokerImpl::new(perms.clone());
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
        let broker = ResourceBrokerImpl::new(perms);
        broker.register_provider(Box::new(MockProvider));
        let caps = broker.list_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].resource_type, ResourceType::Filesystem);
    }

    #[tokio::test]
    async fn execute_no_provider_fails() {
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new(perms.clone());

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
}
