//! Standalone network provider compatibility type.
//!
//! Agent HTTP requires kernel-owned sandbox identity, allowlisted and pinned
//! DNS answers, bounded request/response data, and broker lifecycle ownership.
//! This standalone type cannot carry that authority, so it deliberately
//! advertises no operations and fails closed.

use kernel::resources::{ResourceProvider, ResourceType};
use kernel::ResourceError;

pub struct NetworkProvider;

impl Default for NetworkProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ResourceProvider for NetworkProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Network
    }

    fn supported_operations(&self) -> Vec<String> {
        Vec::new()
    }

    async fn execute(
        &self,
        operation: &str,
        _params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError> {
        Err(ResourceError::UnsupportedOperation {
            resource: "Network".into(),
            operation: operation.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn standalone_network_fails_closed_without_sandbox_authority() {
        let provider = NetworkProvider::new();
        assert!(provider.supported_operations().is_empty());

        for operation in ["get", "post", "put", "delete", "browse"] {
            let error = provider
                .execute(
                    operation,
                    &serde_json::json!({"url": "https://example.invalid"}),
                )
                .await
                .expect_err("standalone ambient network operation must fail");
            assert_eq!(
                error,
                ResourceError::UnsupportedOperation {
                    resource: "Network".into(),
                    operation: operation.into(),
                }
            );
        }
    }
}
