//! Standalone application provider compatibility type.
//!
//! Agent command execution requires kernel-owned sandbox identity, a
//! digest-pinned rootless container, bounded input/output, and broker lifecycle
//! ownership. This standalone type cannot carry that authority, so it
//! deliberately advertises no operations and fails closed.

use kernel::resources::{ResourceProvider, ResourceType};
use kernel::ResourceError;

pub struct ApplicationProvider;

#[async_trait::async_trait]
impl ResourceProvider for ApplicationProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Application
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
            resource: "Application".into(),
            operation: operation.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn standalone_application_fails_closed_without_sandbox_authority() {
        let provider = ApplicationProvider;
        assert!(provider.supported_operations().is_empty());

        for operation in ["launch", "close", "send_input", "read_output"] {
            let error = provider
                .execute(
                    operation,
                    &serde_json::json!({"command": "ambient-host-denied"}),
                )
                .await
                .expect_err("standalone ambient application operation must fail");
            assert_eq!(
                error,
                ResourceError::UnsupportedOperation {
                    resource: "Application".into(),
                    operation: operation.into(),
                }
            );
        }
    }
}
