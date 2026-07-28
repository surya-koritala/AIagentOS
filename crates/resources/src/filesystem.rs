//! Standalone filesystem provider compatibility type.
//!
//! Agent filesystem access requires kernel-owned sandbox identity and a
//! directory capability. This crate cannot supply that authority, so it
//! advertises no operations and fails closed. Use the kernel resource broker
//! instead.

use kernel::resources::{ResourceProvider, ResourceType};
use kernel::ResourceError;

pub struct FilesystemProvider;

#[async_trait::async_trait]
impl ResourceProvider for FilesystemProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Filesystem
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
            resource: "Filesystem".into(),
            operation: operation.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn standalone_filesystem_fails_closed_without_sandbox_authority() {
        let provider = FilesystemProvider;
        assert!(provider.supported_operations().is_empty());

        for operation in ["read", "write", "create", "delete", "list"] {
            let error = provider
                .execute(
                    operation,
                    &serde_json::json!({"path": "/tmp/ambient-denied"}),
                )
                .await
                .expect_err("standalone ambient filesystem operation must fail");
            assert_eq!(
                error,
                ResourceError::UnsupportedOperation {
                    resource: "Filesystem".into(),
                    operation: operation.into(),
                }
            );
        }
    }
}
