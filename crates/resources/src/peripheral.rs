//! Peripheral resource provider placeholder.
//!
//! No peripheral operation is implemented or advertised. The type remains so
//! downstream code receives a typed unsupported error instead of fabricated
//! success while platform-specific providers are still being qualified.

use kernel::resources::{ResourceProvider, ResourceType};
use kernel::ResourceError;

pub struct PeripheralProvider;

#[async_trait::async_trait]
impl ResourceProvider for PeripheralProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Peripheral
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
            resource: "Peripheral".into(),
            operation: operation.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peripheral_placeholder_is_typed_unsupported_and_advertises_nothing() {
        let provider = PeripheralProvider;
        assert!(provider.supported_operations().is_empty());

        for operation in ["capture_image", "record_audio", "play_audio", "print"] {
            let error = provider
                .execute(operation, &serde_json::json!({}))
                .await
                .expect_err("placeholder peripheral operation must fail");
            assert_eq!(
                error,
                ResourceError::UnsupportedOperation {
                    resource: "Peripheral".into(),
                    operation: operation.into(),
                }
            );
        }
    }
}
