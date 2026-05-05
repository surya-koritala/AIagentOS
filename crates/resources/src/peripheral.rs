//! Peripheral resource provider — stub for camera, microphone, speakers, printers.

use kernel::resources::{ResourceProvider, ResourceType};
use kernel::ResourceError;

pub struct PeripheralProvider;

#[async_trait::async_trait]
impl ResourceProvider for PeripheralProvider {
    fn resource_type(&self) -> ResourceType { ResourceType::Peripheral }

    fn supported_operations(&self) -> Vec<String> {
        vec!["capture_image".into(), "record_audio".into(), "play_audio".into(), "print".into()]
    }

    async fn execute(&self, operation: &str, _params: &serde_json::Value) -> Result<serde_json::Value, ResourceError> {
        // Stub implementation — would integrate with platform-specific APIs
        match operation {
            "capture_image" | "record_audio" | "play_audio" | "print" => {
                Ok(serde_json::json!({"status": "not_available", "message": "Peripheral not connected"}))
            }
            _ => Err(ResourceError::OperationFailed(format!("Unknown operation: {}", operation))),
        }
    }
}
