//! Filesystem resource provider — read, write, create, delete, list operations.

use kernel::resources::{ResourceProvider, ResourceType};
use kernel::ResourceError;

pub struct FilesystemProvider;

#[async_trait::async_trait]
impl ResourceProvider for FilesystemProvider {
    fn resource_type(&self) -> ResourceType { ResourceType::Filesystem }

    fn supported_operations(&self) -> Vec<String> {
        vec!["read".into(), "write".into(), "create".into(), "delete".into(), "list".into()]
    }

    async fn execute(&self, operation: &str, params: &serde_json::Value) -> Result<serde_json::Value, ResourceError> {
        let path = params.get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ResourceError::OperationFailed("Missing 'path' parameter".into()))?;

        match operation {
            "read" => {
                let content = tokio::fs::read_to_string(path).await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"content": content}))
            }
            "write" => {
                let content = params.get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ResourceError::OperationFailed("Missing 'content' parameter".into()))?;
                tokio::fs::write(path, content).await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"written": true}))
            }
            "create" => {
                let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("");
                tokio::fs::write(path, content).await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"created": true}))
            }
            "delete" => {
                tokio::fs::remove_file(path).await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                Ok(serde_json::json!({"deleted": true}))
            }
            "list" => {
                let mut entries = Vec::new();
                let mut dir = tokio::fs::read_dir(path).await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                while let Some(entry) = dir.next_entry().await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))? {
                    entries.push(entry.file_name().to_string_lossy().to_string());
                }
                Ok(serde_json::json!({"entries": entries}))
            }
            _ => Err(ResourceError::OperationFailed(format!("Unknown operation: {}", operation))),
        }
    }
}
