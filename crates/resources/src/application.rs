//! Application resource provider — launch/close apps, send input, read output.

use kernel::resources::{ResourceProvider, ResourceType};
use kernel::ResourceError;

pub struct ApplicationProvider;

#[async_trait::async_trait]
impl ResourceProvider for ApplicationProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Application
    }

    fn supported_operations(&self) -> Vec<String> {
        vec![
            "launch".into(),
            "close".into(),
            "send_input".into(),
            "read_output".into(),
        ]
    }

    async fn execute(
        &self,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError> {
        match operation {
            "launch" => {
                let cmd = params
                    .get("command")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ResourceError::OperationFailed("Missing 'command' parameter".into())
                    })?;
                let args: Vec<&str> = params
                    .get("args")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();

                let output = tokio::process::Command::new(cmd)
                    .args(&args)
                    .output()
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;

                Ok(serde_json::json!({
                    "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
                    "stderr": String::from_utf8_lossy(&output.stderr).to_string(),
                    "exit_code": output.status.code(),
                }))
            }
            "read_output" => {
                // Stub: would read from a running process
                Ok(serde_json::json!({"output": ""}))
            }
            "close" | "send_input" => {
                // Stub: would interact with a running process
                Ok(serde_json::json!({"success": true}))
            }
            _ => Err(ResourceError::OperationFailed(format!(
                "Unknown operation: {}",
                operation
            ))),
        }
    }
}
