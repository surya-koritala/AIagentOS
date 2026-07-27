//! Application resource provider.
//!
//! Only one-shot command launch is implemented. Stateful process interaction
//! is intentionally not advertised until it has real lifecycle semantics.

use kernel::resources::{ResourceProvider, ResourceType};
use kernel::ResourceError;

pub struct ApplicationProvider;

#[async_trait::async_trait]
impl ResourceProvider for ApplicationProvider {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Application
    }

    fn supported_operations(&self) -> Vec<String> {
        vec!["launch".into()]
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

                let mut command = tokio::process::Command::new(cmd);
                command.args(&args).kill_on_drop(true);
                let output = command
                    .output()
                    .await
                    .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;

                Ok(serde_json::json!({
                    "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
                    "stderr": String::from_utf8_lossy(&output.stderr).to_string(),
                    "exit_code": output.status.code(),
                }))
            }
            _ => Err(ResourceError::UnsupportedOperation {
                resource: "Application".into(),
                operation: operation.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stateful_process_stubs_are_typed_unsupported_and_not_advertised() {
        let provider = ApplicationProvider;
        assert_eq!(provider.supported_operations(), vec!["launch"]);

        for operation in ["close", "send_input", "read_output"] {
            let error = provider
                .execute(operation, &serde_json::json!({}))
                .await
                .expect_err("placeholder application operation must fail");
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
