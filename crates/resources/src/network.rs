//! Network resource provider — HTTP requests via reqwest.

use kernel::resources::{ResourceProvider, ResourceType};
use kernel::ResourceError;

pub struct NetworkProvider {
    client: reqwest::Client,
}

impl NetworkProvider {
    pub fn new() -> Self {
        Self { client: reqwest::Client::new() }
    }
}

#[async_trait::async_trait]
impl ResourceProvider for NetworkProvider {
    fn resource_type(&self) -> ResourceType { ResourceType::Network }

    fn supported_operations(&self) -> Vec<String> {
        vec!["get".into(), "post".into(), "put".into(), "delete".into()]
    }

    async fn execute(&self, operation: &str, params: &serde_json::Value) -> Result<serde_json::Value, ResourceError> {
        let url = params.get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ResourceError::OperationFailed("Missing 'url' parameter".into()))?;

        let response = match operation {
            "get" => self.client.get(url).send().await,
            "post" => {
                let body = params.get("body").cloned().unwrap_or(serde_json::Value::Null);
                self.client.post(url).json(&body).send().await
            }
            "put" => {
                let body = params.get("body").cloned().unwrap_or(serde_json::Value::Null);
                self.client.put(url).json(&body).send().await
            }
            "delete" => self.client.delete(url).send().await,
            _ => return Err(ResourceError::OperationFailed(format!("Unknown operation: {}", operation))),
        };

        let resp = response.map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.map_err(|e| ResourceError::OperationFailed(e.to_string()))?;

        Ok(serde_json::json!({"status": status, "body": body}))
    }
}
