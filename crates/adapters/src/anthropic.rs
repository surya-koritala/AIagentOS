//! Anthropic API adapter with retry and exponential backoff.

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

pub struct AnthropicAdapter {
    id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl AnthropicAdapter {
    pub fn new(api_key: String) -> Self {
        Self {
            id: "anthropic".to_string(),
            client: reqwest::Client::new(),
            api_key,
            base_url: "https://api.anthropic.com/v1".to_string(),
        }
    }

    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }
}

struct AnthropicSession {
    provider_id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

#[async_trait::async_trait]
impl LlmSession for AnthropicSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        let mut body = serde_json::json!({
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 4096,
            "messages": messages.iter().map(|m| serde_json::json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
        });

        if !tools.is_empty() {
            let tool_defs: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name, "description": t.description, "input_schema": t.parameters
                    })
                })
                .collect();
            body["tools"] = serde_json::json!(tool_defs);
        }

        let mut last_err = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000 * (1 << attempt))).await;
            }

            let result = self
                .client
                .post(format!("{}/messages", self.base_url))
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .json(&body)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    let json: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| ConnectorError::ProtocolError(e.to_string()))?;
                    let content = json["content"][0]["text"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let input_tokens = json["usage"]["input_tokens"].as_u64().unwrap_or(0);
                    let output_tokens = json["usage"]["output_tokens"].as_u64().unwrap_or(0);
                    let tool_calls = json["content"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|block| {
                                    if block["type"].as_str()? == "tool_use" {
                                        Some(ToolCall {
                                            id: block["id"].as_str()?.to_string(),
                                            name: block["name"].as_str()?.to_string(),
                                            arguments: block["input"].clone(),
                                        })
                                    } else {
                                        None
                                    }
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    return Ok(LlmResponse {
                        content,
                        finish_reason: json["stop_reason"].as_str().map(|s| s.to_string()),
                        tokens_used: (input_tokens + output_tokens) as u32,
                        tool_calls,
                    });
                }
                Ok(resp) => {
                    last_err = Some(ConnectorError::ConnectionFailed(format!(
                        "HTTP {}",
                        resp.status()
                    )));
                }
                Err(e) => {
                    last_err = Some(ConnectorError::ConnectionFailed(e.to_string()));
                }
            }
        }
        Err(last_err.unwrap())
    }

    fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for AnthropicAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn name(&self) -> &str {
        "Anthropic"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }

    async fn is_available(&self) -> bool {
        // Simple connectivity check
        self.client.get(&self.base_url).send().await.is_ok()
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(AnthropicSession {
            provider_id: self.id.clone(),
            client: self.client.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
        }))
    }

    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": msg.role, "content": msg.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage {
            role: value.get("role")?.as_str()?.to_string(),
            content: value.get("content")?.as_str().unwrap_or("").to_string(),
            tool_call_id: None,
            tool_calls: None,
        })
    }
}
