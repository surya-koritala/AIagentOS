//! OpenAI API adapter with retry and exponential backoff.

use std::sync::Arc;

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

pub struct OpenAiAdapter {
    id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl OpenAiAdapter {
    pub fn new(api_key: String) -> Self {
        Self {
            id: "openai".to_string(),
            client: reqwest::Client::new(),
            api_key,
            base_url: "https://api.openai.com/v1".to_string(),
        }
    }

    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }
}

struct OpenAiSession {
    provider_id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

#[async_trait::async_trait]
impl LlmSession for OpenAiSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(&self, messages: Vec<StandardMessage>, tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
        let msgs: Vec<serde_json::Value> = messages.iter().map(|m| {
            let mut obj = serde_json::json!({"role": m.role, "content": m.content});
            if let Some(ref id) = m.tool_call_id {
                obj["tool_call_id"] = serde_json::json!(id);
            }
            if let Some(ref tcs) = m.tool_calls {
                obj["tool_calls"] = serde_json::json!(tcs.iter().map(|tc| serde_json::json!({
                    "id": tc.id, "type": "function",
                    "function": {"name": tc.name, "arguments": tc.arguments.to_string()}
                })).collect::<Vec<_>>());
            }
            obj
        }).collect();

        let mut body = serde_json::json!({
            "model": "gpt-4",
            "messages": msgs,
        });

        if !tools.is_empty() {
            let tool_defs: Vec<serde_json::Value> = tools.iter().map(|t| serde_json::json!({
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.parameters}
            })).collect();
            body["tools"] = serde_json::json!(tool_defs);
        }

        let mut last_err = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000 * (1 << attempt))).await;
            }

            let result = self.client
                .post(format!("{}/chat/completions", self.base_url))
                .header("Authorization", format!("Bearer {}", self.api_key))
                .json(&body)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    let json: serde_json::Value = resp.json().await
                        .map_err(|e| ConnectorError::ProtocolError(e.to_string()))?;
                    let content = json["choices"][0]["message"]["content"]
                        .as_str().unwrap_or("").to_string();
                    let tokens = json["usage"]["total_tokens"].as_u64().unwrap_or(0) as u32;
                    let tool_calls = json["choices"][0]["message"]["tool_calls"]
                        .as_array()
                        .map(|arr| arr.iter().filter_map(|tc| {
                            Some(ToolCall {
                                id: tc["id"].as_str()?.to_string(),
                                name: tc["function"]["name"].as_str()?.to_string(),
                                arguments: serde_json::from_str(tc["function"]["arguments"].as_str()?).unwrap_or(serde_json::Value::Null),
                            })
                        }).collect())
                        .unwrap_or_default();
                    return Ok(LlmResponse {
                        content,
                        finish_reason: json["choices"][0]["finish_reason"].as_str().map(|s| s.to_string()),
                        tokens_used: tokens,
                        tool_calls,
                    });
                }
                Ok(resp) => {
                    last_err = Some(ConnectorError::ConnectionFailed(format!("HTTP {}", resp.status())));
                }
                Err(e) => {
                    last_err = Some(ConnectorError::ConnectionFailed(e.to_string()));
                }
            }
        }
        Err(last_err.unwrap())
    }

    fn provider_id(&self) -> &ProviderId { &self.provider_id }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for OpenAiAdapter {
    fn id(&self) -> &ProviderId { &self.id }
    fn name(&self) -> &str { "OpenAI" }
    fn provider_type(&self) -> ProviderType { ProviderType::Cloud }

    async fn is_available(&self) -> bool {
        self.client.get(format!("{}/models", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send().await.map(|r| r.status().is_success()).unwrap_or(false)
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(OpenAiSession {
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
