//! Local LLM adapter (Ollama/llama.cpp) via HTTP.

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

pub struct LocalLlmAdapter {
    id: ProviderId,
    client: reqwest::Client,
    base_url: String,
    model: String,
}

impl LocalLlmAdapter {
    pub fn new(base_url: String, model: String) -> Self {
        Self {
            id: "local".to_string(),
            client: reqwest::Client::new(),
            base_url,
            model,
        }
    }
}

struct LocalSession {
    provider_id: ProviderId,
    client: reqwest::Client,
    base_url: String,
    model: String,
}

#[async_trait::async_trait]
impl LlmSession for LocalSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": messages.iter().map(|m| serde_json::json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
            "stream": false,
        });

        let resp = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| ConnectorError::ConnectionFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ConnectorError::ConnectionFailed(format!(
                "HTTP {}",
                resp.status()
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ConnectorError::ProtocolError(e.to_string()))?;
        let content = json["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(LlmResponse {
            content,
            finish_reason: Some("stop".to_string()),
            tokens_used: json["eval_count"].as_u64().unwrap_or(0) as u32,
            tool_calls: vec![],
        })
    }

    fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for LocalLlmAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn name(&self) -> &str {
        "Local LLM (Ollama)"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        self.client
            .get(format!("{}/api/tags", self.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(LocalSession {
            provider_id: self.id.clone(),
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
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
