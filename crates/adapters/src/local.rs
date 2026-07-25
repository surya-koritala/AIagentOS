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
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_options(messages, tools, LlmRequestOptions::default())
            .await
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        let mut body = serde_json::json!({
            "model": self.model,
            "messages": messages.iter().map(|m| serde_json::json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
            "stream": false,
        });
        if let Some(max_output_tokens) = options.max_output_tokens {
            body["options"] = serde_json::json!({
                "num_predict": max_output_tokens
            });
        }

        let resp = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| crate::transport_error(&self.provider_id, e))?;

        if !resp.status().is_success() {
            return Err(crate::provider_http_error(&self.provider_id, resp).await);
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ConnectorError::ProtocolError(e.to_string()))?;
        let content = json["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let prompt_tokens = json["prompt_eval_count"].as_u64().unwrap_or(0);
        let output_tokens = json["eval_count"].as_u64().unwrap_or(0);

        Ok(LlmResponse {
            content,
            finish_reason: Some("stop".to_string()),
            tokens_used: crate::saturating_usage_sum(prompt_tokens, output_tokens),
            usage: kernel::connector::LlmUsage::reported(
                crate::saturating_usage_u32(prompt_tokens),
                crate::saturating_usage_u32(output_tokens),
                0,
            ),
            tool_calls: vec![],
        })
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }

    fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    fn model_id(&self) -> &str {
        &self.model
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
    fn capabilities(&self) -> kernel::connector::ProviderCapabilities {
        kernel::connector::ProviderCapabilities {
            prompt_cancellation: true,
            api_family: "ollama-v1".into(),
            ..Default::default()
        }
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
