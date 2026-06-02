//! HuggingFace adapter (Text Generation Inference / Inference API) with retry and
//! exponential backoff.
//!
//! Uses the native text-generation shape: POST `{base}/models/{model}` with a
//! `{"inputs": "...", "parameters": {...}}` body and a Bearer token. The response
//! is an array of `{"generated_text": "..."}` objects. Chat turns are flattened
//! into a single prompt since the endpoint is completion-style.

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

const DEFAULT_BASE_URL: &str = "https://api-inference.huggingface.co";
const DEFAULT_MODEL: &str = "meta-llama/Llama-3.1-8B-Instruct";

pub struct HuggingFaceAdapter {
    id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
}

impl HuggingFaceAdapter {
    pub fn new(api_key: String) -> Self {
        Self {
            id: "huggingface".to_string(),
            client: reqwest::Client::new(),
            api_key,
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
        }
    }

    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }

    pub fn with_model(mut self, model: String) -> Self {
        self.model = model;
        self
    }
}

struct HuggingFaceSession {
    provider_id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
}

/// Flattens chat turns into a single prompt string for the completion endpoint.
fn flatten_prompt(messages: &[StandardMessage]) -> String {
    let mut prompt = String::new();
    for m in messages {
        prompt.push_str(&m.role);
        prompt.push_str(": ");
        prompt.push_str(&m.content);
        prompt.push('\n');
    }
    prompt.push_str("assistant: ");
    prompt
}

#[async_trait::async_trait]
impl LlmSession for HuggingFaceSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        let body = serde_json::json!({
            "inputs": flatten_prompt(&messages),
            "parameters": {
                "return_full_text": false,
            },
        });

        let url = format!("{}/models/{}", self.base_url, self.model);

        let mut last_err = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000 * (1 << attempt))).await;
            }

            let mut req = self.client.post(&url).json(&body);
            if !self.api_key.is_empty() {
                req = req.header("Authorization", format!("Bearer {}", self.api_key));
            }
            let result = req.send().await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    let json: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| ConnectorError::ProtocolError(e.to_string()))?;
                    // TGI / Inference API returns either an array of
                    // `{"generated_text": ...}` or a single such object.
                    let content = json[0]["generated_text"]
                        .as_str()
                        .or_else(|| json["generated_text"].as_str())
                        .unwrap_or("")
                        .to_string();
                    return Ok(LlmResponse {
                        content,
                        finish_reason: Some("stop".to_string()),
                        tokens_used: 0,
                        tool_calls: vec![],
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
impl LlmProviderAdapter for HuggingFaceAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn name(&self) -> &str {
        "HuggingFace"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }

    async fn is_available(&self) -> bool {
        let url = format!("{}/models/{}", self.base_url, self.model);
        let mut req = self.client.get(url);
        if !self.api_key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
        }
        req.send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(HuggingFaceSession {
            provider_id: self.id.clone(),
            client: self.client.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
        }))
    }

    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": msg.role, "content": msg.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage {
            role: value
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("assistant")
                .to_string(),
            content: value
                .get("generated_text")
                .or_else(|| value.get("content"))
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string(),
            tool_call_id: None,
            tool_calls: None,
        })
    }
}
