//! Google Gemini (Generative Language API) adapter with retry and exponential backoff.
//!
//! Uses Gemini's native `generateContent` shape rather than an OpenAI-compatible
//! surface: requests carry a `contents` array of role-tagged `parts`, and the
//! API key travels as a query parameter. Roles map `assistant` -> `model`,
//! everything else -> `user`.

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com";
const DEFAULT_MODEL: &str = "gemini-1.5-flash";

pub struct GeminiAdapter {
    id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
}

impl GeminiAdapter {
    pub fn new(api_key: String) -> Self {
        Self {
            id: "gemini".to_string(),
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

struct GeminiSession {
    provider_id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
}

/// Maps a standard chat role to Gemini's role vocabulary (`user` / `model`).
fn gemini_role(role: &str) -> &'static str {
    match role {
        "assistant" | "model" => "model",
        _ => "user",
    }
}

#[async_trait::async_trait]
impl LlmSession for GeminiSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        let contents: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| {
                serde_json::json!({
                    "role": gemini_role(&m.role),
                    "parts": [{"text": m.content}],
                })
            })
            .collect();

        let body = serde_json::json!({ "contents": contents });

        let url = format!(
            "{}/v1beta/models/{}:generateContent?key={}",
            self.base_url, self.model, self.api_key
        );

        let mut last_err = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000 * (1 << attempt))).await;
            }

            let result = self.client.post(&url).json(&body).send().await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    let json: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| ConnectorError::ProtocolError(e.to_string()))?;
                    let content = json["candidates"][0]["content"]["parts"][0]["text"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let tokens = json["usageMetadata"]["totalTokenCount"]
                        .as_u64()
                        .unwrap_or(0) as u32;
                    let finish_reason = json["candidates"][0]["finishReason"]
                        .as_str()
                        .map(|s| s.to_string());
                    return Ok(LlmResponse {
                        content,
                        finish_reason,
                        tokens_used: tokens,
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
impl LlmProviderAdapter for GeminiAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn name(&self) -> &str {
        "Google Gemini"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }

    async fn is_available(&self) -> bool {
        let url = format!("{}/v1beta/models?key={}", self.base_url, self.api_key);
        self.client
            .get(url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(GeminiSession {
            provider_id: self.id.clone(),
            client: self.client.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
        }))
    }

    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
        serde_json::json!({
            "role": gemini_role(&msg.role),
            "parts": [{"text": msg.content}],
        })
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        let role = value.get("role")?.as_str()?;
        let text = value["parts"][0]["text"].as_str().unwrap_or("").to_string();
        let std_role = if role == "model" { "assistant" } else { "user" };
        Some(StandardMessage {
            role: std_role.to_string(),
            content: text,
            tool_call_id: None,
            tool_calls: None,
        })
    }
}
