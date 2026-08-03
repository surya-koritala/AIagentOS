//! Google Gemini (Generative Language API) adapter.
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
        let contents: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| {
                serde_json::json!({
                    "role": gemini_role(&m.role),
                    "parts": [{"text": m.content}],
                })
            })
            .collect();

        let mut body = serde_json::json!({ "contents": contents });
        if let Some(max_output_tokens) = options.max_output_tokens {
            body["generationConfig"] = serde_json::json!({
                "maxOutputTokens": max_output_tokens
            });
        }

        // The key travels in `x-goog-api-key`, never the query string: reqwest
        // renders the request URL into its `Display`, so a key in the URL would
        // reach transport error text, logs, and wire clients verbatim.
        let url = format!(
            "{}/v1beta/models/{}:generateContent",
            self.base_url, self.model
        );

        let result = self
            .client
            .post(&url)
            .header("x-goog-api-key", &self.api_key)
            .json(&body)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                let json: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ConnectorError::ProtocolError(e.to_string()))?;
                if let Some(error) = crate::content_filter_error(
                    &self.provider_id,
                    json["candidates"][0]["finishReason"].as_str(),
                ) {
                    return Err(error);
                }
                let content = json["candidates"][0]["content"]["parts"][0]["text"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                let tokens = crate::json_usage_u32(&json["usageMetadata"]["totalTokenCount"]);
                let finish_reason = json["candidates"][0]["finishReason"]
                    .as_str()
                    .map(|s| s.to_string());
                Ok(LlmResponse {
                    content,
                    finish_reason,
                    tokens_used: tokens,
                    usage: kernel::connector::LlmUsage::reported(
                        crate::json_usage_u32(&json["usageMetadata"]["promptTokenCount"]),
                        crate::json_usage_u32(&json["usageMetadata"]["candidatesTokenCount"]),
                        crate::json_usage_u32(&json["usageMetadata"]["cachedContentTokenCount"]),
                    ),
                    tool_calls: vec![],
                })
            }
            Ok(resp) => Err(crate::provider_http_error(&self.provider_id, resp).await),
            Err(e) => Err(crate::transport_error(&self.provider_id, e)),
        }
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
    fn capabilities(&self) -> kernel::connector::ProviderCapabilities {
        kernel::connector::ProviderCapabilities {
            prompt_cancellation: true,
            api_family: "gemini-generate-content-v1beta".into(),
            ..Default::default()
        }
    }

    async fn is_available(&self) -> bool {
        let url = format!("{}/v1beta/models", self.base_url);
        self.client
            .get(url)
            .header("x-goog-api-key", &self.api_key)
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
