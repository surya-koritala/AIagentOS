//! Google Gemini (Generative Language API) adapter.
//!
//! Uses Gemini's native `generateContent` shape rather than an OpenAI-compatible
//! surface: requests carry a `contents` array of role-tagged `parts`, and the
//! API key travels in a header. Native function calls, results and signed
//! assistant parts survive durable multi-step conversations.

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

#[path = "gemini_protocol.rs"]
mod protocol;

const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com";
const DEFAULT_MODEL: &str = "gemini-1.5-flash";

pub struct GeminiAdapter {
    id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    image_profile: Option<kernel::connector::ImageInputProfile>,
}

impl GeminiAdapter {
    pub fn new(api_key: String) -> Self {
        Self {
            id: "gemini".to_string(),
            client: reqwest::Client::new(),
            image_profile: None,
            api_key,
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
        }
    }

    /// Declare a conservative image-token bound for the exact selected model.
    pub fn with_image_input_profile(mut self, profile: kernel::connector::ImageInputProfile) -> Self {
        self.image_profile = Some(profile);
        self
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
    image_profile: Option<kernel::connector::ImageInputProfile>,
}

impl GeminiSession {
    async fn stream(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: Option<ProviderEventSink>,
    ) -> Result<LlmResponse, ConnectorError> {
        let mut body = protocol::request(&messages, tools, &self.provider_id, &self.model)?;
        if let Some(max_output_tokens) = options.max_output_tokens {
            body["generationConfig"] = serde_json::json!({"maxOutputTokens": max_output_tokens});
        }
        let request = self
            .client
            .post(format!(
                "{}/v1beta/models/{}:streamGenerateContent?alt=sse",
                self.base_url.trim_end_matches('/'),
                self.model
            ))
            .header("x-goog-api-key", &self.api_key)
            .json(&body);
        let state = protocol::GeminiStream::new(self.provider_id.clone(), self.model.clone());
        crate::streaming::send_native_sse_controlled(
            &self.provider_id,
            request,
            state,
            options,
            cancellation,
            events,
        )
        .await
    }
}

#[async_trait::async_trait]
impl LlmSession for GeminiSession {
    fn validate_content(&self, messages: &[StandardMessage]) -> Result<u32, ConnectorError> {
        crate::vision::preflight(&self.provider_id, &self.model, self.image_profile.as_ref(), messages)
    }

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
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.validate_content(&messages)?;
        let mut body = protocol::request(&messages, tools, &self.provider_id, &self.model)?;
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
                let bytes = protocol::response_bytes(resp).await?;
                let json: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
                    ConnectorError::ProtocolError("invalid Gemini response JSON".into())
                })?;
                protocol::response(&json, &self.provider_id, &self.model)
            }
            Ok(resp) => Err(crate::provider_http_error(&self.provider_id, resp).await),
            Err(e) => Err(crate::transport_error(&self.provider_id, e)),
        }
    }

    async fn send_streaming(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_streaming_with_options(messages, tools, LlmRequestOptions::default())
            .await
    }

    async fn send_streaming_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.stream(
            messages,
            tools,
            options,
            &tokio_util::sync::CancellationToken::new(),
            None,
        )
        .await
    }

    async fn send_streaming_controlled(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<LlmResponse, ConnectorError> {
        self.validate_content(&messages)?;
        self.stream(messages, tools, options, cancellation, None)
            .await
    }

    async fn send_streaming_events_controlled(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: ProviderEventSink,
    ) -> Result<LlmResponse, ConnectorError> {
        self.validate_content(&messages)?;
        self.stream(messages, tools, options, cancellation, Some(events))
            .await
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
    fn validate_content(&self, messages: &[StandardMessage]) -> Result<u32, ConnectorError> {
        crate::vision::preflight(&self.id, &self.model, self.image_profile.as_ref(), messages)
    }
    fn image_input_profile(&self) -> Option<&kernel::connector::ImageInputProfile> { self.image_profile.as_ref() }

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
            vision: self.image_profile.is_some(),
            native_streaming: true,
            tool_calls: true,
            parallel_tool_calls: true,
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
            image_profile: self.image_profile.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
        }))
    }

    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
        // Pairing tool results requires complete history. The session request
        // compiler is the fallible authority for multi-step conversations.
        protocol::single_message(msg, &self.id, &self.model)
            .ok()
            .unwrap_or(serde_json::Value::Null)
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        protocol::message(value, &self.id, &self.model).ok()
    }
}
