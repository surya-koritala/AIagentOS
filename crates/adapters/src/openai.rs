//! OpenAI API adapter.

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

pub struct OpenAiAdapter {
    id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    image_profile: Option<kernel::connector::ImageInputProfile>,
}

impl OpenAiAdapter {
    pub fn new(api_key: String) -> Self {
        Self {
            id: "openai".to_string(),
            client: reqwest::Client::new(),
            image_profile: None,
            api_key,
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4".to_string(),
        }
    }

    /// Declare a conservative image-token bound for the exact selected model.
    pub fn with_image_input_profile(
        mut self,
        profile: kernel::connector::ImageInputProfile,
    ) -> Self {
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

struct OpenAiSession {
    provider_id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    image_profile: Option<kernel::connector::ImageInputProfile>,
}

impl OpenAiSession {
    fn streaming_request(
        &self,
        messages: &[StandardMessage],
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> reqwest::RequestBuilder {
        let body =
            crate::streaming::openai_streaming_body(messages, tools, options, Some(&self.model));
        let request = self
            .client
            .post(format!(
                "{}/chat/completions",
                self.base_url.trim_end_matches('/')
            ))
            .json(&body);
        if self.api_key.is_empty() {
            request
        } else {
            request.bearer_auth(&self.api_key)
        }
    }
}

#[async_trait::async_trait]
impl LlmSession for OpenAiSession {
    fn validate_content(&self, messages: &[StandardMessage]) -> Result<u32, ConnectorError> {
        crate::vision::preflight(
            &self.provider_id,
            &self.model,
            self.image_profile.as_ref(),
            messages,
        )
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
        let body = crate::openai_chat::request(&messages, tools, options, Some(&self.model));

        let result = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                crate::openai_chat::response(resp, &self.provider_id).await
            }
            Ok(resp) => Err(crate::vision::protect_error(
                crate::provider_http_error(&self.provider_id, resp).await,
                &messages,
            )),
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
        let cancellation = tokio_util::sync::CancellationToken::new();
        self.send_streaming_controlled(messages, tools, options, &cancellation)
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
        crate::streaming::send_openai_stream_controlled(
            &self.provider_id,
            self.streaming_request(&messages, tools, options),
            options,
            cancellation,
            None,
        )
        .await
        .map_err(|error| crate::vision::protect_error(error, &messages))
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
        crate::streaming::send_openai_stream_controlled(
            &self.provider_id,
            self.streaming_request(&messages, tools, options),
            options,
            cancellation,
            Some(events),
        )
        .await
        .map_err(|error| crate::vision::protect_error(error, &messages))
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
impl LlmProviderAdapter for OpenAiAdapter {
    fn validate_content(&self, messages: &[StandardMessage]) -> Result<u32, ConnectorError> {
        crate::vision::preflight(&self.id, &self.model, self.image_profile.as_ref(), messages)
    }
    fn image_input_profile(&self) -> Option<&kernel::connector::ImageInputProfile> {
        self.image_profile.as_ref()
    }

    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn name(&self) -> &str {
        "OpenAI"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }
    fn capabilities(&self) -> kernel::connector::ProviderCapabilities {
        kernel::connector::ProviderCapabilities {
            model_discovery: true,
            vision: self
                .image_profile
                .as_ref()
                .is_some_and(|profile| profile.validate(&self.model).is_ok()),
            native_streaming: true,
            tool_calls: true,
            parallel_tool_calls: true,
            prompt_cancellation: true,
            api_family: "openai-v1".into(),
            ..Default::default()
        }
    }

    async fn list_models(&self) -> Result<Vec<String>, ConnectorError> {
        crate::model_discovery::discover(
            &self.id,
            &self.base_url,
            crate::model_discovery::DiscoveryApi::OpenAi,
            &self.api_key,
        )
        .await
    }

    async fn is_available(&self) -> bool {
        self.client
            .get(format!("{}/models", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(OpenAiSession {
            provider_id: self.id.clone(),
            client: self.client.clone(),
            image_profile: self.image_profile.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
        }))
    }

    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": msg.role, "content": crate::vision::openai_content(&msg.content)})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage {
            provider_metadata: None,
            role: value.get("role")?.as_str()?.to_string(),
            content: value.get("content")?.as_str().unwrap_or("").into(),
            tool_call_id: None,
            tool_calls: None,
        })
    }
}
