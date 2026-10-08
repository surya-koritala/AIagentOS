//! Hugging Face completion and explicitly selected chat-router protocols.
//! Legacy completions flatten chat turns; chat mode preserves messages and
//! native functions through the shared bounded OpenAI-shaped JSON/SSE codecs.

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

const DEFAULT_BASE_URL: &str = "https://api-inference.huggingface.co";
const DEFAULT_MODEL: &str = "meta-llama/Llama-3.1-8B-Instruct";
const CHAT_BASE_URL: &str = "https://router.huggingface.co/v1";

pub struct HuggingFaceAdapter {
    id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    chat_completions: bool,
}

impl HuggingFaceAdapter {
    pub fn new(api_key: String) -> Self {
        Self {
            id: "huggingface".to_string(),
            client: reqwest::Client::new(),
            api_key,
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            chat_completions: false,
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

    /// Select the router's OpenAI-shaped chat protocol. Model/provider selection
    /// is operator-owned; unsupported combinations return upstream errors.
    pub fn with_chat_completions(mut self) -> Self {
        self.chat_completions = true;
        self.base_url = CHAT_BASE_URL.into();
        self
    }
}

struct HuggingFaceSession {
    provider_id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    chat_completions: bool,
}

impl HuggingFaceSession {
    fn chat_request(
        &self,
        messages: &[StandardMessage],
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        stream: bool,
    ) -> reqwest::RequestBuilder {
        let body = if stream {
            crate::streaming::openai_streaming_body(messages, tools, options, Some(&self.model))
        } else {
            crate::openai_chat::request(messages, tools, options, Some(&self.model))
        };
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
        validate_provider_history(&messages, &self.provider_id, &self.model)?;
        if self.chat_completions {
            let response = self
                .chat_request(&messages, tools, options, false)
                .send()
                .await
                .map_err(|error| crate::transport_error(&self.provider_id, error))?;
            if !response.status().is_success() {
                return Err(crate::provider_http_error(&self.provider_id, response).await);
            }
            return crate::openai_chat::response(response, &self.provider_id).await;
        }
        if !tools.is_empty() {
            return Err(ConnectorError::ToolIncompatiblePrimary(kernel::ProviderErrorContext {
                provider: self.provider_id.clone(), message: "completion-only endpoint does not accept native tools; use the governed degraded-shim policy or explicit chat-completions mode".into(), request_id: None,
            }));
        }
        let prompt = flatten_prompt(&messages);
        let input_tokens = u32::try_from(prompt.len()).unwrap_or(u32::MAX);
        let mut body = serde_json::json!({
            "inputs": prompt,
            "parameters": {
                "return_full_text": false,
            },
        });
        if let Some(max_output_tokens) = options.max_output_tokens {
            body["parameters"]["max_new_tokens"] = serde_json::json!(max_output_tokens);
        }

        let url = format!("{}/models/{}", self.base_url, self.model);

        let mut req = self.client.post(&url).json(&body);
        if !self.api_key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
        }
        let result = req.send().await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                let json = crate::openai_chat::read_json(resp).await?;
                // TGI / Inference API returns either an array of
                // `{"generated_text": ...}` or a single such object.
                let content = json[0]["generated_text"]
                    .as_str()
                    .or_else(|| json["generated_text"].as_str())
                    .ok_or_else(|| {
                        ConnectorError::ProtocolError("missing completion generated text".into())
                    })?
                    .to_string();
                let output_tokens = u32::try_from(content.len()).unwrap_or(u32::MAX);
                Ok(LlmResponse {
                    provider_metadata: None,
                    content,
                    finish_reason: Some("stop".to_string()),
                    tokens_used: output_tokens,
                    usage: LlmUsage {
                        input_tokens,
                        output_tokens,
                        cached_tokens: 0,
                        provider_reported: false,
                    },
                    tool_calls: vec![],
                })
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
        self.send_streaming_controlled(
            messages,
            tools,
            options,
            &tokio_util::sync::CancellationToken::new(),
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
        if !self.chat_completions {
            return self
                .send_controlled(messages, tools, options, cancellation)
                .await;
        }
        validate_provider_history(&messages, &self.provider_id, &self.model)?;
        crate::streaming::send_openai_stream_controlled(
            &self.provider_id,
            self.chat_request(&messages, tools, options, true),
            options,
            cancellation,
            None,
        )
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
        if !self.chat_completions {
            let response = self
                .send_controlled(messages, tools, options, cancellation)
                .await?;
            if !response.content.is_empty() {
                events
                    .emit(ProviderStreamEvent::TextDelta(response.content.clone()))
                    .await;
            }
            return Ok(response);
        }
        validate_provider_history(&messages, &self.provider_id, &self.model)?;
        crate::streaming::send_openai_stream_controlled(
            &self.provider_id,
            self.chat_request(&messages, tools, options, true),
            options,
            cancellation,
            Some(events),
        )
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
    fn capabilities(&self) -> kernel::connector::ProviderCapabilities {
        kernel::connector::ProviderCapabilities {
            prompt_cancellation: true,
            native_streaming: self.chat_completions,
            tool_calls: self.chat_completions,
            parallel_tool_calls: self.chat_completions,
            api_family: if self.chat_completions {
                "huggingface-chat-completions-v1"
            } else {
                "huggingface-text-generation"
            }
            .into(),
            ..Default::default()
        }
    }

    async fn is_available(&self) -> bool {
        let url = if self.chat_completions {
            format!("{}/models", self.base_url.trim_end_matches('/'))
        } else {
            format!("{}/models/{}", self.base_url, self.model)
        };
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
            chat_completions: self.chat_completions,
        }))
    }

    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
        if self.chat_completions {
            return crate::openai_chat::request(
                std::slice::from_ref(msg),
                &[],
                LlmRequestOptions::default(),
                None,
            )["messages"][0]
                .clone();
        }
        serde_json::json!({"role": msg.role, "content": msg.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        if self.chat_completions {
            let role = value.get("role")?.as_str()?;
            if role == "assistant" {
                let response = crate::openai_chat::parse(
                    &serde_json::json!({"choices":[{"message":value}]}),
                    &self.id,
                )
                .ok()?;
                return Some(StandardMessage {
                    role: role.into(),
                    content: response.content.into(),
                    tool_call_id: None,
                    tool_calls: (!response.tool_calls.is_empty()).then_some(response.tool_calls),
                    provider_metadata: None,
                });
            }
            return Some(StandardMessage {
                role: role.into(),
                content: value.get("content")?.as_str()?.into(),
                tool_call_id: value
                    .get("tool_call_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                tool_calls: None,
                provider_metadata: None,
            });
        }
        Some(StandardMessage {
            provider_metadata: None,
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
                .into(),
            tool_call_id: None,
            tool_calls: None,
        })
    }
}
