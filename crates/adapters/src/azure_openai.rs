//! Azure OpenAI API adapter.
//!
//! Uses Azure's OpenAI Service endpoints which differ from standard OpenAI:
//! - Base URL: https://{resource}.openai.azure.com/openai/deployments/{deployment}
//! - Auth: api-key header instead of Bearer token
//! - API version query parameter required

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};
use tokio_stream::StreamExt;

const MAX_AZURE_STREAM_BYTES: usize = 8 * 1024 * 1024;

pub struct AzureOpenAiAdapter {
    id: ProviderId,
    client: reqwest::Client,
    api_key: String,
    /// e.g. "<https://myresource.openai.azure.com>"
    endpoint: String,
    /// e.g. "gpt-4o"
    deployment: String,
    /// e.g. "2024-08-01-preview"
    api_version: String,
}

impl AzureOpenAiAdapter {
    pub fn new(endpoint: String, deployment: String, api_key: String) -> Self {
        Self {
            id: "azure-openai".to_string(),
            client: reqwest::Client::new(),
            api_key,
            endpoint,
            deployment,
            api_version: "2024-08-01-preview".to_string(),
        }
    }

    pub fn with_api_version(mut self, version: String) -> Self {
        self.api_version = version;
        self
    }

    fn chat_url(&self) -> String {
        format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            self.endpoint.trim_end_matches('/'),
            self.deployment,
            self.api_version
        )
    }
}

struct AzureSession {
    provider_id: ProviderId,
    model_id: String,
    client: reqwest::Client,
    api_key: String,
    chat_url: String,
}

#[async_trait::async_trait]
impl LlmSession for AzureSession {
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
        let msgs: Vec<serde_json::Value> =
            messages
                .iter()
                .map(|m| {
                    let mut obj = serde_json::json!({"role": m.role, "content": m.content});
                    if let Some(ref id) = m.tool_call_id {
                        obj["tool_call_id"] = serde_json::json!(id);
                    }
                    if let Some(ref tcs) = m.tool_calls {
                        obj["tool_calls"] =
                            serde_json::json!(tcs.iter().map(|tc| serde_json::json!({
                    "id": tc.id, "type": "function",
                    "function": {"name": tc.name, "arguments": tc.arguments.to_string()}
                })).collect::<Vec<_>>());
                    }
                    obj
                })
                .collect();

        let mut body = serde_json::json!({ "messages": msgs });

        if !tools.is_empty() {
            let tool_defs: Vec<serde_json::Value> = tools.iter().map(|t| serde_json::json!({
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.parameters}
            })).collect();
            body["tools"] = serde_json::json!(tool_defs);
        }
        if let Some(max_output_tokens) = options.max_output_tokens {
            body["max_tokens"] = serde_json::json!(max_output_tokens);
        }

        let result = self
            .client
            .post(&self.chat_url)
            .header("api-key", &self.api_key)
            .header("Content-Type", "application/json")
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
                    json["choices"][0]["finish_reason"].as_str(),
                ) {
                    return Err(error);
                }
                let content = json["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                let tokens = crate::json_usage_u32(&json["usage"]["total_tokens"]);
                let tool_calls = json["choices"][0]["message"]["tool_calls"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|tc| {
                                Some(ToolCall {
                                    id: tc["id"].as_str()?.to_string(),
                                    name: tc["function"]["name"].as_str()?.to_string(),
                                    arguments: serde_json::from_str(
                                        tc["function"]["arguments"].as_str()?,
                                    )
                                    .unwrap_or(serde_json::Value::Null),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(LlmResponse {
                    content,
                    finish_reason: json["choices"][0]["finish_reason"]
                        .as_str()
                        .map(|s| s.to_string()),
                    tokens_used: tokens,
                    usage: kernel::connector::LlmUsage::reported(
                        crate::json_usage_u32(&json["usage"]["prompt_tokens"]),
                        crate::json_usage_u32(&json["usage"]["completion_tokens"]),
                        crate::json_usage_u32(
                            &json["usage"]["prompt_tokens_details"]["cached_tokens"],
                        ),
                    ),
                    tool_calls,
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
        &self.model_id
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
        let msgs: Vec<serde_json::Value> = messages.iter().map(|m| {
            let mut obj = serde_json::json!({"role": m.role, "content": m.content});
            if let Some(ref id) = m.tool_call_id { obj["tool_call_id"] = serde_json::json!(id); }
            if let Some(ref tcs) = m.tool_calls {
                obj["tool_calls"] = serde_json::json!(tcs.iter().map(|tc| serde_json::json!({
                    "id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": tc.arguments.to_string()}
                })).collect::<Vec<_>>());
            }
            obj
        }).collect();

        let mut body = serde_json::json!({"messages": msgs, "stream": true, "stream_options": {"include_usage": true}});
        if !tools.is_empty() {
            let tool_defs: Vec<serde_json::Value> = tools.iter().map(|t| serde_json::json!({
                "type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}
            })).collect();
            body["tools"] = serde_json::json!(tool_defs);
        }
        if let Some(max_output_tokens) = options.max_output_tokens {
            body["max_tokens"] = serde_json::json!(max_output_tokens);
        }

        let resp = self
            .client
            .post(&self.chat_url)
            .header("api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| crate::transport_error(&self.provider_id, e))?;

        if !resp.status().is_success() {
            return Err(crate::provider_http_error(&self.provider_id, resp).await);
        }

        let mut body_stream = resp.bytes_stream();
        let mut full_body = Vec::new();
        while let Some(chunk) = body_stream.next().await {
            let chunk = chunk.map_err(|e| ConnectorError::StreamError(e.to_string()))?;
            if full_body.len().saturating_add(chunk.len()) > MAX_AZURE_STREAM_BYTES {
                return Err(ConnectorError::ProtocolError(format!(
                    "azure streaming response exceeded {MAX_AZURE_STREAM_BYTES} bytes"
                )));
            }
            full_body.extend_from_slice(&chunk);
        }
        let full_body = String::from_utf8(full_body)
            .map_err(|_| ConnectorError::ProtocolError("azure stream was not UTF-8".into()))?;

        // If response is not SSE (e.g., from wiremock), parse as regular JSON
        if !full_body.starts_with("data:") {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&full_body) {
                if let Some(error) = crate::content_filter_error(
                    &self.provider_id,
                    json["choices"][0]["finish_reason"].as_str(),
                ) {
                    return Err(error);
                }
                let content = json["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                let tokens = crate::json_usage_u32(&json["usage"]["total_tokens"]);
                let tool_calls = json["choices"][0]["message"]["tool_calls"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|tc| {
                                Some(ToolCall {
                                    id: tc["id"].as_str()?.to_string(),
                                    name: tc["function"]["name"].as_str()?.to_string(),
                                    arguments: serde_json::from_str(
                                        tc["function"]["arguments"].as_str()?,
                                    )
                                    .unwrap_or(serde_json::Value::Null),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                return Ok(LlmResponse {
                    content,
                    finish_reason: json["choices"][0]["finish_reason"]
                        .as_str()
                        .map(ToString::to_string),
                    tokens_used: tokens,
                    usage: kernel::connector::LlmUsage::reported(
                        crate::json_usage_u32(&json["usage"]["prompt_tokens"]),
                        crate::json_usage_u32(&json["usage"]["completion_tokens"]),
                        crate::json_usage_u32(
                            &json["usage"]["prompt_tokens_details"]["cached_tokens"],
                        ),
                    ),
                    tool_calls,
                });
            }
        }

        // Parse SSE stream
        let mut content = String::new();
        let mut tool_calls: Vec<ToolCall> = Vec::new();
        let mut tool_args: std::collections::HashMap<usize, String> =
            std::collections::HashMap::new();
        let mut tokens_used: u32 = 0;
        let mut input_tokens: u32 = 0;
        let mut output_tokens: u32 = 0;
        let mut cached_tokens: u32 = 0;
        let mut finish_reason: Option<String> = None;

        for line in full_body.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if data == "[DONE]" {
                    continue;
                }
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(delta) = json["choices"].get(0).and_then(|c| c.get("delta")) {
                        if let Some(text) = delta["content"].as_str() {
                            content.push_str(text);
                        }
                        if let Some(tcs) = delta["tool_calls"].as_array() {
                            for tc in tcs {
                                let idx = tc["index"].as_u64().unwrap_or(0) as usize;
                                if let Some(id) = tc["id"].as_str() {
                                    let name =
                                        tc["function"]["name"].as_str().unwrap_or("").to_string();
                                    tool_calls.push(ToolCall {
                                        id: id.to_string(),
                                        name,
                                        arguments: serde_json::Value::Null,
                                    });
                                }
                                if let Some(args) = tc["function"]["arguments"].as_str() {
                                    tool_args.entry(idx).or_default().push_str(args);
                                }
                            }
                        }
                    }
                    if let Some(reason) = json["choices"]
                        .get(0)
                        .and_then(|choice| choice["finish_reason"].as_str())
                    {
                        if let Some(error) =
                            crate::content_filter_error(&self.provider_id, Some(reason))
                        {
                            return Err(error);
                        }
                        finish_reason = Some(reason.to_string());
                    }
                    if let Some(usage) = json.get("usage") {
                        tokens_used = crate::json_usage_u32(&usage["total_tokens"]);
                        input_tokens = crate::json_usage_u32(&usage["prompt_tokens"]);
                        output_tokens = crate::json_usage_u32(&usage["completion_tokens"]);
                        cached_tokens =
                            crate::json_usage_u32(&usage["prompt_tokens_details"]["cached_tokens"]);
                    }
                }
            }
        }

        for (idx, args) in &tool_args {
            if let Some(tc) = tool_calls.get_mut(*idx) {
                tc.arguments = serde_json::from_str(args).unwrap_or(serde_json::Value::Null);
            }
        }

        Ok(LlmResponse {
            content,
            finish_reason,
            tokens_used,
            usage: if input_tokens > 0 || output_tokens > 0 {
                kernel::connector::LlmUsage::reported(input_tokens, output_tokens, cached_tokens)
            } else {
                Default::default()
            },
            tool_calls,
        })
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for AzureOpenAiAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn name(&self) -> &str {
        "Azure OpenAI"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Cloud
    }
    fn capabilities(&self) -> kernel::connector::ProviderCapabilities {
        kernel::connector::ProviderCapabilities {
            native_streaming: true,
            tool_calls: true,
            parallel_tool_calls: true,
            prompt_cancellation: true,
            api_family: "azure-openai".into(),
            ..Default::default()
        }
    }

    async fn is_available(&self) -> bool {
        // Azure endpoints don't respond to bare GET — just check we have credentials
        !self.api_key.is_empty() && !self.endpoint.is_empty()
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(AzureSession {
            provider_id: self.id.clone(),
            model_id: self.deployment.clone(),
            client: self.client.clone(),
            api_key: self.api_key.clone(),
            chat_url: self.chat_url(),
        }))
    }

    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": msg.role, "content": msg.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage {
            role: value.get("role")?.as_str()?.to_string(),
            content: value
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            tool_call_id: None,
            tool_calls: None,
        })
    }
}
