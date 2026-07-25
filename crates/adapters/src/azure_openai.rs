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

#[derive(Default)]
struct AzureStreamState {
    content: String,
    tool_calls: Vec<ToolCall>,
    tool_args: std::collections::HashMap<usize, String>,
    tokens_used: u32,
    input_tokens: u32,
    output_tokens: u32,
    cached_tokens: u32,
    finish_reason: Option<String>,
}

fn sse_delimiter(buffer: &[u8]) -> Option<(usize, usize)> {
    let lf = buffer.windows(2).position(|window| window == b"\n\n");
    let crlf = buffer.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(left), Some(right)) if left <= right => Some((left, 2)),
        (Some(left), Some(_)) => Some((left, 2)),
        (None, Some(right)) => Some((right, 4)),
        (Some(left), None) => Some((left, 2)),
        (None, None) => None,
    }
}

impl AzureSession {
    fn streaming_body(
        messages: &[StandardMessage],
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> serde_json::Value {
        let msgs = messages
            .iter()
            .map(|message| {
                let mut value =
                    serde_json::json!({"role": message.role, "content": message.content});
                if let Some(tool_call_id) = message.tool_call_id.as_ref() {
                    value["tool_call_id"] = serde_json::json!(tool_call_id);
                }
                if let Some(tool_calls) = message.tool_calls.as_ref() {
                    value["tool_calls"] = serde_json::json!(tool_calls
                        .iter()
                        .map(|tool_call| serde_json::json!({
                            "id": tool_call.id,
                            "type": "function",
                            "function": {
                                "name": tool_call.name,
                                "arguments": tool_call.arguments.to_string()
                            }
                        }))
                        .collect::<Vec<_>>());
                }
                value
            })
            .collect::<Vec<_>>();
        let mut body = serde_json::json!({
            "messages": msgs,
            "stream": true,
            "stream_options": {"include_usage": true}
        });
        if !tools.is_empty() {
            body["tools"] = serde_json::json!(tools
                .iter()
                .map(|tool| serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters
                    }
                }))
                .collect::<Vec<_>>());
        }
        if let Some(max_output_tokens) = options.max_output_tokens {
            body["max_tokens"] = serde_json::json!(max_output_tokens);
        }
        body
    }

    fn regular_stream_response(
        &self,
        json: &serde_json::Value,
    ) -> Result<LlmResponse, ConnectorError> {
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
        let tool_calls = json["choices"][0]["message"]["tool_calls"]
            .as_array()
            .map(|calls| {
                calls
                    .iter()
                    .filter_map(|call| {
                        Some(ToolCall {
                            id: call["id"].as_str()?.to_string(),
                            name: call["function"]["name"].as_str()?.to_string(),
                            arguments: serde_json::from_str(
                                call["function"]["arguments"].as_str()?,
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
                .map(ToString::to_string),
            tokens_used: crate::json_usage_u32(&json["usage"]["total_tokens"]),
            usage: kernel::connector::LlmUsage::reported(
                crate::json_usage_u32(&json["usage"]["prompt_tokens"]),
                crate::json_usage_u32(&json["usage"]["completion_tokens"]),
                crate::json_usage_u32(&json["usage"]["prompt_tokens_details"]["cached_tokens"]),
            ),
            tool_calls,
        })
    }

    async fn apply_sse_event(
        &self,
        event: &[u8],
        state: &mut AzureStreamState,
        events: &ProviderEventSink,
    ) -> Result<(), ConnectorError> {
        let event = std::str::from_utf8(event)
            .map_err(|_| ConnectorError::ProtocolError("azure stream was not UTF-8".into()))?;
        for line in event.lines() {
            let line = line.trim_end_matches('\r');
            let Some(data) = line
                .strip_prefix("data:")
                .map(str::trim_start)
                .filter(|data| !data.is_empty() && *data != "[DONE]")
            else {
                continue;
            };
            let json = serde_json::from_str::<serde_json::Value>(data)
                .map_err(|error| ConnectorError::ProtocolError(error.to_string()))?;
            if let Some(delta) = json["choices"]
                .get(0)
                .and_then(|choice| choice.get("delta"))
            {
                if let Some(text) = delta["content"].as_str().filter(|text| !text.is_empty()) {
                    state.content.push_str(text);
                    events
                        .emit(ProviderStreamEvent::TextDelta(text.to_string()))
                        .await;
                }
                if let Some(tool_calls) = delta["tool_calls"].as_array() {
                    for call in tool_calls {
                        let index = call["index"].as_u64().unwrap_or(0) as usize;
                        if let Some(id) = call["id"].as_str() {
                            if state.tool_calls.len() <= index {
                                state.tool_calls.resize_with(index + 1, || ToolCall {
                                    id: String::new(),
                                    name: String::new(),
                                    arguments: serde_json::Value::Null,
                                });
                            }
                            state.tool_calls[index].id = id.to_string();
                            state.tool_calls[index].name =
                                call["function"]["name"].as_str().unwrap_or("").to_string();
                        }
                        if let Some(arguments) = call["function"]["arguments"].as_str() {
                            state
                                .tool_args
                                .entry(index)
                                .or_default()
                                .push_str(arguments);
                        }
                    }
                }
            }
            if let Some(reason) = json["choices"]
                .get(0)
                .and_then(|choice| choice["finish_reason"].as_str())
            {
                if let Some(error) = crate::content_filter_error(&self.provider_id, Some(reason)) {
                    return Err(error);
                }
                state.finish_reason = Some(reason.to_string());
            }
            if let Some(usage) = json.get("usage") {
                state.tokens_used = crate::json_usage_u32(&usage["total_tokens"]);
                state.input_tokens = crate::json_usage_u32(&usage["prompt_tokens"]);
                state.output_tokens = crate::json_usage_u32(&usage["completion_tokens"]);
                state.cached_tokens =
                    crate::json_usage_u32(&usage["prompt_tokens_details"]["cached_tokens"]);
            }
        }
        Ok(())
    }

    async fn send_streaming_events(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        events: ProviderEventSink,
    ) -> Result<LlmResponse, ConnectorError> {
        let body = Self::streaming_body(&messages, tools, options);
        let response = self
            .client
            .post(&self.chat_url)
            .header("api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|error| crate::transport_error(&self.provider_id, error))?;
        if !response.status().is_success() {
            return Err(crate::provider_http_error(&self.provider_id, response).await);
        }

        let mut is_sse = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"));
        let mut bytes = response.bytes_stream();
        let mut total_bytes = 0_usize;
        let mut buffer = Vec::new();
        let mut state = AzureStreamState::default();

        while let Some(chunk) = bytes.next().await {
            let chunk = chunk.map_err(|error| ConnectorError::StreamError(error.to_string()))?;
            total_bytes = total_bytes.saturating_add(chunk.len());
            if total_bytes > MAX_AZURE_STREAM_BYTES {
                return Err(ConnectorError::ProtocolError(format!(
                    "azure streaming response exceeded {MAX_AZURE_STREAM_BYTES} bytes"
                )));
            }
            buffer.extend_from_slice(&chunk);
            let first_non_whitespace = buffer
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .unwrap_or(buffer.len());
            if !is_sse && buffer[first_non_whitespace..].starts_with(b"data:") {
                // Some compatible gateways omit or rewrite Content-Type. The
                // SSE data prefix is unambiguous and preserves incremental
                // delivery instead of buffering the whole response.
                is_sse = true;
            }
            if !is_sse {
                continue;
            }
            while let Some((position, delimiter_len)) = sse_delimiter(&buffer) {
                let event = buffer[..position].to_vec();
                buffer.drain(..position + delimiter_len);
                self.apply_sse_event(&event, &mut state, &events).await?;
            }
        }

        if !is_sse {
            let json = serde_json::from_slice::<serde_json::Value>(&buffer)
                .map_err(|error| ConnectorError::ProtocolError(error.to_string()))?;
            let response = self.regular_stream_response(&json)?;
            if !response.content.is_empty() {
                events
                    .emit(ProviderStreamEvent::TextDelta(response.content.clone()))
                    .await;
            }
            return Ok(response);
        }
        if !buffer.is_empty() {
            self.apply_sse_event(&buffer, &mut state, &events).await?;
        }
        for (index, arguments) in &state.tool_args {
            if let Some(tool_call) = state.tool_calls.get_mut(*index) {
                tool_call.arguments =
                    serde_json::from_str(arguments).unwrap_or(serde_json::Value::Null);
            }
        }
        Ok(LlmResponse {
            content: state.content,
            finish_reason: state.finish_reason,
            tokens_used: state.tokens_used,
            usage: if state.input_tokens > 0 || state.output_tokens > 0 {
                LlmUsage::reported(state.input_tokens, state.output_tokens, state.cached_tokens)
            } else {
                LlmUsage::default()
            },
            tool_calls: state.tool_calls,
        })
    }
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

    async fn send_streaming_events_controlled(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: ProviderEventSink,
    ) -> Result<LlmResponse, ConnectorError> {
        let timeout = options.timeout;
        let provider_id = self.provider_id.clone();
        let send = self.send_streaming_events(messages, tools, options, events);
        tokio::pin!(send);
        match timeout {
            Some(timeout) => {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        Err(ConnectorError::cancelled(provider_id, None))
                    }
                    result = tokio::time::timeout(timeout, &mut send) => {
                        result.unwrap_or_else(|_| {
                            Err(ConnectorError::timeout(
                                provider_id,
                                format!("attempt exceeded {} ms", timeout.as_millis()),
                                None,
                            ))
                        })
                    }
                }
            }
            None => {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        Err(ConnectorError::cancelled(provider_id, None))
                    }
                    result = &mut send => result,
                }
            }
        }
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
