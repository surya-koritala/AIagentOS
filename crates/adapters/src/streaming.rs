//! Bounded OpenAI-compatible SSE decoding shared by hosted and local adapters.

use std::collections::{BTreeMap, HashSet};

use kernel::connector::*;
use kernel::ConnectorError;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

/// Aggregate wire ceiling, including comments and unfinished events.
pub const MAX_OPENAI_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOOL_CALLS: usize = 64;
const MAX_TOOL_IDENTITY_BYTES: usize = 1024;

/// Compatibility events for callers of [`parse_azure_sse_stream`].
#[derive(Debug, Clone)]
pub enum StreamChunk {
    Token(String),
    ToolCallStart { id: String, name: String },
    ToolCallDelta { id: String, arguments_delta: String },
    Done { tokens_used: u32 },
}

enum StreamSink {
    Kernel(Option<ProviderEventSink>),
    Legacy(mpsc::Sender<StreamChunk>),
}

impl StreamSink {
    async fn text(&self, text: &str) {
        match self {
            Self::Kernel(Some(sink)) => {
                sink.emit(ProviderStreamEvent::TextDelta(text.to_string()))
                    .await;
            }
            Self::Legacy(sender) => {
                let _ = sender.send(StreamChunk::Token(text.to_string())).await;
            }
            Self::Kernel(None) => {}
        }
    }
}

/// Build streaming requests without serializing kernel-only message fields.
pub(crate) fn openai_streaming_body(
    messages: &[StandardMessage],
    tools: &[ToolDefinition],
    options: LlmRequestOptions,
    model: Option<&str>,
) -> Value {
    let messages: Vec<_> = messages
        .iter()
        .map(|message| {
            let mut value = json!({"role": message.role, "content": message.content});
            if let Some(id) = &message.tool_call_id {
                value["tool_call_id"] = json!(id);
            }
            if let Some(calls) = &message.tool_calls {
                value["tool_calls"] = json!(calls
                    .iter()
                    .map(|call| json!({
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": call.arguments.to_string()
                        }
                    }))
                    .collect::<Vec<_>>());
            }
            value
        })
        .collect();
    let mut body = json!({
        "messages": messages,
        "stream": true,
        "stream_options": {"include_usage": true}
    });
    if let Some(model) = model {
        body["model"] = json!(model);
    }
    if let Some(max_output_tokens) = options.max_output_tokens {
        body["max_tokens"] = json!(max_output_tokens);
    }
    if !tools.is_empty() {
        body["tools"] = json!(tools
            .iter()
            .map(|tool| json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters
                }
            }))
            .collect::<Vec<_>>());
    }
    body
}

/// Cancellation and deadline stay active during HTTP I/O and sink backpressure.
pub(crate) async fn send_openai_stream_controlled(
    provider: &str,
    request: reqwest::RequestBuilder,
    options: LlmRequestOptions,
    cancellation: &tokio_util::sync::CancellationToken,
    events: Option<ProviderEventSink>,
) -> Result<LlmResponse, ConnectorError> {
    let send = async {
        let response = request
            .send()
            .await
            .map_err(|error| crate::transport_error(provider, error))?;
        if !response.status().is_success() {
            return Err(crate::provider_http_error(provider, response).await);
        }
        parse_openai_stream(response, provider, StreamSink::Kernel(events)).await
    };
    tokio::pin!(send);
    match options.timeout {
        Some(timeout) => {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    Err(ConnectorError::cancelled(provider.to_string(), None))
                }
                result = tokio::time::timeout(timeout, &mut send) => {
                    result.unwrap_or_else(|_| {
                        Err(ConnectorError::timeout(
                            provider.to_string(),
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
                    Err(ConnectorError::cancelled(provider.to_string(), None))
                }
                result = &mut send => result,
            }
        }
    }
}

#[derive(Default)]
struct PendingTool {
    id: String,
    name: String,
    arguments: String,
    legacy_started: bool,
}

#[derive(Default)]
struct StreamState {
    content: String,
    tools: BTreeMap<usize, PendingTool>,
    finish_reason: Option<String>,
    usage: LlmUsage,
    tokens_used: u32,
    done: bool,
}

fn protocol(message: &str) -> ConnectorError {
    ConnectorError::ProtocolError(format!("OpenAI-compatible stream: {message}"))
}

fn update_identity(target: &mut String, value: &Value) -> Result<(), ConnectorError> {
    if value.is_null() {
        return Ok(());
    }
    let text = value
        .as_str()
        .filter(|text| !text.is_empty() && text.len() <= MAX_TOOL_IDENTITY_BYTES)
        .ok_or_else(|| protocol("invalid tool identity"))?;
    if !target.is_empty() && target != text {
        return Err(protocol("tool identity changed between deltas"));
    }
    *target = text.to_string();
    Ok(())
}

fn read_usage(json: &Value) -> Option<(LlmUsage, u32)> {
    let usage = json
        .get("usage")
        .and_then(Value::as_object)
        .or_else(|| json["x_groq"]["usage"].as_object())?;
    let input = crate::json_usage_u32(usage.get("prompt_tokens").unwrap_or(&Value::Null));
    let output = crate::json_usage_u32(usage.get("completion_tokens").unwrap_or(&Value::Null));
    let cached = usage
        .get("prompt_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .or_else(|| usage.get("prompt_cache_hit_tokens"))
        .map(crate::json_usage_u32)
        .unwrap_or(0);
    let total = usage
        .get("total_tokens")
        .map(crate::json_usage_u32)
        .unwrap_or_else(|| input.saturating_add(output));
    Some((LlmUsage::reported(input, output, cached), total))
}

impl StreamState {
    async fn event(
        &mut self,
        data: &[u8],
        provider: &str,
        sink: &StreamSink,
    ) -> Result<(), ConnectorError> {
        let data = std::str::from_utf8(data).map_err(|_| protocol("invalid UTF-8"))?;
        if data == "[DONE]" {
            if self.finish_reason.is_none() {
                return Err(protocol("completion marker preceded finish reason"));
            }
            self.done = true;
            return Ok(());
        }
        let json: Value = serde_json::from_str(data).map_err(|_| protocol("malformed SSE JSON"))?;
        if json.get("error").is_some() || !json["x_groq"]["error"].is_null() {
            return Err(protocol("provider sent an in-band error"));
        }
        let choices = json["choices"]
            .as_array()
            .ok_or_else(|| protocol("missing choices array"))?;
        for choice in choices {
            if choice["index"].as_u64().unwrap_or(0) != 0 {
                return Err(protocol("multiple completion choices are unsupported"));
            }
            if let Some(reason) = choice["finish_reason"].as_str() {
                if let Some(error) = crate::content_filter_error(provider, Some(reason)) {
                    return Err(error);
                }
                if self
                    .finish_reason
                    .as_deref()
                    .is_some_and(|previous| previous != reason)
                {
                    return Err(protocol("conflicting finish reasons"));
                }
                self.finish_reason = Some(reason.to_string());
            }
            let delta = &choice["delta"];
            if let Some(text) = delta["content"].as_str().filter(|text| !text.is_empty()) {
                self.content.push_str(text);
                sink.text(text).await;
            }
            if let Some(calls) = delta["tool_calls"].as_array() {
                for call in calls {
                    if !call["type"].is_null() && call["type"].as_str() != Some("function") {
                        return Err(protocol("unsupported tool type"));
                    }
                    let index = call["index"]
                        .as_u64()
                        .and_then(|index| usize::try_from(index).ok())
                        .filter(|index| *index < MAX_TOOL_CALLS)
                        .ok_or_else(|| protocol("invalid or excessive tool index"))?;
                    let pending = self.tools.entry(index).or_default();
                    update_identity(&mut pending.id, &call["id"])?;
                    update_identity(&mut pending.name, &call["function"]["name"])?;
                    if let Some(arguments) = call["function"]["arguments"].as_str() {
                        pending.arguments.push_str(arguments);
                        if let StreamSink::Legacy(sender) = sink {
                            if !pending.legacy_started
                                && !pending.id.is_empty()
                                && !pending.name.is_empty()
                            {
                                let _ = sender
                                    .send(StreamChunk::ToolCallStart {
                                        id: pending.id.clone(),
                                        name: pending.name.clone(),
                                    })
                                    .await;
                                pending.legacy_started = true;
                            }
                            if pending.legacy_started {
                                let _ = sender
                                    .send(StreamChunk::ToolCallDelta {
                                        id: pending.id.clone(),
                                        arguments_delta: arguments.to_string(),
                                    })
                                    .await;
                            }
                        }
                    }
                }
            }
        }
        if let Some((usage, total)) = read_usage(&json) {
            self.usage = usage;
            self.tokens_used = total;
        }
        Ok(())
    }

    fn response(self) -> Result<LlmResponse, ConnectorError> {
        if !self.done {
            return Err(ConnectorError::StreamError(
                "OpenAI-compatible stream ended before [DONE]".into(),
            ));
        }
        let mut ids = HashSet::new();
        let mut tool_calls = Vec::with_capacity(self.tools.len());
        for (expected_index, (index, pending)) in self.tools.into_iter().enumerate() {
            if index != expected_index
                || pending.id.is_empty()
                || pending.name.is_empty()
                || !ids.insert(pending.id.clone())
            {
                return Err(protocol("incomplete or duplicate tool identity"));
            }
            let arguments: Value = serde_json::from_str(&pending.arguments)
                .map_err(|_| protocol("malformed tool arguments"))?;
            if !arguments.is_object() {
                return Err(protocol("tool arguments must be a JSON object"));
            }
            tool_calls.push(ToolCall {
                id: pending.id,
                name: pending.name,
                arguments,
            });
        }
        Ok(LlmResponse {
            content: self.content,
            finish_reason: self.finish_reason,
            tokens_used: self.tokens_used,
            usage: self.usage,
            tool_calls,
            provider_metadata: None,
        })
    }
}

/// Byte framing preserves split UTF-8 and accepts LF, CRLF, CR and comments.
#[derive(Default)]
pub(crate) struct SseDecoder {
    line: Vec<u8>,
    data: Vec<u8>,
    has_data: bool,
    skip_lf: bool,
}

impl SseDecoder {
    pub(crate) fn byte(&mut self, byte: u8) -> Option<Vec<u8>> {
        if self.skip_lf {
            self.skip_lf = false;
            if byte == b'\n' {
                return None;
            }
        }
        if byte != b'\r' && byte != b'\n' {
            self.line.push(byte);
            return None;
        }
        self.skip_lf = byte == b'\r';
        if self.line.is_empty() {
            if !self.has_data {
                return None;
            }
            self.has_data = false;
            return Some(std::mem::take(&mut self.data));
        }
        if let Some(data) = self.line.strip_prefix(b"data:") {
            if self.has_data {
                self.data.push(b'\n');
            }
            self.has_data = true;
            self.data
                .extend_from_slice(data.strip_prefix(b" ").unwrap_or(data));
        }
        self.line.clear();
        None
    }
}

/// Provider-specific state consumes complete JSON events from common framing.
pub(crate) trait NativeSseProtocol: Send {
    fn event(&mut self, json: Value) -> Result<Vec<String>, ConnectorError>;
    fn complete(&self) -> bool;
    fn finish(self) -> Result<LlmResponse, ConnectorError>;
}

/// Reuse byte framing, aggregate ceilings, cancellation and sink backpressure
/// for protocols whose event JSON differs from Chat Completions.
pub(crate) async fn send_native_sse_controlled<D: NativeSseProtocol>(
    provider: &str,
    request: reqwest::RequestBuilder,
    mut state: D,
    options: LlmRequestOptions,
    cancellation: &tokio_util::sync::CancellationToken,
    events: Option<ProviderEventSink>,
) -> Result<LlmResponse, ConnectorError> {
    let send = async {
        let response = request
            .send()
            .await
            .map_err(|error| crate::transport_error(provider, error))?;
        if !response.status().is_success() {
            return Err(crate::provider_http_error(provider, response).await);
        }
        if response.content_length().is_some_and(|size| size > MAX_OPENAI_STREAM_BYTES as u64) {
            return Err(protocol("response exceeded the 8 MiB wire ceiling"));
        }
        let mut bytes = response.bytes_stream();
        let mut total = 0_usize;
        let mut decoder = SseDecoder::default();
        while let Some(chunk) = bytes.next().await {
            let chunk = chunk.map_err(|_| {
                ConnectorError::StreamError("native SSE transport failed".into())
            })?;
            total = total.saturating_add(chunk.len());
            if total > MAX_OPENAI_STREAM_BYTES {
                return Err(protocol("response exceeded the 8 MiB wire ceiling"));
            }
            for byte in chunk {
                if let Some(data) = decoder.byte(byte) {
                    let json: Value = serde_json::from_slice(&data)
                        .map_err(|_| protocol("malformed native SSE JSON"))?;
                    for text in state.event(json)? {
                        if !text.is_empty() {
                            if let Some(sink) = &events {
                                sink.emit(ProviderStreamEvent::TextDelta(text)).await;
                            }
                        }
                    }
                    if state.complete() {
                        return state.finish();
                    }
                }
                if decoder.line.len().saturating_add(decoder.data.len()) > 1024 * 1024 {
                    return Err(protocol("native SSE event exceeded the 1 MiB ceiling"));
                }
            }
        }
        // An unfinished line/event is a broken wire frame, not a clean EOF.
        if !decoder.line.is_empty() || decoder.has_data {
            return Err(ConnectorError::StreamError("native SSE ended inside an event".into()));
        }
        state.finish()
    };
    tokio::pin!(send);
    match options.timeout {
        Some(timeout) => {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    Err(ConnectorError::cancelled(provider.to_string(), None))
                }
                result = tokio::time::timeout(timeout, &mut send) => {
                    result.unwrap_or_else(|_| {
                        Err(ConnectorError::timeout(provider.to_string(), "native stream attempt exceeded its deadline", None))
                    })
                }
            }
        }
        None => {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(ConnectorError::cancelled(provider.to_string(), None)),
                result = &mut send => result,
            }
        }
    }
}

fn regular_response(json: &Value, provider: &str) -> Result<LlmResponse, ConnectorError> {
    let message = &json["choices"][0]["message"];
    if !message.is_object() {
        return Err(protocol("missing completion message"));
    }
    if let Some(error) =
        crate::content_filter_error(provider, json["choices"][0]["finish_reason"].as_str())
    {
        return Err(error);
    }
    let mut state = StreamState {
        done: true,
        content: message["content"].as_str().unwrap_or("").to_string(),
        finish_reason: json["choices"][0]["finish_reason"]
            .as_str()
            .map(ToString::to_string),
        ..Default::default()
    };
    if let Some((usage, tokens_used)) = read_usage(json) {
        state.usage = usage;
        state.tokens_used = tokens_used;
    }
    if let Some(calls) = message["tool_calls"].as_array() {
        if calls.len() > MAX_TOOL_CALLS {
            return Err(protocol("excessive tool calls"));
        }
        for (index, call) in calls.iter().enumerate() {
            let mut pending = PendingTool::default();
            update_identity(&mut pending.id, &call["id"])?;
            update_identity(&mut pending.name, &call["function"]["name"])?;
            pending.arguments = call["function"]["arguments"]
                .as_str()
                .ok_or_else(|| protocol("invalid tool arguments field"))?
                .to_string();
            state.tools.insert(index, pending);
        }
    }
    state.response()
}

async fn parse_openai_stream(
    response: reqwest::Response,
    provider: &str,
    sink: StreamSink,
) -> Result<LlmResponse, ConnectorError> {
    let mut bytes = response.bytes_stream();
    let mut total_bytes = 0_usize;
    let mut prefix = Vec::new();
    let mut is_sse = None;
    let mut decoder = SseDecoder::default();
    let mut state = StreamState::default();
    while let Some(chunk) = bytes.next().await {
        let chunk = chunk.map_err(|_| {
            ConnectorError::StreamError("OpenAI-compatible stream transport failed".into())
        })?;
        total_bytes = total_bytes.saturating_add(chunk.len());
        if total_bytes > MAX_OPENAI_STREAM_BYTES {
            return Err(protocol("response exceeded the 8 MiB wire ceiling"));
        }
        // Gateways sometimes rewrite Content-Type; inspect the actual prefix.
        if is_sse.is_none() {
            prefix.extend_from_slice(&chunk);
            if let Some(first) = chunk.iter().find(|byte| !byte.is_ascii_whitespace()) {
                is_sse = Some(*first != b'{');
            } else {
                continue;
            }
            if is_sse == Some(true) {
                for byte in prefix.drain(..) {
                    if let Some(data) = decoder.byte(byte) {
                        state.event(&data, provider, &sink).await?;
                        if state.done {
                            break;
                        }
                    }
                }
            } else {
                continue;
            }
        } else if is_sse == Some(true) {
            for byte in chunk {
                if let Some(data) = decoder.byte(byte) {
                    state.event(&data, provider, &sink).await?;
                    if state.done {
                        break;
                    }
                }
            }
        } else {
            prefix.extend_from_slice(&chunk);
        }
        if state.done {
            break;
        }
    }
    let response = if is_sse == Some(false) {
        let json: Value =
            serde_json::from_slice(&prefix).map_err(|_| protocol("malformed completion JSON"))?;
        let response = regular_response(&json, provider)?;
        if !response.content.is_empty() {
            sink.text(&response.content).await;
        }
        response
    } else {
        state.response()?
    };
    if let StreamSink::Legacy(sender) = sink {
        let _ = sender
            .send(StreamChunk::Done {
                tokens_used: response.tokens_used,
            })
            .await;
    }
    Ok(response)
}

/// Read a successful OpenAI-shaped HTTP stream into the kernel's event sink.
pub async fn parse_openai_sse_stream(
    response: reqwest::Response,
    provider: &str,
    events: ProviderEventSink,
) -> Result<LlmResponse, ConnectorError> {
    parse_openai_stream(response, provider, StreamSink::Kernel(Some(events))).await
}

/// Compatibility entry point backed by the same bounded SSE reader.
pub async fn parse_azure_sse_stream(
    response: reqwest::Response,
    tx: mpsc::Sender<StreamChunk>,
) -> Result<LlmResponse, ConnectorError> {
    parse_openai_stream(response, "azure-openai", StreamSink::Legacy(tx)).await
}
