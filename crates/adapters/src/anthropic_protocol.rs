//! Messages history and typed SSE blocks, kept behind the native tool gate.

use std::collections::{BTreeMap, HashSet};

use kernel::connector::*;
use kernel::ConnectorError;
use serde_json::{json, Value};

fn invalid(detail: &str) -> ConnectorError {
    ConnectorError::ProtocolError(format!("Anthropic {detail}"))
}

fn identity(value: &Value) -> Result<&str, ConnectorError> {
    value
        .as_str()
        .filter(|text| !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control))
        .ok_or_else(|| invalid("invalid tool identity"))
}

fn parse_blocks(blocks: &[Value]) -> Result<(String, Vec<ToolCall>), ConnectorError> {
    if blocks.is_empty() || blocks.len() > 64 {
        return Err(invalid("invalid content block count"));
    }
    let mut content = String::new();
    let mut calls = Vec::new();
    let mut ids = HashSet::new();
    for block in blocks {
        match block["type"].as_str() {
            Some("text") => content.push_str(
                block["text"]
                    .as_str()
                    .ok_or_else(|| invalid("invalid text block"))?,
            ),
            Some("tool_use") => {
                let id = identity(&block["id"])?;
                let name = identity(&block["name"])?;
                if !ids.insert(id) || !block["input"].is_object() {
                    return Err(invalid("invalid or duplicate tool block"));
                }
                calls.push(ToolCall {
                    id: id.to_string(),
                    name: name.to_string(),
                    arguments: block["input"].clone(),
                });
            }
            Some("thinking") => {
                if !block["thinking"].is_string() || identity(&block["signature"]).is_err() {
                    // Signatures can exceed tool ID lengths; enforce bytes at
                    // the opaque metadata boundary rather than truncating them.
                    if !block["thinking"].is_string()
                        || !block["signature"].as_str().is_some_and(|signature| {
                            !signature.is_empty() && !signature.chars().any(char::is_control)
                        })
                    {
                        return Err(invalid("invalid signed thinking block"));
                    }
                }
            }
            Some("redacted_thinking")
                if block["data"].as_str().is_some_and(|data| !data.is_empty()) => {}
            _ => return Err(invalid("unsupported native content block")),
        }
    }
    Ok((content, calls))
}

pub(super) fn request(
    messages: &[StandardMessage],
    tools: &[ToolDefinition],
    provider: &str,
    model: &str,
    options: LlmRequestOptions,
    stream: bool,
) -> Result<Value, ConnectorError> {
    validate_provider_history(messages, provider, model)?;
    let mut output = Vec::<Value>::new();
    let mut system = Vec::new();
    let mut pending = HashSet::<String>::new();
    let mut seen = HashSet::<String>::new();
    let mut results = Vec::new();
    for message in messages {
        if message.role != "assistant" && message.tool_calls.as_ref().is_some_and(|calls| !calls.is_empty()) {
            return Err(invalid("non-assistant history cannot request tools"));
        }
        if message.role != "tool" && message.tool_call_id.is_some() {
            return Err(invalid("only tool results may carry a call id"));
        }
        if message.role != "tool" {
            if !pending.is_empty() {
                return Err(invalid("native tools are missing results"));
            }
            if !results.is_empty() {
                output.push(json!({"role": "user", "content": std::mem::take(&mut results)}));
            }
        }
        match message.role.as_str() {
            "system" if message.provider_metadata.is_none() => {
                system.push(json!({"type": "text", "text": message.content}))
            }
            "user" if message.provider_metadata.is_none() => {
                output.push(json!({"role": "user", "content": message.content}))
            }
            "assistant" => {
                let blocks = if let Some(metadata) = &message.provider_metadata {
                    metadata.payload()["blocks"]
                        .as_array()
                        .ok_or_else(|| invalid("invalid replay blocks"))?
                        .clone()
                } else {
                    let mut blocks = Vec::new();
                    if !message.content.is_empty() {
                        blocks.push(json!({"type": "text", "text": message.content}));
                    }
                    blocks.extend(message.tool_calls.as_deref().unwrap_or_default().iter().map(|call| json!({"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments})));
                    blocks
                };
                let (content, calls) = parse_blocks(&blocks)?;
                if content != message.content
                    || calls != message.tool_calls.as_deref().unwrap_or_default()
                {
                    return Err(invalid("native replay content or calls changed"));
                }
                for call in calls {
                    if !seen.insert(call.id.clone()) {
                        return Err(invalid("native tool id was reused"));
                    }
                    pending.insert(call.id);
                }
                output.push(json!({"role": "assistant", "content": blocks}));
            }
            "tool" if message.provider_metadata.is_none() => {
                let id = message
                    .tool_call_id
                    .as_deref()
                    .ok_or_else(|| invalid("tool result has no id"))?;
                if !pending.remove(id) {
                    return Err(invalid("orphan or duplicate tool result"));
                }
                results.push(
                    json!({"type": "tool_result", "tool_use_id": id, "content": message.content}),
                );
            }
            _ => return Err(invalid("unsupported standard message role")),
        }
    }
    if !pending.is_empty() {
        return Err(invalid("native tools are missing results"));
    }
    if !results.is_empty() {
        output.push(json!({"role": "user", "content": results}));
    }
    let mut body = json!({"model": model, "messages": output, "max_tokens": options.max_output_tokens.unwrap_or(4096).min(4096)});
    if stream {
        body["stream"] = json!(true);
    }
    if !system.is_empty() {
        body["system"] = json!(system);
    }
    if !tools.is_empty() {
        body["tools"] = json!(tools.iter().map(|tool| json!({"name": tool.name, "description": tool.description, "input_schema": tool.parameters})).collect::<Vec<_>>());
    }
    Ok(body)
}

struct Block {
    value: Value,
    arguments: String,
    closed: bool,
}

pub(super) struct AnthropicStream {
    provider: String,
    model: String,
    blocks: BTreeMap<usize, Block>,
    started: bool,
    stopped: bool,
    finish_reason: Option<String>,
    usage: Value,
    retained_bytes: usize,
}

impl AnthropicStream {
    pub(super) fn new(provider: String, model: String) -> Self {
        Self {
            provider,
            model,
            blocks: BTreeMap::new(),
            started: false,
            stopped: false,
            finish_reason: None,
            usage: Value::Null,
            retained_bytes: 0,
        }
    }

    fn update_usage(&mut self, usage: &Value) -> Result<(), ConnectorError> {
        if !usage.is_object() {
            return Err(invalid("invalid streamed usage"));
        }
        if !self.usage.is_object() {
            self.usage = json!({});
        }
        for (key, value) in usage.as_object().expect("validated usage") {
            self.usage[key] = value.clone();
        }
        Ok(())
    }
}

impl crate::streaming::NativeSseProtocol for AnthropicStream {
    fn event(&mut self, json: Value) -> Result<Vec<String>, ConnectorError> {
        let kind = json["type"]
            .as_str()
            .ok_or_else(|| invalid("stream event has no type"))?;
        let mut texts = Vec::new();
        match kind {
            "message_start" => {
                if self.started {
                    return Err(invalid("duplicate message start"));
                }
                self.started = true;
                if let Some(usage) = json["message"].get("usage") {
                    self.update_usage(usage)?;
                }
            }
            "content_block_start" | "content_block_delta" | "content_block_stop" => {
                if !self.started {
                    return Err(invalid("content preceded message start"));
                }
                let index = json["index"]
                    .as_u64()
                    .and_then(|index| usize::try_from(index).ok())
                    .filter(|index| *index < 64)
                    .ok_or_else(|| invalid("invalid or excessive block index"))?;
                if kind == "content_block_start" {
                    if self.blocks.contains_key(&index) {
                        return Err(invalid("duplicate content block start"));
                    }
                    let value = json["content_block"].clone();
                    if !value.is_object() {
                        return Err(invalid("invalid content block"));
                    }
                    self.retained_bytes = self.retained_bytes.saturating_add(
                        serde_json::to_vec(&value)
                            .map_err(|_| invalid("invalid block"))?
                            .len(),
                    );
                    if value["type"] == "text" {
                        texts.push(
                            value["text"]
                                .as_str()
                                .ok_or_else(|| invalid("invalid text block"))?
                                .to_string(),
                        );
                    }
                    self.blocks.insert(
                        index,
                        Block {
                            value,
                            arguments: String::new(),
                            closed: false,
                        },
                    );
                } else {
                    let block = self
                        .blocks
                        .get_mut(&index)
                        .filter(|block| !block.closed)
                        .ok_or_else(|| invalid("delta or stop has no open block"))?;
                    if kind == "content_block_stop" {
                        if block.value["type"] == "tool_use" && !block.arguments.is_empty() {
                            let args: Value = serde_json::from_str(&block.arguments)
                                .map_err(|_| invalid("malformed streamed tool arguments"))?;
                            if !args.is_object() {
                                return Err(invalid("tool arguments must be an object"));
                            }
                            block.value["input"] = args;
                        }
                        parse_blocks(std::slice::from_ref(&block.value))?;
                        block.closed = true;
                    } else {
                        let delta = &json["delta"];
                        let (field, fragment) = match delta["type"].as_str() {
                            Some("text_delta") if block.value["type"] == "text" => {
                                ("text", delta["text"].as_str())
                            }
                            Some("input_json_delta") if block.value["type"] == "tool_use" => {
                                ("input", delta["partial_json"].as_str())
                            }
                            Some("thinking_delta") if block.value["type"] == "thinking" => {
                                ("thinking", delta["thinking"].as_str())
                            }
                            Some("signature_delta") if block.value["type"] == "thinking" => {
                                ("signature", delta["signature"].as_str())
                            }
                            _ => return Err(invalid("delta does not match its block")),
                        };
                        let fragment =
                            fragment.ok_or_else(|| invalid("delta fragment must be a string"))?;
                        self.retained_bytes = self.retained_bytes.saturating_add(fragment.len());
                        if field == "input" {
                            block.arguments.push_str(fragment);
                        } else {
                            let value = block
                                .value
                                .as_object_mut()
                                .ok_or_else(|| invalid("invalid delta block"))?
                                .entry(field.to_string())
                                .or_insert_with(|| json!(""));
                            if let Value::String(value) = value {
                                value.push_str(fragment);
                            } else {
                                return Err(invalid("delta destination is not a string"));
                            }
                            if field == "text" {
                                texts.push(fragment.to_string());
                            }
                        }
                    }
                }
            }
            "message_delta" => {
                if !self.started {
                    return Err(invalid("message delta preceded message start"));
                }
                if let Some(reason) = json["delta"]["stop_reason"].as_str() {
                    if let Some(error) = crate::content_filter_error(&self.provider, Some(reason)) {
                        return Err(error);
                    }
                    self.finish_reason = Some(reason.to_string());
                }
                if let Some(usage) = json.get("usage") {
                    self.update_usage(usage)?;
                }
            }
            "message_stop" => {
                if !self.started
                    || self.finish_reason.is_none()
                    || self.blocks.values().any(|block| !block.closed)
                {
                    return Err(invalid("message stopped before content completed"));
                }
                self.stopped = true;
            }
            "error" => return Err(invalid("stream returned an in-band error")),
            // SSE ping and future informational event types contain no tools.
            _ => {}
        }
        if self.retained_bytes > ProviderMessageMetadata::MAX_BYTES - 4096 {
            return Err(invalid("stream exceeds the replay byte limit"));
        }
        Ok(texts)
    }

    fn complete(&self) -> bool {
        self.stopped
    }

    fn finish(self) -> Result<LlmResponse, ConnectorError> {
        if !self.started {
            return Err(invalid("empty stream"));
        }
        if !self.stopped
            && self
                .blocks
                .values()
                .any(|block| block.value["type"] != "text")
        {
            return Err(ConnectorError::StreamError(
                "Anthropic stream ended before native blocks completed".into(),
            ));
        }
        let mut values = Vec::with_capacity(self.blocks.len());
        for (expected, (index, block)) in self.blocks.into_iter().enumerate() {
            if expected != index {
                return Err(invalid("content block indexes are sparse"));
            }
            values.push(block.value);
        }
        let (content, tool_calls) = parse_blocks(&values)?;
        let usage = if self.usage.is_object() {
            LlmUsage::reported(
                crate::json_usage_u32(&self.usage["input_tokens"]),
                crate::json_usage_u32(&self.usage["output_tokens"]),
                crate::json_usage_u32(&self.usage["cache_read_input_tokens"]),
            )
        } else {
            LlmUsage::default()
        };
        let metadata =
            ProviderMessageMetadata::new(self.provider, self.model, json!({"blocks": values}))?;
        Ok(LlmResponse {
            content,
            finish_reason: if self.stopped {
                self.finish_reason
            } else {
                None
            },
            tokens_used: usage.total(),
            usage,
            tool_calls,
            provider_metadata: Some(metadata),
        })
    }
}
