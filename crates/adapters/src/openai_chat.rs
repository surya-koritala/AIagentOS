//! OpenAI-shaped chat bodies and bounded terminal response decoding.

use kernel::connector::*;
use kernel::ConnectorError;
use serde_json::{json, Value};
use std::collections::HashSet;

pub(crate) fn request(
    messages: &[StandardMessage],
    tools: &[ToolDefinition],
    options: LlmRequestOptions,
    model: Option<&str>,
) -> Value {
    let messages: Vec<_> = messages.iter().map(|message| {
        let mut value = json!({"role":message.role,"content":crate::vision::openai_content(&message.content)});
        if let Some(id) = &message.tool_call_id { value["tool_call_id"] = json!(id); }
        if let Some(calls) = &message.tool_calls {
            value["tool_calls"] = json!(calls.iter().map(|call| json!({
                "id":call.id,"type":"function","function":{"name":call.name,"arguments":call.arguments.to_string()}
            })).collect::<Vec<_>>());
        }
        value
    }).collect();
    let mut body = json!({"messages":messages});
    if let Some(model) = model {
        body["model"] = json!(model);
    }
    if let Some(max) = options.max_output_tokens {
        body["max_tokens"] = json!(max);
    }
    if !tools.is_empty() {
        body["tools"] = json!(tools
            .iter()
            .map(|tool| json!({"type":"function","function":{
                "name":tool.name,"description":tool.description,"parameters":tool.parameters
            }}))
            .collect::<Vec<_>>());
    }
    body
}

pub(crate) async fn response(
    response: reqwest::Response,
    provider: &str,
) -> Result<LlmResponse, ConnectorError> {
    let value = read_json(response).await?;
    parse(&value, provider)
}

pub(crate) async fn read_json(response: reqwest::Response) -> Result<Value, ConnectorError> {
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid("response body could not be read"))?
    {
        if bytes.len().saturating_add(chunk.len()) > 8 * 1024 * 1024 {
            return Err(invalid("response exceeds byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid response JSON"))
}

fn invalid(detail: &str) -> ConnectorError {
    ConnectorError::ProtocolError(format!("chat completion {detail}"))
}

pub(crate) fn parse(value: &Value, provider: &str) -> Result<LlmResponse, ConnectorError> {
    let choice = &value["choices"][0];
    if let Some(error) = crate::content_filter_error(provider, choice["finish_reason"].as_str()) {
        return Err(error);
    }
    let message = choice
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("missing assistant message"))?;
    let content = match message.get("content") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.clone(),
        _ => return Err(invalid("unsupported assistant content")),
    };
    let mut calls = Vec::new();
    let mut seen = HashSet::new();
    if let Some(value) = message.get("tool_calls").filter(|value| !value.is_null()) {
        let entries = value
            .as_array()
            .ok_or_else(|| invalid("tool calls must be an array"))?;
        if entries.len() > 64 {
            return Err(invalid("too many tool calls"));
        }
        for entry in entries {
            let id = entry["id"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .ok_or_else(|| invalid("invalid tool id"))?;
            let name = entry["function"]["name"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .ok_or_else(|| invalid("invalid function name"))?;
            if entry["type"] != "function" || !seen.insert(id) {
                return Err(invalid("invalid or duplicate function call"));
            }
            let arguments: Value = serde_json::from_str(
                entry["function"]["arguments"]
                    .as_str()
                    .ok_or_else(|| invalid("missing function arguments"))?,
            )
            .map_err(|_| invalid("malformed function arguments"))?;
            if !arguments.is_object() {
                return Err(invalid("function arguments must be an object"));
            }
            calls.push(ToolCall {
                id: id.to_string(),
                name: name.to_string(),
                arguments,
            });
        }
    }
    let usage_value = value
        .get("usage")
        .filter(|usage| usage.is_object())
        .unwrap_or(&value["x_groq"]["usage"]);
    let reported = usage_value.is_object();
    let usage = LlmUsage {
        input_tokens: crate::json_usage_u32(&usage_value["prompt_tokens"]),
        output_tokens: crate::json_usage_u32(&usage_value["completion_tokens"]),
        cached_tokens: crate::json_usage_u32(
            usage_value["prompt_tokens_details"]
                .get("cached_tokens")
                .or_else(|| usage_value.get("prompt_cache_hit_tokens"))
                .unwrap_or(&Value::Null),
        ),
        provider_reported: reported,
    };
    Ok(LlmResponse {
        tokens_used: if reported {
            crate::json_usage_u32(&usage_value["total_tokens"]).max(usage.total())
        } else {
            u32::try_from(content.len()).unwrap_or(u32::MAX)
        },
        content,
        finish_reason: choice["finish_reason"].as_str().map(str::to_string),
        usage,
        tool_calls: calls,
        provider_metadata: None,
    })
}
