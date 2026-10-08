//! Stateless GenerateContent history compilation and bounded native parsing.

use std::collections::{HashMap, HashSet};

use kernel::connector::{
    LlmResponse, LlmUsage, ProviderMessageMetadata, StandardMessage, ToolCall, ToolDefinition,
};
use kernel::{ConnectorError, ProviderId};
use serde_json::{json, Value};

const MAX_PARTS: usize = 64;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

fn invalid(detail: &str) -> ConnectorError {
    ConnectorError::ProtocolError(format!("Gemini {detail}"))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_:.-".contains(&b))
}

pub(super) async fn response_bytes(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, ConnectorError> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(invalid("response exceeds the byte limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid("response body could not be read"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(invalid("response exceeds the byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

struct ParsedParts {
    content: String,
    calls: Vec<ToolCall>,
    native_ids: Vec<Option<String>>,
}

fn parse_parts(parts: &Value, saved_ids: Option<&[Value]>) -> Result<ParsedParts, ConnectorError> {
    let parts = parts
        .as_array()
        .ok_or_else(|| invalid("parts must be an array"))?;
    if parts.is_empty()
        || parts.len() > MAX_PARTS
        || serde_json::to_vec(parts).map_or(true, |bytes| {
            bytes.len() > ProviderMessageMetadata::MAX_BYTES
        })
    {
        return Err(invalid("parts are empty or exceed replay limits"));
    }
    let response_id = kernel::SessionId::new_v4();
    let mut content = String::new();
    let mut calls = Vec::new();
    let mut native_ids = Vec::new();
    let mut seen = HashSet::new();
    for (index, part) in parts.iter().enumerate() {
        let object = part
            .as_object()
            .ok_or_else(|| invalid("part must be an object"))?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "text" | "functionCall" | "thought" | "thoughtSignature"
            )
        }) {
            return Err(invalid("unsupported native response part"));
        }
        if part
            .get("thought")
            .is_some_and(|thought| !thought.is_boolean())
            || part
                .get("thoughtSignature")
                .is_some_and(|sig| !sig.as_str().is_some_and(valid_id_or_signature))
        {
            return Err(invalid("invalid thought metadata"));
        }
        match (part.get("text"), part.get("functionCall")) {
            (Some(text), None) => {
                let text = text
                    .as_str()
                    .ok_or_else(|| invalid("text part must be a string"))?;
                if part["thought"].as_bool() != Some(true) {
                    content.push_str(text);
                }
            }
            (None, Some(function)) => {
                if part["thought"].as_bool() == Some(true) {
                    return Err(invalid("thought part cannot request a tool"));
                }
                let object = function
                    .as_object()
                    .ok_or_else(|| invalid("function call must be an object"))?;
                if object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "name" | "args" | "id"))
                {
                    return Err(invalid("unsupported function call field"));
                }
                let name = function["name"]
                    .as_str()
                    .filter(|name| valid_name(name))
                    .ok_or_else(|| invalid("invalid function name"))?;
                let arguments = function.get("args").cloned().unwrap_or_else(|| json!({}));
                if !arguments.is_object() {
                    return Err(invalid("function arguments must be an object"));
                }
                let native_id = match function.get("id") {
                    None => None,
                    Some(value) => Some(
                        value
                            .as_str()
                            .filter(|id| valid_id(id))
                            .ok_or_else(|| invalid("invalid function call id"))?
                            .to_string(),
                    ),
                };
                let id = if let Some(saved_ids) = saved_ids {
                    let saved = saved_ids
                        .get(calls.len())
                        .and_then(Value::as_str)
                        .filter(|id| valid_id(id))
                        .ok_or_else(|| invalid("invalid saved function call ids"))?;
                    if native_id.as_deref().is_some_and(|native| native != saved) {
                        return Err(invalid("saved function call id mismatch"));
                    }
                    saved.to_string()
                } else {
                    native_id
                        .clone()
                        .unwrap_or_else(|| format!("gemini-{response_id}-{index}"))
                };
                if !seen.insert(id.clone()) {
                    return Err(invalid("duplicate function call id"));
                }
                calls.push(ToolCall {
                    id,
                    name: name.to_string(),
                    arguments,
                });
                native_ids.push(native_id);
            }
            _ => {
                return Err(invalid(
                    "part must contain exactly one text or function call",
                ))
            }
        }
    }
    if saved_ids.is_some_and(|ids| ids.len() != calls.len()) {
        return Err(invalid("saved function call count mismatch"));
    }
    if content.is_empty() && calls.is_empty() {
        return Err(invalid("response has no visible content or function calls"));
    }
    Ok(ParsedParts {
        content,
        calls,
        native_ids,
    })
}

fn valid_id_or_signature(signature: &str) -> bool {
    !signature.is_empty() && !signature.chars().any(char::is_control)
}

pub(super) fn message(
    value: &Value,
    provider: &ProviderId,
    model: &str,
) -> Result<StandardMessage, ConnectorError> {
    let role = value["role"]
        .as_str()
        .ok_or_else(|| invalid("missing content role"))?;
    if !matches!(role, "model" | "user") {
        return Err(invalid("invalid content role"));
    }
    let parsed = parse_parts(&value["parts"], None)?;
    if role == "user" {
        if !parsed.calls.is_empty() {
            return Err(invalid("user content cannot request a function"));
        }
        return Ok(StandardMessage::user(parsed.content));
    }
    let mut message = StandardMessage::assistant(parsed.content);
    let ids = parsed
        .calls
        .iter()
        .map(|call| call.id.clone())
        .collect::<Vec<_>>();
    if !parsed.calls.is_empty() {
        message.tool_calls = Some(parsed.calls);
    }
    message.provider_metadata = Some(ProviderMessageMetadata::new(
        provider.clone(),
        model.to_string(),
        json!({"parts": value["parts"], "tool_call_ids": ids}),
    )?);
    Ok(message)
}

pub(super) fn response(
    json: &Value,
    provider: &ProviderId,
    model: &str,
) -> Result<LlmResponse, ConnectorError> {
    let candidate = &json["candidates"][0];
    if let Some(error) = crate::content_filter_error(provider, candidate["finishReason"].as_str()) {
        return Err(error);
    }
    let message = message(&candidate["content"], provider, model)?;
    if message.role != "assistant" {
        return Err(invalid("response content must have the model role"));
    }
    let usage = &json["usageMetadata"];
    Ok(LlmResponse {
        content: message.content,
        finish_reason: candidate["finishReason"].as_str().map(str::to_string),
        tokens_used: crate::json_usage_u32(&usage["totalTokenCount"]),
        usage: LlmUsage::reported(
            crate::json_usage_u32(&usage["promptTokenCount"]),
            crate::json_usage_u32(&usage["candidatesTokenCount"])
                .saturating_add(crate::json_usage_u32(&usage["thoughtsTokenCount"])),
            crate::json_usage_u32(&usage["cachedContentTokenCount"]),
        ),
        tool_calls: message.tool_calls.unwrap_or_default(),
        provider_metadata: message.provider_metadata,
    })
}

fn assistant_parts(
    message: &StandardMessage,
    provider: &str,
    model: &str,
) -> Result<(Value, ParsedParts), ConnectorError> {
    let calls = message.tool_calls.as_deref().unwrap_or_default();
    let (parts, parsed) = if let Some(metadata) = &message.provider_metadata {
        if metadata.provider_id() != provider || metadata.model_id() != model {
            return Err(invalid(
                "replay metadata belongs to a different provider or model",
            ));
        }
        let payload = metadata.payload();
        let ids = payload["tool_call_ids"]
            .as_array()
            .ok_or_else(|| invalid("missing saved function call ids"))?;
        let parsed = parse_parts(&payload["parts"], Some(ids))?;
        (payload["parts"].clone(), parsed)
    } else {
        let mut parts = Vec::new();
        if !message.content.is_empty() {
            parts.push(json!({"text": message.content}));
        }
        parts.extend(calls.iter().map(|call| {
            json!({"functionCall": {
                "id": call.id, "name": call.name, "args": call.arguments
            }})
        }));
        let parts = Value::Array(parts);
        let parsed = parse_parts(&parts, None)?;
        (parts, parsed)
    };
    if parsed.content != message.content || parsed.calls != calls {
        return Err(invalid("saved assistant content or function calls changed"));
    }
    Ok((parts, parsed))
}

pub(super) fn single_message(
    message: &StandardMessage,
    provider: &str,
    model: &str,
) -> Result<Value, ConnectorError> {
    match message.role.as_str() {
        "assistant" | "model" => {
            let (parts, _) = assistant_parts(message, provider, model)?;
            Ok(json!({"role": "model", "parts": parts}))
        }
        "user" | "system" if message.provider_metadata.is_none() => {
            Ok(json!({"role": "user", "parts": [{"text": message.content}]}))
        }
        _ => Err(invalid("message needs complete history for translation")),
    }
}

fn flush_tool_results(contents: &mut Vec<Value>, results: &mut Vec<(usize, Value)>) {
    if results.is_empty() {
        return;
    }
    results.sort_by_key(|(order, _)| *order);
    let parts = std::mem::take(results)
        .into_iter()
        .map(|(_, part)| part)
        .collect::<Vec<_>>();
    contents.push(json!({"role": "user", "parts": parts}));
}

pub(super) fn request(
    messages: &[StandardMessage],
    tools: &[ToolDefinition],
    provider: &str,
    model: &str,
) -> Result<Value, ConnectorError> {
    let mut contents = Vec::<Value>::new();
    let mut system = Vec::<Value>::new();
    let mut pending = HashMap::<String, (String, Option<String>, usize)>::new();
    let mut seen = HashSet::new();
    let mut tool_results = Vec::new();
    for message in messages {
        if message.role != "tool" && !pending.is_empty() {
            return Err(invalid(
                "assistant functions are missing their tool results",
            ));
        }
        if message.role != "tool" {
            flush_tool_results(&mut contents, &mut tool_results);
        }
        if !matches!(message.role.as_str(), "assistant" | "model")
            && message.provider_metadata.is_some()
        {
            return Err(invalid(
                "only assistant messages may carry provider replay state",
            ));
        }
        match message.role.as_str() {
            "system" | "user" => {
                if message.tool_call_id.is_some()
                    || message
                        .tool_calls
                        .as_ref()
                        .is_some_and(|calls| !calls.is_empty())
                {
                    return Err(invalid("non-assistant message cannot request functions"));
                }
                if message.role == "system" {
                    system.push(json!({"text": message.content}));
                } else {
                    contents.push(json!({"role": "user", "parts": [{"text": message.content}]}));
                }
            }
            "assistant" | "model" => {
                if message.tool_call_id.is_some() {
                    return Err(invalid("assistant message cannot be a tool result"));
                }
                let (parts, parsed) = assistant_parts(message, provider, model)?;
                for (order, (call, native_id)) in
                    parsed.calls.iter().zip(parsed.native_ids).enumerate()
                {
                    if !seen.insert(call.id.clone()) {
                        return Err(invalid("function call id was reused"));
                    }
                    pending.insert(call.id.clone(), (call.name.clone(), native_id, order));
                }
                contents.push(json!({"role": "model", "parts": parts}));
            }
            "tool" => {
                if message
                    .tool_calls
                    .as_ref()
                    .is_some_and(|calls| !calls.is_empty())
                {
                    return Err(invalid("tool result cannot request functions"));
                }
                let id = message
                    .tool_call_id
                    .as_deref()
                    .ok_or_else(|| invalid("tool result has no call id"))?;
                let (name, native_id, order) = pending
                    .remove(id)
                    .ok_or_else(|| invalid("orphan or duplicate tool result"))?;
                let result = serde_json::from_str::<Value>(&message.content)
                    .unwrap_or_else(|_| Value::String(message.content.clone()));
                let result = if result.is_object() {
                    result
                } else {
                    json!({"result": result})
                };
                let mut function = json!({"name": name, "response": result});
                if let Some(id) = native_id {
                    function["id"] = json!(id);
                }
                let part = json!({"functionResponse": function});
                tool_results.push((order, part));
            }
            _ => return Err(invalid("unsupported standard message role")),
        }
    }
    if !pending.is_empty() {
        return Err(invalid(
            "assistant functions are missing their tool results",
        ));
    }
    flush_tool_results(&mut contents, &mut tool_results);
    let mut body = json!({"contents": contents});
    if !system.is_empty() {
        body["systemInstruction"] = json!({"parts": system});
    }
    if !tools.is_empty() {
        let mut seen = HashSet::new();
        for tool in tools {
            if !valid_name(&tool.name)
                || !seen.insert(&tool.name)
                || !tool.parameters.is_object()
                || tool.parameters["type"] != "object"
            {
                return Err(invalid("invalid or duplicate function declaration"));
            }
        }
        body["tools"] = json!([{"functionDeclarations": tools.iter().map(|tool| json!({
            "name": tool.name, "description": tool.description, "parametersJsonSchema": tool.parameters
        })).collect::<Vec<_>>()}]);
    }
    Ok(body)
}
