//! Bounded Ollama response accumulation; complete calls reach the normal gate.
use kernel::connector::*;
use kernel::ConnectorError;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

fn invalid(detail: &str) -> ConnectorError {
    ConnectorError::ProtocolError(format!("Ollama {detail}"))
}

pub(super) struct OllamaStream {
    content: String,
    calls: BTreeMap<usize, ToolCall>,
    next_index: usize,
    response_id: kernel::SessionId,
    done: bool,
    finish: Option<String>,
    usage: LlmUsage,
}

impl Default for OllamaStream {
    fn default() -> Self {
        Self {
            content: String::new(),
            calls: BTreeMap::new(),
            next_index: 0,
            response_id: kernel::SessionId::new_v4(),
            done: false,
            finish: None,
            usage: LlmUsage::default(),
        }
    }
}

impl crate::streaming::NativeSseProtocol for OllamaStream {
    fn event(&mut self, json: Value) -> Result<Vec<String>, ConnectorError> {
        if json.get("error").is_some() {
            return Err(invalid("stream returned an in-band error"));
        }
        let done = json["done"]
            .as_bool()
            .ok_or_else(|| invalid("record has no done flag"))?;
        let mut texts = Vec::new();
        if let Some(message) = json.get("message") {
            if !message.is_object()
                || message["role"]
                    .as_str()
                    .is_some_and(|role| role != "assistant")
            {
                return Err(invalid("invalid message role"));
            }
            if let Some(content) = message.get("content") {
                let text = content
                    .as_str()
                    .ok_or_else(|| invalid("content is not text"))?;
                self.content.push_str(text);
                if !text.is_empty() {
                    texts.push(text.to_string());
                }
            }
            if let Some(raw_calls) = message.get("tool_calls") {
                let calls = raw_calls
                    .as_array()
                    .ok_or_else(|| invalid("invalid native calls"))?;
                for raw in calls {
                    let explicit = raw["function"].get("index").or_else(|| raw.get("index"));
                    let index = if let Some(value) = explicit {
                        value
                            .as_u64()
                            .and_then(|value| usize::try_from(value).ok())
                            .filter(|value| *value < 64)
                            .ok_or_else(|| invalid("invalid native call index"))?
                    } else {
                        let index = self.next_index;
                        self.next_index += 1;
                        index
                    };
                    if index >= 64 {
                        return Err(invalid("too many native calls"));
                    }
                    self.next_index = self.next_index.max(index + 1);
                    let name = raw["function"]["name"]
                        .as_str()
                        .filter(|name| {
                            !name.is_empty()
                                && name.len() <= 256
                                && !name.chars().any(char::is_control)
                        })
                        .ok_or_else(|| invalid("invalid native function name"))?;
                    let arguments = match &raw["function"]["arguments"] {
                        Value::String(text) => serde_json::from_str(text)
                            .map_err(|_| invalid("malformed native arguments"))?,
                        value => value.clone(),
                    };
                    if !arguments.is_object() {
                        return Err(invalid("native arguments must be an object"));
                    }
                    let id = match raw.get("id") {
                        Some(value) => value
                            .as_str()
                            .filter(|id| {
                                !id.is_empty()
                                    && id.len() <= 256
                                    && !id.chars().any(char::is_control)
                            })
                            .ok_or_else(|| invalid("invalid native call id"))?
                            .to_string(),
                        None => format!("ollama-{}-{index}", self.response_id),
                    };
                    let call = ToolCall {
                        id,
                        name: name.to_string(),
                        arguments,
                    };
                    if self
                        .calls
                        .get(&index)
                        .is_some_and(|previous| previous != &call)
                    {
                        return Err(invalid("native call changed between records"));
                    }
                    self.calls.insert(index, call);
                }
            }
        }
        if done {
            let reason = json["done_reason"].as_str().unwrap_or("stop");
            if let Some(error) = crate::content_filter_error("local", Some(reason)) {
                return Err(error);
            }
            self.finish = Some(reason.to_string());
            self.done = true;
            if json.get("prompt_eval_count").is_some() || json.get("eval_count").is_some() {
                self.usage = LlmUsage::reported(
                    crate::json_usage_u32(&json["prompt_eval_count"]),
                    crate::json_usage_u32(&json["eval_count"]),
                    crate::json_usage_u32(&json["prompt_eval_cached_count"]),
                );
            }
        }
        Ok(texts)
    }

    fn complete(&self) -> bool {
        self.done
    }
    fn finish(self) -> Result<LlmResponse, ConnectorError> {
        if !self.done {
            return Err(ConnectorError::StreamError(
                "Ollama stream ended before done".into(),
            ));
        }
        let mut ids = HashSet::new();
        let mut calls = Vec::with_capacity(self.calls.len());
        for (expected, (index, call)) in self.calls.into_iter().enumerate() {
            if expected != index || !ids.insert(call.id.clone()) {
                return Err(invalid("sparse or duplicate native calls"));
            }
            calls.push(call);
        }
        Ok(LlmResponse {
            content: self.content,
            finish_reason: self.finish,
            tokens_used: self.usage.total(),
            usage: self.usage,
            tool_calls: calls,
            provider_metadata: None,
        })
    }
}
