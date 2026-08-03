//! Local LLM adapter (Ollama/llama.cpp) via HTTP.

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

pub struct LocalLlmAdapter {
    id: ProviderId,
    client: reqwest::Client,
    base_url: String,
    model: String,
}

impl LocalLlmAdapter {
    pub fn new(base_url: String, model: String) -> Self {
        Self {
            id: "local".to_string(),
            client: reqwest::Client::new(),
            base_url,
            model,
        }
    }
}

struct LocalSession {
    provider_id: ProviderId,
    client: reqwest::Client,
    base_url: String,
    model: String,
}

impl LocalSession {
    async fn post_chat(
        &self,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, ConnectorError> {
        self.client
            .post(format!("{}/api/chat", self.base_url))
            .json(body)
            .send()
            .await
            .map_err(|e| crate::transport_error(&self.provider_id, e))
    }
}

#[async_trait::async_trait]
impl LlmSession for LocalSession {
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
        // Assistant tool-call turns and tool results must survive the round
        // trip, or a multi-step tool conversation loses its own history.
        let msgs: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| {
                let mut obj = serde_json::json!({"role": m.role, "content": m.content});
                if let Some(ref calls) = m.tool_calls {
                    obj["tool_calls"] = serde_json::json!(calls
                        .iter()
                        .map(|call| serde_json::json!({
                            "function": {"name": call.name, "arguments": call.arguments}
                        }))
                        .collect::<Vec<_>>());
                }
                obj
            })
            .collect();
        let mut body = serde_json::json!({
            "model": self.model,
            "messages": msgs,
            "stream": false,
        });
        if let Some(max_output_tokens) = options.max_output_tokens {
            body["options"] = serde_json::json!({
                "num_predict": max_output_tokens
            });
        }
        if !tools.is_empty() {
            body["tools"] = serde_json::json!(tools
                .iter()
                .map(|tool| serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters,
                    }
                }))
                .collect::<Vec<_>>());
        }

        let resp = self.post_chat(&body).await?;

        // Ollama rejects `tools` for a model whose template lacks tool support,
        // and the executor sends the agent's whole tool set on every turn — so
        // without this fallback such a model would fail every turn, not just
        // tool-using ones. Retry once without tools and let the existing
        // plaintext recovery in the executor handle any tool intent the model
        // emits as text.
        let resp = if resp.status() == reqwest::StatusCode::BAD_REQUEST && !tools.is_empty() {
            let detail = crate::bounded_response_body(resp).await;
            if detail.contains("does not support tools") {
                tracing::warn!(
                    provider = %self.provider_id,
                    model = %self.model,
                    "model has no tool template; retrying without tool definitions"
                );
                let mut untooled = body.clone();
                if let Some(object) = untooled.as_object_mut() {
                    object.remove("tools");
                }
                self.post_chat(&untooled).await?
            } else {
                return Err(crate::http_status_error(
                    &self.provider_id,
                    reqwest::StatusCode::BAD_REQUEST,
                    Some(&detail),
                    None,
                    None,
                ));
            }
        } else {
            resp
        };

        if !resp.status().is_success() {
            return Err(crate::provider_http_error(&self.provider_id, resp).await);
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ConnectorError::ProtocolError(e.to_string()))?;
        let content = json["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        // `/api/chat` returns arguments as a JSON object; accept an
        // OpenAI-shaped JSON string too so an Ollama-compatible gateway works.
        let tool_calls = json["message"]["tool_calls"]
            .as_array()
            .map(|calls| {
                calls
                    .iter()
                    .enumerate()
                    .filter_map(|(index, call)| {
                        let name = call["function"]["name"].as_str()?.to_string();
                        let raw = &call["function"]["arguments"];
                        let arguments = match raw {
                            serde_json::Value::String(text) => {
                                serde_json::from_str(text).unwrap_or(serde_json::Value::Null)
                            }
                            other => other.clone(),
                        };
                        Some(kernel::connector::ToolCall {
                            id: call["id"]
                                .as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| format!("call_{index}")),
                            name,
                            arguments,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let prompt_tokens = json["prompt_eval_count"].as_u64().unwrap_or(0);
        let output_tokens = json["eval_count"].as_u64().unwrap_or(0);

        Ok(LlmResponse {
            content,
            finish_reason: Some("stop".to_string()),
            tokens_used: crate::saturating_usage_sum(prompt_tokens, output_tokens),
            usage: kernel::connector::LlmUsage::reported(
                crate::saturating_usage_u32(prompt_tokens),
                crate::saturating_usage_u32(output_tokens),
                0,
            ),
            tool_calls,
        })
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
impl LlmProviderAdapter for LocalLlmAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn name(&self) -> &str {
        "Local LLM (Ollama)"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }
    fn capabilities(&self) -> kernel::connector::ProviderCapabilities {
        kernel::connector::ProviderCapabilities {
            prompt_cancellation: true,
            tool_calls: true,
            parallel_tool_calls: true,
            api_family: "ollama-v1".into(),
            ..Default::default()
        }
    }

    async fn is_available(&self) -> bool {
        self.client
            .get(format!("{}/api/tags", self.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(LocalSession {
            provider_id: self.id.clone(),
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
        }))
    }

    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": msg.role, "content": msg.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage {
            role: value.get("role")?.as_str()?.to_string(),
            content: value.get("content")?.as_str().unwrap_or("").to_string(),
            tool_call_id: None,
            tool_calls: None,
        })
    }
}
