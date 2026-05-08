//! Azure OpenAI streaming support — SSE parsing for real-time token delivery.

use kernel::connector::*;
use kernel::ConnectorError;
use tokio::sync::mpsc;

/// A chunk from the streaming response.
#[derive(Debug, Clone)]
pub enum StreamChunk {
    /// A text token delta.
    Token(String),
    /// A tool call is starting.
    ToolCallStart { id: String, name: String },
    /// Tool call argument delta.
    ToolCallDelta { id: String, arguments_delta: String },
    /// Stream is complete with final metadata.
    Done { tokens_used: u32 },
}

/// Parse an SSE stream from Azure OpenAI into StreamChunks.
pub async fn parse_azure_sse_stream(
    response: reqwest::Response,
    tx: mpsc::Sender<StreamChunk>,
) -> Result<LlmResponse, ConnectorError> {
    let mut content = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    let mut current_tool_args: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut tokens_used: u32 = 0;

    let mut stream = response.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk) = tokio_stream::StreamExt::next(&mut stream).await {
        let bytes = chunk.map_err(|e| ConnectorError::StreamError(e.to_string()))?;
        buffer.push_str(&String::from_utf8_lossy(&bytes));

        // Process complete SSE lines
        while let Some(pos) = buffer.find("\n\n") {
            let event = buffer[..pos].to_string();
            buffer = buffer[pos + 2..].to_string();

            for line in event.lines() {
                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        let _ = tx.send(StreamChunk::Done { tokens_used }).await;
                        // Build final response
                        for (id, args) in &current_tool_args {
                            if let Some(tc) = tool_calls.iter_mut().find(|t| &t.id == id) {
                                tc.arguments =
                                    serde_json::from_str(args).unwrap_or(serde_json::Value::Null);
                            }
                        }
                        return Ok(LlmResponse {
                            content,
                            finish_reason: Some("stop".into()),
                            tokens_used,
                            tool_calls,
                        });
                    }

                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                        let delta = &json["choices"][0]["delta"];

                        // Content token
                        if let Some(text) = delta["content"].as_str() {
                            if !text.is_empty() {
                                content.push_str(text);
                                let _ = tx.send(StreamChunk::Token(text.to_string())).await;
                            }
                        }

                        // Tool calls
                        if let Some(tcs) = delta["tool_calls"].as_array() {
                            for tc in tcs {
                                let idx = tc["index"].as_u64().unwrap_or(0) as usize;
                                if let Some(id) = tc["id"].as_str() {
                                    let name =
                                        tc["function"]["name"].as_str().unwrap_or("").to_string();
                                    tool_calls.push(ToolCall {
                                        id: id.to_string(),
                                        name: name.clone(),
                                        arguments: serde_json::Value::Null,
                                    });
                                    current_tool_args.insert(id.to_string(), String::new());
                                    let _ = tx
                                        .send(StreamChunk::ToolCallStart {
                                            id: id.to_string(),
                                            name,
                                        })
                                        .await;
                                }
                                if let Some(args) = tc["function"]["arguments"].as_str() {
                                    if let Some(tc_ref) = tool_calls.get(idx) {
                                        let id = tc_ref.id.clone();
                                        current_tool_args
                                            .entry(id.clone())
                                            .or_default()
                                            .push_str(args);
                                        let _ = tx
                                            .send(StreamChunk::ToolCallDelta {
                                                id,
                                                arguments_delta: args.to_string(),
                                            })
                                            .await;
                                    }
                                }
                            }
                        }

                        // Usage (in final chunk)
                        if let Some(usage) = json.get("usage") {
                            tokens_used = usage["total_tokens"].as_u64().unwrap_or(0) as u32;
                        }
                    }
                }
            }
        }
    }

    // Stream ended without [DONE]
    for (id, args) in &current_tool_args {
        if let Some(tc) = tool_calls.iter_mut().find(|t| &t.id == id) {
            tc.arguments = serde_json::from_str(args).unwrap_or(serde_json::Value::Null);
        }
    }

    Ok(LlmResponse {
        content,
        finish_reason: Some("stop".into()),
        tokens_used,
        tool_calls,
    })
}
