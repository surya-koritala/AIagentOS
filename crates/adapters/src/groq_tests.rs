//! Integration tests for the Groq adapter using wiremock.

#[cfg(test)]
mod tests {
    use crate::groq::GroqAdapter;
    use kernel::connector::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn groq_sends_tools_and_parses_tool_calls() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc123",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": "{\"path\":\"/tmp/test.txt\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"total_tokens": 50}
        });

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let adapter = GroqAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let tools = vec![ToolDefinition {
            name: "read_file".to_string(),
            description: "Read a file".to_string(),
            parameters: serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        }];

        let resp = session
            .send_with_tools(vec![StandardMessage::user("Read /tmp/test.txt")], &tools)
            .await
            .unwrap();

        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].id, "call_abc123");
        assert_eq!(resp.tool_calls[0].name, "read_file");
        assert_eq!(resp.tool_calls[0].arguments["path"], "/tmp/test.txt");
        assert_eq!(resp.tokens_used, 50);
    }

    #[tokio::test]
    async fn groq_plain_content_response() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "Hello from Groq!"},
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 20}
        });

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let adapter = GroqAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("Hi")])
            .await
            .unwrap();

        assert_eq!(resp.content, "Hello from Groq!");
        assert!(resp.tool_calls.is_empty());
        assert_eq!(resp.finish_reason, Some("stop".to_string()));
    }

    #[tokio::test]
    async fn groq_retries_on_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "recovered"}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 5}
            })))
            .mount(&mock_server)
            .await;

        let adapter = GroqAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("test")])
            .await
            .unwrap();
        assert_eq!(resp.content, "recovered");
    }

    #[tokio::test]
    async fn groq_uses_configured_model() {
        let mock_server = MockServer::start().await;

        // Only matches if the request body carries the overridden model.
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(serde_json::json!({"model": "mixtral-8x7b"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 1}
            })))
            .mount(&mock_server)
            .await;

        let adapter = GroqAdapter::new("test-key".to_string())
            .with_base_url(mock_server.uri())
            .with_model("mixtral-8x7b".to_string());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("hi")])
            .await
            .unwrap();
        assert_eq!(resp.content, "ok");
    }
}
