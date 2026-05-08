//! Integration tests for OpenAI adapter function calling using wiremock.

#[cfg(test)]
mod tests {
    use crate::openai::OpenAiAdapter;
    use kernel::connector::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn openai_sends_tools_and_parses_tool_calls() {
        let mock_server = MockServer::start().await;

        // Mock a response with tool_calls
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

        let adapter = OpenAiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
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
    async fn openai_plain_content_response() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "Hello! How can I help?"},
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 20}
        });

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let adapter = OpenAiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("Hi")])
            .await
            .unwrap();

        assert_eq!(resp.content, "Hello! How can I help?");
        assert!(resp.tool_calls.is_empty());
        assert_eq!(resp.finish_reason, Some("stop".to_string()));
    }

    #[tokio::test]
    async fn openai_retries_on_failure() {
        let mock_server = MockServer::start().await;

        // First two calls fail, third succeeds
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

        let adapter = OpenAiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("test")])
            .await
            .unwrap();
        assert_eq!(resp.content, "recovered");
    }

    #[tokio::test]
    async fn openai_multiple_tool_calls() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"/a.txt\"}"}},
                        {"id": "call_2", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"/b.txt\"}"}}
                    ]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"total_tokens": 80}
        });

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let adapter = OpenAiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send_with_tools(
                vec![StandardMessage::user("Read both files")],
                &[ToolDefinition {
                    name: "read_file".into(),
                    description: "Read".into(),
                    parameters: serde_json::json!({}),
                }],
            )
            .await
            .unwrap();

        assert_eq!(resp.tool_calls.len(), 2);
        assert_eq!(resp.tool_calls[0].name, "read_file");
        assert_eq!(resp.tool_calls[1].arguments["path"], "/b.txt");
    }
}
