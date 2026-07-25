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
            "usage": {
                "prompt_tokens": 30,
                "completion_tokens": 20,
                "total_tokens": 50,
                "prompt_tokens_details": {"cached_tokens": 10}
            }
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
        assert_eq!(resp.usage, LlmUsage::reported(30, 20, 10));
    }

    #[tokio::test]
    async fn openai_plain_content_response() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "Hello! How can I help?"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
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
    async fn openai_oversized_usage_saturates_instead_of_wrapping() {
        let mock_server = MockServer::start().await;
        let oversized = u64::from(u32::MAX) + 1;
        let response_body = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "large usage"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": oversized,
                "completion_tokens": u64::MAX,
                "total_tokens": u64::MAX,
                "prompt_tokens_details": {"cached_tokens": oversized}
            }
        });

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let adapter = OpenAiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();
        let response = session
            .send(vec![StandardMessage::user("report usage")])
            .await
            .unwrap();

        assert_eq!(response.tokens_used, u32::MAX);
        assert_eq!(
            response.usage,
            LlmUsage::reported(u32::MAX, u32::MAX, u32::MAX)
        );
    }

    #[tokio::test]
    async fn openai_returns_first_failure_without_hidden_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let adapter = OpenAiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let error = session
            .send(vec![StandardMessage::user("test")])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            kernel::ConnectorError::ServiceUnavailable(_)
        ));
    }

    #[tokio::test]
    async fn openai_applies_per_call_output_bound() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(serde_json::json!({"max_tokens": 37})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "bounded"}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 1}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let adapter = OpenAiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();
        assert!(session.enforces_max_output_tokens());
        let response = session
            .send_with_options(
                vec![StandardMessage::user("test")],
                &[],
                LlmRequestOptions {
                    max_output_tokens: Some(37),
                    ..LlmRequestOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(response.content, "bounded");
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
