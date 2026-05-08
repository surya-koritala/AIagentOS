//! Integration tests for Anthropic adapter with tool use using wiremock.

#[cfg(test)]
mod tests {
    use crate::anthropic::AnthropicAdapter;
    use kernel::connector::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn anthropic_tool_use_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [
                    {"type": "text", "text": "I'll read that file for you."},
                    {"type": "tool_use", "id": "toolu_01", "name": "read_file", "input": {"path": "/tmp/test.txt"}}
                ],
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 30, "output_tokens": 20}
            })))
            .mount(&mock_server)
            .await;

        let adapter =
            AnthropicAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let tools = vec![ToolDefinition {
            name: "read_file".into(),
            description: "Read a file".into(),
            parameters: serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        }];

        let resp = session
            .send_with_tools(vec![StandardMessage::user("Read /tmp/test.txt")], &tools)
            .await
            .unwrap();

        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].id, "toolu_01");
        assert_eq!(resp.tool_calls[0].name, "read_file");
        assert_eq!(resp.tool_calls[0].arguments["path"], "/tmp/test.txt");
        assert_eq!(resp.tokens_used, 50);
    }

    #[tokio::test]
    async fn anthropic_plain_text_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [{"type": "text", "text": "Hello! How can I help?"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 8}
            })))
            .mount(&mock_server)
            .await;

        let adapter =
            AnthropicAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("Hi")])
            .await
            .unwrap();
        assert_eq!(resp.content, "Hello! How can I help?");
        assert!(resp.tool_calls.is_empty());
    }
}
