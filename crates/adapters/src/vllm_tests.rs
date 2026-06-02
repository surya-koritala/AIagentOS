//! Integration tests for the vLLM adapter using wiremock.

#[cfg(test)]
mod tests {
    use crate::vllm::VllmAdapter;
    use kernel::connector::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn vllm_plain_content_response() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "Hello from vLLM!"},
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 20}
        });

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let adapter = VllmAdapter::new(String::new()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("Hi")])
            .await
            .unwrap();

        assert_eq!(resp.content, "Hello from vLLM!");
        assert!(resp.tool_calls.is_empty());
        assert_eq!(resp.finish_reason, Some("stop".to_string()));
        assert_eq!(resp.tokens_used, 20);
    }

    #[tokio::test]
    async fn vllm_sends_tools_and_parses_tool_calls() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "read_file", "arguments": "{\"path\":\"/tmp/x\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"total_tokens": 42}
        });

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let adapter = VllmAdapter::new(String::new()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let tools = vec![ToolDefinition {
            name: "read_file".to_string(),
            description: "Read a file".to_string(),
            parameters: serde_json::json!({"type": "object"}),
        }];

        let resp = session
            .send_with_tools(vec![StandardMessage::user("read")], &tools)
            .await
            .unwrap();

        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].name, "read_file");
        assert_eq!(resp.tool_calls[0].arguments["path"], "/tmp/x");
        assert_eq!(resp.tokens_used, 42);
    }

    #[tokio::test]
    async fn vllm_uses_configured_model() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_partial_json(serde_json::json!({"model": "my-model"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 1}
            })))
            .mount(&mock_server)
            .await;

        let adapter = VllmAdapter::new(String::new())
            .with_base_url(mock_server.uri())
            .with_model("my-model".to_string());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("hi")])
            .await
            .unwrap();
        assert_eq!(resp.content, "ok");
    }

    #[tokio::test]
    async fn vllm_retries_on_failure() {
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

        let adapter = VllmAdapter::new(String::new()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("test")])
            .await
            .unwrap();
        assert_eq!(resp.content, "recovered");
    }
}
