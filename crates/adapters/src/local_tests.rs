//! Integration tests for the Ollama adapter using wiremock.

#[cfg(test)]
mod tests {
    use crate::local::LocalLlmAdapter;
    use kernel::connector::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn read_file_tool() -> ToolDefinition {
        ToolDefinition {
            name: "read_file".to_string(),
            description: "Read a file".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {"path": {"type": "string"}}
            }),
        }
    }

    #[tokio::test]
    async fn ollama_sends_tools_and_parses_native_tool_calls() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .and(body_partial_json(serde_json::json!({
                "tools": [{"type": "function", "function": {"name": "read_file"}}]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "function": {"name": "read_file", "arguments": {"path": "/tmp/a.txt"}}
                    }]
                },
                "prompt_eval_count": 12,
                "eval_count": 4
            })))
            .expect(1)
            .mount(&server)
            .await;

        let adapter = LocalLlmAdapter::new(server.uri(), "llama3.2".to_string());
        let session = adapter.create_session().await.unwrap();
        let response = session
            .send_with_tools(vec![StandardMessage::user("read it")], &[read_file_tool()])
            .await
            .unwrap();

        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "read_file");
        assert_eq!(response.tool_calls[0].arguments["path"], "/tmp/a.txt");
        assert!(
            !response.tool_calls[0].id.is_empty(),
            "a tool call must carry an id even when Ollama omits one"
        );
    }

    /// Ollama returns arguments as an object; an OpenAI-shaped gateway returns
    /// them as a JSON string. Both must parse.
    #[tokio::test]
    async fn ollama_accepts_string_encoded_tool_arguments() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "call_7",
                        "function": {"name": "read_file", "arguments": "{\"path\":\"/etc/hosts\"}"}
                    }]
                }
            })))
            .mount(&server)
            .await;

        let adapter = LocalLlmAdapter::new(server.uri(), "llama3.2".to_string());
        let session = adapter.create_session().await.unwrap();
        let response = session
            .send_with_tools(vec![StandardMessage::user("go")], &[read_file_tool()])
            .await
            .unwrap();

        assert_eq!(response.tool_calls[0].id, "call_7");
        assert_eq!(response.tool_calls[0].arguments["path"], "/etc/hosts");
    }

    /// A model whose template lacks tool support must keep working.
    ///
    /// The executor sends the agent's entire tool set on every turn, so without
    /// this fallback such a model would fail *every* turn once tools started
    /// being sent — not just tool-using ones.
    #[tokio::test]
    async fn model_without_tool_support_falls_back_instead_of_failing_every_turn() {
        let server = MockServer::start().await;
        // With tools: Ollama rejects it the way a tool-less template does.
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .and(body_partial_json(serde_json::json!({"tools": []})))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "registry.ollama.ai/library/gemma2:latest does not support tools"
            })))
            .mount(&server)
            .await;

        let adapter = LocalLlmAdapter::new(server.uri(), "gemma2".to_string());
        let session = adapter.create_session().await.unwrap();
        let response = session
            .send_with_tools(vec![StandardMessage::user("hello")], &[read_file_tool()])
            .await;

        // The retry omits `tools`, so the tools-matching mock no longer applies
        // and wiremock has no match — the call must not have been abandoned at
        // the first 400.
        assert!(
            response.is_err(),
            "unmatched retry is expected here; the point is that a retry happened"
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            2,
            "a tool-less model must be retried once without tool definitions"
        );
        let second: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert!(
            second.get("tools").is_none(),
            "the retry must not carry tool definitions: {second}"
        );
    }

    /// A 400 that is not about tool support must surface, not be retried away.
    #[tokio::test]
    async fn unrelated_bad_request_is_not_retried() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "model 'nope' not found"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let adapter = LocalLlmAdapter::new(server.uri(), "nope".to_string());
        let session = adapter.create_session().await.unwrap();
        let error = session
            .send_with_tools(vec![StandardMessage::user("hi")], &[read_file_tool()])
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("not found"),
            "the original diagnostic must survive: {error}"
        );
    }

    #[tokio::test]
    async fn ollama_advertises_native_tool_calling() {
        let adapter = LocalLlmAdapter::new("http://127.0.0.1:1".to_string(), "llama3.2".into());
        assert!(
            adapter.capabilities().tool_calls,
            "failover eligibility depends on this being honest"
        );
    }
}
