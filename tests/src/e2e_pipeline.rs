//! E2E integration tests for the full agent pipeline with wiremock.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path_regex};

    use kernel::{AgentConfig, AgentKernelImpl, Priority};
    use kernel::connector::LlmProviderAdapter;
    use adapters::azure_openai::AzureOpenAiAdapter;

    /// Full E2E test: create kernel → register Azure adapter → create agent → send message
    /// → LLM returns tool call → tool executes → LLM responds with final answer.
    #[tokio::test]
    async fn e2e_azure_openai_agent_with_tool_call() {
        let mock_server = MockServer::start().await;

        // First LLM call: returns a tool call (read_file)
        Mock::given(method("POST"))
            .and(path_regex("/openai/deployments/.*/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "call_abc",
                            "type": "function",
                            "function": {
                                "name": "read_file",
                                "arguments": "{\"path\":\"/tmp/e2e_test_agent_os.txt\"}"
                            }
                        }]
                    },
                    "finish_reason": "tool_calls"
                }],
                "usage": {"total_tokens": 30}
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // Second LLM call: returns final content after receiving tool result
        Mock::given(method("POST"))
            .and(path_regex("/openai/deployments/.*/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "The file contains: hello from e2e test"
                    },
                    "finish_reason": "stop"
                }],
                "usage": {"total_tokens": 25}
            })))
            .mount(&mock_server)
            .await;

        // Create a real file for the agent to read
        std::fs::write("/tmp/e2e_test_agent_os.txt", "hello from e2e test").unwrap();

        // Set up kernel
        let kernel = AgentKernelImpl::new().unwrap();

        // Register Azure adapter pointing at mock server
        let adapter = AzureOpenAiAdapter::new(
            mock_server.uri(),
            "gpt-4o".to_string(),
            "fake-key".to_string(),
        );
        kernel.register_provider(Arc::new(adapter)).unwrap();

        // Register filesystem provider so read_file actually works
        use kernel::resources::{ResourceBroker, ResourceProvider, ResourceType};
        use kernel::ResourceError;
        struct RealFs;
        #[async_trait::async_trait]
        impl ResourceProvider for RealFs {
            fn resource_type(&self) -> ResourceType { ResourceType::Filesystem }
            fn supported_operations(&self) -> Vec<String> { vec!["read".into(), "write".into(), "list".into()] }
            async fn execute(&self, operation: &str, params: &serde_json::Value) -> Result<serde_json::Value, ResourceError> {
                let path = params["path"].as_str().unwrap_or("");
                match operation {
                    "read" => {
                        let content = tokio::fs::read_to_string(path).await
                            .map_err(|e| ResourceError::OperationFailed(e.to_string()))?;
                        Ok(serde_json::json!({"content": content}))
                    }
                    _ => Ok(serde_json::json!({}))
                }
            }
        }
        kernel.resource_broker.register_provider(Box::new(RealFs));

        // Create agent
        let config = AgentConfig {
            name: "test-agent".into(),
            task: "file reader".into(),
            llm_provider: "azure-openai".into(),
            permission_profile: "full-access".into(), // skip permission checks for test
            priority: Priority::default(),
            sandbox_config: None,
        };
        let handle = kernel.create_agent_full(config).await.unwrap();

        // Send message — this triggers the full pipeline:
        // user msg → LLM → tool_call(read_file) → actually reads /tmp/e2e_test_agent_os.txt → LLM → response
        let output = kernel.send_message(handle.id, "Read the test file").await.unwrap();

        // Verify
        assert!(output.content.contains("hello from e2e test"));
        assert_eq!(output.tool_calls_made, 1);
        assert_eq!(output.tokens_used, 55); // 30 + 25

        // Cleanup
        std::fs::remove_file("/tmp/e2e_test_agent_os.txt").ok();
    }

    /// Test that agent handles LLM returning plain content (no tool calls).
    #[tokio::test]
    async fn e2e_simple_chat_no_tools() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex("/openai/deployments/.*/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": {"role": "assistant", "content": "Hello! I'm your AI assistant."},
                    "finish_reason": "stop"
                }],
                "usage": {"total_tokens": 15}
            })))
            .mount(&mock_server)
            .await;

        let kernel = AgentKernelImpl::new().unwrap();
        let adapter = AzureOpenAiAdapter::new(mock_server.uri(), "gpt-4o".into(), "key".into());
        kernel.register_provider(Arc::new(adapter)).unwrap();

        let handle = kernel.create_agent_full(AgentConfig {
            name: "chat-agent".into(),
            task: "chat".into(),
            llm_provider: "azure-openai".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        }).await.unwrap();

        let output = kernel.send_message(handle.id, "Hi there").await.unwrap();
        assert_eq!(output.content, "Hello! I'm your AI assistant.");
        assert_eq!(output.tool_calls_made, 0);
    }
}
