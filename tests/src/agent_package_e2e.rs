//! E2E: load **and run** a packaged agent through the full LLM pipeline.
//!
//! Exercises `kernel::agent_package` against a wiremock-backed adapter — no real
//! API — so the package's `entry` prompt drives a real `send_message` turn and
//! we observe the mocked completion come back, plus the manifest's seeded memory
//! landing in long-term storage.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use adapters::azure_openai::AzureOpenAiAdapter;
    use kernel::agent_package::{run_package, AgentManifest};
    use kernel::connector::LlmProviderAdapter;
    use kernel::context::ContextManager;
    use kernel::AgentKernelImpl;

    #[tokio::test]
    async fn load_and_run_sample_packaged_agent() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/openai/deployments/.*/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": {"role": "assistant", "content": "Summary: the kernel runs agents."},
                    "finish_reason": "stop"
                }],
                "usage": {"total_tokens": 20}
            })))
            .mount(&mock_server)
            .await;

        let kernel = AgentKernelImpl::new().unwrap();
        let adapter = AzureOpenAiAdapter::new(mock_server.uri(), "gpt-4o".into(), "key".into());
        kernel.register_provider(Arc::new(adapter)).unwrap();

        // A package pointed at the registered provider, with an entry prompt and
        // seeded memory. Mirrors examples/packages/researcher/agent.toml.
        let manifest = AgentManifest::from_toml_str(
            r#"
name = "researcher"
description = "Reads sources and summarizes."
task = "Research and summarize."
entry = "Summarize the project README."
provider = "azure-openai"
profile = "standard"
priority = 2
memory = ["Prefer primary sources.", "Always cite claims."]
"#,
        )
        .expect("manifest parses");

        // Load + run: creates the agent, seeds memory, and drives the entry turn.
        let (handle, output) = run_package(&kernel, &manifest).await.expect("run package");

        let output = output.expect("entry present ⇒ an output turn");
        assert_eq!(output.content, "Summary: the kernel runs agents.");
        assert_eq!(output.tool_calls_made, 0);

        // The seeded memory landed in long-term storage on load.
        let facts = kernel
            .context_manager
            .query_memory(handle.id, "primary sources")
            .await
            .unwrap();
        assert!(
            facts.iter().any(|f| f.content.contains("primary sources")),
            "seeded fact should be queryable: {facts:?}"
        );
    }
}
