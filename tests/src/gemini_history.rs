//! Native provider state through the governed executor and durable restart.

use std::sync::Arc;

use adapters::gemini::GeminiAdapter;
use kernel::{AgentConfig, AgentKernelImpl, IsolationLevel, Priority, SandboxConfig};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(workspace: &std::path::Path) -> AgentConfig {
    AgentConfig {
        name: "gemini-fixture".into(),
        task: "read an owned fixture".into(),
        llm_provider: "gemini".into(),
        permission_profile: "full-access".into(),
        priority: Priority::default(),
        sandbox_config: Some(SandboxConfig {
            workspace_dir: workspace.to_path_buf(),
            isolation_level: IsolationLevel::Trusted,
            allowed_network_hosts: None,
            max_disk_usage_bytes: None,
            max_memory_bytes: None,
            container_image: None,
        }),
    }
}

fn response(parts: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 3,
            "thoughtsTokenCount": 5, "totalTokenCount": 15}
    }))
}

fn register(kernel: &AgentKernelImpl, server: &MockServer) {
    kernel
        .register_provider(Arc::new(
            GeminiAdapter::new("fixture-key".into())
                .with_model("fixture-native-model".into())
                .with_base_url(server.uri()),
        ))
        .unwrap();
}

#[tokio::test]
async fn signed_parallel_tool_turn_and_final_text_replay_after_kernel_restart() {
    let server = MockServer::start().await;
    let root = std::env::temp_dir().join(format!("agentos-gemini-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let file = root.join("fixture.txt");
    std::fs::write(&file, "owned fixture contents").unwrap();
    let db = root.join("store.db");
    // Capability-relative targets are portable. Windows canonical host paths
    // carry device prefixes that the kernel deliberately rejects as input.
    let native_parts = json!([
        {"functionCall": {"name": "read_file", "args": {"path": "fixture.txt"}},
         "thoughtSignature": "c2lnbmVkLWNhdGVnb3J5"},
        {"functionCall": {"name": "read_file", "args": {"path": "fixture.txt"}}}
    ]);
    Mock::given(method("POST"))
        .and(path("/v1beta/models/fixture-native-model:generateContent"))
        .respond_with(response(native_parts.clone()))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    let final_parts = json!([{"text": "verified fixture", "thoughtSignature": "c2lnbmVkLXRleHQ="}]);
    Mock::given(method("POST"))
        .and(path("/v1beta/models/fixture-native-model:generateContent"))
        .respond_with(response(final_parts.clone()))
        .with_priority(2)
        .mount(&server)
        .await;
    let id = {
        let kernel = AgentKernelImpl::with_db_path(&db).unwrap();
        register(&kernel, &server);
        let agent = kernel.create_agent_full(config(&root)).await.unwrap();
        let output = kernel
            .send_message(agent.id, "read the fixture twice")
            .await
            .unwrap();
        assert_eq!(output.content, "verified fixture");
        assert_eq!(output.tool_calls_made, 2);
        assert_eq!(output.usage.output_tokens, 16);
        agent.id
    };
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let body: Value = serde_json::from_slice(&requests[1].body).unwrap();
    let contents = body["contents"].as_array().unwrap();
    assert!(contents
        .iter()
        .any(|content| content["parts"] == native_parts));
    let results = contents
        .iter()
        .find(|content| content["parts"][0].get("functionResponse").is_some())
        .unwrap();
    assert_eq!(results["parts"].as_array().unwrap().len(), 2);
    for part in results["parts"].as_array().unwrap() {
        assert_eq!(part["functionResponse"]["name"], "read_file");
        assert!(
            part["functionResponse"]["response"]
                .to_string()
                .contains("owned fixture contents"),
            "unexpected governed read result: {part}"
        );
    }
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(response(json!([{"text": "continued"}])))
        .expect(1)
        .mount(&server)
        .await;
    {
        let kernel = AgentKernelImpl::with_db_path(&db).unwrap();
        register(&kernel, &server);
        let output = kernel
            .send_message(id, "continue from saved history")
            .await
            .unwrap();
        assert_eq!(output.content, "continued");
        assert_eq!(output.tool_calls_made, 0);
    }
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let contents = body["contents"].as_array().unwrap();
    assert!(contents
        .iter()
        .any(|content| content["parts"] == native_parts));
    assert!(contents
        .iter()
        .any(|content| content["parts"] == final_parts));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn malformed_native_round_never_executes_its_earlier_valid_write() {
    let server = MockServer::start().await;
    let root =
        std::env::temp_dir().join(format!("agentos-gemini-malformed-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let file = root.join("fixture.txt");
    std::fs::write(&file, "original").unwrap();
    Mock::given(method("POST")).respond_with(response(json!([
        {"functionCall": {"name": "write_file", "args": {"path": "fixture.txt", "content": "changed"}}},
        {"functionCall": {"name": "write_file", "args": "invalid arguments"}}
    ]))).expect(1).mount(&server).await;
    let kernel = AgentKernelImpl::new().unwrap();
    register(&kernel, &server);
    let agent = kernel.create_agent_full(config(&root)).await.unwrap();
    assert!(kernel.send_message(agent.id, "try a patch").await.is_err());
    assert_eq!(std::fs::read_to_string(file).unwrap(), "original");
    drop(kernel);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn signed_native_text_containing_a_tool_example_is_only_text() {
    let server = MockServer::start().await;
    let root = std::env::temp_dir().join(format!("agentos-gemini-text-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let file = root.join("fixture.txt");
    std::fs::write(&file, "original").unwrap();
    let example = json!({"tool": "write_file", "arguments": {
        "path": "fixture.txt", "content": "changed"
    }})
    .to_string();
    Mock::given(method("POST"))
        .respond_with(response(json!([
            {"text": example, "thoughtSignature": "c2ln"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let kernel = AgentKernelImpl::new().unwrap();
    register(&kernel, &server);
    let agent = kernel.create_agent_full(config(&root)).await.unwrap();
    let output = kernel
        .send_message(agent.id, "show a code example")
        .await
        .unwrap();
    assert_eq!(output.content, example);
    assert_eq!(output.tool_calls_made, 0);
    assert_eq!(std::fs::read_to_string(file).unwrap(), "original");
    drop(kernel);
    std::fs::remove_dir_all(root).unwrap();
}
