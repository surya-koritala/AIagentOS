//! Actual agentctl binary fixtures, executed only by hosted CI.
use std::process::Command;
use std::sync::Arc;
use kernel::{AgentConfig,AgentKernelImpl,Priority};
use kernel::connector::ImageInputProfile;
use kernel::syscall_server::SyscallServer;
use serde_json::{json,Value};
use wiremock::{Mock,MockServer,ResponseTemplate};
use wiremock::matchers::{method,path};

const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

#[tokio::test(flavor="multi_thread")]
async fn image_input_actual_agentctl_file_and_stream_roundtrip_and_redacted_refusal() {
    let provider = MockServer::start().await;
    let body = [json!({"choices":[{"delta":{"content":"image result"},"finish_reason":"stop"}]}),json!({"choices":[],"usage":{"prompt_tokens":3000,"completion_tokens":2,"total_tokens":3002}})].iter().map(|chunk|format!("data: {chunk}\n\n")).collect::<String>()+"data: [DONE]\n\n";
    Mock::given(method("POST")).and(path("/chat/completions")).respond_with(ResponseTemplate::new(200).insert_header("content-type","text/event-stream").set_body_string(body)).mount(&provider).await;
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    kernel.register_provider(Arc::new(adapters::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(provider.uri()).with_model("vision-fixture".into()).with_image_input_profile(ImageInputProfile{model_id:"vision-fixture".into(),max_tokens_per_image:3000}))).unwrap();
    let agent = kernel.create_agent_full(AgentConfig{name:"CLI image".into(),task:"bounded input fixture".into(),llm_provider:"openai".into(),permission_profile:"standard".into(),priority:Priority::default(),sandbox_config:None}).await.unwrap().id;
    let server = SyscallServer::bind(kernel.clone(),"127.0.0.1:0").await.unwrap(); let address = server.local_addr().unwrap().to_string(); let task = tokio::spawn(server.serve());
    let root = std::env::temp_dir().join(format!("agentctl-image-{}",uuid::Uuid::new_v4())); std::fs::create_dir_all(&root).unwrap();
    let input = root.join("content.json"); std::fs::write(&input,serde_json::to_vec(&json!([{"type":"text","text":"describe"},{"type":"image","media_type":"image/png","data":PNG}])).unwrap()).unwrap();
    for command in ["message-content","stream-content"] {
        let args: Vec<String> = if command == "message-content" {vec![command.into(),agent.to_string(),input.display().to_string()]} else {vec![command.into(),"cli-image-request".into(),agent.to_string(),input.display().to_string()]};
        let address = address.clone();
        let output = tokio::task::spawn_blocking(move || Command::new(env!("CARGO_BIN_EXE_agentctl")).args(["--addr",&address]).args(args).output().unwrap()).await.unwrap();
        assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(PNG));
        if command == "message-content" { let value: Value = serde_json::from_slice(&output.stdout).unwrap(); assert_eq!(value["content"],"image result"); }
        else {
            let text = String::from_utf8(output.stdout).unwrap(); let frames = text.lines().map(|line|serde_json::from_str::<Value>(line).unwrap()).collect::<Vec<_>>();
            assert!(frames.iter().all(|frame|frame["request_id"]=="cli-image-request"));
            assert!(frames.iter().any(|frame|frame["type"]=="event" && frame["event"]["event"]=="token"));
            assert_eq!(frames.last().unwrap()["type"],"completed"); assert_eq!(frames.last().unwrap()["result"]["content"],"image result");
        }
    }
    std::fs::write(&input,serde_json::to_vec(&json!([{"type":"image","media_type":"image/gif","data":PNG}])).unwrap()).unwrap();
    let refused = tokio::task::spawn_blocking(move ||Command::new(env!("CARGO_BIN_EXE_agentctl")).args(["--addr",&address,"message-content",&agent.to_string()]).arg(input).output().unwrap()).await.unwrap();
    assert!(!refused.status.success()); assert!(!String::from_utf8_lossy(&refused.stderr).contains(PNG)); assert!(refused.stdout.is_empty());
    assert_eq!(provider.received_requests().await.unwrap().len(),2);
    task.abort(); let _ = task.await; kernel.stop_agent(agent).await.unwrap(); std::fs::remove_dir_all(root).unwrap();
}
