//! Keyless fixtures across the real public wire and durable agent lifecycle.

use adapters::openai::OpenAiAdapter;
use agent_sdk::{
    ContentPart, ImageInput, ImageInputProfile, ImageMediaType, KernelClient, MessageContent,
    MessageStreamEvent, WireErrorCode,
};
use kernel::auth::Role;
use kernel::syscall_server::{Syscall, SyscallClient, SyscallReply, SyscallServer};
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use serde_json::{json, Value};
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";
fn content() -> MessageContent {
    MessageContent::parts(vec![
        ContentPart::Text {
            text: "before".into(),
        },
        ContentPart::Image {
            image: ImageInput::new(ImageMediaType::Png, PNG.into()).unwrap(),
        },
        ContentPart::Text {
            text: "after".into(),
        },
    ])
    .unwrap()
}
fn config() -> AgentConfig {
    AgentConfig {
        name: "image fixture".into(),
        task: "governed inline input".into(),
        llm_provider: "openai".into(),
        permission_profile: "standard".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }
}
fn register(kernel: &AgentKernelImpl, server: &MockServer) {
    kernel
        .register_provider(Arc::new(
            OpenAiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(ImageInputProfile {
                    model_id: "vision-fixture".into(),
                    max_tokens_per_image: 3000,
                }),
        ))
        .unwrap();
}
async fn mount_response(server: &MockServer) {
    let chunks = [
        json!({"choices":[{"delta":{"content":"image "}}]}),
        json!({"choices":[{"delta":{"content":"result"},"finish_reason":"stop"}]}),
        json!({"choices":[],"usage":{"prompt_tokens":3000,"completion_tokens":2,"total_tokens":3002}}),
    ];
    let body = chunks
        .iter()
        .map(|chunk| format!("data: {chunk}\n\n"))
        .collect::<String>()
        + "data: [DONE]\n\n";
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn image_input_sdk_desktop_tui_wire_auth_and_version_guards_use_the_same_turn_path() {
    let provider = MockServer::start().await;
    mount_response(&provider).await;
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    register(&kernel, &provider);
    let tenant = kernel.create_tenant("image-owner").await.unwrap();
    let foreign = kernel.create_tenant("image-foreign").await.unwrap();
    let user = kernel
        .register_user(&tenant, "image-user", "fixture@image.test", Role::User)
        .await
        .unwrap();
    let token = kernel
        .issue_api_key(&user, "image-input-fixture")
        .await
        .unwrap();
    let owner = kernel
        .create_agent_for_tenant(&tenant, config())
        .await
        .unwrap()
        .id;
    let foreign_agent = kernel
        .create_agent_for_tenant(&foreign, config())
        .await
        .unwrap()
        .id;
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap()
        .with_auth_token("image-system-fixture");
    let address = server.local_addr().unwrap().to_string();
    let task = tokio::spawn(server.serve());
    let mut sdk = KernelClient::connect(&address).await.unwrap();
    let denied = sdk
        .send_message_content(owner.to_string(), content())
        .await
        .unwrap_err();
    assert_eq!(
        denied.wire_code(),
        Some(WireErrorCode::AuthenticationRequired)
    );
    sdk.authenticate(token.clone()).await.unwrap();
    let denied = sdk
        .send_message_content(foreign_agent.to_string(), content())
        .await
        .unwrap_err();
    assert_eq!(denied.wire_code(), Some(WireErrorCode::AuthorizationDenied));
    assert!(provider.received_requests().await.unwrap().is_empty());
    assert_eq!(
        sdk.send_message_content(owner.to_string(), content())
            .await
            .unwrap()
            .content,
        "image result"
    );
    let mut tokens = String::new();
    assert_eq!(
        sdk.send_message_content_stream(
            "image-sdk-stream",
            owner.to_string(),
            content(),
            |event| if let MessageStreamEvent::Token { delta } = event {
                tokens.push_str(delta)
            }
        )
        .await
        .unwrap()
        .content,
        "image result"
    );
    assert_eq!(tokens, "image result");
    let desktop = tauri_app::DesktopClient::connect(&address, Some(&token))
        .await
        .unwrap();
    assert_eq!(
        desktop
            .send_message_content(owner.to_string(), content())
            .await
            .unwrap()
            .content,
        "image result"
    );
    let tui = agent_tui::TuiClient::connect(&address, Some(&token))
        .await
        .unwrap();
    assert_eq!(
        tui.message_client()
            .send_message_content_stream("image-tui-stream", owner.to_string(), content(), |_| {})
            .await
            .unwrap()
            .content,
        "image result"
    );
    let mut v1 = SyscallClient::connect(&address).await.unwrap();
    assert!(matches!(
        v1.call(Syscall::Hello {
            protocol_version: 1
        })
        .await
        .unwrap(),
        SyscallReply::Hello { .. }
    ));
    v1.call(Syscall::Authenticate { token }).await.unwrap();
    let refused = v1
        .call(Syscall::SendMessageContent {
            agent_id: owner.to_string(),
            content: content(),
        })
        .await
        .unwrap();
    assert!(matches!(refused,SyscallReply::Error{message} if message.contains("v2")));
    assert_eq!(provider.received_requests().await.unwrap().len(), 4);
    for request in provider.received_requests().await.unwrap() {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert!(body["messages"].as_array().unwrap().iter().any(|message|message["content"]==json!([
            {"type":"text","text":"before"},{"type":"image_url","image_url":{"url":format!("data:image/png;base64,{PNG}"),"detail":"high"}},{"type":"text","text":"after"}
        ])));
    }
    drop((v1, tui, desktop, sdk));
    task.abort();
    let _ = task.await;
    kernel.stop_agent(owner).await.unwrap();
    kernel.stop_agent(foreign_agent).await.unwrap();
}

#[tokio::test]
async fn image_input_actual_clone_and_kernel_restart_replay_exact_images_and_legacy_text() {
    let provider = MockServer::start().await;
    mount_response(&provider).await;
    let root =
        std::env::temp_dir().join(format!("aiagentos-image-kernel-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("kernel.sqlite");
    let (parent, child) = {
        let kernel = AgentKernelImpl::with_db_path(&database).unwrap();
        register(&kernel, &provider);
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        kernel.send_message(parent, "legacy text").await.unwrap();
        kernel
            .send_message_content(parent, content())
            .await
            .unwrap();
        let child = uuid::Uuid::new_v4();
        let cloned = kernel
            .clone_agent(parent, child, "image child".into(), vec![])
            .await
            .unwrap();
        assert!(cloned.snapshot.is_some());
        kernel
            .send_message(child, "continue inherited image")
            .await
            .unwrap();
        (parent, child)
    };
    provider.reset().await;
    mount_response(&provider).await;
    {
        let kernel = AgentKernelImpl::with_db_path(&database).unwrap();
        register(&kernel, &provider);
        kernel.send_message(child, "restart replay").await.unwrap();
        let requests = provider.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
        let messages = body["messages"].as_array().unwrap();
        assert!(messages
            .iter()
            .any(|message| message["content"] == "legacy text"));
        assert!(messages
            .iter()
            .any(|message| message["content"][1]["image_url"]["url"]
                == format!("data:image/png;base64,{PNG}")));
        kernel.stop_agent(child).await.unwrap();
        kernel.stop_agent(parent).await.unwrap();
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn image_input_typed_stream_fences_and_exact_cancellation_prevent_replay() {
    use agent_sdk::AgentMutationFenceProof;
    use std::time::Duration;
    let provider = MockServer::start().await;
    Mock::given(method("POST")).and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)).set_body_string("data: [DONE]\n\n")).expect(1).mount(&provider).await;
    let kernel = Arc::new(AgentKernelImpl::new().unwrap()); register(&kernel,&provider);
    let agent = kernel.create_agent_full(config()).await.unwrap().id.to_string();
    let proof = AgentMutationFenceProof{cluster_id:uuid::Uuid::new_v4().to_string(),owner_node_id:kernel.cluster_control.identity().node_id.clone(),authority_term:2,authority_generation:7,fencing_token:3,proof_expires_at:chrono::Utc::now()+chrono::Duration::seconds(60)};
    kernel.cluster_control.install_agent_mutation_fence(&agent,&proof.cluster_id,&proof.owner_node_id,proof.authority_term,proof.authority_generation,proof.fencing_token,proof.proof_expires_at,"system","image fixture").unwrap();
    let server = SyscallServer::bind(kernel.clone(),"127.0.0.1:0").await.unwrap().with_auth_token("image-system-fixture");
    let address = server.local_addr().unwrap().to_string(); let task = tokio::spawn(server.serve());
    let mut stream_client = KernelClient::connect(&address).await.unwrap();stream_client.authenticate("image-system-fixture").await.unwrap();
    assert_eq!(stream_client.send_message_content(&agent,content()).await.unwrap_err().wire_code(),Some(WireErrorCode::Conflict));
    let mut stale = proof.clone();stale.fencing_token=2;
    assert_eq!(stream_client.send_message_content_fenced(&agent,stale,content()).await.unwrap_err().wire_code(),Some(WireErrorCode::Conflict));
    assert!(provider.received_requests().await.unwrap().is_empty());
    let mut cancellation = KernelClient::connect(&address).await.unwrap();cancellation.authenticate("image-system-fixture").await.unwrap();
    let owned_agent = agent.clone();let owned_proof = proof.clone();
    let (started,mut events) = tokio::sync::mpsc::unbounded_channel();
    let stream = tokio::spawn(async move {stream_client.send_message_content_stream_fenced("image-fenced-cancel",owned_agent,owned_proof,content(),|event|if matches!(event,MessageStreamEvent::Started){let _=started.send(());}).await});
    tokio::time::timeout(Duration::from_secs(2),events.recv()).await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(2),async {while provider.received_requests().await.unwrap().is_empty(){tokio::task::yield_now().await;}}).await.unwrap();
    assert!(!cancellation.cancel_request_fenced("wrong-image-request",&agent,proof.clone()).await.unwrap());
    assert!(cancellation.cancel_request_fenced("image-fenced-cancel",&agent,proof.clone()).await.unwrap());
    let error = tokio::time::timeout(Duration::from_secs(2),stream).await.unwrap().unwrap().unwrap_err();
    assert_eq!(error.wire_code(),Some(WireErrorCode::Cancelled));
    assert!(!cancellation.cancel_request_fenced("image-fenced-cancel",&agent,proof).await.unwrap());
    assert_eq!(provider.received_requests().await.unwrap().len(),1,"cancelled image turn must not retry");
    drop(cancellation);task.abort();let _=task.await; kernel.stop_agent(agent.parse().unwrap()).await.unwrap();
}
