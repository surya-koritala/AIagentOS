use std::sync::Arc;
use kernel::connector::*;
use kernel::ConnectorError;
use serde_json::json;
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

fn message() -> StandardMessage {
    StandardMessage::user_content(MessageContent::parts(vec![
        ContentPart::Image { image: ImageInput::new(ImageMediaType::Png, PNG.into()).unwrap() },
        ContentPart::Text { text: "describe".into() },
    ]).unwrap())
}
fn profile() -> ImageInputProfile { ImageInputProfile { model_id: "vision-fixture".into(), max_tokens_per_image: 3000 } }

#[tokio::test]
async fn image_input_four_documented_provider_shapes_and_reported_usage() {
    let server = MockServer::start().await;
    let openai = json!({"choices":[{"message":{"content":"fixture result"},"finish_reason":"stop"}], "usage":{"prompt_tokens":3000,"completion_tokens":2,"total_tokens":3002}});
    Mock::given(method("POST")).and(path("/chat/completions")).respond_with(ResponseTemplate::new(200).set_body_json(openai.clone())).mount(&server).await;
    Mock::given(method("POST")).and(path("/openai/deployments/vision-fixture/chat/completions")).respond_with(ResponseTemplate::new(200).set_body_json(openai)).mount(&server).await;
    Mock::given(method("POST")).and(path("/messages")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "content":[{"type":"text","text":"fixture result"}],"stop_reason":"end_turn","usage":{"input_tokens":3000,"output_tokens":2}
    }))).mount(&server).await;
    Mock::given(method("POST")).and(path("/v1beta/models/vision-fixture:generateContent")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "candidates":[{"content":{"parts":[{"text":"fixture result"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3000,"candidatesTokenCount":2,"totalTokenCount":3002}
    }))).mount(&server).await;
    let adapters: Vec<Arc<dyn LlmProviderAdapter>> = vec![
        Arc::new(crate::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(server.uri()).with_model("vision-fixture".into()).with_image_input_profile(profile())),
        Arc::new(crate::azure_openai::AzureOpenAiAdapter::new(server.uri(),"vision-fixture".into(),"fixture-key".into()).with_image_input_profile(profile())),
        Arc::new(crate::anthropic::AnthropicAdapter::new("fixture-key".into()).with_base_url(server.uri()).with_model("vision-fixture".into()).with_image_input_profile(profile())),
        Arc::new(crate::gemini::GeminiAdapter::new("fixture-key".into()).with_base_url(server.uri()).with_model("vision-fixture".into()).with_image_input_profile(profile())),
    ];
    for adapter in adapters {
        assert!(adapter.capabilities().vision);
        let session = adapter.create_session().await.unwrap();
        assert_eq!(session.validate_content(&[message()]).unwrap(), 3000);
        let response = session.send_with_options(vec![message()], &[], LlmRequestOptions { max_output_tokens: Some(8), ..Default::default() }).await.unwrap();
        assert_eq!(response.content,"fixture result");
        assert!(response.usage.provider_reported);
        assert_eq!(response.usage.input_tokens,3000);
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(),4);
    for request in requests {
        let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        if request.url.path().ends_with("chat/completions") {
            assert_eq!(value["messages"][0]["content"],json!([
                {"type":"image_url","image_url":{"url":format!("data:image/png;base64,{PNG}"),"detail":"high"}},
                {"type":"text","text":"describe"}
            ]));
        } else if request.url.path()=="/messages" {
            assert_eq!(value["messages"][0]["content"],json!([
                {"type":"image","source":{"type":"base64","media_type":"image/png","data":PNG}},
                {"type":"text","text":"describe"}
            ]));
        } else {
            assert_eq!(value["contents"][0]["parts"],json!([
                {"inlineData":{"mimeType":"image/png","data":PNG}}, {"text":"describe"}
            ]));
        }
    }
}

#[tokio::test]
async fn image_input_unknown_profile_unsupported_modes_and_audio_send_zero_requests() {
    let server = MockServer::start().await;
    let adapters: Vec<Arc<dyn LlmProviderAdapter>> = vec![
        Arc::new(crate::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(server.uri())),
        Arc::new(crate::azure_openai::AzureOpenAiAdapter::new(server.uri(),"fixture".into(),"fixture-key".into())),
        Arc::new(crate::anthropic::AnthropicAdapter::new("fixture-key".into()).with_base_url(server.uri())),
        Arc::new(crate::gemini::GeminiAdapter::new("fixture-key".into()).with_base_url(server.uri())),
        Arc::new(crate::groq::GroqAdapter::new("fixture-key".into()).with_base_url(server.uri())),
        Arc::new(crate::deepseek::DeepseekAdapter::new("fixture-key".into()).with_base_url(server.uri())),
        Arc::new(crate::vllm::VllmAdapter::new(String::new()).with_base_url(server.uri())),
        Arc::new(crate::local::LocalLlmAdapter::new(server.uri(),"fixture".into())),
        Arc::new(crate::huggingface::HuggingFaceAdapter::new("fixture-key".into()).with_base_url(server.uri())),
        Arc::new(crate::huggingface::HuggingFaceAdapter::new("fixture-key".into()).with_chat_completions().with_base_url(server.uri())),
    ];
    #[cfg(feature="candle")]
    let adapters = { let mut all = adapters; all.push(Arc::new(crate::on_device::controlled_streaming_fixture())); all };
    for adapter in adapters {
        assert!(!adapter.capabilities().vision);
        let session = adapter.create_session().await.unwrap();
        for message in [message(), StandardMessage::user_content(MessageContent::parts(vec![ContentPart::Audio]).unwrap())] {
            assert!(matches!(session.send(vec![message.clone()]).await, Err(ConnectorError::UnsupportedContent(_))));
            assert!(matches!(session.send_streaming_controlled(vec![message], &[], LlmRequestOptions::default(), &tokio_util::sync::CancellationToken::new()).await, Err(ConnectorError::UnsupportedContent(_))));
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
