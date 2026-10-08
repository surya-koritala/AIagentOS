use kernel::connector::*;
use kernel::ConnectorError;
use serde_json::json;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

fn message() -> StandardMessage {
    StandardMessage::user_content(
        MessageContent::parts(vec![
            ContentPart::Image {
                image: ImageInput::new(ImageMediaType::Png, PNG.into()).unwrap(),
            },
            ContentPart::Text {
                text: "describe".into(),
            },
        ])
        .unwrap(),
    )
}
fn profile() -> ImageInputProfile {
    ImageInputProfile {
        model_id: "vision-fixture".into(),
        max_tokens_per_image: 3000,
    }
}

#[tokio::test]
async fn image_input_four_documented_provider_shapes_and_reported_usage() {
    let server = MockServer::start().await;
    let openai = json!({"choices":[{"message":{"content":"fixture result"},"finish_reason":"stop"}], "usage":{"prompt_tokens":3000,"completion_tokens":2,"total_tokens":3002}});
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai.clone()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/openai/deployments/vision-fixture/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai))
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path("/messages")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "content":[{"type":"text","text":"fixture result"}],"stop_reason":"end_turn","usage":{"input_tokens":3000,"output_tokens":2}
    }))).mount(&server).await;
    Mock::given(method("POST")).and(path("/v1beta/models/vision-fixture:generateContent")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "candidates":[{"content":{"role":"model","parts":[{"text":"fixture result"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3000,"candidatesTokenCount":2,"totalTokenCount":3002}
    }))).mount(&server).await;
    let adapters: Vec<Arc<dyn LlmProviderAdapter>> = vec![
        Arc::new(
            crate::openai::OpenAiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ),
        Arc::new(
            crate::azure_openai::AzureOpenAiAdapter::new(
                server.uri(),
                "vision-fixture".into(),
                "fixture-key".into(),
            )
            .with_image_input_profile(profile()),
        ),
        Arc::new(
            crate::anthropic::AnthropicAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ),
        Arc::new(
            crate::gemini::GeminiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ),
    ];
    for adapter in adapters {
        assert!(adapter.capabilities().vision);
        let session = adapter.create_session().await.unwrap();
        assert_eq!(session.validate_content(&[message()]).unwrap(), 3000);
        let response = session
            .send_with_options(
                vec![message()],
                &[],
                LlmRequestOptions {
                    max_output_tokens: Some(8),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(response.content, "fixture result");
        assert!(response.usage.provider_reported);
        assert_eq!(response.usage.input_tokens, 3000);
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    for request in requests {
        let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        if request.url.path().ends_with("chat/completions") {
            assert_eq!(
                value["messages"][0]["content"],
                json!([
                    {"type":"image_url","image_url":{"url":format!("data:image/png;base64,{PNG}"),"detail":"high"}},
                    {"type":"text","text":"describe"}
                ])
            );
        } else if request.url.path() == "/messages" {
            assert!(value["messages"][0]["content"][0]
                .get("media_type")
                .is_none());
            assert!(value["messages"][0]["content"][0].get("data").is_none());
            assert_eq!(
                value["messages"][0]["content"],
                json!([
                    {"type":"image","source":{"type":"base64","media_type":"image/png","data":PNG}},
                    {"type":"text","text":"describe"}
                ])
            );
        } else {
            assert_eq!(
                value["contents"][0]["parts"],
                json!([
                    {"inlineData":{"mimeType":"image/png","data":PNG}}, {"text":"describe"}
                ])
            );
        }
    }
}

#[tokio::test]
async fn image_input_unknown_profile_unsupported_modes_and_audio_send_zero_requests() {
    let server = MockServer::start().await;
    let adapters: Vec<Arc<dyn LlmProviderAdapter>> = vec![
        Arc::new(
            crate::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(server.uri()),
        ),
        Arc::new(crate::azure_openai::AzureOpenAiAdapter::new(
            server.uri(),
            "fixture".into(),
            "fixture-key".into(),
        )),
        Arc::new(
            crate::anthropic::AnthropicAdapter::new("fixture-key".into())
                .with_base_url(server.uri()),
        ),
        Arc::new(
            crate::gemini::GeminiAdapter::new("fixture-key".into()).with_base_url(server.uri()),
        ),
        Arc::new(crate::groq::GroqAdapter::new("fixture-key".into()).with_base_url(server.uri())),
        Arc::new(
            crate::deepseek::DeepseekAdapter::new("fixture-key".into()).with_base_url(server.uri()),
        ),
        Arc::new(crate::vllm::VllmAdapter::new(String::new()).with_base_url(server.uri())),
        Arc::new(crate::local::LocalLlmAdapter::new(
            server.uri(),
            "fixture".into(),
        )),
        Arc::new(
            crate::huggingface::HuggingFaceAdapter::new("fixture-key".into())
                .with_base_url(server.uri()),
        ),
        Arc::new(
            crate::huggingface::HuggingFaceAdapter::new("fixture-key".into())
                .with_chat_completions()
                .with_base_url(server.uri()),
        ),
    ];
    #[cfg(feature = "candle")]
    let adapters = {
        let mut all = adapters;
        all.push(Arc::new(crate::on_device::controlled_streaming_fixture()));
        all
    };
    for adapter in adapters {
        assert!(!adapter.capabilities().vision);
        let session = adapter.create_session().await.unwrap();
        for message in [
            message(),
            StandardMessage::user_content(MessageContent::parts(vec![ContentPart::Audio]).unwrap()),
        ] {
            assert!(matches!(
                session.send(vec![message.clone()]).await,
                Err(ConnectorError::UnsupportedContent(_))
            ), "{} must refuse unsupported content before send I/O", adapter.id());
            assert!(matches!(
                session
                    .send_streaming_with_options(
                        vec![message.clone()],
                        &[],
                        LlmRequestOptions::default()
                    )
                    .await,
                Err(ConnectorError::UnsupportedContent(_))
            ), "{} must refuse unsupported content before stream I/O", adapter.id());
            assert!(matches!(
                session
                    .send_streaming_controlled(
                        vec![message],
                        &[],
                        LlmRequestOptions::default(),
                        &tokio_util::sync::CancellationToken::new()
                    )
                    .await,
                Err(ConnectorError::UnsupportedContent(_))
            ), "{} must refuse unsupported content before controlled stream I/O", adapter.id());
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn image_input_four_native_stream_compilers_preserve_order_and_native_output() {
    let server = MockServer::start().await;
    let event = |value: serde_json::Value| format!("data: {value}\n\n");
    let openai = [event(json!({"choices":[{"delta":{"content":"image result"}}]})),
        event(json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3000,"completion_tokens":2,"total_tokens":3002}})),"data: [DONE]\n\n".into()].concat();
    for route in [
        "/chat/completions",
        "/openai/deployments/vision-fixture/chat/completions",
    ] {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(openai.clone()),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    let anthropic = [event(json!({"type":"message_start","message":{"usage":{"input_tokens":3000}}})),
        event(json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})),
        event(json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"image result"}})),
        event(json!({"type":"content_block_stop","index":0})),
        event(json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}})),
        event(json!({"type":"message_stop"}))].concat();
    Mock::given(method("POST"))
        .and(path("/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(anthropic),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path("/v1beta/models/vision-fixture:streamGenerateContent"))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type","text/event-stream").set_body_string(event(json!({"candidates":[{"content":{"role":"model","parts":[{"text":"image result","thoughtSignature":"c2ln"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3000,"candidatesTokenCount":2,"totalTokenCount":3002}})))).expect(1).mount(&server).await;
    let adapters: Vec<Box<dyn LlmProviderAdapter>> = vec![
        Box::new(
            crate::openai::OpenAiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ),
        Box::new(
            crate::azure_openai::AzureOpenAiAdapter::new(
                server.uri(),
                "vision-fixture".into(),
                "fixture-key".into(),
            )
            .with_image_input_profile(profile()),
        ),
        Box::new(
            crate::anthropic::AnthropicAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ),
        Box::new(
            crate::gemini::GeminiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ),
    ];
    for adapter in adapters {
        let session = adapter.create_session().await.unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let send = session.send_streaming_events_controlled(
            vec![message()],
            &[],
            LlmRequestOptions::default(),
            &cancellation,
            ProviderEventSink::new(sender),
        );
        let drain = async {
            let mut text = String::new();
            while let Some(ProviderStreamEvent::TextDelta(delta)) = receiver.recv().await {
                text.push_str(&delta);
            }
            text
        };
        let (response, deltas) = tokio::join!(send, drain);
        let response = response.unwrap();
        assert_eq!(deltas, "image result");
        assert_eq!(response.content, deltas);
        assert!(response.usage.provider_reported);
        assert_eq!(response.usage.input_tokens, 3000);
        assert!(adapter.capabilities().native_streaming);
    }
    for request in server.received_requests().await.unwrap() {
        let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        match request.url.path() {
            "/messages" => {
                assert_eq!(
                    value["messages"][0]["content"][0],
                    json!({"type":"image","source":{"type":"base64","media_type":"image/png","data":PNG}})
                );
                assert_eq!(value["stream"], true);
            }
            "/v1beta/models/vision-fixture:streamGenerateContent" => assert_eq!(
                value["contents"][0]["parts"][0],
                json!({"inlineData":{"mimeType":"image/png","data":PNG}})
            ),
            _ => assert_eq!(
                value["messages"][0]["content"][0],
                json!({"type":"image_url","image_url":{"url":format!("data:image/png;base64,{PNG}"),"detail":"high"}})
            ),
        }
    }
}

#[tokio::test]
async fn image_input_invalid_containers_and_model_profiles_fail_before_io() {
    let server = MockServer::start().await;
    let adapter = crate::openai::OpenAiAdapter::new("fixture-key".into())
        .with_base_url(server.uri())
        .with_model("vision-fixture".into())
        .with_image_input_profile(profile());
    let session = adapter.create_session().await.unwrap();
    let mut corrupted = PNG.to_string();
    corrupted.replace_range(40..41, if &PNG[40..41] == "A" { "B" } else { "A" });
    let invalid_parts = [
        json!([{"type":"image","media_type":"image/png","data":corrupted}]),
        json!([{"type":"image","media_type":"image/jpeg","data":PNG}]),
        json!([{"type":"image","data":PNG}]),
        json!([{"type":"image","media_type":"image/png","data":"x".repeat(kernel::message_content::MAX_IMAGE_BYTES.div_ceil(3)*4+1)}]),
    ];
    for content in invalid_parts {
        let request = json!({"op":"send_message_content","agent_id":"00000000-0000-0000-0000-000000000000","content":content});
        assert!(serde_json::from_value::<kernel::syscall_server::Syscall>(request).is_err());
    }
    let oversized = MessageContent::Parts(vec![
        ContentPart::Text { text: "x".into() };
        kernel::message_content::MAX_CONTENT_PARTS + 1
    ]);
    assert!(session
        .send(vec![StandardMessage::user_content(oversized)])
        .await
        .is_err());
    for profile in [
        ImageInputProfile {
            model_id: "different-model".into(),
            max_tokens_per_image: 3000,
        },
        ImageInputProfile {
            model_id: "vision-fixture".into(),
            max_tokens_per_image: 0,
        },
    ] {
        let adapter = crate::openai::OpenAiAdapter::new("fixture-key".into())
            .with_base_url(server.uri())
            .with_model("vision-fixture".into())
            .with_image_input_profile(profile);
        let session = adapter.create_session().await.unwrap();
        assert!(session.send(vec![message()]).await.is_err());
        assert!(session
            .send_streaming_controlled(
                vec![message()],
                &[],
                LlmRequestOptions::default(),
                &tokio_util::sync::CancellationToken::new()
            )
            .await
            .is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn image_input_failover_reserves_largest_profile_and_skips_unsupported_backup() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path("/openai/deployments/vision-fixture/chat/completions")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"choices":[{"message":{"content":"image backup"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7000,"completion_tokens":2}}))).expect(1).mount(&server).await;
    let connector = Arc::new(AgentConnectorImpl::new().with_retry_policy(RetryPolicy {
        max_attempts: 1,
        ..RetryPolicy::default()
    }));
    connector
        .register_provider(Arc::new(
            crate::openai::OpenAiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ))
        .unwrap();
    connector
        .register_provider(Arc::new(crate::local::LocalLlmAdapter::new(
            server.uri(),
            "fixture".into(),
        )))
        .unwrap();
    connector
        .register_provider(Arc::new(
            crate::azure_openai::AzureOpenAiAdapter::new(
                server.uri(),
                "vision-fixture".into(),
                "fixture-key".into(),
            )
            .with_image_input_profile(ImageInputProfile {
                model_id: "vision-fixture".into(),
                max_tokens_per_image: 7000,
            }),
        ))
        .unwrap();
    connector.set_backup(&"openai".into(), &"local".into());
    connector.set_backup(&"local".into(), &"azure-openai".into());
    let session = connector
        .connect_resilient(
            "00000000-0000-0000-0000-000000000001".parse().unwrap(),
            &"openai".into(),
        )
        .await
        .unwrap();
    assert_eq!(session.validate_content(&[message()]).unwrap(), 7000);
    let response = session.send(vec![message()]).await.unwrap();
    assert_eq!(response.content, "image backup");
    assert_eq!(
        session.last_attribution(),
        Some(("azure-openai".into(), "vision-fixture".into()))
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| request.url.path().ends_with("chat/completions")));
}

#[test]
fn image_input_jpeg_mime_is_preserved_by_all_four_documented_compilers() {
    let mut bytes = vec![0xff, 0xd8];
    let mut segment = |marker: u8, data: &[u8]| {
        bytes.extend_from_slice(&[0xff, marker]);
        bytes.extend_from_slice(&((data.len() + 2) as u16).to_be_bytes());
        bytes.extend_from_slice(data);
    };
    let mut quantization = vec![0];
    quantization.extend_from_slice(&[1; 64]);
    segment(0xdb, &quantization);
    segment(0xc0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]);
    let mut huffman = vec![0, 1];
    huffman.extend_from_slice(&[0; 15]);
    huffman.push(0);
    huffman.extend_from_slice(&[0x10, 1]);
    huffman.extend_from_slice(&[0; 15]);
    huffman.push(0);
    segment(0xc4, &huffman);
    segment(0xda, &[1, 1, 0, 0, 63, 0]);
    bytes.extend_from_slice(&[0x3f, 0xff, 0xd9]);
    let image = ImageInput::from_bytes(ImageMediaType::Jpeg, &bytes).unwrap();
    let data = image.base64_data().to_string();
    let content = MessageContent::parts(vec![ContentPart::Image { image }]).unwrap();
    assert_eq!(
        crate::vision::openai_content(&content)[0]["image_url"]["url"],
        format!("data:image/jpeg;base64,{data}")
    );
    assert_eq!(
        crate::vision::anthropic_content(&content)[0]["source"],
        json!({"type":"base64","media_type":"image/jpeg","data":data})
    );
    assert_eq!(
        crate::vision::gemini_parts(&content)[0]["inlineData"],
        json!({"mimeType":"image/jpeg","data":data})
    );
}

#[tokio::test]
async fn image_input_http_diagnostics_and_request_ids_cannot_echo_encoded_images() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(429).insert_header("x-request-id",PNG).insert_header("retry-after","2")
        .set_body_json(json!({"error":{"message":format!("vendor echoed {PNG}"),"data":PNG,"image_url":format!("data:image/png;base64,{PNG}")}}))).expect(8).mount(&server).await;
    let adapters: Vec<Box<dyn LlmProviderAdapter>> = vec![
        Box::new(
            crate::openai::OpenAiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ),
        Box::new(
            crate::azure_openai::AzureOpenAiAdapter::new(
                server.uri(),
                "vision-fixture".into(),
                "fixture-key".into(),
            )
            .with_image_input_profile(profile()),
        ),
        Box::new(
            crate::anthropic::AnthropicAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ),
        Box::new(
            crate::gemini::GeminiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("vision-fixture".into())
                .with_image_input_profile(profile()),
        ),
    ];
    for adapter in adapters {
        let session = adapter.create_session().await.unwrap();
        for error in [
            session.send(vec![message()]).await.unwrap_err(),
            session
                .send_streaming_controlled(
                    vec![message()],
                    &[],
                    LlmRequestOptions::default(),
                    &tokio_util::sync::CancellationToken::new(),
                )
                .await
                .unwrap_err(),
        ] {
            assert!(!format!("{error:?}").contains(PNG));
            assert!(!error.to_string().contains(PNG));
            assert!(error.request_id().is_none());
            match error {
                ConnectorError::RateLimited(rate) => assert_eq!(rate.retry_after_ms, Some(2000)),
                other => panic!("changed typed throttle class: {other:?}"),
            }
        }
    }
}
