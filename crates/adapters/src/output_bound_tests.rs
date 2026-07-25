//! Cross-adapter wire fixtures for the kernel's per-call output bound.

#[cfg(test)]
mod tests {
    use crate::anthropic::AnthropicAdapter;
    use crate::azure_openai::AzureOpenAiAdapter;
    use crate::deepseek::DeepseekAdapter;
    use crate::gemini::GeminiAdapter;
    use crate::groq::GroqAdapter;
    use crate::huggingface::HuggingFaceAdapter;
    use crate::local::LocalLlmAdapter;
    use crate::vllm::VllmAdapter;
    use kernel::connector::{
        LlmProviderAdapter, LlmRequestOptions, ProviderEventSink, ProviderStreamEvent,
        StandardMessage,
    };
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn bound(limit: u32) -> LlmRequestOptions {
        LlmRequestOptions {
            max_output_tokens: Some(limit),
            ..LlmRequestOptions::default()
        }
    }

    fn openai_response() -> serde_json::Value {
        serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "bounded"},
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 1}
        })
    }

    #[tokio::test]
    async fn openai_compatible_adapters_translate_output_bound() {
        for case in ["deepseek", "groq", "vllm"] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/chat/completions"))
                .and(body_partial_json(serde_json::json!({"max_tokens": 41})))
                .respond_with(ResponseTemplate::new(200).set_body_json(openai_response()))
                .expect(1)
                .mount(&server)
                .await;

            let adapter: Box<dyn LlmProviderAdapter> = match case {
                "deepseek" => {
                    Box::new(DeepseekAdapter::new("key".into()).with_base_url(server.uri()))
                }
                "groq" => Box::new(GroqAdapter::new("key".into()).with_base_url(server.uri())),
                "vllm" => Box::new(VllmAdapter::new(String::new()).with_base_url(server.uri())),
                _ => unreachable!(),
            };
            let session = adapter.create_session().await.unwrap();
            assert!(session.enforces_max_output_tokens(), "{case}");
            session
                .send_with_options(vec![StandardMessage::user("bounded")], &[], bound(41))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn anthropic_translates_output_bound() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .and(body_partial_json(serde_json::json!({"max_tokens": 43})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [{"type": "text", "text": "bounded"}],
                "usage": {"input_tokens": 1, "output_tokens": 1}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let adapter = AnthropicAdapter::new("key".into()).with_base_url(server.uri());
        let session = adapter.create_session().await.unwrap();
        assert!(session.enforces_max_output_tokens());
        session
            .send_with_options(vec![StandardMessage::user("bounded")], &[], bound(43))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn anthropic_and_azure_return_first_retryable_failure() {
        let anthropic_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&anthropic_server)
            .await;
        let anthropic = AnthropicAdapter::new("key".into()).with_base_url(anthropic_server.uri());
        let anthropic_error = anthropic
            .create_session()
            .await
            .unwrap()
            .send(vec![StandardMessage::user("one attempt")])
            .await
            .unwrap_err();
        assert!(kernel::connector::is_transient(&anthropic_error));

        let azure_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/openai/deployments/test/chat/completions"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&azure_server)
            .await;
        let azure = AzureOpenAiAdapter::new(azure_server.uri(), "test".into(), "key".into());
        let azure_error = azure
            .create_session()
            .await
            .unwrap()
            .send(vec![StandardMessage::user("one attempt")])
            .await
            .unwrap_err();
        assert!(kernel::connector::is_transient(&azure_error));
    }

    #[tokio::test]
    async fn gemini_translates_output_bound() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-1.5-flash:generateContent"))
            .and(body_partial_json(serde_json::json!({
                "generationConfig": {"maxOutputTokens": 47}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "bounded"}]}
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let adapter = GeminiAdapter::new("key".into()).with_base_url(server.uri());
        let session = adapter.create_session().await.unwrap();
        assert!(session.enforces_max_output_tokens());
        session
            .send_with_options(vec![StandardMessage::user("bounded")], &[], bound(47))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn huggingface_translates_output_bound() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/models/meta-llama/Llama-3.1-8B-Instruct"))
            .and(body_partial_json(serde_json::json!({
                "parameters": {"max_new_tokens": 53}
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"generated_text": "bounded"}])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let adapter = HuggingFaceAdapter::new("key".into()).with_base_url(server.uri());
        let session = adapter.create_session().await.unwrap();
        assert!(session.enforces_max_output_tokens());
        session
            .send_with_options(vec![StandardMessage::user("bounded")], &[], bound(53))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn azure_non_streaming_and_streaming_translate_output_bound() {
        let server = MockServer::start().await;
        let request_path = "/openai/deployments/test/chat/completions";
        Mock::given(method("POST"))
            .and(path(request_path))
            .and(body_partial_json(serde_json::json!({
                "max_tokens": 59,
                "stream": true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(openai_response()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(request_path))
            .and(body_partial_json(serde_json::json!({"max_tokens": 61})))
            .respond_with(ResponseTemplate::new(200).set_body_json(openai_response()))
            .expect(1)
            .mount(&server)
            .await;

        let adapter = AzureOpenAiAdapter::new(server.uri(), "test".into(), "key".into());
        let session = adapter.create_session().await.unwrap();
        assert!(session.enforces_max_output_tokens());
        session
            .send_streaming_with_options(vec![StandardMessage::user("bounded")], &[], bound(59))
            .await
            .unwrap();
        session
            .send_with_options(vec![StandardMessage::user("bounded")], &[], bound(61))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn azure_native_stream_emits_ordered_sse_deltas_before_completion() {
        let server = MockServer::start().await;
        let request_path = "/openai/deployments/test/chat/completions";
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":2,\"total_tokens\":4}}\n\n",
            "data: [DONE]\n\n"
        );
        Mock::given(method("POST"))
            .and(path(request_path))
            .and(body_partial_json(serde_json::json!({"stream": true})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(body)
                    .insert_header("content-type", "text/event-stream"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let adapter = AzureOpenAiAdapter::new(server.uri(), "test".into(), "key".into());
        let session = adapter.create_session().await.unwrap();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(4);
        let cancellation = tokio_util::sync::CancellationToken::new();
        let response = session
            .send_streaming_events_controlled(
                vec![StandardMessage::user("stream")],
                &[],
                bound(59),
                &cancellation,
                ProviderEventSink::new(events_tx),
            )
            .await
            .unwrap();

        assert_eq!(response.content, "Hello");
        assert_eq!(response.tokens_used, 4);
        assert_eq!(
            events_rx.recv().await,
            Some(ProviderStreamEvent::TextDelta("Hel".into()))
        );
        assert_eq!(
            events_rx.recv().await,
            Some(ProviderStreamEvent::TextDelta("lo".into()))
        );
        assert_eq!(events_rx.recv().await, None);
    }

    #[tokio::test]
    async fn ollama_translates_output_bound() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .and(body_partial_json(serde_json::json!({
                "options": {"num_predict": 67}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {"content": "bounded"},
                "prompt_eval_count": 1,
                "eval_count": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        let adapter = LocalLlmAdapter::new(server.uri(), "test".into());
        let session = adapter.create_session().await.unwrap();
        assert!(session.enforces_max_output_tokens());
        session
            .send_with_options(vec![StandardMessage::user("bounded")], &[], bound(67))
            .await
            .unwrap();
    }
}
