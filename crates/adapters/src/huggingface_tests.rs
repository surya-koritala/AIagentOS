//! Integration tests for the HuggingFace adapter using wiremock.

#[cfg(test)]
mod tests {
    use crate::huggingface::HuggingFaceAdapter;
    use kernel::connector::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn huggingface_array_response_parses() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([{"generated_text": "Hello from HF!"}]);

        Mock::given(method("POST"))
            .and(path("/models/meta-llama/Llama-3.1-8B-Instruct"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let adapter =
            HuggingFaceAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("Hi")])
            .await
            .unwrap();

        assert_eq!(resp.content, "Hello from HF!");
        assert!(resp.tool_calls.is_empty());
    }

    #[tokio::test]
    async fn huggingface_request_has_inputs_shape() {
        let mock_server = MockServer::start().await;

        // Only matches if the request body carries the TGI/Inference `inputs` shape.
        Mock::given(method("POST"))
            .and(path("/models/meta-llama/Llama-3.1-8B-Instruct"))
            .and(body_partial_json(serde_json::json!({
                "parameters": {"return_full_text": false}
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"generated_text": "ok"}])),
            )
            .mount(&mock_server)
            .await;

        let adapter =
            HuggingFaceAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("ping")])
            .await
            .unwrap();
        assert_eq!(resp.content, "ok");
    }

    #[tokio::test]
    async fn huggingface_uses_configured_model() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/models/custom/model"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"generated_text": "custom"}])),
            )
            .mount(&mock_server)
            .await;

        let adapter = HuggingFaceAdapter::new("test-key".to_string())
            .with_base_url(mock_server.uri())
            .with_model("custom/model".to_string());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("hi")])
            .await
            .unwrap();
        assert_eq!(resp.content, "custom");
    }

    #[tokio::test]
    async fn huggingface_returns_first_failure_without_hidden_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/models/meta-llama/Llama-3.1-8B-Instruct"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&mock_server)
            .await;

        let adapter =
            HuggingFaceAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let error = session
            .send(vec![StandardMessage::user("test")])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            kernel::ConnectorError::ServiceUnavailable(_)
        ));
    }

    fn definition() -> ToolDefinition {
        ToolDefinition { name:"lookup".into(), description:"lookup owned data".into(),
            parameters:serde_json::json!({"type":"object","properties":{},"additionalProperties":false}) }
    }

    #[tokio::test]
    async fn huggingface_completion_is_explicitly_estimated_and_rejects_direct_tools() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200)
            .set_body_json(serde_json::json!([{"generated_text":"estimated text"}]))).expect(1).mount(&server).await;
        let adapter = HuggingFaceAdapter::new("key".into()).with_base_url(server.uri()).with_model("fixture".into());
        assert!(!adapter.capabilities().tool_calls && !adapter.capabilities().native_streaming);
        let session = adapter.create_session().await.unwrap();
        let response = session.send(vec![StandardMessage::user("hello")]).await.unwrap();
        assert!(!response.usage.provider_reported);
        assert!(response.usage.input_tokens>0 && response.usage.output_tokens>0 && response.tokens_used>0);
        let error = session.send_with_tools(vec![StandardMessage::user("private prompt")], &[definition()]).await.unwrap_err();
        assert!(matches!(error,kernel::ConnectorError::ToolIncompatiblePrimary(_)));
        assert!(!error.to_string().contains("private prompt"));
        assert_eq!(server.received_requests().await.unwrap().len(),1);
    }

    #[tokio::test]
    async fn huggingface_chat_keeps_messages_tools_model_pin_and_usage() {
        let server = MockServer::start().await;
        let tool=definition();
        Mock::given(method("POST")).and(path("/chat/completions"))
            .and(body_partial_json(serde_json::json!({"model":"Qwen/Qwen3.5-9B:deepinfra","max_tokens":37,
                "tools":[{"type":"function","function":{"name":tool.name,"description":tool.description,"parameters":tool.parameters}}]})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{
                    "id":"call-1","type":"function","function":{"name":"lookup","arguments":"{}"}
                }]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":3,"total_tokens":14}
            }))).expect(1).mount(&server).await;
        let adapter=HuggingFaceAdapter::new("fixture-key".into()).with_chat_completions()
            .with_base_url(server.uri()).with_model("Qwen/Qwen3.5-9B:deepinfra".into());
        assert!(adapter.capabilities().tool_calls && adapter.capabilities().native_streaming);
        let session=adapter.create_session().await.unwrap();
        let mut assistant=StandardMessage::assistant("");
        assistant.tool_calls=Some(vec![ToolCall{id:"previous".into(),name:"lookup".into(),arguments:serde_json::json!({})}]);
        let response=session.send_with_options(vec![StandardMessage::system("policy"),StandardMessage::user("hello"),
            assistant,StandardMessage::tool_result("previous","result")],&[definition()],LlmRequestOptions{
                max_output_tokens:Some(37),..Default::default()
            }).await.unwrap();
        assert_eq!(response.usage,LlmUsage::reported(11,3,0));
        assert_eq!(response.tool_calls.len(),1);
        assert_eq!(response.tool_calls[0].arguments,serde_json::json!({}));
        let requests=server.received_requests().await.unwrap();
        let body:serde_json::Value=serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["messages"][2]["tool_calls"][0]["id"],"previous");
        assert_eq!(body["messages"][3]["tool_call_id"],"previous");
        assert!(body.get("inputs").is_none());
    }

    #[tokio::test]
    async fn huggingface_chat_emits_native_deltas_and_assembled_tools() {
        let server=MockServer::start().await;
        let data = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello \"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"world\",\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":3,\"total_tokens\":14}}\n\n",
            "data: [DONE]\n\n"
        );
        Mock::given(method("POST")).and(path("/chat/completions"))
            .and(body_partial_json(serde_json::json!({"stream":true,"stream_options":{"include_usage":true}})))
            .respond_with(ResponseTemplate::new(200).set_body_string(data).insert_header("content-type","text/event-stream"))
            .expect(1).mount(&server).await;
        let session=HuggingFaceAdapter::new("key".into()).with_chat_completions().with_base_url(server.uri())
            .with_model("Qwen/Qwen3.5-9B:deepinfra".into()).create_session().await.unwrap();
        let (tx,mut rx)=tokio::sync::mpsc::channel(16);
        let response=session.send_streaming_events_controlled(vec![StandardMessage::user("hello")],&[definition()],
            LlmRequestOptions::default(),&tokio_util::sync::CancellationToken::new(),ProviderEventSink::new(tx))
            .await.unwrap();
        let mut deltas=Vec::new();
        while let Some(ProviderStreamEvent::TextDelta(text))=rx.recv().await { deltas.push(text); }
        assert_eq!(deltas,vec!["Hello ","world"]);
        assert_eq!(response.content,"Hello world");
        assert_eq!(response.tool_calls[0].id,"call-1");
        assert_eq!(response.usage,LlmUsage::reported(11,3,0));
    }

    #[tokio::test]
    async fn huggingface_chat_rejects_malformed_native_calls_without_partial_execution() {
        let server=MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices":[{"message":{"content":null,"tool_calls":[
                {"id":"a","type":"function","function":{"name":"lookup","arguments":"{}"}},
                {"id":"b","type":"function","function":{"name":"lookup","arguments":"private invalid"}}
            ]}}]
        }))).mount(&server).await;
        let session=HuggingFaceAdapter::new("secret-key".into()).with_chat_completions().with_base_url(server.uri())
            .create_session().await.unwrap();
        let error=session.send(vec![StandardMessage::user("private invalid")]).await.unwrap_err();
        assert!(matches!(error,kernel::ConnectorError::ProtocolError(_)));
        assert!(!error.to_string().contains("private invalid")&&!error.to_string().contains("secret-key"));
    }

    #[tokio::test]
    async fn huggingface_chat_without_usage_is_unreported_and_translation_keeps_calls() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices":[{"message":{"role":"assistant","content":"estimated answer"},"finish_reason":"stop"}]
        }))).expect(1).mount(&server).await;
        let adapter = HuggingFaceAdapter::new("key".into()).with_chat_completions().with_base_url(server.uri());
        let response = adapter.create_session().await.unwrap().send(vec![StandardMessage::user("hello")]).await.unwrap();
        assert!(!response.usage.provider_reported);
        assert!(response.tokens_used>0);
        let mut message = StandardMessage::assistant("");
        message.tool_calls = Some(vec![ToolCall { id:"call".into(),name:"lookup".into(),arguments:serde_json::json!({"id":7}) }]);
        let native = adapter.translate_to_provider(&message);
        assert_eq!(adapter.translate_from_provider(&native).unwrap().tool_calls,message.tool_calls);
        let result = StandardMessage::tool_result("call","done");
        let native = adapter.translate_to_provider(&result);
        assert_eq!(adapter.translate_from_provider(&native).unwrap().tool_call_id,result.tool_call_id);
    }

    #[tokio::test]
    async fn huggingface_chat_refuses_duplicate_ids_and_oversized_body() {
        for body in [serde_json::json!({"choices":[{"message":{"tool_calls":[
            {"id":"same","type":"function","function":{"name":"lookup","arguments":"{}"}},
            {"id":"same","type":"function","function":{"name":"lookup","arguments":"{}"}}
        ]}}]}).to_string(),serde_json::json!({"choices":[{"message":{"content":"x".repeat(8*1024*1024)}}]}).to_string()] {
            let server = MockServer::start().await;
            Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_string(body)).expect(1).mount(&server).await;
            let session = HuggingFaceAdapter::new("key".into()).with_chat_completions().with_base_url(server.uri())
                .create_session().await.unwrap();
            assert!(matches!(session.send(vec![StandardMessage::user("hello")]).await.unwrap_err(),kernel::ConnectorError::ProtocolError(_)));
        }
    }

}
