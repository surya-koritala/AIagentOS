//! Integration tests for the Gemini adapter using wiremock.

#[cfg(test)]
mod tests {
    use crate::gemini::GeminiAdapter;
    use kernel::connector::*;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn gemini_plain_content_response() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Hello from Gemini!"}]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 7,
                "cachedContentTokenCount": 4,
                "totalTokenCount": 17
            }
        });

        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-1.5-flash:generateContent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let adapter = GeminiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("Hi")])
            .await
            .unwrap();

        assert_eq!(resp.content, "Hello from Gemini!");
        assert_eq!(resp.tokens_used, 17);
        assert_eq!(resp.usage, LlmUsage::reported(10, 7, 4));
        assert_eq!(resp.finish_reason, Some("STOP".to_string()));
        assert!(resp.tool_calls.is_empty());
    }

    #[tokio::test]
    async fn gemini_request_has_contents_parts_shape() {
        let mock_server = MockServer::start().await;

        // Only matches if the request body carries Gemini's contents/parts shape
        // with a mapped user role.
        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-1.5-flash:generateContent"))
            .and(body_partial_json(serde_json::json!({
                "contents": [{"role": "user", "parts": [{"text": "ping"}]}]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "candidates": [{"content": {"role": "model", "parts": [{"text": "pong"}]}}]
            })))
            .mount(&mock_server)
            .await;

        let adapter = GeminiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("ping")])
            .await
            .unwrap();
        assert_eq!(resp.content, "pong");
    }

    #[tokio::test]
    async fn gemini_maps_assistant_role_to_model() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-1.5-flash:generateContent"))
            .and(body_partial_json(serde_json::json!({
                "contents": [{"role": "model", "parts": [{"text": "prior reply"}]}]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}]}}]
            })))
            .mount(&mock_server)
            .await;

        let adapter = GeminiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let mut msg = StandardMessage::user("prior reply");
        msg.role = "assistant".to_string();
        let resp = session.send(vec![msg]).await.unwrap();
        assert_eq!(resp.content, "ok");
    }

    #[tokio::test]
    async fn gemini_returns_first_failure_without_hidden_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-1.5-flash:generateContent"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&mock_server)
            .await;

        let adapter = GeminiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
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

    /// The credential must travel in a header. Gemini also accepts `?key=`, but
    /// `reqwest::Error` renders the request URL into its `Display`, so a key in
    /// the query string reaches error text, logs, and wire clients verbatim.
    #[tokio::test]
    async fn gemini_sends_the_key_as_a_header_and_never_in_the_url() {
        let mock_server = MockServer::start().await;
        let response_body = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "ok"}]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {"totalTokenCount": 1}
        });

        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-1.5-flash:generateContent"))
            .and(header("x-goog-api-key", "super-secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let adapter =
            GeminiAdapter::new("super-secret-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();
        session
            .send(vec![StandardMessage::user("Hi")])
            .await
            .unwrap();

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "expected exactly one provider request");
        let url = requests[0].url.to_string();
        assert!(
            !url.contains("super-secret-key") && !url.contains("key="),
            "the API key must never appear in the request URL: {url}"
        );
    }

    /// A transport failure must not carry the destination URL, which is the one
    /// field the adapter error path does not redact.
    #[tokio::test]
    async fn gemini_transport_failure_reveals_no_url_or_credential() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Keep the listener owned throughout the request. A dropped wiremock
        // server can be returned to its pool and reused by a parallel fixture.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let adapter =
            GeminiAdapter::new("super-secret-key".to_string()).with_base_url(base_url.clone());
        let session = adapter.create_session().await.unwrap();
        let malformed_server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream.write_all(b"invalid HTTP response\r\n").await.unwrap();
            stream.shutdown().await.unwrap();
        };
        let request = session.send(vec![StandardMessage::user("Hi")]);
        let (_, result) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(malformed_server, request)
        })
        .await
        .expect("reserved malformed server must return a bounded transport failure");
        let error = result.unwrap_err();

        let rendered = error.to_string();
        assert!(
            !rendered.contains("super-secret-key"),
            "transport error leaked the credential: {rendered}"
        );
        assert!(
            !rendered.contains(&base_url) && !rendered.contains("http"),
            "transport error leaked the destination URL: {rendered}"
        );
    }

    fn tool() -> ToolDefinition {
        ToolDefinition {
            name: "lookup_weather".into(),
            description: "Look up weather".into(),
            parameters: serde_json::json!({
                "type": "object", "properties": {"city": {"type": "string"}},
                "required": ["city"], "additionalProperties": false
            }),
        }
    }

    fn reply(parts: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"candidates": [{"content": {"role": "model", "parts": parts},
            "finishReason": "STOP"}], "usageMetadata": {
            "promptTokenCount": 4, "candidatesTokenCount": 2, "thoughtsTokenCount": 3,
            "totalTokenCount": 9
        }})
    }

    async fn mount_reply(server: &MockServer, parts: serde_json::Value) {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(reply(parts)))
            .mount(server)
            .await;
    }

    fn saved_assistant(response: LlmResponse) -> StandardMessage {
        let mut message = StandardMessage::assistant(response.content);
        if !response.tool_calls.is_empty() {
            message.tool_calls = Some(response.tool_calls);
        }
        message.provider_metadata = response.provider_metadata;
        message
    }

    #[tokio::test]
    async fn gemini_sends_native_json_schema_and_system_instruction() {
        let server = MockServer::start().await;
        mount_reply(&server, serde_json::json!([{"text": "ok"}])).await;
        let adapter = GeminiAdapter::new("key".into()).with_base_url(server.uri());
        let session = adapter.create_session().await.unwrap();
        let supplied = tool();
        let response = session
            .send_with_tools(
                vec![
                    StandardMessage::system("policy"),
                    StandardMessage::user("weather"),
                ],
                std::slice::from_ref(&supplied),
            )
            .await
            .unwrap();
        assert_eq!(response.usage, LlmUsage::reported(4, 5, 0));
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(
            body["tools"][0]["functionDeclarations"],
            serde_json::json!([{
                "name": supplied.name, "description": supplied.description,
                "parametersJsonSchema": supplied.parameters
            }])
        );
        assert!(body["tools"][0]["functionDeclarations"][0]
            .get("parameters")
            .is_none());
        assert_eq!(
            body["systemInstruction"],
            serde_json::json!({"parts": [{"text": "policy"}]})
        );
        assert_eq!(
            body["contents"],
            serde_json::json!([{"role": "user", "parts": [{"text": "weather"}]}])
        );
        assert!(adapter.capabilities().tool_calls);
        assert!(adapter.capabilities().parallel_tool_calls);
    }

    #[tokio::test]
    async fn gemini_single_and_parallel_calls_preserve_order_and_objects() {
        for count in [1, 2] {
            let server = MockServer::start().await;
            let parts: Vec<_> = (0..count)
                .map(|n| {
                    serde_json::json!({"functionCall": {
                        "name": "lookup_weather", "args": {"city": format!("city-{n}")}
                    }})
                })
                .collect();
            mount_reply(&server, serde_json::json!(parts)).await;
            let session = GeminiAdapter::new("key".into())
                .with_base_url(server.uri())
                .create_session()
                .await
                .unwrap();
            let response = session
                .send_with_tools(vec![StandardMessage::user("weather")], &[tool()])
                .await
                .unwrap();
            assert!(response.content.is_empty());
            assert_eq!(response.tool_calls.len(), count);
            for (n, call) in response.tool_calls.iter().enumerate() {
                assert_eq!(call.name, "lookup_weather");
                assert_eq!(
                    call.arguments,
                    serde_json::json!({"city": format!("city-{n}")})
                );
                assert!(!call.id.is_empty());
            }
            if count == 2 {
                assert_ne!(response.tool_calls[0].id, response.tool_calls[1].id);
            }
        }
    }

    #[tokio::test]
    async fn gemini_signed_parallel_history_survives_serialization_and_second_round() {
        let server = MockServer::start().await;
        let original = serde_json::json!([
            {"text": "private summary", "thought": true},
            {"text": "Checking weather"},
            {"functionCall": {"name": "lookup_weather", "args": {"city": "Toronto"}},
             "thoughtSignature": "c2lnbmF0dXJlLTE="},
            {"functionCall": {"name": "lookup_weather", "args": {"city": "London"}}}
        ]);
        mount_reply(&server, original.clone()).await;
        let adapter = GeminiAdapter::new("key".into()).with_base_url(server.uri());
        let session = adapter.create_session().await.unwrap();
        let first = session
            .send_with_tools(vec![StandardMessage::user("weather")], &[tool()])
            .await
            .unwrap();
        assert_eq!(first.content, "Checking weather");
        let calls = first.tool_calls.clone();
        let assistant = saved_assistant(first);
        let encoded = serde_json::to_vec(&assistant).unwrap();
        let restored: StandardMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored, assistant);
        assert!(!format!("{:?}", restored.provider_metadata).contains("c2lnbmF0dXJl"));
        assert_eq!(adapter.translate_to_provider(&restored)["parts"], original);
        server.reset().await;
        mount_reply(
            &server,
            serde_json::json!([{"text": "Done", "thoughtSignature": "dGV4dC1zaWc="}]),
        )
        .await;
        let mut history = vec![StandardMessage::user("weather"), restored];
        history.push(StandardMessage::tool_result(
            &calls[0].id,
            r#"{"temperature": 18}"#,
        ));
        history.push(StandardMessage::tool_result(&calls[1].id, "rain"));
        // Results may arrive in the opposite order. The wire group must still
        // follow the original calls, especially for repeated names without IDs.
        let history_len = history.len();
        history.swap(history_len - 1, history_len - 2);
        let final_response = session.send_with_tools(history, &[tool()]).await.unwrap();
        assert_eq!(final_response.content, "Done");
        assert!(final_response.tool_calls.is_empty());
        assert_eq!(
            final_response.provider_metadata.unwrap().payload()["parts"][0]["thoughtSignature"],
            "dGV4dC1zaWc="
        );
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["contents"][1]["parts"], original);
        assert_eq!(
            body["contents"][2],
            serde_json::json!({"role": "user", "parts": [
                {"functionResponse": {"name": "lookup_weather", "response": {"temperature": 18}}},
                {"functionResponse": {"name": "lookup_weather", "response": {"result": "rain"}}}
            ]})
        );
    }

    #[tokio::test]
    async fn gemini_native_ids_and_no_arg_functions_round_trip() {
        let server = MockServer::start().await;
        mount_reply(
            &server,
            serde_json::json!([{"functionCall": {"name": "ping", "id": "native-7"},
            "thoughtSignature": "c2ln"}]),
        )
        .await;
        let session = GeminiAdapter::new("key".into())
            .with_base_url(server.uri())
            .create_session()
            .await
            .unwrap();
        let response = session
            .send(vec![StandardMessage::user("ping")])
            .await
            .unwrap();
        assert_eq!(response.tool_calls[0].id, "native-7");
        assert_eq!(response.tool_calls[0].arguments, serde_json::json!({}));
        let assistant = saved_assistant(response);
        server.reset().await;
        mount_reply(&server, serde_json::json!([{"text": "ok"}])).await;
        session
            .send(vec![
                StandardMessage::user("ping"),
                assistant,
                StandardMessage::tool_result("native-7", "7"),
            ])
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(
            body["contents"][2]["parts"][0]["functionResponse"],
            serde_json::json!({
                "id": "native-7", "name": "ping", "response": {"result": 7}
            })
        );
    }

    #[tokio::test]
    async fn gemini_legacy_assistant_call_and_result_round_trip() {
        let server = MockServer::start().await;
        mount_reply(&server, serde_json::json!([{"text": "ok"}])).await;
        let adapter = GeminiAdapter::new("key".into()).with_base_url(server.uri());
        let session = adapter.create_session().await.unwrap();
        let mut assistant = StandardMessage::assistant("");
        assistant.tool_calls = Some(vec![ToolCall {
            id: "legacy-1".into(),
            name: "lookup_weather".into(),
            arguments: serde_json::json!({"city": "Toronto"}),
        }]);
        assert_eq!(
            adapter.translate_to_provider(&assistant)["parts"][0]["functionCall"]["id"],
            "legacy-1"
        );
        session
            .send(vec![
                StandardMessage::user("weather"),
                assistant,
                StandardMessage::tool_result("legacy-1", r#"{"ok": true}"#),
            ])
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(
            body["contents"][1]["parts"][0]["functionCall"]["args"],
            serde_json::json!({"city": "Toronto"})
        );
        assert_eq!(
            body["contents"][2]["parts"][0]["functionResponse"],
            serde_json::json!({
                "name": "lookup_weather", "id": "legacy-1", "response": {"ok": true}
            })
        );
        assert!(body.get("tools").is_none());
    }

    #[tokio::test]
    async fn gemini_synthetic_ids_are_distinct_across_identical_rounds() {
        let server = MockServer::start().await;
        mount_reply(
            &server,
            serde_json::json!([{"functionCall": {"name": "ping", "args": {}}}]),
        )
        .await;
        let session = GeminiAdapter::new("key".into())
            .with_base_url(server.uri())
            .create_session()
            .await
            .unwrap();
        let first = session
            .send(vec![StandardMessage::user("ping")])
            .await
            .unwrap();
        let second = session
            .send(vec![StandardMessage::user("ping")])
            .await
            .unwrap();
        assert_ne!(first.tool_calls[0].id, second.tool_calls[0].id);
    }

    #[tokio::test]
    async fn gemini_rejects_malformed_calls_without_returning_partial_tools() {
        let server = MockServer::start().await;
        let session = GeminiAdapter::new("secret-key".into())
            .with_base_url(server.uri())
            .create_session()
            .await
            .unwrap();
        let malformed = [
            serde_json::json!({"functionCall": {"name": "ping", "args": "secret-prompt"}}),
            serde_json::json!({"functionCall": {"name": "", "args": {}}}),
            serde_json::json!({"functionCall": {"name": "ping", "args": {}, "id": ""}}),
            serde_json::json!({"text": "secret-prompt", "functionCall": {"name": "ping"}}),
            serde_json::json!({"inlineData": {"data": "secret-prompt"}}),
            serde_json::json!({"text": "secret-prompt", "thoughtSignature": 8}),
        ];
        for bad in malformed {
            server.reset().await;
            mount_reply(
                &server,
                serde_json::json!([
                    {"functionCall": {"name": "ping", "args": {}}}, bad
                ]),
            )
            .await;
            let error = session
                .send(vec![StandardMessage::user("secret-prompt")])
                .await
                .unwrap_err();
            assert!(matches!(error, kernel::ConnectorError::ProtocolError(_)));
            let text = error.to_string();
            assert!(!text.contains("secret-prompt") && !text.contains("secret-key"));
        }
        server.reset().await;
        mount_reply(
            &server,
            serde_json::json!([
                {"functionCall": {"name": "ping", "id": "duplicate"}},
                {"functionCall": {"name": "pong", "id": "duplicate"}}
            ]),
        )
        .await;
        assert!(session
            .send(vec![StandardMessage::user("ping")])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn gemini_rejects_changed_or_foreign_signed_history_before_io() {
        let server = MockServer::start().await;
        mount_reply(
            &server,
            serde_json::json!([{"text": "ok", "thoughtSignature": "c2ln"}]),
        )
        .await;
        let session = GeminiAdapter::new("key".into())
            .with_base_url(server.uri())
            .create_session()
            .await
            .unwrap();
        let original = saved_assistant(
            session
                .send(vec![StandardMessage::user("ping")])
                .await
                .unwrap(),
        );
        server.reset().await;
        let mut changed = original.clone();
        changed.content = "changed".into();
        assert!(session.send(vec![changed]).await.is_err());
        let other = GeminiAdapter::new("key".into())
            .with_base_url(server.uri())
            .with_model("different-model".into())
            .create_session()
            .await
            .unwrap();
        assert!(other.send(vec![original]).await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn gemini_rejects_orphan_duplicate_missing_results_and_bad_declarations_before_io() {
        let server = MockServer::start().await;
        let session = GeminiAdapter::new("key".into())
            .with_base_url(server.uri())
            .create_session()
            .await
            .unwrap();
        assert!(session
            .send(vec![StandardMessage::tool_result("orphan", "ok")])
            .await
            .is_err());
        let mut assistant = StandardMessage::assistant("");
        assistant.tool_calls = Some(vec![ToolCall {
            id: "call".into(),
            name: "ping".into(),
            arguments: serde_json::json!({}),
        }]);
        assert!(session.send(vec![assistant.clone()]).await.is_err());
        assert!(session
            .send(vec![
                assistant,
                StandardMessage::tool_result("call", "ok"),
                StandardMessage::tool_result("call", "again")
            ])
            .await
            .is_err());
        let mut bad = tool();
        bad.parameters = serde_json::json!({"type": "array"});
        assert!(session
            .send_with_tools(vec![StandardMessage::user("ping")], &[bad])
            .await
            .is_err());
        assert!(session
            .send_with_tools(vec![StandardMessage::user("ping")], &[tool(), tool()])
            .await
            .is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn gemini_response_and_replay_limits_fail_closed() {
        let server = MockServer::start().await;
        let session = GeminiAdapter::new("key".into())
            .with_base_url(server.uri())
            .create_session()
            .await
            .unwrap();
        for parts in [
            serde_json::json!(vec![serde_json::json!({"text": "x"}); 65]),
            serde_json::json!([{"text": "x", "thoughtSignature": "x".repeat(256*1024)}]),
            serde_json::json!([]),
        ] {
            server.reset().await;
            mount_reply(&server, parts).await;
            assert!(session
                .send(vec![StandardMessage::user("ping")])
                .await
                .is_err());
        }
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(1024 * 1024 + 1)))
            .mount(&server)
            .await;
        assert!(session
            .send(vec![StandardMessage::user("ping")])
            .await
            .is_err());
    }
}
