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
        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();
        // Stopping the server turns the next request into a connection failure.
        drop(mock_server);

        let adapter =
            GeminiAdapter::new("super-secret-key".to_string()).with_base_url(base_url.clone());
        let session = adapter.create_session().await.unwrap();
        let error = session
            .send(vec![StandardMessage::user("Hi")])
            .await
            .unwrap_err();

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
}
