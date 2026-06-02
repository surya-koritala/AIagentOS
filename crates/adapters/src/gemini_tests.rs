//! Integration tests for the Gemini adapter using wiremock.

#[cfg(test)]
mod tests {
    use crate::gemini::GeminiAdapter;
    use kernel::connector::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn gemini_plain_content_response() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Hello from Gemini!"}]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {"totalTokenCount": 17}
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
    async fn gemini_retries_on_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-1.5-flash:generateContent"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-1.5-flash:generateContent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "candidates": [{"content": {"role": "model", "parts": [{"text": "recovered"}]}}]
            })))
            .mount(&mock_server)
            .await;

        let adapter = GeminiAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("test")])
            .await
            .unwrap();
        assert_eq!(resp.content, "recovered");
    }
}
