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
    async fn huggingface_retries_on_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/models/meta-llama/Llama-3.1-8B-Instruct"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/models/meta-llama/Llama-3.1-8B-Instruct"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"generated_text": "recovered"}])),
            )
            .mount(&mock_server)
            .await;

        let adapter =
            HuggingFaceAdapter::new("test-key".to_string()).with_base_url(mock_server.uri());
        let session = adapter.create_session().await.unwrap();

        let resp = session
            .send(vec![StandardMessage::user("test")])
            .await
            .unwrap();
        assert_eq!(resp.content, "recovered");
    }
}
