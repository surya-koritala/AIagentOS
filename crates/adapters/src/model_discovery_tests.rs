//! Public listing contracts use disposable HTTP fixtures, never vendor keys.

use std::sync::Arc;
use std::time::Duration;

use kernel::connector::{AgentConnector, AgentConnectorImpl, LlmProviderAdapter};
use kernel::model_discovery::{MAX_DISCOVERED_MODELS, MAX_MODEL_DISCOVERY_BYTES};
use kernel::ConnectorError;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn network_adapters(base: &str) -> Vec<Arc<dyn LlmProviderAdapter>> {
    vec![
        Arc::new(crate::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(base.into())),
        Arc::new(crate::groq::GroqAdapter::new("fixture-key".into()).with_base_url(base.into())),
        Arc::new(crate::deepseek::DeepseekAdapter::new("fixture-key".into()).with_base_url(base.into())),
        Arc::new(crate::vllm::VllmAdapter::new("fixture-key".into()).with_base_url(base.into())),
        Arc::new(crate::anthropic::AnthropicAdapter::new("fixture-key".into()).with_base_url(base.into())),
        Arc::new(crate::gemini::GeminiAdapter::new("fixture-key".into()).with_base_url(base.into())),
        Arc::new(crate::local::LocalLlmAdapter::new(base.into(), "configured-model".into())),
    ]
}

#[tokio::test]
async fn model_discovery_capabilities_match_every_adapter_and_registered_catalog() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/models"))
        .and(header("authorization", "Bearer fixture-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id":"org/Model:latest", "owned_by":"account-secret"}, {"id":"a-model"}, {"id":"a-model"}]
        }))).expect(4).mount(&server).await;
    Mock::given(method("GET")).and(path("/models"))
        .and(header("x-api-key", "fixture-key")).and(header("anthropic-version", "2023-06-01"))
        .and(query_param("limit", "1000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id":"org/Model:latest"}, {"id":"a-model"}, {"id":"a-model"}], "has_more":false
        }))).expect(1).mount(&server).await;
    Mock::given(method("GET")).and(path("/v1beta/models"))
        .and(header("x-goog-api-key", "fixture-key")).and(query_param("pageSize", "1000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [{"name":"models/org/Model:latest"}, {"name":"models/a-model"}, {"name":"models/a-model"}]
        }))).expect(1).mount(&server).await;
    Mock::given(method("GET")).and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [{"model":"org/Model:latest", "digest":"private-digest"}, {"name":"a-model"}, {"model":"a-model"}]
        }))).expect(1).mount(&server).await;
    let connector = AgentConnectorImpl::new();
    for adapter in network_adapters(&server.uri()) {
        assert!(adapter.capabilities().model_discovery, "{}", adapter.id());
        let id = adapter.id().clone();
        connector.register_provider(adapter).unwrap();
        let catalog = connector.list_provider_models(&id, &CancellationToken::new()).await.unwrap();
        assert_eq!(catalog.provider_id, id);
        assert_eq!(catalog.models, vec!["a-model", "org/Model:latest"]);
        let result = serde_json::to_string(&catalog).unwrap();
        for secret in ["fixture-key", "account-secret", "private-digest", &server.uri()] {
            assert!(!result.contains(secret));
        }
    }
    let unsupported: Vec<Arc<dyn LlmProviderAdapter>> = vec![
        Arc::new(crate::azure_openai::AzureOpenAiAdapter::new(server.uri(), "deployment".into(), "fixture-key".into())),
        Arc::new(crate::huggingface::HuggingFaceAdapter::new("fixture-key".into()).with_base_url(server.uri())),
    ];
    #[cfg(feature = "candle")]
    let unsupported = {
        let mut adapters = unsupported;
        adapters.push(Arc::new(crate::on_device::controlled_streaming_fixture()));
        adapters
    };
    for adapter in unsupported {
        assert!(!adapter.capabilities().model_discovery, "{}", adapter.id());
        assert!(matches!(adapter.list_models().await, Err(ConnectorError::UnsupportedFeature(_))));
        let id = adapter.id().clone();
        connector.register_provider(adapter).unwrap();
        assert!(matches!(connector.list_provider_models(&id, &CancellationToken::new()).await,
            Err(ConnectorError::UnsupportedFeature(_))));
    }
    assert!(matches!(connector.list_provider_models(&"absent".into(), &CancellationToken::new()).await,
        Err(ConnectorError::ProviderUnavailable(_))));
    for request in server.received_requests().await.unwrap() {
        assert!(!request.url.as_str().contains("fixture-key"));
    }
}

#[tokio::test]
async fn model_discovery_pagination_preserves_ids_and_uses_header_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/models")).and(query_param("after_id", "cursor-a"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data":[{"id":"a-model"}], "has_more":false
        }))).expect(1).mount(&server).await;
    Mock::given(method("GET")).and(path("/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data":[{"id":"z-model"}], "has_more":true, "last_id":"cursor-a"
        }))).expect(1).with_priority(10).mount(&server).await;
    let anthropic = crate::anthropic::AnthropicAdapter::new("fixture-key".into()).with_base_url(server.uri());
    assert_eq!(anthropic.list_models().await.unwrap(), vec!["a-model", "z-model"]);
    Mock::given(method("GET")).and(path("/v1beta/models")).and(query_param("pageToken", "opaque+/="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models":[{"name":"models/a-model"}]
        }))).expect(1).mount(&server).await;
    Mock::given(method("GET")).and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models":[{"name":"models/z-model"}], "nextPageToken":"opaque+/="
        }))).expect(1).with_priority(10).mount(&server).await;
    let gemini = crate::gemini::GeminiAdapter::new("fixture-key".into()).with_base_url(server.uri());
    assert_eq!(gemini.list_models().await.unwrap(), vec!["a-model", "z-model"]);
    for request in server.received_requests().await.unwrap() {
        assert!(!request.url.as_str().contains("fixture-key"));
        assert!(request.headers.get("authorization").is_none());
    }
}

#[tokio::test]
async fn model_discovery_malformed_oversized_and_untrusted_ids_fail_redacted() {
    let server = MockServer::start().await;
    let adapter = crate::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(server.uri());
    let cases = vec![
        ResponseTemplate::new(200).set_body_string("{not-json fixture-key"),
        ResponseTemplate::new(200).set_body_json(json!({"data":[{"id":"secret\nvalue"}]})),
        ResponseTemplate::new(200).set_body_json(json!({"data":[{"id":"model-fixture-key"}]})),
        ResponseTemplate::new(200).set_body_json(json!({"data":[{"id":42}]})),
        ResponseTemplate::new(200).set_body_json(json!({"account":"private-account"})),
        ResponseTemplate::new(200).set_body_json(json!({"data":vec![json!({"id":"a-model"}); MAX_DISCOVERED_MODELS+1]})),
        ResponseTemplate::new(200).set_body_string("fixture-key".repeat(MAX_MODEL_DISCOVERY_BYTES / 11 + 1)),
        ResponseTemplate::new(200).set_body_json(json!({"data":[], "has_more":true})),
    ];
    for response in cases {
        server.reset().await;
        Mock::given(method("GET")).and(path("/models")).respond_with(response).expect(1).mount(&server).await;
        let error = adapter.list_models().await.unwrap_err();
        assert!(matches!(error, ConnectorError::ProtocolError(_)), "{error:?}");
        let rendered = error.to_string();
        assert!(rendered.len() <= 8192);
        for secret in ["fixture-key", "private-account", "secret\nvalue", &server.uri()] {
            assert!(!rendered.contains(secret));
        }
    }
}

#[tokio::test]
async fn model_discovery_http_failures_are_typed_redacted_and_never_retried() {
    let server = MockServer::start().await;
    for status in [401, 403, 429, 503, 400] {
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status)
                .set_body_string("fixture-key private-account".repeat(1024))
                .insert_header("x-request-id", "private-request-id"))
            .mount(&server).await;
        for adapter in network_adapters(&server.uri()) {
            let error = adapter.list_models().await.unwrap_err();
            assert!(match status {
                401 => matches!(error, ConnectorError::Authentication(_)),
                403 => matches!(error, ConnectorError::Authorization(_)),
                429 => matches!(error, ConnectorError::RateLimited(_)),
                503 => matches!(error, ConnectorError::ServiceUnavailable(_)),
                _ => matches!(error, ConnectorError::InvalidRequest(_)),
            });
            assert!(error.request_id().is_none());
            let rendered = error.to_string();
            assert!(rendered.len() <= 8192);
            for secret in ["fixture-key", "private-account", "private-request-id", &server.uri()] {
                assert!(!rendered.contains(secret));
            }
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 7);
    }
}

#[tokio::test]
async fn model_discovery_redirect_cannot_forward_credentials() {
    let source = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":[]})))
        .expect(0).mount(&target).await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(302).insert_header("location", format!("{}/private", target.uri())))
        .mount(&source).await;
    for adapter in network_adapters(&source.uri()) {
        assert!(matches!(adapter.list_models().await, Err(ConnectorError::InvalidRequest(_))));
    }
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn model_discovery_repeated_cursor_and_total_counts_fail_without_truncation() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "models":[{"name":"models/a-model"}], "nextPageToken":"repeated-cursor"
    }))).expect(2).mount(&server).await;
    let adapter = crate::gemini::GeminiAdapter::new("fixture-key".into()).with_base_url(server.uri());
    assert!(matches!(adapter.list_models().await, Err(ConnectorError::ProtocolError(_))));
    server.reset().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "models":vec![json!({"name":"models/a-model"}); 600], "nextPageToken":"next-cursor"
    }))).expect(2).mount(&server).await;
    assert!(matches!(adapter.list_models().await, Err(ConnectorError::ProtocolError(_))));
}

#[tokio::test]
async fn model_discovery_cancellation_drops_inflight_lookup_and_prevents_start() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)
        .set_body_json(json!({"data":[]})).set_delay(Duration::from_secs(30)))
        .mount(&server).await;
    let adapter = crate::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(server.uri());
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(adapter.list_models_controlled(&cancellation).await, Err(ConnectorError::Cancelled(_))));
    assert!(server.received_requests().await.unwrap().is_empty());
    let cancellation = CancellationToken::new();
    let lookup = adapter.list_models_controlled(&cancellation);
    tokio::pin!(lookup);
    tokio::select! {
        result = &mut lookup => panic!("lookup completed before cancellation: {result:?}"),
        _ = async {
            for _ in 0..100 {
                if !server.received_requests().await.unwrap().is_empty() { return; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("fixture lookup never started");
        } => {}
    }
    cancellation.cancel();
    assert!(matches!(tokio::time::timeout(Duration::from_secs(1), lookup).await.unwrap(), Err(ConnectorError::Cancelled(_))));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn model_discovery_deadline_is_typed_and_bounds_direct_adapter_use() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)
        .set_body_json(json!({"data":[]})).set_delay(Duration::from_secs(30)))
        .expect(1).mount(&server).await;
    let adapter = crate::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(server.uri());
    assert!(matches!(tokio::time::timeout(Duration::from_secs(12), adapter.list_models()).await.unwrap(), Err(ConnectorError::Timeout(_))));
}

struct PaginatedCatalog { padding: usize }

impl Respond for PaginatedCatalog {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let previous = request.url.query_pairs().find(|(key, _)| key == "after_id")
            .and_then(|(_, value)| value.strip_prefix("page-").and_then(|n| n.parse::<usize>().ok()))
            .unwrap_or(0);
        ResponseTemplate::new(200).set_body_json(json!({
            "data":[{"id":format!("model-{previous}")}],
            "has_more":true, "last_id":format!("page-{}", previous+1),
            "ignored_metadata":"x".repeat(self.padding)
        }))
    }
}

#[tokio::test]
async fn model_discovery_bounds_total_pagination_bytes_and_request_count() {
    for (padding, expected_requests, reason) in [
        (0, 16, "pagination limit"),
        (100_000, 11, "byte limit"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(PaginatedCatalog { padding })
            .expect(expected_requests).mount(&server).await;
        let adapter = crate::anthropic::AnthropicAdapter::new("fixture-key".into()).with_base_url(server.uri());
        let error = adapter.list_models().await.unwrap_err();
        assert!(matches!(error, ConnectorError::ProtocolError(_)));
        assert!(error.to_string().contains(reason), "{error}");
    }
}

async fn chunked_catalog(chunks: Vec<Vec<u8>>) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if socket.read_exact(&mut byte).await.is_err() { return; }
            request.extend_from_slice(&byte);
            assert!(request.len() <= 8192);
        }
        if socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.is_err() { return; }
        for chunk in chunks {
            if socket.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await.is_err() { return; }
            if socket.write_all(&chunk).await.is_err() { return; }
            if socket.write_all(b"\r\n").await.is_err() { return; }
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn model_discovery_chunked_body_is_byte_safe_and_bounded_without_content_length() {
    let body = json!({"data":[{"id":"a-model", "owned_by":"private-\u{03bb}-account"}]}).to_string().into_bytes();
    let (base, task) = chunked_catalog(body.chunks(1).map(|chunk| chunk.to_vec()).collect()).await;
    let adapter = crate::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(base);
    assert_eq!(adapter.list_models().await.unwrap(), vec!["a-model"]);
    task.await.unwrap();
    let chunks = vec![vec![b'x'; 64 * 1024]; MAX_MODEL_DISCOVERY_BYTES / (64 * 1024) + 1];
    let (base, task) = chunked_catalog(chunks).await;
    let adapter = crate::openai::OpenAiAdapter::new("fixture-key".into()).with_base_url(base);
    let error = adapter.list_models().await.unwrap_err();
    assert!(matches!(error, ConnectorError::ProtocolError(_)));
    assert!(error.to_string().contains("byte limit"));
    task.await.unwrap();
}

#[tokio::test]
async fn model_discovery_empty_catalog_is_success_but_invalid_endpoint_is_redacted() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":[]})))
        .expect(1).mount(&server).await;
    let adapter = crate::vllm::VllmAdapter::new(String::new()).with_base_url(server.uri());
    assert!(adapter.list_models().await.unwrap().is_empty());
    assert!(server.received_requests().await.unwrap()[0].headers.get("authorization").is_none());
    for base in ["http://user:private-secret@127.0.0.1:1", "http://127.0.0.1:1?key=private-secret", "file:///private-secret"] {
        let adapter = crate::gemini::GeminiAdapter::new("fixture-key".into()).with_base_url(base.into());
        let error = adapter.list_models().await.unwrap_err();
        assert!(matches!(error, ConnectorError::ProtocolError(_)));
        assert!(!error.to_string().contains("private-secret"));
    }
}
