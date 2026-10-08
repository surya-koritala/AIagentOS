//! NDJSON protocol fixtures and controlled decoder conformance, never weights.
use std::sync::Arc;
use std::time::Duration;
use kernel::connector::*;
use kernel::ConnectorError;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use crate::local::LocalLlmAdapter;
use crate::streaming_conformance_tests::{collect, assert_conformance, paused_stream};

fn line(value: Value) -> String { format!("{value}\n") }
pub(super) fn ndjson_fixture() -> String {
    [line(json!({"message": {"role": "assistant", "content": "Hel"}, "done": false})),
        line(json!({"message": {"content": "lo "}, "done": false})),
        line(json!({"message": {"content": "🌐"}, "done": true, "prompt_eval_count": 11, "eval_count": 3, "done_reason": "stop"}))].concat()
}

#[tokio::test]
async fn ollama_native_ndjson_delivers_three_fragments_and_terminal_usage() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/api/chat")).and(body_partial_json(json!({"stream": true})))
        .respond_with(ResponseTemplate::new(200).set_body_string(ndjson_fixture())).expect(1).mount(&server).await;
    let adapter = LocalLlmAdapter::new(server.uri(), "fixture".into());
    let (response, deltas) = collect(&adapter, &[]).await.unwrap();
    assert_conformance(&adapter, &response, &deltas);
    assert_eq!(deltas, ["Hel", "lo ", "🌐"]); assert_eq!(response.content, "Hello 🌐");
    assert_eq!(response.usage, LlmUsage::reported(11, 3, 0)); assert_eq!(response.tokens_used, 14);
}

fn tool() -> ToolDefinition { ToolDefinition { name: "read".into(), description: "fixture".into(), parameters: json!({"type": "object"}) } }

async fn template_rejection(server: &MockServer) {
    Mock::given(method("POST")).and(body_partial_json(json!({"tools": [{"type": "function"}]})))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "fixture does not support tools"})))
        .expect(1).with_priority(1).mount(server).await;
}

#[tokio::test]
async fn ollama_streaming_template_retry_is_reserved_and_counted_exactly() {
    let server = MockServer::start().await; template_rejection(&server).await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_string(ndjson_fixture())).expect(1).with_priority(6).mount(&server).await;
    let connector = Arc::new(AgentConnectorImpl::new());
    connector.register_provider(Arc::new(LocalLlmAdapter::new(server.uri(), "fixture".into()))).unwrap();
    let session = connector.connect_resilient(kernel::AgentId::new_v4(), &"local".into()).await.unwrap();
    assert_eq!(session.max_provider_attempts(), 2);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
    let response = session.send_streaming_events_controlled(vec![StandardMessage::user("fixture")], &[tool()], LlmRequestOptions::default(), &CancellationToken::new(), ProviderEventSink::new(sender)).await.unwrap();
    assert_eq!(response.content, "Hello 🌐"); assert_eq!(session.last_attempts(), Some(2));
    assert!(receiver.recv().await.is_some());
    let requests = server.received_requests().await.unwrap(); let retry: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert!(retry.get("tools").is_none()); assert_eq!(retry["stream"], true);
}

#[tokio::test]
async fn ollama_stream_assembles_native_calls_by_index_without_executing_fragments() {
    let server = MockServer::start().await;
    let body = [line(json!({"message": {"tool_calls": [{"function": {"index": 1, "name": "read", "arguments": {"path": "two"}}}]}, "done": false})),
        line(json!({"message": {"tool_calls": [{"function": {"index": 0, "name": "read", "arguments": "{\"path\":\"one\"}"}}]}, "done": true, "eval_count": 2}))].concat();
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_string(body)).expect(1).mount(&server).await;
    let adapter = LocalLlmAdapter::new(server.uri(), "fixture".into());
    let (response, deltas) = collect(&adapter, &[tool()]).await.unwrap(); assert!(deltas.is_empty());
    assert_eq!(response.tool_calls.iter().map(|call| call.arguments.clone()).collect::<Vec<_>>(), [json!({"path": "one"}), json!({"path": "two"})]);
    assert_ne!(response.tool_calls[0].id, response.tool_calls[1].id);
}

#[tokio::test]
async fn ollama_truncated_visible_stream_is_not_replayed_or_failed_over() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/api/chat")).respond_with(ResponseTemplate::new(200).set_body_string(line(json!({"message": {"content": "partial"}, "done": false})))).expect(1).mount(&server).await;
    let connector = Arc::new(AgentConnectorImpl::new());
    connector.register_provider(Arc::new(LocalLlmAdapter::new(server.uri(), "fixture".into()))).unwrap();
    let session = connector.connect_resilient(kernel::AgentId::new_v4(), &"local".into()).await.unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    assert!(matches!(session.send_streaming_events_controlled(vec![StandardMessage::user("fixture")], &[], LlmRequestOptions::default(), &CancellationToken::new(), ProviderEventSink::new(sender)).await.unwrap_err(), ConnectorError::PartialStream(_)));
    assert_eq!(receiver.recv().await, Some(ProviderStreamEvent::TextDelta("partial".into()))); assert_eq!(session.last_attempts(), Some(1));
}

#[tokio::test]
async fn ollama_stream_is_incremental_and_cancellable_before_terminal_ndjson() {
    let first = line(json!({"message": {"content": "first"}, "done": false}));
    let last = line(json!({"message": {"content": "last"}, "done": true, "eval_count": 2}));
    let (uri, resume, server) = paused_stream(vec![first.into_bytes(), last.into_bytes()]).await;
    let session = LocalLlmAdapter::new(uri, "fixture".into()).create_session().await.unwrap();
    let cancellation = CancellationToken::new(); let cancel = cancellation.clone(); let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move { session.send_streaming_events_controlled(vec![StandardMessage::user("fixture")], &[], LlmRequestOptions::default(), &cancellation, ProviderEventSink::new(sender)).await });
    assert_eq!(tokio::time::timeout(Duration::from_secs(2), receiver.recv()).await.unwrap(), Some(ProviderStreamEvent::TextDelta("first".into())));
    assert!(!task.is_finished()); cancel.cancel(); assert!(matches!(task.await.unwrap().unwrap_err(), ConnectorError::Cancelled(_)));
    assert_eq!(receiver.recv().await, None); drop(resume); server.abort();
}

#[cfg(feature = "candle")]
#[tokio::test]
async fn controlled_candle_decoder_passes_the_shared_native_stream_contract() {
    let adapter = crate::on_device::controlled_streaming_fixture();
    let (response, deltas) = collect(&adapter, &[]).await.unwrap();
    assert_conformance(&adapter, &response, &deltas);
    let batch = adapter.create_session().await.unwrap().send(vec![StandardMessage::user("fixture")]).await.unwrap();
    assert_eq!(response.content, batch.content); assert_eq!(response.tokens_used, batch.tokens_used);
    assert_eq!(deltas, ["one", " two", " three"]);
}
