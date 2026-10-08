//! Typed SSE fixtures; no live providers or model weights.

use crate::anthropic::AnthropicAdapter;
use crate::gemini::GeminiAdapter;
use crate::streaming_conformance_tests::{collect, paused_stream};
use kernel::connector::*;
use kernel::ConnectorError;
use serde_json::{json, Value};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn event(value: Value) -> String {
    format!("data: {value}\n\n")
}
fn adapters(uri: &str) -> Vec<Box<dyn LlmProviderAdapter>> {
    vec![
        Box::new(
            AnthropicAdapter::new("fixture-key".into())
                .with_base_url(uri.into())
                .with_model("fixture".into()),
        ),
        Box::new(
            GeminiAdapter::new("fixture-key".into())
                .with_base_url(uri.into())
                .with_model("fixture".into()),
        ),
    ]
}

pub(super) fn anthropic_text_fixture() -> String {
    [event(json!({"type": "message_start", "message": {"usage": {"input_tokens": 11, "output_tokens": 1, "cache_read_input_tokens": 4}}})),
        event(json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})),
        event(json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello "}})),
        event(json!({"type": "ping"})),
        event(json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "🌐"}})),
        event(json!({"type": "content_block_stop", "index": 0})),
        event(json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 3}})),
        event(json!({"type": "message_stop"}))].concat()
}

pub(super) fn gemini_text_fixture() -> String {
    [event(json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "Hello "}]}}]})),
        event(json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "🌐"}]}}]})),
        event(json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "", "thoughtSignature": "c2lnbmF0dXJl"}]}, "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 3, "totalTokenCount": 14, "cachedContentTokenCount": 4}}))].concat()
}

#[tokio::test]
async fn anthropic_streamed_usage_matches_unary_and_retains_cumulative_counters() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(ResponseTemplate::new(200).set_body_string(anthropic_text_fixture()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"content": [{"type": "text", "text": "Hello 🌐"}], "stop_reason": "end_turn", "usage": {"input_tokens": 11, "output_tokens": 3, "cache_read_input_tokens": 4}}))).with_priority(6).expect(1).mount(&server).await;
    let adapter = adapters(&server.uri()).remove(0);
    let (streamed, deltas) = collect(adapter.as_ref(), &[]).await.unwrap();
    let unary = adapter
        .create_session()
        .await
        .unwrap()
        .send(vec![StandardMessage::user("fixture")])
        .await
        .unwrap();
    assert_eq!(streamed.usage, unary.usage);
    assert_eq!(streamed.tokens_used, unary.tokens_used);
    assert_eq!(deltas, ["Hello ", "🌐"]);
}

#[tokio::test]
async fn gemini_preserves_late_empty_signatures_and_small_chunk_boundaries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1beta/models/fixture:streamGenerateContent"))
        .and(query_param("alt", "sse"))
        .and(header("x-goog-api-key", "fixture-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string(gemini_text_fixture()))
        .expect(1)
        .mount(&server)
        .await;
    let adapter = adapters(&server.uri()).remove(1);
    let (response, deltas) = collect(adapter.as_ref(), &[]).await.unwrap();
    assert_eq!(deltas.concat(), "Hello 🌐");
    assert_eq!(
        response.provider_metadata.as_ref().unwrap().payload()["chunk_part_counts"],
        json!([1, 1, 1])
    );
    server.reset().await;
    let mut history = StandardMessage::assistant(response.content);
    history.provider_metadata = response.provider_metadata;
    Mock::given(method("POST")).and(body_partial_json(json!({"contents": [
        {"role": "model", "parts": [{"text": "Hello "}]}, {"role": "model", "parts": [{"text": "🌐"}]},
        {"role": "model", "parts": [{"text": "", "thoughtSignature": "c2lnbmF0dXJl"}]},
        {"role": "user", "parts": [{"text": "continue"}]}
    ]}))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "continued"}]}, "finishReason": "STOP"}]}))).expect(1).mount(&server).await;
    adapter
        .create_session()
        .await
        .unwrap()
        .send(vec![history, StandardMessage::user("continue")])
        .await
        .unwrap();
    assert!(!server.received_requests().await.unwrap()[0]
        .url
        .query()
        .unwrap_or("")
        .contains("fixture-key"));
}

#[tokio::test]
async fn gemini_multiple_signed_function_contents_replay_without_flattening() {
    let server = MockServer::start().await;
    let first = json!({"functionCall": {"id": "first", "name": "read", "args": {"id": 1}}, "thoughtSignature": "c2lnMQ=="});
    let second = json!({"functionCall": {"id": "second", "name": "read", "args": {"id": 2}}, "thoughtSignature": "c2lnMg=="});
    let body = [event(json!({"candidates": [{"content": {"role": "model", "parts": [first.clone()]}}]})), event(json!({"candidates": [{"content": {"role": "model", "parts": [second.clone()]}, "finishReason": "STOP"}]}))].concat();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
        .mount(&server)
        .await;
    let adapter = adapters(&server.uri()).remove(1);
    let (response, _) = collect(adapter.as_ref(), &[]).await.unwrap();
    assert_eq!(response.tool_calls.len(), 2);
    server.reset().await;
    let mut assistant = StandardMessage::assistant("");
    assistant.tool_calls = Some(response.tool_calls);
    assistant.provider_metadata = response.provider_metadata;
    Mock::given(method("POST")).and(body_partial_json(json!({"contents": [
        {"role": "model", "parts": [first]}, {"role": "model", "parts": [second]},
        {"role": "user", "parts": [{"functionResponse": {"id": "first", "name": "read", "response": {"result": "one"}}}, {"functionResponse": {"id": "second", "name": "read", "response": {"result": "two"}}}]}
    ]}))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "done"}]}}]}))).expect(1).mount(&server).await;
    adapter
        .create_session()
        .await
        .unwrap()
        .send(vec![
            assistant,
            StandardMessage::tool_result("first", "one"),
            StandardMessage::tool_result("second", "two"),
        ])
        .await
        .unwrap();
}

#[tokio::test]
async fn anthropic_parallel_fragments_and_signed_thinking_replay_are_native() {
    let server = MockServer::start().await;
    let mut parts = vec![
        event(json!({"type": "message_start", "message": {}})),
        event(
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}}),
        ),
        event(
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "fixture thought"}}),
        ),
        event(
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "signed-fixture"}}),
        ),
        event(json!({"type": "content_block_stop", "index": 0})),
    ];
    for (index, id) in [(1, "one"), (2, "two")] {
        parts.push(event(json!({"type": "content_block_start", "index": index, "content_block": {"type": "tool_use", "id": id, "name": "read", "input": {}}})));
        for fragment in ["{\"id\":", &format!("{index}}}")] {
            parts.push(event(json!({"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": fragment}})));
        }
        parts.push(event(json!({"type": "content_block_stop", "index": index})));
    }
    parts.extend([
        event(json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}})),
        event(json!({"type": "message_stop"})),
    ]);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(parts.concat()))
        .expect(1)
        .mount(&server)
        .await;
    let adapter = adapters(&server.uri()).remove(0);
    let (response, deltas) = collect(adapter.as_ref(), &[]).await.unwrap();
    assert!(deltas.is_empty());
    assert_eq!(
        response
            .tool_calls
            .iter()
            .map(|call| call.arguments.clone())
            .collect::<Vec<_>>(),
        [json!({"id": 1}), json!({"id": 2})]
    );
    let blocks = response.provider_metadata.as_ref().unwrap().payload()["blocks"].clone();
    assert_eq!(blocks[0]["signature"], "signed-fixture");
    let mut assistant = StandardMessage::assistant("");
    assistant.tool_calls = Some(response.tool_calls);
    assistant.provider_metadata = response.provider_metadata;
    server.reset().await;
    Mock::given(method("POST")).and(body_partial_json(json!({"messages": [
        {"role": "assistant", "content": blocks}, {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "one", "content": "one-result"}, {"type": "tool_result", "tool_use_id": "two", "content": "two-result"}]}
    ]}))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"}))).expect(1).mount(&server).await;
    adapter
        .create_session()
        .await
        .unwrap()
        .send(vec![
            assistant,
            StandardMessage::tool_result("one", "one-result"),
            StandardMessage::tool_result("two", "two-result"),
        ])
        .await
        .unwrap();
}

#[tokio::test]
async fn terminal_filter_is_typed_and_clean_text_eof_has_no_finish_reason() {
    let server = MockServer::start().await;
    let body = [
        event(json!({"candidates": [{"content": {"parts": [{"text": "partial"}]}}]})),
        event(json!({"candidates": [{"finishReason": "SAFETY"}]})),
    ]
    .concat();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    assert!(matches!(
        collect(adapters(&server.uri()).remove(1).as_ref(), &[])
            .await
            .unwrap_err(),
        ConnectorError::ContentFiltered(_)
    ));
    for index in 0..2 {
        server.reset().await;
        let body = if index == 0 {
            [event(json!({"type": "message_start", "message": {}})), event(json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": "partial"}}))].concat()
        } else {
            event(json!({"candidates": [{"content": {"parts": [{"text": "partial"}]}}]}))
        };
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        let (response, deltas) = collect(adapters(&server.uri()).remove(index).as_ref(), &[])
            .await
            .unwrap();
        assert_eq!(response.content, "partial");
        assert_eq!(deltas.concat(), "partial");
        assert_eq!(response.finish_reason, None);
        assert!(!response.usage.provider_reported);
    }
}

#[tokio::test]
async fn cancellation_stops_mid_stream_without_further_deltas() {
    for index in 0..2 {
        let fixture = if index == 0 {
            anthropic_text_fixture()
        } else {
            gemini_text_fixture()
        };
        let split = fixture.find("Hello ").unwrap();
        let boundary = fixture[split..].find("\n\n").unwrap() + split + 2;
        let (uri, resume, server) = paused_stream(vec![
            fixture.as_bytes()[..boundary].to_vec(),
            fixture.as_bytes()[boundary..].to_vec(),
        ])
        .await;
        let session = adapters(&uri).remove(index).create_session().await.unwrap();
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            session
                .send_streaming_events_controlled(
                    vec![StandardMessage::user("fixture")],
                    &[],
                    LlmRequestOptions {
                        timeout: Some(Duration::from_secs(5)),
                        ..Default::default()
                    },
                    &cancellation,
                    ProviderEventSink::new(sender),
                )
                .await
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .unwrap(),
            Some(ProviderStreamEvent::TextDelta("Hello ".into()))
        );
        cancel.cancel();
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            ConnectorError::Cancelled(_)
        ));
        assert_eq!(receiver.recv().await, None);
        drop(resume);
        server.abort();
    }
}

#[tokio::test]
async fn incomplete_native_tools_are_errors() {
    let fixtures = [
        [event(json!({"type": "message_start", "message": {}})), event(json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "one", "name": "read", "input": {}}}))].concat(),
        event(json!({"candidates": [{"content": {"parts": [{"functionCall": {"name": "read", "args": {}}}]}}]})),
    ];
    for (index, body) in fixtures.into_iter().enumerate() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        assert!(matches!(
            collect(adapters(&server.uri()).remove(index).as_ref(), &[])
                .await
                .unwrap_err(),
            ConnectorError::StreamError(_)
        ));
    }
}
