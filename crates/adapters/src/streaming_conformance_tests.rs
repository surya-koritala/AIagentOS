//! Keyless conformance and adversarial SSE fixtures; executed by GitHub CI.

use std::sync::Arc;
use std::time::Duration;

use kernel::connector::*;
use kernel::ConnectorError;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::anthropic::AnthropicAdapter;
use crate::azure_openai::AzureOpenAiAdapter;
use crate::deepseek::DeepseekAdapter;
use crate::gemini::GeminiAdapter;
use crate::groq::GroqAdapter;
use crate::huggingface::HuggingFaceAdapter;
use crate::local::LocalLlmAdapter;
use crate::openai::OpenAiAdapter;
use crate::vllm::VllmAdapter;

fn native_adapters(uri: &str) -> Vec<Box<dyn LlmProviderAdapter>> {
    vec![
        Box::new(AzureOpenAiAdapter::new(
            uri.into(),
            "fixture".into(),
            "fixture-key".into(),
        )),
        Box::new(
            OpenAiAdapter::new("fixture-key".into())
                .with_base_url(uri.into())
                .with_model("fixture".into()),
        ),
        Box::new(
            GroqAdapter::new("fixture-key".into())
                .with_base_url(uri.into())
                .with_model("fixture".into()),
        ),
        Box::new(
            DeepseekAdapter::new("fixture-key".into())
                .with_base_url(uri.into())
                .with_model("fixture".into()),
        ),
        Box::new(
            VllmAdapter::new(String::new())
                .with_base_url(uri.into())
                .with_model("fixture".into()),
        ),
    ]
}

fn sse_event(value: Value) -> String {
    format!("data: {value}\n\n")
}

fn text_fixture() -> String {
    [
        ": heartbeat\r\n\r\n".to_string(),
        sse_event(json!({"choices": [{"index": 0, "delta": {"content": "Hello "}, "finish_reason": null}], "usage": null})),
        sse_event(json!({"choices": [{"index": 0, "delta": {"content": "🌐"}, "finish_reason": "stop"}], "usage": null})),
        sse_event(json!({"choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14, "prompt_tokens_details": {"cached_tokens": 4}}})),
        "data: [DONE]\n\n".to_string(),
    ]
    .concat()
}

pub(super) async fn collect(
    adapter: &dyn LlmProviderAdapter,
    tools: &[ToolDefinition],
) -> Result<(LlmResponse, Vec<String>), ConnectorError> {
    let session = adapter.create_session().await?;
    let cancellation = CancellationToken::new();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    let send = session.send_streaming_events_controlled(
        vec![StandardMessage::user("fixture")],
        tools,
        LlmRequestOptions {
            max_output_tokens: Some(41),
            timeout: Some(Duration::from_secs(5)),
        },
        &cancellation,
        ProviderEventSink::new(sender),
    );
    let drain = async {
        let mut deltas = Vec::new();
        while let Some(ProviderStreamEvent::TextDelta(text)) = receiver.recv().await {
            deltas.push(text);
        }
        deltas
    };
    let (response, deltas) = tokio::join!(send, drain);
    Ok((response?, deltas))
}

pub(super) fn assert_conformance(adapter: &dyn LlmProviderAdapter, response: &LlmResponse, deltas: &[String]) {
    assert_eq!(deltas.concat(), response.content, "{}", adapter.id());
    if adapter.capabilities().native_streaming {
        assert!(deltas.len() >= 2, "{} claimed native streaming", adapter.id());
    } else {
        assert_eq!(deltas.len(), 1, "{} claimed fallback streaming", adapter.id());
    }
}

#[tokio::test]
async fn nine_network_adapters_conform_to_declared_streaming() {
    let server = MockServer::start().await;
    for request_path in [
        "/chat/completions",
        "/openai/deployments/fixture/chat/completions",
    ] {
        Mock::given(method("POST"))
            .and(path(request_path))
            .and(body_partial_json(json!({
                "stream": true,
                "stream_options": {"include_usage": true},
                "max_tokens": 41
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(text_fixture())
                    .insert_header("content-type", "text/event-stream"),
            )
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(body_partial_json(json!({"stream": true, "max_tokens": 41})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(crate::native_messages_streaming_tests::anthropic_text_fixture()),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1beta/models/fixture:streamGenerateContent"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(crate::native_messages_streaming_tests::gemini_text_fixture()),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path("/api/chat"))
        .and(body_partial_json(json!({"stream": true, "options": {"num_predict": 41}})))
        .respond_with(ResponseTemplate::new(200).set_body_string(crate::local_streaming_tests::ndjson_fixture()))
        .expect(1).mount(&server).await;
    let fallback_fixtures = [
        ("/models/fixture", json!([{"generated_text": "Hello 🌐"}])),
    ];
    for (request_path, fixture) in fallback_fixtures {
        Mock::given(method("POST"))
            .and(path(request_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixture))
            .expect(1)
            .mount(&server)
            .await;
    }
    let mut adapters = native_adapters(&server.uri());
    adapters.extend([
        Box::new(
            AnthropicAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("fixture".into()),
        ) as Box<dyn LlmProviderAdapter>,
        Box::new(
            GeminiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("fixture".into()),
        ),
        Box::new(
            HuggingFaceAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("fixture".into()),
        ),
        Box::new(LocalLlmAdapter::new(server.uri(), "fixture".into())),
    ]);
    let mut ids: Vec<_> = adapters
        .iter()
        .map(|adapter| adapter.id().as_str())
        .collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        [
            "anthropic",
            "azure-openai",
            "deepseek",
            "gemini",
            "groq",
            "huggingface",
            "local",
            "openai",
            "vllm"
        ]
    );
    for adapter in adapters {
        let (response, deltas) = collect(adapter.as_ref(), &[]).await.unwrap();
        assert_eq!(response.content, "Hello 🌐", "{}", adapter.id());
        assert_conformance(adapter.as_ref(), &response, &deltas);
        if adapter.id() == "huggingface" {
            assert_eq!(response.usage, LlmUsage::default());
            assert_eq!(response.tokens_used, 0);
        } else {
            assert!(response.usage.provider_reported, "{}", adapter.id());
            assert_eq!(response.usage.input_tokens, 11, "{}", adapter.id());
            assert_eq!(response.usage.output_tokens, 3, "{}", adapter.id());
            assert_eq!(response.tokens_used, 14, "{}", adapter.id());
            assert_eq!(
                response.usage.cached_tokens,
                if adapter.id() == "local" { 0 } else { 4 }
            );
        }
    }
}

#[tokio::test]
async fn native_adapters_assemble_interleaved_parallel_tool_arguments() {
    let server = MockServer::start().await;
    let body = [
        sse_event(json!({"choices": [{"delta": {"tool_calls": [{"index": 1, "id": "second", "type": "function", "function": {"name": "lookup", "arguments": "{\"id\":"}}, {"index": 0, "id": "first", "type": "function", "function": {"name": "read", "arguments": "{\"path\":\""}}]}}]})),
        sse_event(json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "a.txt\"}"}}, {"index": 1, "function": {"arguments": "7}"}}]}, "finish_reason": "tool_calls"}]})),
        sse_event(json!({"choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14, "prompt_cache_hit_tokens": 5}})),
        "data: [DONE]\n\n".to_string(),
    ]
    .concat();
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"stream": true, "tools": [{"type": "function", "function": {"name": "read", "parameters": {"type": "object"}}}]})))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(5)
        .mount(&server)
        .await;
    let tools = [ToolDefinition {
        name: "read".into(),
        description: "fixture".into(),
        parameters: json!({"type": "object"}),
    }];
    for adapter in native_adapters(&server.uri()) {
        let (response, deltas) = collect(adapter.as_ref(), &tools).await.unwrap();
        assert!(deltas.is_empty());
        assert_eq!(response.finish_reason.as_deref(), Some("tool_calls"));
        assert_eq!(
            response.tool_calls,
            vec![
                ToolCall {
                    id: "first".into(),
                    name: "read".into(),
                    arguments: json!({"path": "a.txt"})
                },
                ToolCall {
                    id: "second".into(),
                    name: "lookup".into(),
                    arguments: json!({"id": 7})
                },
            ]
        );
        assert_eq!(response.tokens_used, 14);
        assert_eq!(response.usage.cached_tokens, 5);
    }
}

#[tokio::test]
async fn native_adapters_reject_oversized_streams_and_malformed_tool_calls() {
    let bad_bodies = [
        " ".repeat(crate::streaming::MAX_OPENAI_STREAM_BYTES + 1),
        [sse_event(json!({"choices": [{"delta": {"tool_calls": [{"index": u64::MAX, "id": "bad"}]}, "finish_reason": "tool_calls"}]})), "data: [DONE]\n\n".into()].concat(),
        [sse_event(json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "bad", "function": {"name": "read", "arguments": "{broken"}}]}, "finish_reason": "tool_calls"}]})), "data: [DONE]\n\n".into()].concat(),
        "data: {\"error\":{\"message\":\"sk-secret prompt-private\"}}\n\n".into(),
        "data: {\"choices\":[],\"x_groq\":{\"error\":\"sk-secret prompt-private\"}}\n\n".into(),
        "data: {broken}\n\n".into(),
    ];
    for body in bad_bodies {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(5)
            .mount(&server)
            .await;
        for adapter in native_adapters(&server.uri()) {
            let error = collect(adapter.as_ref(), &[]).await.unwrap_err();
            assert!(
                matches!(error, ConnectorError::ProtocolError(_)),
                "{error:?}"
            );
            assert!(!error.to_string().contains("sk-secret"));
            assert!(!error.to_string().contains("prompt-private"));
        }
    }
}

// A raw chunked HTTP fixture proves that deltas arrive before the response
// completes, and can split an individual UTF-8 code point across wire chunks.
pub(super) async fn paused_stream(
    chunks: Vec<Vec<u8>>,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    let (resume, resumed) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut bytes = [0; 1024];
            let count = socket.read(&mut bytes).await.unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&bytes[..count]);
            assert!(request.len() < 64 * 1024);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut resumed = Some(resumed);
        for (index, chunk) in chunks.into_iter().enumerate() {
            if index == 1 {
                let _ = resumed.take().unwrap().await;
            }
            socket
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            socket.write_all(&chunk).await.unwrap();
            socket.write_all(b"\r\n").await.unwrap();
            socket.flush().await.unwrap();
        }
        socket.write_all(b"0\r\n\r\n").await.unwrap();
    });
    (uri, resume, server)
}

#[tokio::test]
async fn native_stream_delivers_before_completion_and_preserves_split_utf8() {
    let first = sse_event(json!({"choices": [{"delta": {"content": "first "}}]}));
    let second =
        sse_event(json!({"choices": [{"delta": {"content": "🌐"}, "finish_reason": "stop"}]}))
            .replace('\n', "\r\n");
    let split = second
        .as_bytes()
        .iter()
        .position(|byte| *byte == 0xf0)
        .unwrap()
        + 2;
    for index in 0..5 {
        let (uri, resume, server) = paused_stream(vec![
            first.clone().into_bytes(),
            second.as_bytes()[..split].to_vec(),
            second.as_bytes()[split..].to_vec(),
            b"data: [DONE]\r\n\r\n".to_vec(),
        ])
        .await;
        let adapter = native_adapters(&uri).remove(index);
        let session = adapter.create_session().await.unwrap();
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
                    &CancellationToken::new(),
                    ProviderEventSink::new(sender),
                )
                .await
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .unwrap(),
            Some(ProviderStreamEvent::TextDelta("first ".into()))
        );
        assert!(!task.is_finished());
        resume.send(()).unwrap();
        assert_eq!(
            receiver.recv().await,
            Some(ProviderStreamEvent::TextDelta("🌐".into()))
        );
        assert_eq!(task.await.unwrap().unwrap().content, "first 🌐");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn native_stream_cancellation_and_deadline_cover_backpressure() {
    for index in 0..5 {
        for timeout in [false, true] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_string(text_fixture()))
                .expect(1)
                .mount(&server)
                .await;
            let adapter = native_adapters(&server.uri()).remove(index);
            let session = adapter.create_session().await.unwrap();
            let cancellation = CancellationToken::new();
            let cancel = cancellation.clone();
            let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
            let task = tokio::spawn(async move {
                session
                    .send_streaming_events_controlled(
                        vec![StandardMessage::user("fixture")],
                        &[],
                        LlmRequestOptions {
                            timeout: Some(Duration::from_millis(if timeout { 100 } else { 5000 })),
                            ..Default::default()
                        },
                        &cancellation,
                        ProviderEventSink::new(sender),
                    )
                    .await
            });
            // Waiting until the bounded channel is full makes backpressure
            // deterministic without consuming a delta or timing a sleep.
            tokio::time::timeout(Duration::from_secs(2), async {
                while receiver.is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if !timeout {
                cancel.cancel();
            }
            let error = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            if timeout {
                assert!(matches!(error, ConnectorError::Timeout(_)));
            } else {
                assert!(matches!(error, ConnectorError::Cancelled(_)));
            }
            assert_eq!(
                receiver.recv().await,
                Some(ProviderStreamEvent::TextDelta("Hello ".into()))
            );
            assert_eq!(receiver.recv().await, None);
        }
    }
}

#[tokio::test]
async fn visible_native_failure_suppresses_connector_retry_and_failover() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sse_event(
            json!({"choices": [{"delta": {"content": "partial"}}]}),
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/backup/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string(text_fixture()))
        .expect(0)
        .mount(&server)
        .await;
    let connector = Arc::new(AgentConnectorImpl::new());
    connector
        .register_provider(Arc::new(
            OpenAiAdapter::new("fixture-key".into())
                .with_base_url(server.uri())
                .with_model("fixture".into()),
        ))
        .unwrap();
    connector
        .register_provider(Arc::new(
            GroqAdapter::new("fixture-key".into())
                .with_base_url(format!("{}/backup", server.uri()))
                .with_model("fixture".into()),
        ))
        .unwrap();
    connector.set_backup(&"openai".into(), &"groq".into());
    let session = connector
        .connect_resilient(kernel::AgentId::new_v4(), &"openai".into())
        .await
        .unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    let error = session
        .send_streaming_events_controlled(
            vec![StandardMessage::user("fixture")],
            &[],
            LlmRequestOptions::default(),
            &CancellationToken::new(),
            ProviderEventSink::new(sender),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ConnectorError::PartialStream(_)));
    assert_eq!(
        receiver.recv().await,
        Some(ProviderStreamEvent::TextDelta("partial".into()))
    );
    assert_eq!(session.last_attempts(), Some(1));
}

#[tokio::test]
async fn native_stream_without_event_sink_preserves_history_and_zero_usage() {
    let server = MockServer::start().await;
    let body = [
        sse_event(json!({"choices": [{"delta": {"content": "answer"}, "finish_reason": "stop"}]})),
        sse_event(json!({"choices": [], "usage": null, "x_groq": {"usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}})),
        "data: [DONE]\n\n".to_string(),
    ].concat();
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"stream": true, "max_tokens": 9, "messages": [
            {"role": "assistant", "content": "", "tool_calls": [{"id": "call", "type": "function", "function": {"name": "read", "arguments": "{\"path\":\"a.txt\"}"}}]},
            {"role": "tool", "content": "fixture-result", "tool_call_id": "call"}
        ]})))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(5)
        .mount(&server)
        .await;
    let mut assistant = StandardMessage::assistant("");
    assistant.tool_calls = Some(vec![ToolCall {
        id: "call".into(),
        name: "read".into(),
        arguments: json!({"path": "a.txt"}),
    }]);
    for adapter in native_adapters(&server.uri()) {
        let session = adapter.create_session().await.unwrap();
        let response = session
            .send_streaming_with_options(
                vec![
                    assistant.clone(),
                    StandardMessage::tool_result("call", "fixture-result"),
                ],
                &[],
                LlmRequestOptions {
                    max_output_tokens: Some(9),
                    timeout: Some(Duration::from_secs(5)),
                },
            )
            .await
            .unwrap();
        assert_eq!(response.content, "answer");
        assert_eq!(response.tokens_used, 0);
        assert_eq!(response.usage, LlmUsage::reported(0, 0, 0));
    }
}

#[tokio::test]
async fn cancelled_native_attempt_makes_no_request_and_http_errors_stay_typed() {
    for index in 0..5 {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(json!({"error": {"api_key": "sk-secret"}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let adapter = native_adapters(&server.uri()).remove(index);
        let session = adapter.create_session().await.unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let error = session
            .send_streaming_controlled(
                vec![StandardMessage::user("fixture")],
                &[],
                LlmRequestOptions::default(),
                &cancellation,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ConnectorError::Cancelled(_)));
        assert!(server.received_requests().await.unwrap().is_empty());
        let error = collect(adapter.as_ref(), &[]).await.unwrap_err();
        assert!(matches!(error, ConnectorError::Authentication(_)));
        assert!(!error.to_string().contains("sk-secret"));
    }
}
