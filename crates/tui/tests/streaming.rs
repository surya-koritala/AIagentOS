//! Live public-wire regression for responsive TUI streaming and exact
//! cancellation. The terminal renderer is intentionally not involved here:
//! this proves the three authenticated connections used by the binary.

use std::sync::Arc;
use std::time::Duration;

use agent_sdk::{MessageStreamEvent, WireErrorCode};
use agent_tui::TuiClient;
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, ProviderCapabilities,
    ProviderEventSink, ProviderStreamEvent, ProviderType, StandardMessage, ToolDefinition,
};
use kernel::syscall_server::SyscallServer;
use kernel::{AgentKernelImpl, ConnectorError, ProviderId};

struct BlockingStreamAdapter {
    id: ProviderId,
}

struct BlockingStreamSession {
    id: ProviderId,
}

#[async_trait::async_trait]
impl LlmSession for BlockingStreamSession {
    async fn send(&self, _messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        std::future::pending::<Result<LlmResponse, ConnectorError>>().await
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        std::future::pending::<Result<LlmResponse, ConnectorError>>().await
    }

    async fn send_streaming_events_controlled(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        _options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: ProviderEventSink,
    ) -> Result<LlmResponse, ConnectorError> {
        events
            .emit(ProviderStreamEvent::TextDelta("before-cancel".into()))
            .await;
        cancellation.cancelled().await;
        Err(ConnectorError::cancelled(self.id.clone(), None))
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "tui-stream-test"
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for BlockingStreamAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "TUI stream test"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(BlockingStreamSession {
            id: self.id.clone(),
        }))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            prompt_cancellation: true,
            ..ProviderCapabilities::default()
        }
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

#[tokio::test]
async fn tui_stream_keeps_refresh_live_and_cancels_on_an_exact_dedicated_connection() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    kernel
        .register_provider(Arc::new(BlockingStreamAdapter {
            id: "tui-stream".into(),
        }))
        .expect("register stream provider");
    let token = "tui-stream-auth";
    let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind")
        .with_auth_token(token);
    let address = server.local_addr().expect("address");
    let server_task = tokio::spawn(server.serve());

    let mut client = TuiClient::connect(&address.to_string(), Some(token))
        .await
        .expect("three authenticated TUI connections");
    let messages = client.message_client();
    let agent_id = client
        .create_agent(
            "streaming",
            "prove TUI connection independence",
            Some("tui-stream".into()),
            None,
            None,
        )
        .await
        .expect("create agent");
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let stream_messages = messages.clone();
    let stream_agent = agent_id.clone();
    let mut stream = tokio::spawn(async move {
        stream_messages
            .send_message_stream(
                "tui-request",
                stream_agent,
                "wait for exact cancellation",
                |event| {
                    if matches!(event, MessageStreamEvent::Started) {
                        let _ = started_tx.send(());
                    }
                },
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("stream start timeout")
        .expect("stream start signal");
    tokio::time::timeout(Duration::from_secs(2), client.operator_snapshot())
        .await
        .expect("ordinary operator connection was blocked by stream")
        .expect("operator snapshot");

    assert!(!messages
        .cancel_request("wrong-request", &agent_id)
        .await
        .expect("wrong exact request is not active"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut stream)
            .await
            .is_err(),
        "wrong cancellation must not stop the live stream"
    );
    assert!(messages
        .cancel_request("tui-request", &agent_id)
        .await
        .expect("cancel exact request"));

    let error = tokio::time::timeout(Duration::from_secs(2), stream)
        .await
        .expect("stream cancellation timeout")
        .expect("stream task")
        .expect_err("cancelled stream must fail");
    assert_eq!(error.wire_code(), Some(WireErrorCode::Cancelled));
    assert!(!messages
        .cancel_request("tui-request", &agent_id)
        .await
        .expect("completed stream is no longer active"));
    server_task.abort();
}
