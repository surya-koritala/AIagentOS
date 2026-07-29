//! Backend client for the AI Agent OS desktop application.
//!
//! The desktop UI is a client of the public syscall service. Even though the
//! packaged application hosts its kernel in the same process, it reaches that
//! kernel through an authenticated loopback server so lifecycle and tool calls
//! cannot bypass the canonical authorization path.

use std::sync::Arc;

use agent_sdk::{
    AgentEnforcementInfo, ConnectionProfile, GenerationCheckpointSummary, KernelClient,
    LifecycleResult, MessageResult, MessageStreamEvent, OperatorAgentSnapshot,
    OperatorCgroupSnapshot, OperatorPackageSnapshot, OperatorServiceSnapshot, OperatorSnapshot,
    OperatorTunable, ProviderSummary, SdkError,
};
use kernel::{syscall_gate::GateStats, syscall_server::SyscallServer, AgentKernelImpl};
use serde::Serialize;
use tokio::sync::Mutex;

#[cfg(feature = "desktop-shell")]
pub mod commands;
#[cfg(feature = "desktop-shell")]
pub mod credentials;

/// Serializable agent row consumed by the Svelte UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopAgent {
    pub id: String,
    pub name: String,
    pub state: String,
    pub priority: u8,
    pub scheduler_state: String,
    pub sandbox_active: bool,
    pub capabilities: Vec<String>,
    pub namespace_count: usize,
    pub checkpoint_count: usize,
    pub context_active_tokens: u32,
    pub context_budget_tokens: u32,
    pub stored_spill_bytes: u64,
    pub cgroup: Option<DesktopCgroup>,
    pub gate: DesktopGateView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopCgroup {
    pub id: u64,
    pub scope: String,
    pub tokens_per_minute_limit: u64,
    pub concurrent_tool_limit: u32,
    pub context_token_limit: u64,
    pub agent_limit: u32,
    pub active_tool_calls: u32,
    pub context_tokens: u64,
    pub agent_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopGateView {
    pub allowed: u64,
    pub denied: u64,
    pub audited: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopProvider {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    pub available: bool,
    pub circuit_open: bool,
    pub consecutive_failures: u32,
    pub api_family: String,
    pub required_region: Option<String>,
    pub sampled_at: Option<String>,
    pub probe_duration_ms: Option<u64>,
    pub probe_timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopPackage {
    pub agent_id: String,
    pub name: String,
    pub provider: String,
    pub profile: String,
    pub loaded_at: String,
    pub agent_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopService {
    pub name: String,
    pub state: String,
    pub agent_id: Option<String>,
    pub restart_count: u32,
    pub last_exit_code: Option<i32>,
    pub desired_running: bool,
    pub ready: bool,
    pub healthy: bool,
    pub restart_exhausted: bool,
    pub last_failure: Option<String>,
    pub next_restart_at: Option<String>,
    pub last_transition_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopTunable {
    pub name: String,
    pub value: u64,
    pub revision: u64,
    pub minimum: u64,
    pub maximum: u64,
    pub persisted: bool,
    pub updated_at: String,
    pub updated_by: String,
    pub description: String,
}

/// Non-secret global metrics shown by the desktop dashboard.
///
/// The capture timestamp and telemetry contract version make it explicit
/// which raw operator snapshot the values came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopMetricsView {
    pub captured_at: String,
    pub telemetry_contract_version: u32,
    pub tokens_consumed: u64,
    pub api_calls_made: u64,
    pub time_elapsed_ms: u64,
}

/// One atomic desktop refresh payload with explicit scope omissions and the
/// SDK reconnect generation that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopOperatorView {
    pub captured_at: String,
    pub consistency: String,
    pub scope: String,
    pub kernel_version: String,
    pub protocol_version: u32,
    pub agents: Vec<DesktopAgent>,
    pub total_visible_agents: usize,
    pub agents_truncated: bool,
    pub providers: Vec<DesktopProvider>,
    pub packages: Vec<DesktopPackage>,
    pub services: Option<Vec<DesktopService>>,
    pub tunables: Option<Vec<DesktopTunable>>,
    pub scoped_gate: DesktopGateView,
    pub metrics: Option<DesktopMetricsView>,
    pub warnings: Vec<String>,
    pub reconnect_generation: u64,
}

impl DesktopOperatorView {
    fn from_operator_snapshot(snapshot: OperatorSnapshot, reconnect_generation: u64) -> Self {
        let metrics = DesktopMetricsView::try_from_operator_snapshot(&snapshot).ok();
        let mut warnings = Vec::new();
        if metrics.is_none() {
            warnings.push(
                "Global metrics are unavailable for this caller scope; agent data is current."
                    .to_string(),
            );
        }
        if snapshot.services.is_none() {
            warnings.push(
                "Service supervision is unavailable for this caller scope; no service state was invented."
                    .to_string(),
            );
        }
        if snapshot.tunables.is_none() {
            warnings.push(
                "Operator tunables are unavailable for this caller scope; no defaults were invented."
                    .to_string(),
            );
        }
        if snapshot.agents_truncated {
            warnings.push(format!(
                "Agent results are truncated: showing {} of {} visible agents.",
                snapshot.agents.len(),
                snapshot.total_visible_agents
            ));
        }
        Self {
            captured_at: snapshot.captured_at,
            consistency: snapshot.consistency,
            scope: snapshot.scope,
            kernel_version: snapshot.kernel_version,
            protocol_version: snapshot.protocol_version,
            agents: snapshot
                .agents
                .into_iter()
                .map(DesktopAgent::from)
                .collect(),
            total_visible_agents: snapshot.total_visible_agents,
            agents_truncated: snapshot.agents_truncated,
            providers: snapshot
                .providers
                .into_iter()
                .map(DesktopProvider::from)
                .collect(),
            packages: snapshot
                .packages
                .into_iter()
                .map(DesktopPackage::from)
                .collect(),
            services: snapshot
                .services
                .map(|services| services.into_iter().map(DesktopService::from).collect()),
            tunables: snapshot
                .tunables
                .map(|tunables| tunables.into_iter().map(DesktopTunable::from).collect()),
            scoped_gate: DesktopGateView::from(snapshot.scoped_gate_decisions),
            metrics,
            warnings,
            reconnect_generation,
        }
    }
}

impl From<OperatorAgentSnapshot> for DesktopAgent {
    fn from(agent: OperatorAgentSnapshot) -> Self {
        Self {
            id: agent.id,
            name: agent.name,
            state: agent.state,
            priority: agent.priority,
            scheduler_state: agent.scheduler_state,
            sandbox_active: agent.sandbox_active,
            capabilities: agent.capabilities,
            namespace_count: agent.namespace_details.len().max(agent.namespaces.len()),
            checkpoint_count: agent.checkpoint_count,
            context_active_tokens: agent.context_pressure.active_tokens,
            context_budget_tokens: agent.context_pressure.budget_tokens,
            stored_spill_bytes: agent.context_pressure.stored_spill_bytes,
            cgroup: agent.cgroup.map(DesktopCgroup::from),
            gate: DesktopGateView::from(agent.gate_decisions),
        }
    }
}

impl From<OperatorCgroupSnapshot> for DesktopCgroup {
    fn from(cgroup: OperatorCgroupSnapshot) -> Self {
        Self {
            id: cgroup.id,
            scope: cgroup.scope,
            tokens_per_minute_limit: cgroup.tokens_per_minute_limit,
            concurrent_tool_limit: cgroup.concurrent_tool_limit,
            context_token_limit: cgroup.context_token_limit,
            agent_limit: cgroup.agent_limit,
            active_tool_calls: cgroup.active_tool_calls,
            context_tokens: cgroup.context_tokens,
            agent_count: cgroup.agent_count,
        }
    }
}

impl From<GateStats> for DesktopGateView {
    fn from(gate: GateStats) -> Self {
        Self {
            allowed: gate.allowed,
            denied: gate.denied_capability
                + gate.denied_mac
                + gate.denied_approval
                + gate.denied_cgroup
                + gate.denied_namespace
                + gate.denied_unknown,
            audited: gate.audited,
        }
    }
}

impl From<ProviderSummary> for DesktopProvider {
    fn from(provider: ProviderSummary) -> Self {
        Self {
            id: provider.id,
            name: provider.name,
            provider_type: provider.provider_type,
            available: provider.available,
            circuit_open: provider.circuit_open,
            consecutive_failures: provider.consecutive_failures,
            api_family: provider.capabilities.api_family,
            required_region: provider.routing_policy.required_region,
            sampled_at: provider.sampled_at,
            probe_duration_ms: provider.probe_duration_ms,
            probe_timed_out: provider.probe_timed_out,
        }
    }
}

impl From<OperatorPackageSnapshot> for DesktopPackage {
    fn from(package: OperatorPackageSnapshot) -> Self {
        Self {
            agent_id: package.agent_id,
            name: package.name,
            provider: package.provider,
            profile: package.profile,
            loaded_at: package.loaded_at,
            agent_state: package.agent_state,
        }
    }
}

impl From<OperatorServiceSnapshot> for DesktopService {
    fn from(service: OperatorServiceSnapshot) -> Self {
        Self {
            name: service.name,
            state: service.state,
            agent_id: service.agent_id,
            restart_count: service.restart_count,
            last_exit_code: service.last_exit_code,
            desired_running: service.desired_running,
            ready: service.ready,
            healthy: service.healthy,
            restart_exhausted: service.restart_exhausted,
            last_failure: service.last_failure,
            next_restart_at: service.next_restart_at,
            last_transition_at: service.last_transition_at,
        }
    }
}

impl From<OperatorTunable> for DesktopTunable {
    fn from(tunable: OperatorTunable) -> Self {
        Self {
            name: tunable.name,
            value: tunable.value,
            revision: tunable.revision,
            minimum: tunable.minimum,
            maximum: tunable.maximum,
            persisted: tunable.persisted,
            updated_at: tunable.updated_at,
            updated_by: tunable.updated_by,
            description: tunable.description,
        }
    }
}

impl DesktopMetricsView {
    pub fn try_from_operator_snapshot(snapshot: &OperatorSnapshot) -> Result<Self, &'static str> {
        let metrics = snapshot
            .system_metrics
            .as_ref()
            .ok_or("global metrics are unavailable for this caller scope")?;
        Ok(Self {
            captured_at: snapshot.captured_at.clone(),
            telemetry_contract_version: metrics.telemetry_contract_version,
            tokens_consumed: metrics.tokens_consumed,
            api_calls_made: metrics.api_calls_made,
            time_elapsed_ms: metrics.uptime_seconds.saturating_mul(1_000),
        })
    }
}

/// A serialized, single-connection desktop session.
///
/// Tauri commands may run concurrently, while one wire connection is ordered
/// request/reply. The mutex preserves that protocol invariant.
pub struct DesktopClient {
    inner: Mutex<KernelClient>,
    stream: Mutex<KernelClient>,
    cancellation: Mutex<KernelClient>,
}

impl DesktopClient {
    /// Connect to an existing syscall service and optionally authenticate.
    pub async fn connect(addr: &str, token: Option<&str>) -> Result<Self, SdkError> {
        Self::connect_profile(&ConnectionProfile::plaintext(addr), token).await
    }

    pub async fn connect_profile(
        profile: &ConnectionProfile,
        token: Option<&str>,
    ) -> Result<Self, SdkError> {
        let inner = profile.connect(token).await?;
        let stream = profile.connect(token).await?;
        let cancellation = profile.connect(token).await?;
        Ok(Self {
            inner: Mutex::new(inner),
            stream: Mutex::new(stream),
            cancellation: Mutex::new(cancellation),
        })
    }

    /// Expose an in-process kernel only through an authenticated ephemeral
    /// loopback service, then connect the desktop client to that service.
    pub async fn connect_embedded(kernel: Arc<AgentKernelImpl>) -> Result<Self, String> {
        let token = format!("desktop-{}", uuid::Uuid::new_v4());
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .map_err(|error| format!("failed to bind desktop kernel service: {error}"))?
            .with_auth_token(token.clone());
        let addr = server
            .local_addr()
            .map_err(|error| format!("failed to read desktop service address: {error}"))?;
        tokio::spawn(async move {
            if let Err(error) = server.serve().await {
                tracing::error!("desktop kernel service stopped: {error}");
            }
        });
        Self::connect(&addr.to_string(), Some(&token))
            .await
            .map_err(|error| format!("failed to connect desktop kernel client: {error}"))
    }

    pub async fn ping(&self) -> Result<(), SdkError> {
        self.inner.lock().await.ping().await
    }

    pub async fn authenticate(&self, token: impl Into<String>) -> Result<(), SdkError> {
        self.inner.lock().await.authenticate(token).await
    }

    pub async fn create_agent(
        &self,
        name: impl Into<String>,
        task: impl Into<String>,
        provider: Option<String>,
    ) -> Result<String, SdkError> {
        self.inner
            .lock()
            .await
            .create_agent(
                name,
                task,
                Some(provider.unwrap_or_else(|| "openai".to_string())),
                None,
                None,
            )
            .await
    }

    pub async fn send_message(
        &self,
        agent_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<MessageResult, SdkError> {
        self.inner
            .lock()
            .await
            .send_message(agent_id, message)
            .await
    }

    /// Drive one streamed turn on a dedicated wire connection.
    ///
    /// Keeping the stream separate means operator refreshes remain responsive
    /// and the cancellation connection can stop the exact in-flight request.
    pub async fn send_message_stream<F>(
        &self,
        request_id: impl Into<String>,
        agent_id: impl Into<String>,
        message: impl Into<String>,
        on_event: F,
    ) -> Result<MessageResult, SdkError>
    where
        F: FnMut(&MessageStreamEvent),
    {
        self.stream
            .lock()
            .await
            .send_message_stream(request_id, agent_id, message, on_event)
            .await
    }

    /// Cooperatively cancel one exact streamed turn without replaying it.
    pub async fn cancel_request(
        &self,
        request_id: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Result<bool, SdkError> {
        self.cancellation
            .lock()
            .await
            .cancel_request(request_id, agent_id)
            .await
    }

    pub async fn pause_agent(&self, agent_id: impl Into<String>) -> Result<(), SdkError> {
        self.inner
            .lock()
            .await
            .pause_agent(agent_id)
            .await
            .map(|_| ())
    }

    pub async fn resume_agent(&self, agent_id: impl Into<String>) -> Result<(), SdkError> {
        self.inner
            .lock()
            .await
            .resume_agent(agent_id)
            .await
            .map(|_| ())
    }

    pub async fn stop_agent(&self, agent_id: impl Into<String>) -> Result<(), SdkError> {
        self.inner
            .lock()
            .await
            .stop_agent(agent_id)
            .await
            .map(|_| ())
    }

    pub async fn list_generation_checkpoints(
        &self,
        agent_id: impl Into<String>,
    ) -> Result<Vec<GenerationCheckpointSummary>, SdkError> {
        self.inner
            .lock()
            .await
            .list_generation_checkpoints(agent_id)
            .await
    }

    pub async fn resume_generation_checkpoint(
        &self,
        agent_id: impl Into<String>,
        checkpoint_id: impl Into<String>,
    ) -> Result<LifecycleResult, SdkError> {
        self.inner
            .lock()
            .await
            .resume_generation_checkpoint(agent_id, checkpoint_id)
            .await
    }

    pub async fn delete_generation_checkpoint(
        &self,
        agent_id: impl Into<String>,
        checkpoint_id: impl Into<String>,
    ) -> Result<bool, SdkError> {
        self.inner
            .lock()
            .await
            .delete_generation_checkpoint(agent_id, checkpoint_id)
            .await
    }

    pub async fn operator_snapshot(&self) -> Result<OperatorSnapshot, SdkError> {
        self.inner.lock().await.operator_snapshot().await
    }

    pub async fn operator_view(&self) -> Result<DesktopOperatorView, SdkError> {
        let mut client = self.inner.lock().await;
        let snapshot = client.operator_snapshot().await?;
        Ok(DesktopOperatorView::from_operator_snapshot(
            snapshot,
            client.reconnect_generation(),
        ))
    }

    pub async fn list_agents(&self) -> Result<Vec<DesktopAgent>, SdkError> {
        Ok(self
            .operator_snapshot()
            .await?
            .agents
            .into_iter()
            .map(DesktopAgent::from)
            .collect())
    }

    pub async fn agent_info(
        &self,
        agent_id: impl Into<String>,
    ) -> Result<AgentEnforcementInfo, SdkError> {
        self.inner.lock().await.agent_info(agent_id).await
    }

    pub async fn call_tool(
        &self,
        agent_id: impl Into<String>,
        tool: impl Into<String>,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        self.inner
            .lock()
            .await
            .call_tool(agent_id, tool, args)
            .await
    }
}

/// State managed by Tauri for every backend command.
pub struct AppState {
    pub client: DesktopClient,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::connector::{
        LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, ProviderCapabilities,
        ProviderEventSink, ProviderStreamEvent, ProviderType, StandardMessage, ToolDefinition,
    };
    use kernel::{ConnectorError, ProviderId};

    struct BlockingStreamAdapter {
        id: ProviderId,
    }

    struct BlockingStreamSession {
        id: ProviderId,
    }

    #[async_trait::async_trait]
    impl LlmSession for BlockingStreamSession {
        async fn send(
            &self,
            _messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
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
            "desktop-stream-test"
        }
    }

    #[async_trait::async_trait]
    impl LlmProviderAdapter for BlockingStreamAdapter {
        fn id(&self) -> &ProviderId {
            &self.id
        }

        fn name(&self) -> &str {
            "desktop stream test"
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
    async fn embedded_desktop_reaches_the_kernel_only_through_its_wire_client() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
        let client = DesktopClient::connect_embedded(kernel)
            .await
            .expect("embedded desktop");

        client.ping().await.expect("authenticated ping");
        assert!(client.list_agents().await.expect("initial list").is_empty());
        let id = client
            .create_agent("desktop-test", "wire boundary", Some("stub".to_string()))
            .await
            .expect("create over wire");
        let view = client.operator_view().await.expect("updated operator view");
        let agent = view
            .agents
            .iter()
            .find(|agent| agent.id == id)
            .expect("created agent");
        assert!(!agent.scheduler_state.is_empty());
        assert!(agent.sandbox_active);
        assert_eq!(agent.context_active_tokens, 0);
        assert!(agent.cgroup.is_some());
        assert_eq!(view.total_visible_agents, 1);
        assert!(!view.agents_truncated);
        assert!(view.services.is_some());
        assert!(view
            .tunables
            .as_ref()
            .is_some_and(|items| !items.is_empty()));
    }

    #[tokio::test]
    async fn desktop_stream_keeps_refresh_live_and_cancels_on_a_dedicated_connection() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
        kernel
            .register_provider(Arc::new(BlockingStreamAdapter {
                id: "desktop-stream".into(),
            }))
            .expect("register stream provider");
        let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
            .await
            .expect("bind");
        let address = server.local_addr().expect("address");
        tokio::spawn(server.serve());

        let client = Arc::new(
            DesktopClient::connect(&address.to_string(), None)
                .await
                .expect("desktop client"),
        );
        let agent_id = client
            .create_agent(
                "streaming",
                "prove independent connections",
                Some("desktop-stream".into()),
            )
            .await
            .expect("create agent");
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let stream_client = Arc::clone(&client);
        let stream_agent = agent_id.clone();
        let stream = tokio::spawn(async move {
            stream_client
                .send_message_stream(
                    "desktop-request",
                    stream_agent,
                    "wait for cancellation",
                    |event| {
                        if matches!(event, MessageStreamEvent::Started) {
                            let _ = started_tx.send(());
                        }
                    },
                )
                .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), started_rx.recv())
            .await
            .expect("stream start timeout")
            .expect("stream start signal");
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.operator_snapshot(),
        )
        .await
        .expect("operator refresh was blocked by stream")
        .expect("operator refresh");
        assert!(client
            .cancel_request("desktop-request", &agent_id)
            .await
            .expect("cancel request"));

        let error = tokio::time::timeout(std::time::Duration::from_secs(2), stream)
            .await
            .expect("stream cancellation timeout")
            .expect("stream task")
            .expect_err("cancelled stream must fail");
        assert_eq!(error.wire_code(), Some(agent_sdk::WireErrorCode::Cancelled));
        assert!(!client
            .cancel_request("desktop-request", &agent_id)
            .await
            .expect("completed stream is not active"));
    }

    #[test]
    fn scoped_operator_view_is_partial_instead_of_inventing_global_zeroes() {
        let snapshot = OperatorSnapshot {
            captured_at: "2026-07-28T00:00:00Z".into(),
            consistency: "atomic".into(),
            scope: "tenant".into(),
            kernel_version: "test".into(),
            protocol_version: 2,
            agents: Vec::new(),
            total_visible_agents: 0,
            agents_truncated: false,
            providers: Vec::new(),
            packages: Vec::new(),
            scoped_gate_decisions: Default::default(),
            tunables: None,
            services: None,
            system_metrics: None,
            global_spend_usd: None,
        };

        let view = DesktopOperatorView::from_operator_snapshot(snapshot, 3);
        assert_eq!(view.reconnect_generation, 3);
        assert!(view.metrics.is_none());
        assert!(view.services.is_none());
        assert!(view.tunables.is_none());
        assert_eq!(view.warnings.len(), 3);
    }

    #[test]
    fn desktop_operator_view_preserves_scope_safe_operator_sections() {
        let snapshot = OperatorSnapshot {
            captured_at: "2026-07-28T00:00:00Z".into(),
            consistency: "atomic".into(),
            scope: "global".into(),
            kernel_version: "test".into(),
            protocol_version: 2,
            agents: Vec::new(),
            total_visible_agents: 0,
            agents_truncated: false,
            providers: vec![ProviderSummary {
                id: "stub".into(),
                name: "Stub".into(),
                provider_type: "Local".into(),
                available: true,
                circuit_open: false,
                consecutive_failures: 0,
                capabilities: Default::default(),
                routing_policy: Default::default(),
                sampled_at: Some("2026-07-28T00:00:00Z".into()),
                probe_duration_ms: Some(4),
                probe_timed_out: false,
            }],
            packages: vec![OperatorPackageSnapshot {
                agent_id: "agent-1".into(),
                tenant_id: "tenant-1".into(),
                name: "reviewer".into(),
                provider: "stub".into(),
                profile: "safe".into(),
                loaded_at: "2026-07-28T00:00:00Z".into(),
                agent_state: "Running".into(),
            }],
            scoped_gate_decisions: Default::default(),
            tunables: Some(vec![OperatorTunable {
                name: "kernel.max_agents".into(),
                value: 10,
                revision: 2,
                minimum: 0,
                maximum: 100,
                persisted: true,
                updated_at: "2026-07-28T00:00:00Z".into(),
                updated_by: "operator".into(),
                description: "limit".into(),
            }]),
            services: Some(vec![OperatorServiceSnapshot {
                name: "worker".into(),
                state: "Running".into(),
                agent_id: None,
                restart_count: 0,
                last_exit_code: None,
                desired_running: true,
                ready: true,
                healthy: true,
                restart_exhausted: false,
                last_failure: None,
                next_restart_at: None,
                last_transition_at: "2026-07-28T00:00:00Z".into(),
            }]),
            system_metrics: None,
            global_spend_usd: None,
        };

        let view = DesktopOperatorView::from_operator_snapshot(snapshot, 0);
        assert_eq!(view.scope, "global");
        assert_eq!(view.providers[0].id, "stub");
        assert_eq!(view.packages[0].name, "reviewer");
        assert_eq!(view.services.as_ref().expect("services")[0].name, "worker");
        assert_eq!(
            view.tunables.as_ref().expect("tunables")[0].name,
            "kernel.max_agents"
        );
        assert_eq!(
            view.warnings,
            vec![
                "Global metrics are unavailable for this caller scope; agent data is current."
                    .to_string()
            ]
        );
    }
}
