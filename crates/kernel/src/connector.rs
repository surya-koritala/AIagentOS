//! Agent Connector — manages LLM provider connections and sessions.
//!
//! Provides provider registration, session creation, failover, and
//! unavailability detection.
//!
//! ## Hardening: failover, retry/backoff
//!
//! The send path ([`AgentConnectorImpl::send_with_failover`]) is the
//! load-bearing entry point for resilient LLM calls:
//!
//! * **Retry with bounded exponential backoff** — transient errors (provider
//!   unavailable, connection/stream failures) are retried up to
//!   [`RetryPolicy::max_attempts`] with exponentially growing delays capped at
//!   [`RetryPolicy::max_backoff`]. *Permanent* errors (protocol/auth) are
//!   surfaced immediately and never retried (see [`is_transient`]).
//! * **Failover** — once retries against the primary are exhausted, the next
//!   registered backup provider is tried (also with retry). Provider ordering
//!   is preserved: the explicit `set_backup` chain is followed in order.
//!
//! Backoff is driven through an injectable [`Clock`] so tests stay fast and
//! deterministic — production uses [`TokioClock`] (real `tokio::time::sleep`),
//! tests use a no-op clock.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::{AgentId, ConnectorError, ProviderId};

/// Classify a connector error as transient (worth retrying) or permanent.
///
/// Permanent errors are protocol-level failures — malformed requests, auth
/// rejections, unsupported models — which will deterministically fail again on
/// retry. Everything else (unavailability, dropped connections, stream resets)
/// is treated as transient.
pub fn is_transient(err: &ConnectorError) -> bool {
    match err {
        ConnectorError::ProviderUnavailable(_)
        | ConnectorError::ConnectionFailed(_)
        | ConnectorError::StreamError(_)
        | ConnectorError::RateLimited(_)
        | ConnectorError::ServiceUnavailable(_)
        | ConnectorError::Timeout(_) => true,
        // Protocol errors include auth / bad-request style failures that will
        // not succeed on retry.
        ConnectorError::ProtocolError(_)
        | ConnectorError::PartialStream(_)
        | ConnectorError::Authentication(_)
        | ConnectorError::Authorization(_)
        | ConnectorError::InvalidRequest(_)
        | ConnectorError::ContentFiltered(_)
        | ConnectorError::Cancelled(_) => false,
    }
}

/// Abstracts the passage of time so backoff can be tested without real sleeps.
#[async_trait::async_trait]
pub trait Clock: Send + Sync {
    async fn sleep(&self, dur: Duration);
}

/// Production clock backed by `tokio::time::sleep`.
#[derive(Debug, Default, Clone)]
pub struct TokioClock;

#[async_trait::async_trait]
impl Clock for TokioClock {
    async fn sleep(&self, dur: Duration) {
        tokio::time::sleep(dur).await;
    }
}

/// Configuration for retry-with-backoff behavior on the send path.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts *per provider* (must be >= 1).
    pub max_attempts: u32,
    /// Base backoff applied before the first retry; doubles each attempt.
    pub base_backoff: Duration,
    /// Upper bound on any single backoff delay.
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl RetryPolicy {
    /// Backoff delay before the retry following `attempt` (the 0-indexed
    /// attempt that just failed): `2^attempt * base`, clamped to `max_backoff`.
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        // Saturating shift so a large attempt count cannot overflow.
        let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let millis = (self.base_backoff.as_millis() as u64).saturating_mul(factor);
        Duration::from_millis(millis).min(self.max_backoff)
    }
}

/// Type of LLM provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderType {
    Cloud,
    Local,
}

/// Provider features that have an adapter implementation and qualification
/// evidence. Defaults are deliberately conservative for third-party adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub native_streaming: bool,
    pub tool_calls: bool,
    pub parallel_tool_calls: bool,
    pub vision: bool,
    pub audio: bool,
    pub prompt_cancellation: bool,
    pub model_discovery: bool,
    /// Operator-facing API family/version such as `openai-v1`.
    pub api_family: String,
    /// Regions in which the adapter guarantees processing. Empty means no
    /// data-residency guarantee is being made.
    pub data_regions: Vec<String>,
}

impl Default for ProviderCapabilities {
    fn default() -> Self {
        Self {
            native_streaming: false,
            tool_calls: false,
            parallel_tool_calls: false,
            vision: false,
            audio: false,
            prompt_cancellation: false,
            model_discovery: false,
            api_family: "custom".into(),
            data_regions: Vec::new(),
        }
    }
}

/// Fail-closed routing controls for provider failover.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRoutingPolicy {
    /// Required processing region. A provider with no region declaration is
    /// incompatible when this is set.
    pub required_region: Option<String>,
    /// Local prompts do not fail over to cloud providers unless explicitly
    /// allowed by an operator.
    pub allow_local_to_cloud: bool,
}

/// Information about a registered provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub id: ProviderId,
    pub name: String,
    pub provider_type: ProviderType,
    pub available: bool,
    #[serde(default)]
    pub circuit_open: bool,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub capabilities: ProviderCapabilities,
    #[serde(default)]
    pub routing_policy: ProviderRoutingPolicy,
}

/// A standard message format for LLM communication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandardMessage {
    pub role: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

impl StandardMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".into(),
            content: content.into(),
            tool_call_id: None,
            tool_calls: None,
        }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".into(),
            content: content.into(),
            tool_call_id: None,
            tool_calls: None,
        }
    }
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".into(),
            content: content.into(),
            tool_call_id: None,
            tool_calls: None,
        }
    }
    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: "tool".into(),
            content: content.into(),
            tool_call_id: Some(tool_call_id.into()),
            tool_calls: None,
        }
    }
}

/// A tool call requested by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// A tool definition provided to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Response from an LLM provider.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmUsage {
    /// Provider-reported prompt/input tokens.
    pub input_tokens: u32,
    /// Provider-reported completion/output tokens.
    pub output_tokens: u32,
    /// Cached input tokens (a subset of input tokens when the provider reports it).
    pub cached_tokens: u32,
    /// True only when the provider response supplied usage fields.
    pub provider_reported: bool,
}

impl LlmUsage {
    pub fn reported(input_tokens: u32, output_tokens: u32, cached_tokens: u32) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cached_tokens: cached_tokens.min(input_tokens),
            provider_reported: true,
        }
    }

    pub fn total(self) -> u32 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub finish_reason: Option<String>,
    pub tokens_used: u32,
    /// Detailed provider usage. Older/custom adapters may leave this at the
    /// default; the executor records that the conservative fallback was used.
    #[serde(default)]
    pub usage: LlmUsage,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
}

/// Provider-originated deltas forwarded to the executor's bounded stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStreamEvent {
    TextDelta(String),
}

/// Cloneable bounded event sink that records whether output became visible.
///
/// The visibility bit lets retry/failover fail closed after a partial stream:
/// once a delta reached the caller, replaying the request could duplicate
/// content or side effects.
#[derive(Clone)]
pub struct ProviderEventSink {
    sender: tokio::sync::mpsc::Sender<ProviderStreamEvent>,
    emitted: Arc<std::sync::atomic::AtomicBool>,
}

impl ProviderEventSink {
    pub fn new(sender: tokio::sync::mpsc::Sender<ProviderStreamEvent>) -> Self {
        Self {
            sender,
            emitted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub async fn emit(&self, event: ProviderStreamEvent) {
        if self.sender.send(event).await.is_ok() {
            self.emitted
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    pub fn has_emitted(&self) -> bool {
        self.emitted.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Per-call generation bounds supplied by the kernel.
///
/// This is deliberately separate from provider configuration: the execution
/// path can reduce an output allowance for an individual admitted request
/// without rebuilding the provider session. Custom adapters remain
/// source-compatible because [`LlmSession::send_with_options`] has a default
/// implementation, but adapters that need a hard output bound must override
/// that method and translate `max_output_tokens` to their provider's wire
/// format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LlmRequestOptions {
    /// Maximum number of new/completion tokens the provider may generate.
    /// `None` preserves the adapter's configured default.
    pub max_output_tokens: Option<u32>,
    /// Per-attempt wall-clock timeout. This remains effective across resilient
    /// retry and failover because it is forwarded to every fresh session.
    pub timeout: Option<Duration>,
}

/// An LLM session for an agent.
#[async_trait::async_trait]
pub trait LlmSession: Send + Sync {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError>;
    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError>;

    /// Send with kernel-supplied per-call generation bounds.
    ///
    /// The default preserves compatibility for external adapters. Production
    /// adapters should override this method before callers rely on a hard
    /// output-token ceiling.
    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        _options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, tools).await
    }

    /// Cancellation-aware non-streaming send. Hosted adapters inherit
    /// cancellation by dropping their request future. Local inference adapters
    /// should override this and observe the token inside their decode loop.
    async fn send_controlled(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<LlmResponse, ConnectorError> {
        let provider_id = self.provider_id().clone();
        let send = self.send_with_options(messages, tools, options);
        tokio::pin!(send);
        match options.timeout {
            Some(timeout) => {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        Err(ConnectorError::cancelled(provider_id, None))
                    }
                    result = tokio::time::timeout(timeout, &mut send) => {
                        result.unwrap_or_else(|_| {
                            Err(ConnectorError::timeout(
                                provider_id,
                                format!("attempt exceeded {} ms", timeout.as_millis()),
                                None,
                            ))
                        })
                    }
                }
            }
            None => {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        Err(ConnectorError::cancelled(provider_id, None))
                    }
                    result = &mut send => result,
                }
            }
        }
    }

    /// Whether this session translates and enforces
    /// [`LlmRequestOptions::max_output_tokens`].
    ///
    /// The compatibility default is intentionally `false`: a kernel configured
    /// with a hard per-request output ceiling can fail closed instead of
    /// silently relying on an external adapter that ignores the option.
    fn enforces_max_output_tokens(&self) -> bool {
        false
    }

    fn provider_id(&self) -> &ProviderId;

    /// Concrete model/deployment used by this session. Adapters should
    /// override this whenever the provider exposes a stable model identifier;
    /// the fallback is explicit so accounting never invents a model name.
    fn model_id(&self) -> &str {
        "unspecified"
    }

    /// Provider/model-aware token estimate for an already-standardized prompt.
    /// Adapters with a real tokenizer should override this. `None` selects the
    /// runtime's documented conservative UTF-8 byte fallback.
    fn estimate_prompt_tokens(&self, _messages: &[StandardMessage]) -> Option<u32> {
        None
    }

    /// Actual provider and model that served the latest successful call.
    fn last_attribution(&self) -> Option<(ProviderId, String)> {
        None
    }

    /// Number of provider attempts used by the latest successful call.
    fn last_attempts(&self) -> Option<u32> {
        None
    }

    /// Whether retry and failover are already managed inside this session.
    fn handles_retries(&self) -> bool {
        false
    }

    /// Worst-case number of provider attempts one logical send can start.
    fn max_provider_attempts(&self) -> u32 {
        1
    }

    /// Send with streaming support. Default falls back to non-streaming.
    async fn send_streaming(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, tools).await
    }

    /// Streaming counterpart to [`LlmSession::send_with_options`].
    ///
    /// Non-streaming adapters inherit the bounded send implementation. A
    /// streaming adapter must override this when its streaming wire request is
    /// built independently.
    async fn send_streaming_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_options(messages, tools, options).await
    }

    /// Cancellation-aware streaming counterpart.
    async fn send_streaming_controlled(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<LlmResponse, ConnectorError> {
        let provider_id = self.provider_id().clone();
        let send = self.send_streaming_with_options(messages, tools, options);
        tokio::pin!(send);
        match options.timeout {
            Some(timeout) => {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        Err(ConnectorError::cancelled(provider_id, None))
                    }
                    result = tokio::time::timeout(timeout, &mut send) => {
                        result.unwrap_or_else(|_| {
                            Err(ConnectorError::timeout(
                                provider_id,
                                format!("attempt exceeded {} ms", timeout.as_millis()),
                                None,
                            ))
                        })
                    }
                }
            }
            None => {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        Err(ConnectorError::cancelled(provider_id, None))
                    }
                    result = &mut send => result,
                }
            }
        }
    }

    /// Cancellation-aware streaming with a bounded delta sink.
    ///
    /// The compatibility default emits the completed response as one text
    /// delta. Native streaming adapters override this to publish finer-grained
    /// deltas while retaining the same terminal [`LlmResponse`].
    async fn send_streaming_events_controlled(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: ProviderEventSink,
    ) -> Result<LlmResponse, ConnectorError> {
        let response = self
            .send_streaming_controlled(messages, tools, options, cancellation)
            .await?;
        if !response.content.is_empty() {
            events
                .emit(ProviderStreamEvent::TextDelta(response.content.clone()))
                .await;
        }
        Ok(response)
    }
}

/// An LLM provider adapter.
#[async_trait::async_trait]
pub trait LlmProviderAdapter: Send + Sync {
    fn id(&self) -> &ProviderId;
    fn name(&self) -> &str;
    fn provider_type(&self) -> ProviderType;
    async fn is_available(&self) -> bool;
    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError>;
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }
    /// Translate standard messages to provider format and back (for testing round-trip).
    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value;
    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage>;
}

/// The Agent Connector trait.
#[async_trait::async_trait]
pub trait AgentConnector: Send + Sync {
    fn register_provider(&self, adapter: Arc<dyn LlmProviderAdapter>)
        -> Result<(), ConnectorError>;
    async fn connect(
        &self,
        agent_id: AgentId,
        provider_id: &ProviderId,
    ) -> Result<Box<dyn LlmSession>, ConnectorError>;
    fn list_providers(&self) -> Vec<ProviderInfo>;
}

/// Outcome of a resilient send: the response plus which provider served it.
#[derive(Debug, Clone)]
pub struct SendOutcome {
    pub response: LlmResponse,
    /// The provider that ultimately produced the response (may be a backup).
    pub served_by: ProviderId,
    /// Concrete provider model/deployment that produced the response.
    pub model_id: String,
    /// Total number of attempts made across all providers tried.
    pub attempts: u32,
}

/// Whether a send should use the streaming or non-streaming session method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMode {
    NonStreaming,
    Streaming,
}

struct ProviderSend<'a> {
    messages: &'a [StandardMessage],
    tools: &'a [ToolDefinition],
    mode: SendMode,
    options: LlmRequestOptions,
    cancellation: &'a tokio_util::sync::CancellationToken,
    events: Option<tokio::sync::mpsc::Sender<ProviderStreamEvent>>,
}

struct FailoverControls<'a> {
    mode: SendMode,
    options: LlmRequestOptions,
    cancellation: &'a tokio_util::sync::CancellationToken,
    observed_attempts: Option<&'a std::sync::atomic::AtomicU32>,
    max_attempts_per_provider: Option<u32>,
    events: Option<tokio::sync::mpsc::Sender<ProviderStreamEvent>>,
}

struct ProviderAttemptOutcome {
    response: LlmResponse,
    model_id: String,
}

/// Concrete agent connector implementation.
pub struct AgentConnectorImpl {
    providers: DashMap<ProviderId, Arc<dyn LlmProviderAdapter>>,
    /// Optional backup provider for failover.
    backup_provider: DashMap<ProviderId, ProviderId>,
    /// Active sessions per agent.
    sessions: DashMap<AgentId, ProviderId>,
    /// Retry/backoff policy applied per provider on the send path.
    retry_policy: RetryPolicy,
    /// Clock used for backoff sleeps (injectable for deterministic tests).
    clock: Arc<dyn Clock>,
    /// Per-provider failure isolation.
    circuit_breakers: DashMap<ProviderId, Arc<crate::production::CircuitBreaker>>,
    /// Fail-closed residency and local/cloud routing rules, keyed by primary.
    routing_policies: DashMap<ProviderId, ProviderRoutingPolicy>,
}

impl Default for AgentConnectorImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentConnectorImpl {
    pub fn new() -> Self {
        Self {
            providers: DashMap::new(),
            backup_provider: DashMap::new(),
            sessions: DashMap::new(),
            retry_policy: RetryPolicy::default(),
            clock: Arc::new(TokioClock),
            circuit_breakers: DashMap::new(),
            routing_policies: DashMap::new(),
        }
    }

    /// Override the retry/backoff policy (builder-style).
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Probe each registered adapter at snapshot time. Unlike
    /// `list_providers`, this reports actual async health instead of assuming a
    /// registered provider is reachable.
    pub async fn probe_providers(&self) -> Vec<ProviderInfo> {
        let providers: Vec<_> = self
            .providers
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        let mut health = Vec::with_capacity(providers.len());
        for provider in providers {
            health.push(ProviderInfo {
                id: provider.id().clone(),
                name: provider.name().to_string(),
                provider_type: provider.provider_type(),
                available: provider.is_available().await,
                circuit_open: self
                    .circuit_breakers
                    .get(provider.id())
                    .is_some_and(|breaker| !breaker.status().0),
                consecutive_failures: self
                    .circuit_breakers
                    .get(provider.id())
                    .map(|breaker| breaker.status().1)
                    .unwrap_or(0),
                capabilities: provider.capabilities(),
                routing_policy: self.routing_policy(provider.id()),
            });
        }
        health.sort_by(|a, b| a.id.cmp(&b.id));
        health
    }

    /// Inject a custom clock (used by tests to avoid real sleeps).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Set a backup provider for failover.
    pub fn set_backup(&self, primary: &ProviderId, backup: &ProviderId) {
        self.backup_provider.insert(primary.clone(), backup.clone());
    }

    pub fn set_routing_policy(&self, provider: &ProviderId, policy: ProviderRoutingPolicy) {
        self.routing_policies.insert(provider.clone(), policy);
    }

    fn routing_policy(&self, provider: &ProviderId) -> ProviderRoutingPolicy {
        self.routing_policies
            .get(provider)
            .map(|policy| policy.value().clone())
            .unwrap_or_default()
    }

    fn provider_is_compatible(
        &self,
        primary_type: &ProviderType,
        candidate: &dyn LlmProviderAdapter,
        tools: &[ToolDefinition],
        policy: &ProviderRoutingPolicy,
        is_primary: bool,
    ) -> bool {
        let capabilities = candidate.capabilities();
        // An explicitly selected primary may be a third-party adapter written
        // before capability declarations were added. Compatibility is a
        // failover boundary: conservative defaults must prevent a prompt from
        // reaching an incompatible *backup* without breaking the chosen
        // primary's existing contract.
        if !is_primary && !tools.is_empty() && !capabilities.tool_calls {
            return false;
        }
        if !is_primary
            && *primary_type == ProviderType::Local
            && candidate.provider_type() == ProviderType::Cloud
            && !policy.allow_local_to_cloud
        {
            return false;
        }
        if let Some(required_region) = &policy.required_region {
            return capabilities
                .data_regions
                .iter()
                .any(|region| region.eq_ignore_ascii_case(required_region));
        }
        true
    }

    /// Resolve the ordered failover chain starting at `primary`: the primary
    /// itself followed by its backup, the backup's backup, and so on. Stops at
    /// the first cycle or unregistered link so the chain is always finite.
    fn failover_chain(&self, primary: &ProviderId) -> Vec<ProviderId> {
        let mut chain = vec![primary.clone()];
        let mut current = primary.clone();
        // Bounded by the number of registered providers to guard against cycles.
        let max_len = self.providers.len().saturating_add(1);
        while chain.len() < max_len {
            match self.backup_provider.get(&current) {
                Some(next) => {
                    let next_id = next.value().clone();
                    if chain.contains(&next_id) {
                        break;
                    }
                    chain.push(next_id.clone());
                    current = next_id;
                }
                None => break,
            }
        }
        chain
    }

    /// Send a request resiliently: retry-with-backoff against the primary, then
    /// fail over down the backup chain. Transient errors are retried; permanent
    /// (protocol/auth) errors short-circuit retry for that provider but still
    /// permit failover to the next provider.
    ///
    /// `mode` selects the streaming vs non-streaming session method; both honor
    /// the same retry/failover semantics.
    pub async fn send_with_failover(
        &self,
        primary: &ProviderId,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        mode: SendMode,
    ) -> Result<SendOutcome, ConnectorError> {
        let cancellation = tokio_util::sync::CancellationToken::new();
        self.send_with_failover_controlled(
            primary,
            messages,
            tools,
            mode,
            LlmRequestOptions::default(),
            &cancellation,
        )
        .await
    }

    /// Cancellation- and output-bound-aware resilient send used by production
    /// executors. Every retry and failover attempt receives the same controls.
    pub async fn send_with_failover_controlled(
        &self,
        primary: &ProviderId,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        mode: SendMode,
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<SendOutcome, ConnectorError> {
        self.send_with_failover_observed(
            primary,
            messages,
            tools,
            FailoverControls {
                mode,
                options,
                cancellation,
                observed_attempts: None,
                max_attempts_per_provider: None,
                events: None,
            },
        )
        .await
    }

    async fn send_with_failover_observed(
        &self,
        primary: &ProviderId,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        controls: FailoverControls<'_>,
    ) -> Result<SendOutcome, ConnectorError> {
        if let Some(attempts) = controls.observed_attempts {
            attempts.store(0, std::sync::atomic::Ordering::Release);
        }
        let chain = self.failover_chain(primary);
        let mut total_attempts: u32 = 0;
        let mut last_err: Option<ConnectorError> = None;
        let routing_policy = self.routing_policy(primary);
        let primary_type = self
            .providers
            .get(primary)
            .map(|provider| provider.provider_type())
            .unwrap_or(ProviderType::Cloud);

        for (provider_index, provider_id) in chain.into_iter().enumerate() {
            let adapter = match self.providers.get(&provider_id) {
                Some(a) => a.value().clone(),
                None => {
                    last_err = Some(ConnectorError::ProviderUnavailable(provider_id.clone()));
                    continue;
                }
            };
            if !self.provider_is_compatible(
                &primary_type,
                adapter.as_ref(),
                tools,
                &routing_policy,
                provider_index == 0,
            ) {
                last_err = Some(ConnectorError::ProviderUnavailable(format!(
                    "{provider_id} is incompatible with the request routing policy"
                )));
                continue;
            }
            let breaker = self
                .circuit_breakers
                .get(&provider_id)
                .map(|breaker| Arc::clone(breaker.value()));
            if breaker
                .as_ref()
                .is_some_and(|breaker| !breaker.is_available())
            {
                last_err = Some(ConnectorError::ProviderUnavailable(format!(
                    "{provider_id} circuit is open"
                )));
                continue;
            }

            match self
                .send_one_provider(
                    &adapter,
                    ProviderSend {
                        messages: &messages,
                        tools,
                        mode: controls.mode,
                        options: controls.options,
                        cancellation: controls.cancellation,
                        events: controls.events.clone(),
                    },
                    &mut total_attempts,
                    controls.observed_attempts,
                    controls.max_attempts_per_provider,
                )
                .await
            {
                Ok(outcome) => {
                    if let Some(breaker) = &breaker {
                        breaker.record_success();
                    }
                    return Ok(SendOutcome {
                        response: outcome.response,
                        served_by: provider_id,
                        model_id: outcome.model_id,
                        attempts: total_attempts,
                    });
                }
                Err(error) => {
                    if matches!(
                        error,
                        ConnectorError::Cancelled(_)
                            | ConnectorError::ContentFiltered(_)
                            | ConnectorError::PartialStream(_)
                    ) {
                        return Err(error);
                    }
                    if is_transient(&error) {
                        if let Some(breaker) = &breaker {
                            breaker.record_failure();
                        }
                    }
                    last_err = Some(error);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| ConnectorError::ProviderUnavailable(primary.clone()))
            .clone())
    }

    /// Drive retry-with-backoff against a single provider. Returns the first
    /// success, or the last error once attempts are exhausted / a permanent
    /// error is hit.
    async fn send_one_provider(
        &self,
        adapter: &Arc<dyn LlmProviderAdapter>,
        request: ProviderSend<'_>,
        total_attempts: &mut u32,
        observed_attempts: Option<&std::sync::atomic::AtomicU32>,
        max_attempts_per_provider: Option<u32>,
    ) -> Result<ProviderAttemptOutcome, ConnectorError> {
        let max_attempts = max_attempts_per_provider
            .unwrap_or(self.retry_policy.max_attempts)
            .max(1);
        let mut last_err: Option<ConnectorError> = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                tokio::select! {
                    biased;
                    _ = request.cancellation.cancelled() => {
                        return Err(ConnectorError::cancelled(adapter.id().clone(), None));
                    }
                    _ = self.clock.sleep(self.retry_policy.backoff_for(attempt - 1)) => {}
                }
            }
            *total_attempts = total_attempts.saturating_add(1);
            if let Some(observed) = observed_attempts {
                observed.store(*total_attempts, std::sync::atomic::Ordering::Release);
            }

            // A fresh session per attempt so a torn-down connection is rebuilt.
            let session = match adapter.create_session().await {
                Ok(s) => s,
                Err(e) => {
                    let transient = is_transient(&e);
                    last_err = Some(e);
                    if !transient {
                        break;
                    }
                    continue;
                }
            };
            if request.options.max_output_tokens.is_some() && !session.enforces_max_output_tokens()
            {
                return Err(ConnectorError::invalid_request(
                    adapter.id().clone(),
                    "adapter does not enforce max_output_tokens",
                    None,
                ));
            }
            let model_id = session.model_id().to_string();

            let result = match request.mode {
                SendMode::NonStreaming => {
                    session
                        .send_controlled(
                            request.messages.to_vec(),
                            request.tools,
                            request.options,
                            request.cancellation,
                        )
                        .await
                }
                SendMode::Streaming => {
                    if let Some(events) = request.events.as_ref() {
                        let sink = ProviderEventSink::new(events.clone());
                        let result = session
                            .send_streaming_events_controlled(
                                request.messages.to_vec(),
                                request.tools,
                                request.options,
                                request.cancellation,
                                sink.clone(),
                            )
                            .await;
                        if result.is_err()
                            && sink.has_emitted()
                            && !matches!(result, Err(ConnectorError::Cancelled(_)))
                        {
                            return Err(ConnectorError::PartialStream(
                                "provider failed after publishing output; retry and failover were suppressed"
                                    .into(),
                            ));
                        }
                        result
                    } else {
                        session
                            .send_streaming_controlled(
                                request.messages.to_vec(),
                                request.tools,
                                request.options,
                                request.cancellation,
                            )
                            .await
                    }
                }
            };

            match result {
                Ok(response) => return Ok(ProviderAttemptOutcome { response, model_id }),
                Err(e) => {
                    if matches!(
                        e,
                        ConnectorError::Cancelled(_) | ConnectorError::ContentFiltered(_)
                    ) {
                        return Err(e);
                    }
                    let transient = is_transient(&e);
                    last_err = Some(e);
                    // Permanent errors won't improve with retry on this provider.
                    if !transient {
                        break;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            ConnectorError::ConnectionFailed("no attempts produced a result".into())
        }))
    }

    /// Create a session that keeps retry and failover load-bearing after the
    /// executor has been constructed.
    pub async fn connect_resilient(
        self: &Arc<Self>,
        agent_id: AgentId,
        provider_id: &ProviderId,
    ) -> Result<Box<dyn LlmSession>, ConnectorError> {
        let provider = self
            .providers
            .get(provider_id)
            .map(|provider| Arc::clone(provider.value()))
            .ok_or_else(|| ConnectorError::ProviderUnavailable(provider_id.clone()))?;
        let configured_model = provider.create_session().await?.model_id().to_string();
        self.sessions.insert(agent_id, provider_id.clone());
        Ok(Box::new(ResilientSession {
            connector: Arc::clone(self),
            primary: provider_id.clone(),
            configured_model: configured_model.clone(),
            last_attribution: RwLock::new((provider_id.clone(), configured_model)),
            last_attempts: std::sync::atomic::AtomicU32::new(0),
        }))
    }
}

struct ResilientSession {
    connector: Arc<AgentConnectorImpl>,
    primary: ProviderId,
    configured_model: String,
    last_attribution: RwLock<(ProviderId, String)>,
    last_attempts: std::sync::atomic::AtomicU32,
}

#[async_trait::async_trait]
impl LlmSession for ResilientSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_options(messages, tools, LlmRequestOptions::default())
            .await
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        let cancellation = tokio_util::sync::CancellationToken::new();
        self.send_controlled(messages, tools, options, &cancellation)
            .await
    }

    async fn send_controlled(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<LlmResponse, ConnectorError> {
        let outcome = self
            .connector
            .send_with_failover_observed(
                &self.primary,
                messages,
                tools,
                FailoverControls {
                    mode: SendMode::NonStreaming,
                    options,
                    cancellation,
                    observed_attempts: Some(&self.last_attempts),
                    max_attempts_per_provider: Some(1),
                    events: None,
                },
            )
            .await?;
        self.last_attempts
            .store(outcome.attempts, std::sync::atomic::Ordering::Release);
        *self
            .last_attribution
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            (outcome.served_by, outcome.model_id);
        Ok(outcome.response)
    }

    async fn send_streaming_events_controlled(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: ProviderEventSink,
    ) -> Result<LlmResponse, ConnectorError> {
        let outcome = self
            .connector
            .send_with_failover_observed(
                &self.primary,
                messages,
                tools,
                FailoverControls {
                    mode: SendMode::Streaming,
                    options,
                    cancellation,
                    observed_attempts: Some(&self.last_attempts),
                    max_attempts_per_provider: Some(1),
                    events: Some(events.sender.clone()),
                },
            )
            .await?;
        self.last_attempts
            .store(outcome.attempts, std::sync::atomic::Ordering::Release);
        *self
            .last_attribution
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            (outcome.served_by, outcome.model_id);
        Ok(outcome.response)
    }

    async fn send_streaming(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        let cancellation = tokio_util::sync::CancellationToken::new();
        self.send_streaming_controlled(messages, tools, LlmRequestOptions::default(), &cancellation)
            .await
    }

    async fn send_streaming_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        let cancellation = tokio_util::sync::CancellationToken::new();
        self.send_streaming_controlled(messages, tools, options, &cancellation)
            .await
    }

    async fn send_streaming_controlled(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<LlmResponse, ConnectorError> {
        let outcome = self
            .connector
            .send_with_failover_observed(
                &self.primary,
                messages,
                tools,
                FailoverControls {
                    mode: SendMode::Streaming,
                    options,
                    cancellation,
                    observed_attempts: Some(&self.last_attempts),
                    max_attempts_per_provider: Some(1),
                    events: None,
                },
            )
            .await?;
        self.last_attempts
            .store(outcome.attempts, std::sync::atomic::Ordering::Release);
        *self
            .last_attribution
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            (outcome.served_by, outcome.model_id);
        Ok(outcome.response)
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }

    fn provider_id(&self) -> &ProviderId {
        &self.primary
    }

    fn model_id(&self) -> &str {
        &self.configured_model
    }

    fn last_attribution(&self) -> Option<(ProviderId, String)> {
        Some(
            self.last_attribution
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
    }

    fn last_attempts(&self) -> Option<u32> {
        Some(
            self.last_attempts
                .load(std::sync::atomic::Ordering::Acquire),
        )
    }

    fn handles_retries(&self) -> bool {
        false
    }

    fn max_provider_attempts(&self) -> u32 {
        u32::try_from(self.connector.failover_chain(&self.primary).len())
            .unwrap_or(u32::MAX)
            .max(1)
    }
}

#[async_trait::async_trait]
impl AgentConnector for AgentConnectorImpl {
    fn register_provider(
        &self,
        adapter: Arc<dyn LlmProviderAdapter>,
    ) -> Result<(), ConnectorError> {
        let id = adapter.id().clone();
        self.providers.insert(id.clone(), adapter);
        self.circuit_breakers
            .insert(id, Arc::new(crate::production::CircuitBreaker::new(3, 30)));
        Ok(())
    }

    async fn connect(
        &self,
        agent_id: AgentId,
        provider_id: &ProviderId,
    ) -> Result<Box<dyn LlmSession>, ConnectorError> {
        let provider = self
            .providers
            .get(provider_id)
            .ok_or_else(|| ConnectorError::ProviderUnavailable(provider_id.clone()))?;

        // Check availability
        if !provider.is_available().await {
            // Try failover
            if let Some(backup_id) = self.backup_provider.get(provider_id) {
                if let Some(backup) = self.providers.get(backup_id.value()) {
                    if backup.is_available().await {
                        let session = backup.create_session().await?;
                        self.sessions.insert(agent_id, backup_id.value().clone());
                        return Ok(session);
                    }
                }
            }
            return Err(ConnectorError::ProviderUnavailable(format!(
                "{} is unavailable and no backup available",
                provider_id
            )));
        }

        let session = provider.create_session().await?;
        self.sessions.insert(agent_id, provider_id.clone());
        Ok(session)
    }

    fn list_providers(&self) -> Vec<ProviderInfo> {
        self.providers
            .iter()
            .map(|entry| {
                let adapter = entry.value();
                ProviderInfo {
                    id: adapter.id().clone(),
                    name: adapter.name().to_string(),
                    provider_type: adapter.provider_type(),
                    available: self
                        .circuit_breakers
                        .get(adapter.id())
                        .is_none_or(|breaker| breaker.status().0),
                    circuit_open: self
                        .circuit_breakers
                        .get(adapter.id())
                        .is_some_and(|breaker| !breaker.status().0),
                    consecutive_failures: self
                        .circuit_breakers
                        .get(adapter.id())
                        .map(|breaker| breaker.status().1)
                        .unwrap_or(0),
                    capabilities: adapter.capabilities(),
                    routing_policy: self.routing_policy(adapter.id()),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAdapter {
        id: ProviderId,
        available: bool,
    }

    struct MockSession {
        provider_id: ProviderId,
    }

    #[async_trait::async_trait]
    impl LlmSession for MockSession {
        async fn send(
            &self,
            _messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            Ok(LlmResponse {
                content: "response".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 10,
                usage: Default::default(),
                tool_calls: vec![],
            })
        }
        async fn send_with_tools(
            &self,
            messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            self.send(messages).await
        }
        fn provider_id(&self) -> &ProviderId {
            &self.provider_id
        }
    }

    #[async_trait::async_trait]
    impl LlmProviderAdapter for MockAdapter {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn name(&self) -> &str {
            "Mock"
        }
        fn provider_type(&self) -> ProviderType {
            ProviderType::Cloud
        }
        async fn is_available(&self) -> bool {
            self.available
        }
        async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
            Ok(Box::new(MockSession {
                provider_id: self.id.clone(),
            }))
        }
        fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
            serde_json::json!({"role": msg.role, "content": msg.content})
        }
        fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
            Some(StandardMessage::user(
                value.get("content")?.as_str()?.to_string(),
            ))
        }
    }

    /// No-op clock so backoff tests run instantly and deterministically.
    struct NoopClock;
    #[async_trait::async_trait]
    impl Clock for NoopClock {
        async fn sleep(&self, _dur: Duration) {}
    }

    /// Adapter whose session fails a configurable number of times before
    /// succeeding, with a configurable error kind. Counts attempts so tests can
    /// assert retry/no-retry behavior precisely.
    struct ScriptedAdapter {
        id: ProviderId,
        available: bool,
        /// Number of leading attempts that fail (per fresh session, the failure
        /// is decided by the shared counter).
        fail_count: u32,
        /// Whether the failure is transient (retryable) or permanent.
        transient: bool,
        attempts: Arc<std::sync::atomic::AtomicU32>,
    }

    struct ScriptedSession {
        provider_id: ProviderId,
        fail_count: u32,
        transient: bool,
        attempts: Arc<std::sync::atomic::AtomicU32>,
    }

    #[async_trait::async_trait]
    impl LlmSession for ScriptedSession {
        async fn send(
            &self,
            _messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            let n = self
                .attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < self.fail_count {
                if self.transient {
                    Err(ConnectorError::ConnectionFailed(format!("transient #{n}")))
                } else {
                    Err(ConnectorError::ProtocolError(format!("permanent #{n}")))
                }
            } else {
                Ok(LlmResponse {
                    content: format!("ok from {}", self.provider_id),
                    finish_reason: Some("stop".into()),
                    tokens_used: 7,
                    usage: Default::default(),
                    tool_calls: vec![],
                })
            }
        }
        async fn send_with_tools(
            &self,
            messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            self.send(messages).await
        }
        fn provider_id(&self) -> &ProviderId {
            &self.provider_id
        }
    }

    struct PartialStreamAdapter {
        id: ProviderId,
        fail_after_delta: bool,
        attempts: Arc<std::sync::atomic::AtomicU32>,
    }

    struct PartialStreamSession {
        provider_id: ProviderId,
        fail_after_delta: bool,
        attempts: Arc<std::sync::atomic::AtomicU32>,
    }

    #[async_trait::async_trait]
    impl LlmSession for PartialStreamSession {
        async fn send(
            &self,
            _messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(LlmResponse {
                content: "complete".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 1,
                usage: LlmUsage::reported(1, 1, 0),
                tool_calls: vec![],
            })
        }

        async fn send_with_tools(
            &self,
            messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            self.send(messages).await
        }

        async fn send_streaming_events_controlled(
            &self,
            _messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
            _options: LlmRequestOptions,
            _cancellation: &tokio_util::sync::CancellationToken,
            events: ProviderEventSink,
        ) -> Result<LlmResponse, ConnectorError> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            events
                .emit(ProviderStreamEvent::TextDelta("partial".into()))
                .await;
            if self.fail_after_delta {
                Err(ConnectorError::StreamError(
                    "transport failed after a visible delta".into(),
                ))
            } else {
                Ok(LlmResponse {
                    content: "complete".into(),
                    finish_reason: Some("stop".into()),
                    tokens_used: 1,
                    usage: LlmUsage::reported(1, 1, 0),
                    tool_calls: vec![],
                })
            }
        }

        fn enforces_max_output_tokens(&self) -> bool {
            true
        }

        fn provider_id(&self) -> &ProviderId {
            &self.provider_id
        }
    }

    #[async_trait::async_trait]
    impl LlmProviderAdapter for PartialStreamAdapter {
        fn id(&self) -> &ProviderId {
            &self.id
        }

        fn name(&self) -> &str {
            "partial stream"
        }

        fn provider_type(&self) -> ProviderType {
            ProviderType::Cloud
        }

        async fn is_available(&self) -> bool {
            true
        }

        async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
            Ok(Box::new(PartialStreamSession {
                provider_id: self.id.clone(),
                fail_after_delta: self.fail_after_delta,
                attempts: Arc::clone(&self.attempts),
            }))
        }

        fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
            serde_json::json!({"role": message.role, "content": message.content})
        }

        fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
            Some(StandardMessage::assistant(value.get("content")?.as_str()?))
        }
    }

    struct QualificationAdapter {
        id: ProviderId,
        provider_type: ProviderType,
        capabilities: ProviderCapabilities,
        model_id: String,
        error: Option<ConnectorError>,
        block: bool,
        attempts: Arc<std::sync::atomic::AtomicU32>,
    }

    struct QualificationSession {
        provider_id: ProviderId,
        model_id: String,
        error: Option<ConnectorError>,
        block: bool,
        attempts: Arc<std::sync::atomic::AtomicU32>,
    }

    #[async_trait::async_trait]
    impl LlmSession for QualificationSession {
        async fn send(
            &self,
            _messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.block {
                std::future::pending::<()>().await;
            }
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            Ok(LlmResponse {
                content: format!("ok from {}", self.provider_id),
                finish_reason: Some("stop".into()),
                tokens_used: 7,
                usage: LlmUsage::reported(5, 2, 0),
                tool_calls: vec![],
            })
        }

        async fn send_with_tools(
            &self,
            messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            self.send(messages).await
        }

        fn enforces_max_output_tokens(&self) -> bool {
            true
        }

        fn provider_id(&self) -> &ProviderId {
            &self.provider_id
        }

        fn model_id(&self) -> &str {
            &self.model_id
        }
    }

    #[async_trait::async_trait]
    impl LlmProviderAdapter for QualificationAdapter {
        fn id(&self) -> &ProviderId {
            &self.id
        }

        fn name(&self) -> &str {
            "Qualification"
        }

        fn provider_type(&self) -> ProviderType {
            self.provider_type.clone()
        }

        async fn is_available(&self) -> bool {
            true
        }

        async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
            Ok(Box::new(QualificationSession {
                provider_id: self.id.clone(),
                model_id: self.model_id.clone(),
                error: self.error.clone(),
                block: self.block,
                attempts: Arc::clone(&self.attempts),
            }))
        }

        fn capabilities(&self) -> ProviderCapabilities {
            self.capabilities.clone()
        }

        fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
            serde_json::json!({"role": msg.role, "content": msg.content})
        }

        fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
            Some(StandardMessage::user(value.get("content")?.as_str()?))
        }
    }

    fn qualification_adapter(
        id: &str,
        provider_type: ProviderType,
        model_id: &str,
        error: Option<ConnectorError>,
        attempts: Arc<std::sync::atomic::AtomicU32>,
    ) -> QualificationAdapter {
        QualificationAdapter {
            id: id.into(),
            provider_type,
            capabilities: ProviderCapabilities {
                tool_calls: true,
                prompt_cancellation: true,
                ..ProviderCapabilities::default()
            },
            model_id: model_id.into(),
            error,
            block: false,
            attempts,
        }
    }

    #[async_trait::async_trait]
    impl LlmProviderAdapter for ScriptedAdapter {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn name(&self) -> &str {
            "Scripted"
        }
        fn provider_type(&self) -> ProviderType {
            ProviderType::Cloud
        }
        async fn is_available(&self) -> bool {
            self.available
        }
        async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
            if !self.available {
                return Err(ConnectorError::ProviderUnavailable(self.id.clone()));
            }
            Ok(Box::new(ScriptedSession {
                provider_id: self.id.clone(),
                fail_count: self.fail_count,
                transient: self.transient,
                attempts: self.attempts.clone(),
            }))
        }
        fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
            serde_json::json!({"role": msg.role, "content": msg.content})
        }
        fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
            Some(StandardMessage::user(
                value.get("content")?.as_str()?.to_string(),
            ))
        }
    }

    fn fast_connector() -> AgentConnectorImpl {
        AgentConnectorImpl::new()
            .with_clock(Arc::new(NoopClock))
            .with_retry_policy(RetryPolicy {
                max_attempts: 3,
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(1),
            })
    }

    #[test]
    fn backoff_is_bounded_and_exponential() {
        let p = RetryPolicy {
            max_attempts: 10,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(500),
        };
        assert_eq!(p.backoff_for(0), Duration::from_millis(100));
        assert_eq!(p.backoff_for(1), Duration::from_millis(200));
        assert_eq!(p.backoff_for(2), Duration::from_millis(400));
        // Capped at max_backoff.
        assert_eq!(p.backoff_for(3), Duration::from_millis(500));
        assert_eq!(p.backoff_for(60), Duration::from_millis(500));
    }

    #[test]
    fn error_classification() {
        assert!(is_transient(&ConnectorError::ProviderUnavailable(
            "x".into()
        )));
        assert!(is_transient(&ConnectorError::ConnectionFailed("x".into())));
        assert!(is_transient(&ConnectorError::StreamError("x".into())));
        assert!(!is_transient(&ConnectorError::ProtocolError("auth".into())));
    }

    #[tokio::test]
    async fn failover_send_to_secondary_on_primary_failure() {
        let connector = fast_connector();
        let primary_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let secondary_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        // Primary always fails (more failures than attempts allowed).
        connector
            .register_provider(Arc::new(ScriptedAdapter {
                id: "primary".into(),
                available: true,
                fail_count: 100,
                transient: true,
                attempts: primary_attempts.clone(),
            }))
            .unwrap();
        connector
            .register_provider(Arc::new(ScriptedAdapter {
                id: "secondary".into(),
                available: true,
                fail_count: 0,
                transient: true,
                attempts: secondary_attempts.clone(),
            }))
            .unwrap();
        connector.set_backup(&"primary".into(), &"secondary".into());

        let out = connector
            .send_with_failover(
                &"primary".into(),
                vec![StandardMessage::user("hi")],
                &[],
                SendMode::NonStreaming,
            )
            .await
            .expect("should fail over to secondary");
        assert_eq!(out.served_by, "secondary");
        assert_eq!(out.response.content, "ok from secondary");
        // Primary exhausted its retry budget before failover.
        assert_eq!(
            primary_attempts.load(std::sync::atomic::Ordering::SeqCst),
            3
        );
    }

    #[tokio::test]
    async fn transient_error_retried_then_succeeds() {
        let connector = fast_connector();
        let attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        // Fail twice (transient), succeed on the 3rd attempt.
        connector
            .register_provider(Arc::new(ScriptedAdapter {
                id: "p".into(),
                available: true,
                fail_count: 2,
                transient: true,
                attempts: attempts.clone(),
            }))
            .unwrap();

        let out = connector
            .send_with_failover(
                &"p".into(),
                vec![StandardMessage::user("hi")],
                &[],
                SendMode::NonStreaming,
            )
            .await
            .expect("transient errors should be retried");
        assert_eq!(out.served_by, "p");
        assert_eq!(out.attempts, 3);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn permanent_error_not_retried() {
        let connector = fast_connector();
        let attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        // Permanent failure: must NOT be retried (single attempt), and no
        // backup is configured so the call fails.
        connector
            .register_provider(Arc::new(ScriptedAdapter {
                id: "p".into(),
                available: true,
                fail_count: 100,
                transient: false,
                attempts: attempts.clone(),
            }))
            .unwrap();

        let err = connector
            .send_with_failover(
                &"p".into(),
                vec![StandardMessage::user("hi")],
                &[],
                SendMode::NonStreaming,
            )
            .await
            .expect_err("permanent error should surface");
        assert!(matches!(err, ConnectorError::ProtocolError(_)));
        // Exactly one attempt — no retry on a permanent error.
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn permanent_error_still_fails_over() {
        let connector = fast_connector();
        let p_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let s_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        connector
            .register_provider(Arc::new(ScriptedAdapter {
                id: "p".into(),
                available: true,
                fail_count: 100,
                transient: false, // permanent
                attempts: p_attempts.clone(),
            }))
            .unwrap();
        connector
            .register_provider(Arc::new(ScriptedAdapter {
                id: "s".into(),
                available: true,
                fail_count: 0,
                transient: true,
                attempts: s_attempts.clone(),
            }))
            .unwrap();
        connector.set_backup(&"p".into(), &"s".into());

        let out = connector
            .send_with_failover(
                &"p".into(),
                vec![StandardMessage::user("hi")],
                &[],
                SendMode::NonStreaming,
            )
            .await
            .expect("should fail over after permanent error on primary");
        assert_eq!(out.served_by, "s");
        // Primary tried exactly once (no retry), then failover.
        assert_eq!(p_attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unavailable_primary_fails_over_without_burning_retries() {
        let connector = fast_connector();
        let p_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let s_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        connector
            .register_provider(Arc::new(ScriptedAdapter {
                id: "p".into(),
                available: false, // unavailable
                fail_count: 0,
                transient: true,
                attempts: p_attempts.clone(),
            }))
            .unwrap();
        connector
            .register_provider(Arc::new(ScriptedAdapter {
                id: "s".into(),
                available: true,
                fail_count: 0,
                transient: true,
                attempts: s_attempts.clone(),
            }))
            .unwrap();
        connector.set_backup(&"p".into(), &"s".into());

        let out = connector
            .send_with_failover(
                &"p".into(),
                vec![StandardMessage::user("hi")],
                &[],
                SendMode::Streaming,
            )
            .await
            .expect("unavailable primary should fail over");
        assert_eq!(out.served_by, "s");
        // No session was created against the unavailable primary.
        assert_eq!(p_attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn streaming_mode_respects_retry() {
        let connector = fast_connector();
        let attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        connector
            .register_provider(Arc::new(ScriptedAdapter {
                id: "p".into(),
                available: true,
                fail_count: 1,
                transient: true,
                attempts: attempts.clone(),
            }))
            .unwrap();
        let out = connector
            .send_with_failover(
                &"p".into(),
                vec![StandardMessage::user("hi")],
                &[],
                SendMode::Streaming,
            )
            .await
            .expect("streaming path should retry transient errors");
        assert_eq!(out.served_by, "p");
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failover_chain_is_acyclic_and_ordered() {
        let connector = fast_connector();
        for id in ["a", "b", "c"] {
            connector
                .register_provider(Arc::new(ScriptedAdapter {
                    id: id.into(),
                    available: true,
                    fail_count: 0,
                    transient: true,
                    attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                }))
                .unwrap();
        }
        connector.set_backup(&"a".into(), &"b".into());
        connector.set_backup(&"b".into(), &"c".into());
        // Introduce a cycle: c -> a. The chain must terminate.
        connector.set_backup(&"c".into(), &"a".into());
        let chain = connector.failover_chain(&"a".into());
        assert_eq!(
            chain,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[tokio::test]
    async fn cancellation_stops_retry_and_failover_without_duplicate_side_effects() {
        let connector = fast_connector();
        let primary_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let backup_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut primary = qualification_adapter(
            "primary",
            ProviderType::Cloud,
            "primary-model",
            None,
            Arc::clone(&primary_attempts),
        );
        primary.block = true;
        connector.register_provider(Arc::new(primary)).unwrap();
        connector
            .register_provider(Arc::new(qualification_adapter(
                "backup",
                ProviderType::Cloud,
                "backup-model",
                None,
                Arc::clone(&backup_attempts),
            )))
            .unwrap();
        connector.set_backup(&"primary".into(), &"backup".into());

        let cancellation = tokio_util::sync::CancellationToken::new();
        let cancellation_trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            cancellation_trigger.cancel();
        });
        let error = connector
            .send_with_failover_controlled(
                &"primary".into(),
                vec![StandardMessage::user("cancel me")],
                &[],
                SendMode::NonStreaming,
                LlmRequestOptions::default(),
                &cancellation,
            )
            .await
            .expect_err("cancellation must stop the whole failover chain");

        assert!(matches!(error, ConnectorError::Cancelled(_)));
        assert_eq!(
            primary_attempts.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(backup_attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn visible_partial_stream_suppresses_retry_and_failover() {
        let connector = fast_connector();
        let primary_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let backup_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        connector
            .register_provider(Arc::new(PartialStreamAdapter {
                id: "primary".into(),
                fail_after_delta: true,
                attempts: Arc::clone(&primary_attempts),
            }))
            .unwrap();
        connector
            .register_provider(Arc::new(PartialStreamAdapter {
                id: "backup".into(),
                fail_after_delta: false,
                attempts: Arc::clone(&backup_attempts),
            }))
            .unwrap();
        connector.set_backup(&"primary".into(), &"backup".into());
        let cancellation = tokio_util::sync::CancellationToken::new();
        let (events, mut received) = tokio::sync::mpsc::channel(4);

        let error = connector
            .send_with_failover_observed(
                &"primary".into(),
                vec![StandardMessage::user("stream once")],
                &[],
                FailoverControls {
                    mode: SendMode::Streaming,
                    options: LlmRequestOptions::default(),
                    cancellation: &cancellation,
                    observed_attempts: None,
                    max_attempts_per_provider: None,
                    events: Some(events),
                },
            )
            .await
            .expect_err("visible partial output must stop replay");

        assert!(matches!(error, ConnectorError::PartialStream(_)));
        assert_eq!(
            received.recv().await,
            Some(ProviderStreamEvent::TextDelta("partial".into()))
        );
        assert_eq!(
            primary_attempts.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(backup_attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn incompatible_tool_backup_is_never_invoked() {
        let connector = fast_connector();
        let primary_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let backup_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        connector
            .register_provider(Arc::new(qualification_adapter(
                "primary",
                ProviderType::Cloud,
                "primary-model",
                Some(ConnectorError::ConnectionFailed("offline".into())),
                Arc::clone(&primary_attempts),
            )))
            .unwrap();
        let mut backup = qualification_adapter(
            "backup",
            ProviderType::Cloud,
            "backup-model",
            None,
            Arc::clone(&backup_attempts),
        );
        backup.capabilities.tool_calls = false;
        connector.register_provider(Arc::new(backup)).unwrap();
        connector.set_backup(&"primary".into(), &"backup".into());
        let tools = vec![ToolDefinition {
            name: "read".into(),
            description: "read".into(),
            parameters: serde_json::json!({"type": "object"}),
        }];

        let error = connector
            .send_with_failover(
                &"primary".into(),
                vec![StandardMessage::user("use a tool")],
                &tools,
                SendMode::NonStreaming,
            )
            .await
            .expect_err("an incompatible backup must not receive the request");
        assert!(matches!(error, ConnectorError::ProviderUnavailable(_)));
        assert_eq!(backup_attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn local_to_cloud_failover_requires_explicit_operator_opt_in() {
        let connector = fast_connector();
        let local_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cloud_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        connector
            .register_provider(Arc::new(qualification_adapter(
                "local",
                ProviderType::Local,
                "local-model",
                Some(ConnectorError::ConnectionFailed("offline".into())),
                Arc::clone(&local_attempts),
            )))
            .unwrap();
        connector
            .register_provider(Arc::new(qualification_adapter(
                "cloud",
                ProviderType::Cloud,
                "cloud-model",
                None,
                Arc::clone(&cloud_attempts),
            )))
            .unwrap();
        connector.set_backup(&"local".into(), &"cloud".into());

        connector
            .send_with_failover(
                &"local".into(),
                vec![StandardMessage::user("private")],
                &[],
                SendMode::NonStreaming,
            )
            .await
            .expect_err("local data must not fail over to cloud by default");
        assert_eq!(cloud_attempts.load(std::sync::atomic::Ordering::SeqCst), 0);

        connector.set_routing_policy(
            &"local".into(),
            ProviderRoutingPolicy {
                required_region: None,
                allow_local_to_cloud: true,
            },
        );
        let outcome = connector
            .send_with_failover(
                &"local".into(),
                vec![StandardMessage::user("operator approved")],
                &[],
                SendMode::NonStreaming,
            )
            .await
            .expect("explicit opt-in should allow cloud failover");
        assert_eq!(outcome.served_by, "cloud");
        assert_eq!(outcome.model_id, "cloud-model");
    }

    #[tokio::test]
    async fn resilient_session_reports_actual_provider_model_and_attempts() {
        let connector = Arc::new(fast_connector());
        let primary_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let backup_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        connector
            .register_provider(Arc::new(qualification_adapter(
                "primary",
                ProviderType::Cloud,
                "configured-primary",
                Some(ConnectorError::ConnectionFailed("offline".into())),
                Arc::clone(&primary_attempts),
            )))
            .unwrap();
        connector
            .register_provider(Arc::new(qualification_adapter(
                "backup",
                ProviderType::Cloud,
                "served-backup",
                None,
                Arc::clone(&backup_attempts),
            )))
            .unwrap();
        connector.set_backup(&"primary".into(), &"backup".into());

        let session = connector
            .connect_resilient(uuid::Uuid::new_v4(), &"primary".into())
            .await
            .unwrap();
        assert_eq!(session.model_id(), "configured-primary");
        assert_eq!(session.max_provider_attempts(), 2);
        assert!(
            !session.handles_retries(),
            "the executor owns retry rounds; this session owns one compatible failover attempt per provider"
        );
        session
            .send(vec![StandardMessage::user("hello")])
            .await
            .unwrap();
        assert_eq!(
            session.last_attribution(),
            Some(("backup".into(), "served-backup".into()))
        );
        assert_eq!(session.last_attempts(), Some(2));
    }

    #[tokio::test]
    async fn register_and_connect() {
        let connector = AgentConnectorImpl::new();
        let adapter = Arc::new(MockAdapter {
            id: "openai".into(),
            available: true,
        });
        connector.register_provider(adapter).unwrap();

        let agent_id = uuid::Uuid::new_v4();
        let session = connector.connect(agent_id, &"openai".into()).await.unwrap();
        assert!(
            !session.enforces_max_output_tokens(),
            "external adapters must opt in before the kernel trusts a hard bound"
        );
        let resp = session
            .send(vec![StandardMessage::user("hi")])
            .await
            .unwrap();
        assert_eq!(resp.content, "response");
    }

    #[tokio::test]
    async fn connect_unavailable_fails() {
        let connector = AgentConnectorImpl::new();
        let adapter = Arc::new(MockAdapter {
            id: "openai".into(),
            available: false,
        });
        connector.register_provider(adapter).unwrap();

        let agent_id = uuid::Uuid::new_v4();
        let result = connector.connect(agent_id, &"openai".into()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn failover_to_backup() {
        let connector = AgentConnectorImpl::new();
        let primary = Arc::new(MockAdapter {
            id: "openai".into(),
            available: false,
        });
        let backup = Arc::new(MockAdapter {
            id: "anthropic".into(),
            available: true,
        });
        connector.register_provider(primary).unwrap();
        connector.register_provider(backup).unwrap();
        connector.set_backup(&"openai".into(), &"anthropic".into());

        let agent_id = uuid::Uuid::new_v4();
        let session = connector.connect(agent_id, &"openai".into()).await.unwrap();
        assert_eq!(session.provider_id(), "anthropic");
    }

    #[tokio::test]
    async fn list_providers_returns_registered() {
        let connector = AgentConnectorImpl::new();
        connector
            .register_provider(Arc::new(MockAdapter {
                id: "openai".into(),
                available: true,
            }))
            .unwrap();
        connector
            .register_provider(Arc::new(MockAdapter {
                id: "local".into(),
                available: true,
            }))
            .unwrap();
        let providers = connector.list_providers();
        assert_eq!(providers.len(), 2);
    }
}
