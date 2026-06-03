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

use std::sync::Arc;
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
        ConnectorError::ProviderUnavailable(_) => true,
        ConnectorError::ConnectionFailed(_) => true,
        ConnectorError::StreamError(_) => true,
        // Protocol errors include auth / bad-request style failures that will
        // not succeed on retry.
        ConnectorError::ProtocolError(_) => false,
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

/// Information about a registered provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub id: ProviderId,
    pub name: String,
    pub provider_type: ProviderType,
    pub available: bool,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub finish_reason: Option<String>,
    pub tokens_used: u32,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
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
    fn provider_id(&self) -> &ProviderId;

    /// Send with streaming support. Default falls back to non-streaming.
    async fn send_streaming(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, tools).await
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
    /// Total number of attempts made across all providers tried.
    pub attempts: u32,
}

/// Whether a send should use the streaming or non-streaming session method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMode {
    NonStreaming,
    Streaming,
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
        }
    }

    /// Override the retry/backoff policy (builder-style).
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
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
        let chain = self.failover_chain(primary);
        let mut total_attempts: u32 = 0;
        let mut last_err: Option<ConnectorError> = None;

        for provider_id in chain {
            let adapter = match self.providers.get(&provider_id) {
                Some(a) => a.value().clone(),
                None => {
                    last_err = Some(ConnectorError::ProviderUnavailable(provider_id.clone()));
                    continue;
                }
            };

            // A registered-but-unavailable provider is a transient condition:
            // skip straight to failover without burning the retry budget.
            if !adapter.is_available().await {
                total_attempts = total_attempts.saturating_add(1);
                last_err = Some(ConnectorError::ProviderUnavailable(provider_id.clone()));
                continue;
            }

            match self
                .send_one_provider(&adapter, &messages, tools, mode, &mut total_attempts)
                .await
            {
                Ok(response) => {
                    return Ok(SendOutcome {
                        response,
                        served_by: provider_id,
                        attempts: total_attempts,
                    });
                }
                Err(e) => last_err = Some(e),
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
        messages: &[StandardMessage],
        tools: &[ToolDefinition],
        mode: SendMode,
        total_attempts: &mut u32,
    ) -> Result<LlmResponse, ConnectorError> {
        let max_attempts = self.retry_policy.max_attempts.max(1);
        let mut last_err: Option<ConnectorError> = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                self.clock
                    .sleep(self.retry_policy.backoff_for(attempt - 1))
                    .await;
            }
            *total_attempts = total_attempts.saturating_add(1);

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

            let result = match mode {
                SendMode::NonStreaming => session.send_with_tools(messages.to_vec(), tools).await,
                SendMode::Streaming => session.send_streaming(messages.to_vec(), tools).await,
            };

            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
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
}

#[async_trait::async_trait]
impl AgentConnector for AgentConnectorImpl {
    fn register_provider(
        &self,
        adapter: Arc<dyn LlmProviderAdapter>,
    ) -> Result<(), ConnectorError> {
        let id = adapter.id().clone();
        self.providers.insert(id, adapter);
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
                    available: true, // Async check not possible in sync method
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
    async fn register_and_connect() {
        let connector = AgentConnectorImpl::new();
        let adapter = Arc::new(MockAdapter {
            id: "openai".into(),
            available: true,
        });
        connector.register_provider(adapter).unwrap();

        let agent_id = uuid::Uuid::new_v4();
        let session = connector.connect(agent_id, &"openai".into()).await.unwrap();
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
