//! Property-based tests for Connector (Properties 13, 14).
//!
//! Property 13: Provider protocol validation — compile-time via Rust traits.
//! Property 14: Protocol message translation round-trip — for any StandardMessage,
//! translate to provider format and back SHALL produce semantically equivalent message.

use proptest::prelude::*;

use adapters::anthropic::AnthropicAdapter;
use adapters::local::LocalLlmAdapter;
use adapters::openai::OpenAiAdapter;
use kernel::connector::*;

fn arb_standard_message() -> impl Strategy<Value = StandardMessage> {
    (
        prop_oneof![Just("user"), Just("assistant"), Just("system")],
        "[a-zA-Z0-9 .,!?]{5,100}",
    )
        .prop_map(|(role, content)| StandardMessage {
            role: role.to_string(),
            content,
            tool_call_id: None,
            tool_calls: None,
        })
}

proptest! {
    /// Property 13: Provider protocol validation is enforced at compile time
    /// by Rust's trait system. If a type implements LlmProviderAdapter, it has
    /// all required methods. This test verifies the adapters compile and implement
    /// the trait correctly.
    #[test]
    fn prop13_provider_protocol_validation(msg in arb_standard_message()) {
        // The fact that these compile proves Property 13
        let openai = OpenAiAdapter::new("test-key".to_string());
        let anthropic = AnthropicAdapter::new("test-key".to_string());
        let local = LocalLlmAdapter::new("http://localhost:11434".to_string(), "llama3".to_string());

        // All implement LlmProviderAdapter (compile-time check)
        let _: &dyn LlmProviderAdapter = &openai;
        let _: &dyn LlmProviderAdapter = &anthropic;
        let _: &dyn LlmProviderAdapter = &local;

        // Verify they have valid IDs
        prop_assert!(!openai.id().is_empty());
        prop_assert!(!anthropic.id().is_empty());
        prop_assert!(!local.id().is_empty());
    }

    /// Property 14: For any StandardMessage, translate to provider format and back
    /// SHALL produce semantically equivalent message.
    #[test]
    fn prop14_message_translation_round_trip(msg in arb_standard_message()) {
        // Test OpenAI adapter round-trip
        let openai = OpenAiAdapter::new("test-key".to_string());
        let provider_format = openai.translate_to_provider(&msg);
        let restored = openai.translate_from_provider(&provider_format);
        prop_assert!(restored.is_some(), "OpenAI: translation back should succeed");
        let restored = restored.unwrap();
        prop_assert_eq!(&restored.role, &msg.role, "OpenAI: role should match");
        prop_assert_eq!(&restored.content, &msg.content, "OpenAI: content should match");

        // Test Anthropic adapter round-trip
        let anthropic = AnthropicAdapter::new("test-key".to_string());
        let provider_format = anthropic.translate_to_provider(&msg);
        let restored = anthropic.translate_from_provider(&provider_format);
        prop_assert!(restored.is_some(), "Anthropic: translation back should succeed");
        let restored = restored.unwrap();
        prop_assert_eq!(&restored.role, &msg.role, "Anthropic: role should match");
        prop_assert_eq!(&restored.content, &msg.content, "Anthropic: content should match");

        // Test Local adapter round-trip
        let local = LocalLlmAdapter::new("http://localhost:11434".to_string(), "llama3".to_string());
        let provider_format = local.translate_to_provider(&msg);
        let restored = local.translate_from_provider(&provider_format);
        prop_assert!(restored.is_some(), "Local: translation back should succeed");
        let restored = restored.unwrap();
        prop_assert_eq!(&restored.role, &msg.role, "Local: role should match");
        prop_assert_eq!(&restored.content, &msg.content, "Local: content should match");
    }
}

/// Load + resilience tests for the hardened LLM path: failover, retry/backoff,
/// and rate-limiting under concurrent callers. These exercise the connector and
/// rate limiter through their public APIs with in-crate fake adapters — no real
/// network, fully deterministic, and fast (backoff uses a no-op clock).
mod hardening {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use kernel::connector::{
        AgentConnector, AgentConnectorImpl, Clock, LlmProviderAdapter, LlmResponse, LlmSession,
        ProviderType, RetryPolicy, SendMode, StandardMessage, ToolDefinition,
    };
    use kernel::rate_limit::{RateLimitConfig, RateLimiter};
    use kernel::ConnectorError;

    /// No-op clock so backoff is instant in tests.
    struct NoopClock;
    #[async_trait]
    impl Clock for NoopClock {
        async fn sleep(&self, _dur: Duration) {}
    }

    /// Fake adapter: fails the first `fail_count` send attempts (counted across
    /// all sessions), with a transient or permanent error, then succeeds.
    struct FakeAdapter {
        id: String,
        available: bool,
        fail_count: u32,
        transient: bool,
        attempts: Arc<AtomicU32>,
    }

    struct FakeSession {
        id: String,
        fail_count: u32,
        transient: bool,
        attempts: Arc<AtomicU32>,
    }

    #[async_trait]
    impl LlmSession for FakeSession {
        async fn send(&self, _m: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
            let n = self.attempts.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_count {
                return if self.transient {
                    Err(ConnectorError::ConnectionFailed("transient".into()))
                } else {
                    Err(ConnectorError::ProtocolError("auth".into()))
                };
            }
            Ok(LlmResponse {
                content: format!("ok:{}", self.id),
                finish_reason: Some("stop".into()),
                tokens_used: 3,
                tool_calls: vec![],
            })
        }
        async fn send_with_tools(
            &self,
            m: Vec<StandardMessage>,
            _t: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            self.send(m).await
        }
        fn provider_id(&self) -> &String {
            &self.id
        }
    }

    #[async_trait]
    impl LlmProviderAdapter for FakeAdapter {
        fn id(&self) -> &String {
            &self.id
        }
        fn name(&self) -> &str {
            "Fake"
        }
        fn provider_type(&self) -> ProviderType {
            ProviderType::Cloud
        }
        async fn is_available(&self) -> bool {
            self.available
        }
        async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
            Ok(Box::new(FakeSession {
                id: self.id.clone(),
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

    fn adapter(
        id: &str,
        available: bool,
        fail_count: u32,
        transient: bool,
    ) -> (Arc<FakeAdapter>, Arc<AtomicU32>) {
        let attempts = Arc::new(AtomicU32::new(0));
        (
            Arc::new(FakeAdapter {
                id: id.into(),
                available,
                fail_count,
                transient,
                attempts: attempts.clone(),
            }),
            attempts,
        )
    }

    /// (a) Failover: a primary that always fails hands off to a healthy secondary.
    #[tokio::test]
    async fn failover_to_secondary_on_primary_failure() {
        let c = fast_connector();
        let (primary, _) = adapter("primary", true, 1000, true);
        let (secondary, _) = adapter("secondary", true, 0, true);
        c.register_provider(primary).unwrap();
        c.register_provider(secondary).unwrap();
        c.set_backup(&"primary".into(), &"secondary".into());

        let out = c
            .send_with_failover(
                &"primary".into(),
                vec![StandardMessage::user("hi")],
                &[],
                SendMode::NonStreaming,
            )
            .await
            .expect("should fail over");
        assert_eq!(out.served_by, "secondary");
    }

    /// (b) Transient error is retried and then succeeds on the same provider.
    #[tokio::test]
    async fn transient_retried_then_succeeds() {
        let c = fast_connector();
        let (a, attempts) = adapter("p", true, 2, true);
        c.register_provider(a).unwrap();

        let out = c
            .send_with_failover(
                &"p".into(),
                vec![StandardMessage::user("hi")],
                &[],
                SendMode::Streaming,
            )
            .await
            .expect("transient should retry");
        assert_eq!(out.served_by, "p");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    /// (c) Permanent error is NOT retried (single attempt, then surfaced).
    #[tokio::test]
    async fn permanent_not_retried() {
        let c = fast_connector();
        let (a, attempts) = adapter("p", true, 1000, false);
        c.register_provider(a).unwrap();

        let err = c
            .send_with_failover(
                &"p".into(),
                vec![StandardMessage::user("hi")],
                &[],
                SendMode::NonStreaming,
            )
            .await
            .expect_err("permanent should fail");
        assert!(matches!(err, ConnectorError::ProtocolError(_)));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    /// (d) Rate-limit concurrency bound holds under many concurrent callers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rate_limit_concurrency_bound_under_load() {
        let max_concurrent = 4u32;
        let limiter = Arc::new(RateLimiter::new(RateLimitConfig {
            rpm: 100_000,
            tpm: 100_000_000,
            max_concurrent,
        }));
        let live = Arc::new(AtomicU32::new(0));
        let peak = Arc::new(AtomicU32::new(0));

        let mut handles = Vec::new();
        for _ in 0..128 {
            let limiter = limiter.clone();
            let live = live.clone();
            let peak = peak.clone();
            handles.push(tokio::spawn(async move {
                let _g = limiter.acquire().await;
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(2)).await;
                live.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            peak.load(Ordering::SeqCst) <= max_concurrent,
            "peak {} exceeded bound {}",
            peak.load(Ordering::SeqCst),
            max_concurrent
        );
        assert_eq!(limiter.stats().concurrent_available, max_concurrent);
    }

    /// (d') Rate-limit RPM bound holds under concurrent reservation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rate_limit_rpm_bound_under_load() {
        let rpm = 6u32;
        let limiter = Arc::new(RateLimiter::new(RateLimitConfig {
            rpm,
            tpm: 100_000_000,
            max_concurrent: 64,
        }));
        let mut handles = Vec::new();
        for _ in 0..40 {
            let limiter = limiter.clone();
            handles.push(tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_millis(40), limiter.acquire_tokens(1))
                    .await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            limiter.stats().requests_this_minute,
            rpm as u64,
            "more than rpm admitted in one window"
        );
    }
}
