//! Explicit degraded provider execution through the ordinary kernel gate.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use kernel::connector::*;
use kernel::observability::ObservabilityEngine;
use kernel::{AgentConfig, AgentKernelImpl, ConnectorError, Priority};
use kernel::sandbox::SandboxManager;

struct CompletionAdapter { id: String, sends: Arc<AtomicUsize> }
struct CompletionSession { id: String, sends: Arc<AtomicUsize> }

#[async_trait::async_trait]
impl LlmSession for CompletionSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }
    async fn send_with_tools(&self, messages: Vec<StandardMessage>, tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
        assert!(tools.is_empty(), "degraded endpoint must receive no native definitions");
        assert!(messages[0].content.contains("Available tools:"));
        self.sends.fetch_add(1, Ordering::SeqCst);
        let completed = messages.iter().any(|message| message.role == "tool");
        Ok(LlmResponse {
            content: if completed { "finished".into() } else {
                serde_json::json!({"tool":"write_file","arguments":{"path":"proof.txt","content":"owned proof"}}).to_string()
            },
            finish_reason: Some("stop".into()), tokens_used: 5,
            usage: LlmUsage::reported(3, 2, 0), tool_calls: Vec::new(), provider_metadata: None,
        })
    }
    fn provider_id(&self) -> &String { &self.id }
    fn model_id(&self) -> &str { "completion-fixture" }
    fn enforces_max_output_tokens(&self) -> bool { true }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for CompletionAdapter {
    fn id(&self) -> &String { &self.id }
    fn name(&self) -> &str { "completion fixture" }
    fn provider_type(&self) -> ProviderType { ProviderType::Cloud }
    async fn is_available(&self) -> bool { true }
    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(CompletionSession { id: self.id.clone(), sends: self.sends.clone() }))
    }
    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role":message.role,"content":message.content})
    }
    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value["content"].as_str()?))
    }
}

fn config(profile: &str) -> AgentConfig {
    AgentConfig { name: "policy-fixture".into(), task: "owned file".into(),
        llm_provider: "completion".into(), permission_profile: profile.into(),
        priority: Priority::default(), sandbox_config: None }
}

#[tokio::test]
async fn provider_policy_default_runs_shim_once_audits_and_exposes_turn_mode() {
    let kernel = AgentKernelImpl::new().unwrap();
    let sends = Arc::new(AtomicUsize::new(0));
    kernel.register_provider(Arc::new(CompletionAdapter { id: "completion".into(), sends: sends.clone() })).unwrap();
    let agent = kernel.create_agent_full(config("full-access")).await.unwrap();
    let output = kernel.send_message(agent.id, "write owned proof").await.unwrap();
    assert_eq!(output.content, "finished");
    assert_eq!(output.tool_calls_made, 1);
    assert_eq!(output.usage.shim_recovered_tool_calls, 1);
    assert_eq!(output.usage.degraded_requests, 2);
    assert!(output.usage.dropped_native_tool_definitions >= 2);
    assert_eq!(sends.load(Ordering::SeqCst), 2);
    let sandbox = kernel.sandbox_manager.get_sandbox_for_agent(agent.id).unwrap();
    let path = kernel.sandbox_manager.resolve_file_path(sandbox, std::path::Path::new("proof.txt")).unwrap();
    assert_eq!(std::fs::read_to_string(path).unwrap(), "owned proof");
    let logs = kernel.observability.get_activity_log(agent.id, None);
    let degraded: Vec<_> = logs.iter().filter(|record| record.action_type == "provider_tool_degradation").collect();
    assert_eq!(degraded.len(), 1);
    let record: ProviderToolDegradation = serde_json::from_str(&degraded[0].description).unwrap();
    assert_eq!(record.provider_id, "completion");
    assert_eq!(record.model_id, "completion-fixture");
    assert!(!degraded[0].description.contains("write owned proof"));
    let view = kernel.connector.list_providers();
    assert_eq!(view[0].routing_policy.tool_incompatible_primary, ToolIncompatiblePrimaryPolicy::DegradedShim);
    kernel.stop_agent(agent.id).await.unwrap();
}

#[tokio::test]
async fn provider_policy_reject_precedes_runtime_io_and_shim_keeps_permissions() {
    let kernel = AgentKernelImpl::new().unwrap();
    let sends = Arc::new(AtomicUsize::new(0));
    kernel.register_provider(Arc::new(CompletionAdapter { id: "completion".into(), sends: sends.clone() })).unwrap();
    kernel.connector.set_routing_policy(&"completion".into(), ProviderRoutingPolicy {
        tool_incompatible_primary: ToolIncompatiblePrimaryPolicy::Reject, ..Default::default()
    });
    let rejected = kernel.create_agent_full(config("full-access")).await.unwrap();
    let error = kernel.send_message(rejected.id, "write owned proof").await.unwrap_err();
    assert!(matches!(error, kernel::KernelError::Connector(ConnectorError::ToolIncompatiblePrimary(_))));
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    kernel.connector.set_routing_policy(&"completion".into(), ProviderRoutingPolicy::default());
    let readonly = kernel.create_agent_full(config("read-only")).await.unwrap();
    let output = kernel.send_message(readonly.id, "write owned proof").await.unwrap();
    assert_eq!(output.usage.shim_recovered_tool_calls, 1);
    let sandbox = kernel.sandbox_manager.get_sandbox_for_agent(readonly.id).unwrap();
    let path = kernel.sandbox_manager.resolve_file_path(sandbox, std::path::Path::new("proof.txt")).unwrap();
    assert!(!path.exists(), "shim must not bypass readonly authority");
    kernel.stop_agent(readonly.id).await.unwrap();
    kernel.stop_agent(rejected.id).await.unwrap();
}

#[test]
fn provider_policy_operator_config_round_trips_and_rejects_unknown_modes() {
    let mut config = kernel::config::Config::default();
    config.provider_routing.insert("completion".into(), ProviderRoutingPolicy {
        tool_incompatible_primary: ToolIncompatiblePrimaryPolicy::Reject, ..Default::default()
    });
    let encoded = toml::to_string(&config).unwrap();
    let restored: kernel::config::Config = toml::from_str(&encoded).unwrap();
    assert_eq!(restored.provider_routing["completion"].tool_incompatible_primary, ToolIncompatiblePrimaryPolicy::Reject);
    assert!(toml::from_str::<kernel::config::Config>(&encoded.replace("reject", "silent-drop")).is_err());
}
