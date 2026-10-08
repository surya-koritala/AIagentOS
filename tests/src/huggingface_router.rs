//! Actual Hugging Face adapter through ordinary CLI registration and governance.

use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};
use agent_cli::providers::register_providers;
use kernel::connector::*;
use kernel::observability::ObservabilityEngine;
use kernel::sandbox::SandboxManager;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use wiremock::matchers::{method, path};

struct LegacyResponder { calls: Arc<AtomicUsize> }
impl Respond for LegacyResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert!(body.get("tools").is_none());
        let prompt = body["inputs"].as_str().unwrap();
        assert!(prompt.contains("Available tools:") && prompt.contains("write_file"));
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let text = if call == 0 {
            serde_json::json!({"tool":"write_file","arguments":{"path":"hf-proof.txt","content":"governed"}}).to_string()
        } else { "finished".into() };
        ResponseTemplate::new(200).set_body_json(serde_json::json!([{"generated_text":text}]))
    }
}

fn agent_config(profile: &str) -> AgentConfig {
    AgentConfig { name:"hf-fixture".into(), task:"owned file".into(), llm_provider:"huggingface".into(),
        permission_profile:profile.into(), priority:Priority::default(), sandbox_config:None }
}

fn operator_config(uri: String) -> kernel::config::Config {
    let mut config = kernel::config::Config { llm_provider:"huggingface".into(), default_model:"Qwen/Qwen3.5-9B:deepinfra".into(),
        huggingface_base_url:Some(uri), ..Default::default() };
    config.set_api_key("huggingface", "fixture-key".into());
    config
}

#[tokio::test]
async fn huggingface_router_legacy_governed_calls_are_estimated_and_audited_once() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST")).respond_with(LegacyResponder { calls:calls.clone() })
        .expect(2).mount(&server).await;
    let kernel = AgentKernelImpl::new().unwrap();
    register_providers(&kernel, &operator_config(server.uri()));
    let agent = kernel.create_agent_full(agent_config("full-access")).await.unwrap();
    let output = kernel.send_message(agent.id,"write owned proof").await.unwrap();
    assert_eq!(output.content,"finished");
    assert_eq!(output.usage.shim_recovered_tool_calls,1);
    assert_eq!(output.usage.degraded_requests,2);
    assert_eq!(calls.load(Ordering::SeqCst),2);
    let sandbox = kernel.sandbox_manager.get_sandbox_for_agent(agent.id).unwrap();
    let file = kernel.sandbox_manager.resolve_file_path(sandbox,std::path::Path::new("hf-proof.txt")).unwrap();
    assert_eq!(std::fs::read_to_string(file).unwrap(),"governed");
    let records = kernel.observability.get_activity_log(agent.id,None);
    let events:Vec<_> = records.iter().filter(|r| r.action_type=="provider_tool_degradation").collect();
    assert_eq!(events.len(),1);
    let audit:ProviderToolDegradation = serde_json::from_str(&events[0].description).unwrap();
    assert_eq!(audit.provider_id,"huggingface");
    assert_eq!(audit.model_id,"Qwen/Qwen3.5-9B:deepinfra");
    assert!(!events[0].description.contains("write owned proof"));
    kernel.stop_agent(agent.id).await.unwrap();
}

#[tokio::test]
async fn huggingface_router_legacy_reject_has_zero_io_and_readonly_shim_cannot_write() {
    let server = MockServer::start().await;
    let kernel = AgentKernelImpl::new().unwrap();
    register_providers(&kernel,&operator_config(server.uri()));
    kernel.connector.set_routing_policy(&"huggingface".into(),ProviderRoutingPolicy {
        tool_incompatible_primary:ToolIncompatiblePrimaryPolicy::Reject, ..Default::default()
    });
    let rejected = kernel.create_agent_full(agent_config("full-access")).await.unwrap();
    assert!(matches!(kernel.send_message(rejected.id,"owned proof").await.unwrap_err(),
        kernel::KernelError::Connector(kernel::ConnectorError::ToolIncompatiblePrimary(_))));
    assert!(server.received_requests().await.unwrap().is_empty());
    kernel.connector.set_routing_policy(&"huggingface".into(),ProviderRoutingPolicy::default());
    Mock::given(method("POST")).respond_with(LegacyResponder { calls:Arc::new(AtomicUsize::new(0)) })
        .expect(2).mount(&server).await;
    let readonly = kernel.create_agent_full(agent_config("read-only")).await.unwrap();
    let output = kernel.send_message(readonly.id,"owned proof").await.unwrap();
    assert_eq!(output.usage.shim_recovered_tool_calls,1);
    let sandbox = kernel.sandbox_manager.get_sandbox_for_agent(readonly.id).unwrap();
    assert!(!kernel.sandbox_manager.resolve_file_path(sandbox,std::path::Path::new("hf-proof.txt")).unwrap().exists());
    kernel.stop_agent(readonly.id).await.unwrap();
    kernel.stop_agent(rejected.id).await.unwrap();
}

#[tokio::test]
async fn huggingface_router_operator_chat_mode_round_trips_and_registers_native_protocol() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"native answer\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":3,\"total_tokens\":14}}\n\n",
            "data: [DONE]\n\n"))).expect(1).mount(&server).await;
    let mut config = operator_config(server.uri());
    config.huggingface_api_mode = kernel::config::HuggingFaceApiMode::ChatCompletions;
    let encoded = toml::to_string(&config).unwrap();
    let config:kernel::config::Config = toml::from_str(&encoded).unwrap();
    assert!(toml::from_str::<kernel::config::Config>(&encoded.replace("chat-completions","auto-guess")).is_err());
    let kernel = AgentKernelImpl::new().unwrap();
    register_providers(&kernel,&config);
    let view = kernel.connector.list_providers();
    assert!(view[0].capabilities.tool_calls && view[0].capabilities.native_streaming);
    let agent = kernel.create_agent_full(agent_config("full-access")).await.unwrap();
    let output = kernel.send_message(agent.id,"native fixture").await.unwrap();
    assert_eq!(output.content,"native answer");
    assert_eq!(output.usage.degraded_requests,0);
    assert!(!kernel.observability.get_activity_log(agent.id,None).iter()
        .any(|r| r.action_type=="provider_tool_degradation"));
    let requests = server.received_requests().await.unwrap();
    let body:serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["model"],"Qwen/Qwen3.5-9B:deepinfra");
    assert!(body["tools"].as_array().unwrap().len()>1);
    kernel.stop_agent(agent.id).await.unwrap();
}
