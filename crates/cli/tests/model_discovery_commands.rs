use std::process::{Command, Output};
use std::sync::Arc;

use kernel::auth::Role;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn agentctl(address: &str, token: &str, command: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .args(["--addr", address, "--token", token]).args(command)
        .env_remove("AGENT_SERVER_TOKEN").env_remove("AGENT_SERVER_ADDR")
        .output().expect("agentctl command")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agentctl_model_discovery_prints_configured_catalog_and_preserves_authorization() {
    let provider = MockServer::start().await;
    Mock::given(method("GET")).and(path("/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data":[{"id":"z-model", "owned_by":"private-account"}, {"id":"a-model"}]
        }))).expect(1).mount(&provider).await;
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    kernel.register_provider(Arc::new(adapters::openai::OpenAiAdapter::new("fixture-key".into())
        .with_base_url(provider.uri()))).unwrap();
    kernel.register_provider(Arc::new(adapters::huggingface::HuggingFaceAdapter::new("fixture-key".into())
        .with_base_url(provider.uri()))).unwrap();
    let tenant = kernel.create_tenant("catalog-cli").await.unwrap();
    let admin = kernel.register_user(&tenant, "admin", "admin@catalog-cli.test", Role::Admin).await.unwrap();
    let tenant_token = kernel.issue_api_key(&admin, "catalog-cli").await.unwrap();
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0").await.unwrap()
        .with_auth_token("fixture-operator-token");
    let address = server.local_addr().unwrap().to_string();
    let task = tokio::spawn(server.serve());
    let listed = agentctl(&address, "fixture-operator-token", &["providers"]);
    assert!(listed.status.success(), "{}", String::from_utf8_lossy(&listed.stderr));
    assert!(provider.received_requests().await.unwrap().is_empty(), "listing configured providers must not enumerate accounts");
    let models = agentctl(&address, "fixture-operator-token", &["models", "openai"]);
    assert!(models.status.success(), "{}", String::from_utf8_lossy(&models.stderr));
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&models.stdout).unwrap(),
        json!({"provider_id":"openai", "models":["a-model", "z-model"]}));
    for secret in ["fixture-key", "private-account", &provider.uri()] {
        assert!(!String::from_utf8_lossy(&models.stdout).contains(secret));
    }
    for (token, id, code) in [
        (tenant_token.as_str(), "openai", "AuthorizationDenied"),
        (tenant_token.as_str(), "absent", "AuthorizationDenied"),
        ("fixture-operator-token", "huggingface", "Unsupported"),
        ("fixture-operator-token", "absent", "NotFound"),
    ] {
        let failed = agentctl(&address, token, &["models", id]);
        assert!(!failed.status.success());
        assert!(failed.stdout.is_empty());
        assert!(String::from_utf8_lossy(&failed.stderr).contains(code), "{}", String::from_utf8_lossy(&failed.stderr));
    }
    assert_eq!(provider.received_requests().await.unwrap().len(), 1);
    task.abort();
    let _ = task.await;
}
