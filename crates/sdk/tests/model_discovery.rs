use std::sync::Arc;

use agent_sdk::{KernelClient, WireErrorCode};
use kernel::auth::Role;
use kernel::syscall_server::{Syscall, SyscallClient, SyscallReply, SyscallServer};
use kernel::AgentKernelImpl;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn model_discovery_operator_wire_preserves_catalog_capabilities_and_typed_errors() {
    let provider = MockServer::start().await;
    Mock::given(method("GET")).and(path("/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data":[{"id":"z-model", "owned_by":"account-secret"}, {"id":"a-model"}, {"id":"a-model"}]
        }))).expect(1).mount(&provider).await;
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    kernel.register_provider(Arc::new(adapters::openai::OpenAiAdapter::new("fixture-key".into())
        .with_base_url(provider.uri()))).unwrap();
    kernel.register_provider(Arc::new(adapters::huggingface::HuggingFaceAdapter::new("fixture-key".into())
        .with_base_url(provider.uri()))).unwrap();
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0").await.unwrap()
        .with_auth_token("fixture-operator-token");
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(addr).await.unwrap();
    assert_eq!(client.list_provider_models("openai").await.unwrap_err().wire_code(),
        Some(WireErrorCode::AuthenticationRequired));
    client.authenticate("fixture-operator-token").await.unwrap();
    let catalog = client.list_provider_models("openai").await.unwrap();
    assert_eq!(catalog.provider_id, "openai");
    assert_eq!(catalog.models, vec!["a-model", "z-model"]);
    let rendered = serde_json::to_string(&catalog).unwrap();
    for secret in ["fixture-key", "account-secret", &provider.uri()] {
        assert!(!rendered.contains(secret));
    }
    let summaries = client.list_providers().await.unwrap();
    assert!(summaries.iter().find(|provider| provider.id == "openai").unwrap().capabilities.model_discovery);
    assert!(!summaries.iter().find(|provider| provider.id == "huggingface").unwrap().capabilities.model_discovery);
    let unsupported = client.list_provider_models("huggingface").await.unwrap_err();
    assert_eq!(unsupported.wire_code(), Some(WireErrorCode::Unsupported));
    assert!(!unsupported.is_retryable());
    assert_eq!(client.list_provider_models("absent").await.unwrap_err().wire_code(), Some(WireErrorCode::NotFound));
    let tenant = kernel.create_tenant("model-catalog-tenant").await.unwrap();
    for role in [Role::ReadOnly, Role::User, Role::Admin] {
        let user = kernel.register_user(&tenant, role.as_str(), &format!("{}@catalog.test", role.as_str()), role).await.unwrap();
        let token = kernel.issue_api_key(&user, "model-catalog-test").await.unwrap();
        let mut tenant_client = KernelClient::connect(addr).await.unwrap();
        tenant_client.authenticate(token).await.unwrap();
        for id in ["openai", "absent"] {
            assert_eq!(tenant_client.list_provider_models(id).await.unwrap_err().wire_code(), Some(WireErrorCode::AuthorizationDenied));
        }
    }
    let mut legacy = SyscallClient::connect(addr).await.unwrap();
    legacy.call(Syscall::Hello { protocol_version: 1 }).await.unwrap();
    legacy.authenticate("fixture-operator-token").await.unwrap();
    assert!(matches!(legacy.call(Syscall::ListProviderModels { provider_id: "openai".into() }).await.unwrap(),
        SyscallReply::Error { message } if message.contains("v2 is required")));
    assert_eq!(provider.received_requests().await.unwrap().len(), 1);
    task.abort();
    let _ = task.await;
}
