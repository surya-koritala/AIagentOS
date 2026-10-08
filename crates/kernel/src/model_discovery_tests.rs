use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::auth::{Principal, Role};
use crate::connector::{
    AgentConnector, AgentConnectorImpl, LlmProviderAdapter, LlmSession, ProviderCapabilities,
    ProviderType, StandardMessage,
};
use crate::model_discovery::MAX_DISCOVERED_MODELS;
use crate::syscall_server::{dispatch, dispatch_scoped, Syscall, SyscallReply, WireErrorCode};
use crate::{AgentKernelImpl, ConnectorError, ProviderId};
use tokio_util::sync::CancellationToken;

struct CatalogFixture {
    id: ProviderId,
    calls: Arc<AtomicUsize>,
    models: Vec<String>,
    pending: bool,
    fail: bool,
}

#[async_trait::async_trait]
impl LlmProviderAdapter for CatalogFixture {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn name(&self) -> &str {
        "catalog fixture"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            model_discovery: true,
            ..Default::default()
        }
    }
    async fn is_available(&self) -> bool {
        panic!("discovery must not probe health")
    }
    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        panic!("discovery must not create an inference session")
    }
    async fn list_models(&self) -> Result<Vec<String>, ConnectorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.pending {
            std::future::pending::<()>().await;
        }
        if self.fail {
            return Err(ConnectorError::ProtocolError(
                "private-provider-secret".into(),
            ));
        }
        Ok(self.models.clone())
    }
    fn translate_to_provider(&self, _: &StandardMessage) -> serde_json::Value {
        unreachable!()
    }
    fn translate_from_provider(&self, _: &serde_json::Value) -> Option<StandardMessage> {
        unreachable!()
    }
}

#[tokio::test]
async fn model_discovery_third_party_catalogs_are_revalidated_and_cancellable() {
    let connector = AgentConnectorImpl::new();
    let calls = Arc::new(AtomicUsize::new(0));
    for (id, models) in [
        ("invalid", vec!["private\nsecret".into()]),
        ("overflow", vec!["a".into(); MAX_DISCOVERED_MODELS + 1]),
    ] {
        connector
            .register_provider(Arc::new(CatalogFixture {
                id: id.into(),
                calls: calls.clone(),
                models,
                pending: false,
                fail: false,
            }))
            .unwrap();
        assert!(matches!(
            connector
                .list_provider_models(&id.into(), &CancellationToken::new())
                .await,
            Err(ConnectorError::ProtocolError(_))
        ));
    }
    connector
        .register_provider(Arc::new(CatalogFixture {
            id: "pending".into(),
            calls: calls.clone(),
            models: vec![],
            pending: true,
            fail: false,
        }))
        .unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(
        connector
            .list_provider_models(&"pending".into(), &cancellation)
            .await,
        Err(ConnectorError::Cancelled(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let cancellation = CancellationToken::new();
    let pending_id = "pending".to_string();
    let result = connector.list_provider_models(&pending_id, &cancellation);
    tokio::pin!(result);
    tokio::select! {
        reply = &mut result => panic!("pending adapter completed: {reply:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
    }
    cancellation.cancel();
    assert!(matches!(result.await, Err(ConnectorError::Cancelled(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let unsupported =
        ConnectorError::unsupported_feature("legacy".into(), "model discovery unsupported");
    assert!(!crate::connector::is_transient(&unsupported));
    assert!(unsupported.request_id().is_none());
}

#[tokio::test]
async fn model_discovery_requires_system_scope_before_provider_io() {
    let kernel = AgentKernelImpl::new().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    kernel
        .register_provider(Arc::new(CatalogFixture {
            id: "catalog".into(),
            calls: calls.clone(),
            models: vec!["z-model".into(), "a-model".into()],
            pending: false,
            fail: false,
        }))
        .unwrap();
    let tenant = kernel.create_tenant("catalog-tenant").await.unwrap();
    for role in [Role::ReadOnly, Role::User, Role::Admin] {
        let user = kernel
            .register_user(
                &tenant,
                role.as_str(),
                &format!("{}@catalog.test", role.as_str()),
                role,
            )
            .await
            .unwrap();
        let principal = Principal {
            user_id: user,
            tenant_id: tenant.clone(),
            role,
            credential: None,
        };
        for provider_id in ["catalog", "absent", "invalid?credential=secret"] {
            let reply = dispatch_scoped(
                &kernel,
                Syscall::ListProviderModels {
                    provider_id: provider_id.into(),
                },
                Some(&principal),
            )
            .await;
            let rendered = serde_json::to_string(&reply).unwrap();
            assert!(!rendered.contains("secret"));
            assert!(matches!(reply, SyscallReply::Error { .. }));
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let reply = dispatch(
        &kernel,
        Syscall::ListProviderModels {
            provider_id: "catalog".into(),
        },
    )
    .await;
    match reply {
        SyscallReply::ProviderModels { catalog } => {
            assert_eq!(catalog.provider_id, "catalog");
            assert_eq!(catalog.models, vec!["a-model", "z-model"]);
        }
        other => panic!("expected catalog: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn model_discovery_wire_failures_are_typed_and_redact_adapter_prose() {
    let kernel = AgentKernelImpl::new().unwrap();
    kernel
        .register_provider(Arc::new(CatalogFixture {
            id: "failing".into(),
            calls: Arc::new(AtomicUsize::new(0)),
            models: vec![],
            pending: false,
            fail: true,
        }))
        .unwrap();
    for (id, expected) in [
        ("failing", WireErrorCode::InvalidRequest),
        ("absent", WireErrorCode::NotFound),
        ("x?key=secret", WireErrorCode::InvalidArgument),
    ] {
        let reply = dispatch(
            &kernel,
            Syscall::ListProviderModels {
                provider_id: id.into(),
            },
        )
        .await;
        assert!(!serde_json::to_string(&reply).unwrap().contains("secret"));
        assert!(
            matches!(reply, SyscallReply::TypedError { code, retryable: false, .. } if code == expected)
        );
    }
}
