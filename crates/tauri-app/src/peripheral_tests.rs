use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use kernel::resources::{ResourceBroker, ResourceProvider, ResourceType};
use kernel::tools::{ApprovalPolicy, SecurityAction, ToolBinding, ToolSecurity};
use kernel::{
    AgentConfig, AgentKernelImpl, PeripheralOperatorRequest, PeripheralRequestStatus, Priority,
    ResourceError,
};
use tokio_util::sync::CancellationToken;

use crate::{trusted_peripheral_window, AppState, DesktopClient};

struct CameraFixture(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ResourceProvider for CameraFixture {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Peripheral
    }
    fn supported_operations(&self) -> Vec<String> {
        vec!["capture_image".into()]
    }
    async fn execute(
        &self,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<serde_json::Value, ResourceError> {
        panic!("fixture must receive broker cancellation");
    }
    async fn execute_controlled(
        &self,
        operation: &str,
        _: &serde_json::Value,
        cancellation: &CancellationToken,
    ) -> Result<serde_json::Value, ResourceError> {
        assert_eq!(operation, "capture_image");
        self.0.fetch_add(1, Ordering::SeqCst);
        cancellation.cancelled().await;
        Err(ResourceError::OperationFailed(
            "peripheral use revoked".into(),
        ))
    }
}

async fn next_request(state: &AppState, count: usize) -> PeripheralOperatorRequest {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let requests = state.peripheral_requests().unwrap();
            if requests.len() >= count {
                return requests[count - 1].clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("desktop pending peripheral state")
}

async fn wait_started(started: &AtomicUsize, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while started.load(Ordering::SeqCst) < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("approved stub provider call");
}

async fn camera_call(
    kernel: Arc<AgentKernelImpl>,
    agent_id: kernel::AgentId,
    tool: &str,
) -> Result<serde_json::Value, agent_sdk::SdkError> {
    let client = DesktopClient::connect_embedded(kernel).await.unwrap();
    client
        .call_tool(
            agent_id.to_string(),
            tool,
            serde_json::json!({"device": "never-display-this-private-camera-target"}),
        )
        .await
}

#[test]
fn peripheral_decisions_require_the_exact_trusted_native_window() {
    for origin in [
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
    ] {
        assert!(trusted_peripheral_window("main", origin));
        assert!(!trusted_peripheral_window("secondary", origin));
    }
    for origin in [
        "https://example.invalid",
        "file:///tmp/approval.html",
        "http://localhost:1421",
        "http://tauri.localhost.attacker.invalid",
        "tauri://localhost:8000",
        "null",
    ] {
        assert!(!trusted_peripheral_window("main", origin));
    }
}

#[tokio::test]
async fn desktop_peripheral_stub_transcript_proves_pending_active_exact_revocation_and_stop() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let started = Arc::new(AtomicUsize::new(0));
    kernel
        .resource_broker
        .register_provider(Box::new(CameraFixture(Arc::clone(&started))))
        .unwrap();
    for name in ["camera_fixture", "alternate_camera_fixture"] {
        kernel.tool_registry.register(ToolBinding {
            name: name.into(), description: "CI controlled peripheral fixture".into(),
            parameters_schema: serde_json::json!({"type": "object", "properties": {"device": {"type": "string"}}, "required": ["device"]}),
            resource_type: ResourceType::Peripheral, operation: "capture_image".into(),
            security: ToolSecurity::argument(SecurityAction::Read, "device").with_approval(ApprovalPolicy::User).sandboxed(),
        }).unwrap();
    }
    let agent = kernel
        .create_agent_full(AgentConfig {
            name: "Desktop camera fixture".into(),
            task: "local operator contract".into(),
            llm_provider: "stub".into(),
            permission_profile: "full-access".into(),
            priority: Priority::default(),
            sandbox_config: None,
        })
        .await
        .unwrap();
    let operator = kernel.attach_local_peripheral_operator().unwrap();
    let state = AppState {
        client: DesktopClient::connect_embedded(Arc::clone(&kernel))
            .await
            .unwrap(),
        peripheral_operator: Some(operator),
    };

    let call_kernel = Arc::clone(&kernel);
    let denied =
        tokio::spawn(async move { camera_call(call_kernel, agent.id, "camera_fixture").await });
    let request = next_request(&state, 1).await;
    assert_eq!(request.status, PeripheralRequestStatus::AwaitingApproval);
    assert_eq!(request.agent_name, "Desktop camera fixture");
    assert!(!request.grant_pending);
    assert_eq!(request.active_uses, 0);
    state
        .deny_peripheral_request(&request.request_id.to_string())
        .unwrap();
    assert!(denied.await.unwrap().is_err());
    assert_eq!(started.load(Ordering::SeqCst), 0);

    let call_kernel = Arc::clone(&kernel);
    let pending =
        tokio::spawn(async move { camera_call(call_kernel, agent.id, "camera_fixture").await });
    let request = next_request(&state, 2).await;
    state
        .approve_peripheral_request(&request.request_id.to_string())
        .unwrap();
    assert!(state.peripheral_requests().unwrap()[1].grant_pending);
    let revoked = state
        .revoke_peripheral_request(&request.request_id.to_string())
        .unwrap();
    assert!(revoked.pending_grant_revoked);
    assert_eq!(revoked.active_uses_cancelled, 0);
    assert!(pending.await.unwrap().is_err());
    assert_eq!(started.load(Ordering::SeqCst), 0);
    println!(
        "pending revoke: {}",
        serde_json::to_string(&revoked).unwrap()
    );

    let mut active = Vec::new();
    for (index, tool) in [
        "camera_fixture",
        "camera_fixture",
        "alternate_camera_fixture",
    ]
    .into_iter()
    .enumerate()
    {
        let call_kernel = Arc::clone(&kernel);
        active.push(tokio::spawn(async move {
            camera_call(call_kernel, agent.id, tool).await
        }));
        let request = next_request(&state, index + 3).await;
        state
            .approve_peripheral_request(&request.request_id.to_string())
            .unwrap();
        wait_started(&started, index + 1).await;
    }
    let snapshot = state.peripheral_requests().unwrap();
    assert_eq!(snapshot[2].active_uses, 2);
    assert_eq!(snapshot[4].active_uses, 1);
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains("never-display-this-private-camera-target"));
    assert!(!encoded.contains("parameters") && !encoded.contains("device"));
    println!("active state: {encoded}");
    let revoked = state
        .revoke_peripheral_request(&snapshot[2].request_id.to_string())
        .unwrap();
    assert!(!revoked.pending_grant_revoked);
    assert_eq!(revoked.active_uses_cancelled, 2);
    println!(
        "exact active revoke: {}",
        serde_json::to_string(&revoked).unwrap()
    );
    for _ in 0..2 {
        assert!(active
            .remove(0)
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("peripheral use revoked"));
    }
    assert_eq!(state.peripheral_requests().unwrap()[4].active_uses, 1);
    state.client.stop_agent(agent.id.to_string()).await.unwrap();
    assert!(active
        .remove(0)
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("peripheral use revoked"));
    let stopped = state.peripheral_requests().unwrap();
    assert!(stopped
        .iter()
        .all(|request| !request.grant_pending && request.active_uses == 0));
    println!("stop cleanup: {}", serde_json::to_string(&stopped).unwrap());
    assert!(state
        .approve_peripheral_request("never-display-this-private-camera-target")
        .unwrap_err()
        .contains("invalid peripheral request identity"));

    let remote = AppState {
        client: DesktopClient::connect_embedded(Arc::clone(&kernel))
            .await
            .unwrap(),
        peripheral_operator: None,
    };
    assert!(remote.peripheral_requests().is_err());
    assert!(remote
        .approve_peripheral_request(&snapshot[2].request_id.to_string())
        .is_err());
    assert!(remote
        .revoke_peripheral_request(&snapshot[2].request_id.to_string())
        .is_err());
}
