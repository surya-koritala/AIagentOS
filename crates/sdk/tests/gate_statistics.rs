use std::sync::Arc;

use agent_sdk::{GateStats, KernelClient, SdkError, WireErrorCode};
use kernel::auth::Role;
use kernel::syscall_server::{SyscallReply, SyscallServer};
use kernel::{AgentConfig, AgentKernelImpl, Priority};

fn config(name: &str) -> AgentConfig {
    AgentConfig { name: name.into(), task: "counter fixture".into(), llm_provider: "stub".into(),
        permission_profile: "read-only".into(), priority: Priority::default(), sandbox_config: None }
}

#[tokio::test]
async fn sdk_agent_counter_accessor_is_readonly_owned_and_isolated() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let tenant_a = kernel.create_tenant("sdk-counter-a").await.unwrap();
    let tenant_b = kernel.create_tenant("sdk-counter-b").await.unwrap();
    let reader = kernel.register_user(&tenant_a, "reader", "reader@sdk-counter.invalid", Role::ReadOnly).await.unwrap();
    let reader_key = kernel.issue_api_key(&reader, "counter-read").await.unwrap();
    let own = kernel.create_agent_for_tenant(&tenant_a, config("own")).await.unwrap();
    let foreign = kernel.create_agent_for_tenant(&tenant_b, config("foreign")).await.unwrap();
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0").await.unwrap().with_auth_token("sdk-counter-system");
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut system = KernelClient::connect(address).await.unwrap();
    system.authenticate("sdk-counter-system").await.unwrap();
    assert!(system.call_tool(own.id.to_string(), "write_file", serde_json::json!({"path":"counter-never-written.txt","content":"x"})).await.is_err());
    for _ in 0..2 {
        assert!(system.call_tool(foreign.id.to_string(), "write_file", serde_json::json!({"path":"counter-never-written.txt","content":"x"})).await.is_err());
    }
    let mut client = KernelClient::connect(address).await.unwrap();
    client.authenticate(reader_key).await.unwrap();
    let own_stats = client.agent_gate_stats(own.id.to_string()).await.unwrap();
    assert_eq!(own_stats, GateStats { denied_capability: 1, ..Default::default() });
    assert_eq!(client.agent_info(own.id.to_string()).await.unwrap().gate_decisions, own_stats);
    for id in [foreign.id, uuid::Uuid::new_v4()] {
        assert!(matches!(client.agent_gate_stats(id.to_string()).await, Err(SdkError::Wire {
            code: WireErrorCode::AuthorizationDenied, retryable: false, ..
        })));
    }
    assert!(matches!(client.gate_stats().await, Err(SdkError::Wire {
        code: WireErrorCode::AuthorizationDenied, ..
    })));
    let description = client.describe_protocol().await.unwrap();
    assert!(description.features.contains(&"agent_gate_statistics".to_string()));
    client.close().await.unwrap();
    system.close().await.unwrap();
    task.abort();
    let _ = task.await;
}

#[test]
fn sdk_maps_all_eight_distinct_counter_fields_from_the_wire_fixture() {
    let reply: SyscallReply = serde_json::from_str(include_str!("../../../protocol/v2/agent-info.json")).unwrap();
    let SyscallReply::AgentInfo { gate_decisions, .. } = reply else { panic!("expected AgentInfo") };
    let stats: GateStats = gate_decisions.into();
    assert_eq!(serde_json::to_value(stats).unwrap(), serde_json::json!({
        "allowed":1,"denied_capability":2,"denied_mac":3,"denied_approval":4,
        "denied_cgroup":5,"denied_unknown":6,"denied_namespace":7,"audited":1,
    }));
}
