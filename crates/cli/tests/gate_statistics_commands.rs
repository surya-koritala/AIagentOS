use std::process::{Command, Output};
use std::sync::Arc;

use agent_sdk::KernelClient;
use kernel::auth::Role;
use kernel::syscall_server::SyscallServer;
use kernel::{AgentConfig, AgentKernelImpl, Priority};

fn command(address: &str, token: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentctl")).args(["--addr", address, "--token", token])
        .args(args).output().unwrap()
}

fn config(name: &str) -> AgentConfig {
    AgentConfig { name: name.into(), task: "CLI counter fixture".into(), llm_provider: "stub".into(),
        permission_profile: "read-only".into(), priority: Priority::default(), sandbox_config: None }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agentctl_agent_counters_preserve_global_bytes_and_tenant_boundaries() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let tenant_a = kernel.create_tenant("cli-counter-a").await.unwrap();
    let tenant_b = kernel.create_tenant("cli-counter-b").await.unwrap();
    let reader = kernel.register_user(&tenant_a, "reader", "reader@cli-counter.invalid", Role::ReadOnly).await.unwrap();
    let key = kernel.issue_api_key(&reader, "counter-read").await.unwrap();
    let own = kernel.create_agent_for_tenant(&tenant_a, config("own")).await.unwrap();
    let foreign = kernel.create_agent_for_tenant(&tenant_b, config("foreign")).await.unwrap();
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0").await.unwrap().with_auth_token("cli-counter-system");
    let addr = server.local_addr().unwrap();
    let address = addr.to_string();
    let task = tokio::spawn(server.serve());

    // The literal captures the existing public bytes and field order.
    let global = command(&address, "cli-counter-system", &["gate-stats"]);
    assert!(global.status.success(), "{}", String::from_utf8_lossy(&global.stderr));
    assert_eq!(global.stdout, b"{\n  \"allowed\": 0,\n  \"denied_capability\": 0,\n  \"denied_mac\": 0,\n  \"denied_approval\": 0,\n  \"denied_cgroup\": 0,\n  \"denied_namespace\": 0,\n  \"denied_unknown\": 0,\n  \"audited\": 0\n}\n");

    let mut system = KernelClient::connect(addr).await.unwrap();
    system.authenticate("cli-counter-system").await.unwrap();
    for id in [own.id, foreign.id, foreign.id] {
        assert!(system.call_tool(id.to_string(), "write_file", serde_json::json!({"path":"counter-never-written.txt","content":"x"})).await.is_err());
    }
    let own_id = own.id.to_string();
    let output = command(&address, &key, &["gate-stats", &own_id]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(), serde_json::json!({
        "allowed":0,"denied_capability":1,"denied_mac":0,"denied_approval":0,
        "denied_cgroup":0,"denied_namespace":0,"denied_unknown":0,"audited":0,
    }));
    for id in [foreign.id, uuid::Uuid::new_v4()] {
        let id = id.to_string();
        let denied = command(&address, &key, &["gate-stats", &id]);
        assert!(!denied.status.success());
        assert!(denied.stdout.is_empty(), "foreign counter output leaked");
        assert!(String::from_utf8_lossy(&denied.stderr).contains("AuthorizationDenied"));
    }
    let global_denied = command(&address, &key, &["gate-stats"]);
    assert!(!global_denied.status.success());
    assert!(global_denied.stdout.is_empty());
    assert!(String::from_utf8_lossy(&global_denied.stderr).contains("AuthorizationDenied"));
    let extra = command(&address, "cli-counter-system", &["gate-stats", &own_id, "extra"]);
    assert_eq!(extra.status.code(), Some(2));
    assert!(extra.stdout.is_empty());
    let global = command(&address, "cli-counter-system", &["gate-stats"]);
    assert!(global.status.success());
    assert_eq!(global.stdout, b"{\n  \"allowed\": 0,\n  \"denied_capability\": 3,\n  \"denied_mac\": 0,\n  \"denied_approval\": 0,\n  \"denied_cgroup\": 0,\n  \"denied_namespace\": 0,\n  \"denied_unknown\": 0,\n  \"audited\": 0\n}\n");
    system.close().await.unwrap();
    task.abort();
    let _ = task.await;
}

#[test]
fn agentctl_help_documents_optional_agent_and_process_local_reset() {
    let output = Command::new(env!("CARGO_BIN_EXE_agentctl")).arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("gate-stats [AGENT_ID]"));
    assert!(help.contains("process-local and reset on restart"));
}
