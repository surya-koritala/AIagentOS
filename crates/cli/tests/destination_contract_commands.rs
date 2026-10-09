use std::process::{Command, Output};
use std::sync::Arc;

use kernel::agent::AgentKernel;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;

fn agentctl(address: &str, command: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .args(["--addr", address])
        .args(command)
        .env_remove("AGENT_SERVER_TOKEN")
        .env_remove("AGENT_SERVER_ADDR")
        .output()
        .expect("agentctl command")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agentctl_destination_contract_is_pre_auth_and_never_grants_mutation_authority() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap()
        .with_auth_token("destination-fixture-operator-token");
    let address = server.local_addr().unwrap().to_string();
    let serving = tokio::spawn(server.serve());

    let discovery = agentctl(&address, &["destination-contract"]);
    assert!(
        discovery.status.success(),
        "{}",
        String::from_utf8_lossy(&discovery.stderr)
    );
    let description: kernel::destination_authority::DestinationContractDescription =
        serde_json::from_slice(&discovery.stdout).unwrap();
    assert_eq!(description.version, 1);
    assert_eq!(
        description.supported_mode,
        kernel::destination_authority::DestinationAuthorityMode::OnlineQuorumV1
    );
    assert!(description.required_mode.is_none());
    assert!(description.cluster_id.is_none());
    assert!(!description.installation_bound);
    assert!(!description.quorum_configured);
    assert!(!description.admission_supported);
    assert!(discovery.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&discovery.stdout).contains("operator-token"));

    for command in [&["list"][..], &["create", "must-not-exist", "denied"][..]] {
        let denied = agentctl(&address, command);
        assert!(!denied.status.success());
        assert!(denied.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&denied.stderr).contains("AuthenticationRequired"),
            "{}",
            String::from_utf8_lossy(&denied.stderr)
        );
    }
    assert!(kernel.agent_manager.list_agents(None).is_empty());
    serving.abort();
    let _ = serving.await;
}
