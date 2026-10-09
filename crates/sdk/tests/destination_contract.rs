use std::sync::Arc;

use agent_sdk::{KernelClient, SdkError, WireErrorCode};
use kernel::destination_authority::DestinationAuthorityMode;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;

#[tokio::test]
async fn destination_discovery_precedes_credentials_and_does_not_claim_admission() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await.unwrap().with_auth_token("contract-fixture-only");
        let address = server.local_addr().unwrap();
        let serving = tokio::spawn(server.serve());
        let mut client = KernelClient::connect(address).await.unwrap();
        let description = client.destination_contract().await.unwrap();
        assert_eq!(description.version, 1);
        assert_eq!(description.supported_mode, DestinationAuthorityMode::OnlineQuorumV1);
        assert_eq!(description.required_mode, None);
        assert_eq!(description.cluster_id, None);
        assert!(!description.installation_bound);
        assert!(!description.quorum_configured);
        assert!(!description.admission_supported);
        assert!(matches!(client.list_agents().await, Err(SdkError::Wire {
            code: WireErrorCode::AuthenticationRequired, ..
        })));
        client.authenticate("contract-fixture-only").await.unwrap();
        assert!(client.list_agents().await.unwrap().is_empty());
        client.close().await.unwrap();
        serving.abort();
        let _ = serving.await;
        drop(kernel);
    }).await.expect("actual unauthenticated discovery is bounded");
}

#[tokio::test]
async fn a_v1_connection_cannot_discover_or_silently_downgrade_the_destination_contract() {
    use kernel::syscall_server::{Syscall, SyscallClient, SyscallReply};
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await.unwrap().with_auth_token("contract-fixture-only");
        let address = server.local_addr().unwrap();
        let serving = tokio::spawn(server.serve());
        let mut client = SyscallClient::connect(address).await.unwrap();
        assert!(matches!(client.call(Syscall::Hello { protocol_version: 1 }).await.unwrap(),
            SyscallReply::Hello { .. }));
        assert!(matches!(client.call(Syscall::GetDestinationContract).await.unwrap(),
            SyscallReply::Error { .. }));
        assert!(matches!(client.call(Syscall::ListAgents).await.unwrap(),
            SyscallReply::Error { .. }));
        assert!(matches!(client.call(Syscall::Hello { protocol_version: 2 }).await.unwrap(),
            SyscallReply::Hello { .. }));
        assert!(matches!(client.call(Syscall::GetDestinationContract).await.unwrap(),
            SyscallReply::DestinationContract { description } if !description.admission_supported));
        assert!(matches!(client.call(Syscall::ListAgents).await.unwrap(),
            SyscallReply::TypedError { code: WireErrorCode::AuthenticationRequired, .. }));
        client.close().await.unwrap();
        serving.abort();
        let _ = serving.await;
        drop(kernel);
    }).await.expect("mixed-version discovery refuses downgrade within its bound");
}
