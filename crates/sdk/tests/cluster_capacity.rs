use agent_sdk::{ClusterClient, KernelClient, Placement, SdkError, WireErrorCode};
use kernel::syscall_server::SyscallServer;
use std::sync::Arc;

#[tokio::test]
async fn unsigned_compatible_node_info_parses_but_cannot_place() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let root = tempfile::tempdir().unwrap();
        let kernel = Arc::new(
            kernel::AgentKernelImpl::with_db_path(&root.path().join("unsigned.db")).unwrap(),
        );
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let serving = tokio::spawn(server.serve());
        let mut direct = KernelClient::connect(address).await.unwrap();
        let legacy = direct.node_info().await.unwrap();
        assert!(
            legacy.observed_at.is_none()
                && legacy.signature_hex.is_none()
                && legacy.signed_capacity.is_none()
        );
        let mut client = ClusterClient::connect(&[address.to_string()])
            .await
            .unwrap();
        let error = client
            .create_agent(
                "unsigned",
                "must not place",
                None,
                None,
                None,
                Placement::LeastLoaded,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            SdkError::Wire {
                code: WireErrorCode::Unavailable,
                retryable: true,
                ..
            }
        ));
        assert_eq!(direct.node_info().await.unwrap().agent_count, 0);
        direct.close().await.unwrap();
        drop(client);
        serving.abort();
        let _ = serving.await;
        drop(kernel);
        root.close().unwrap();
    })
    .await
    .expect("unsigned compatibility fixture is bounded");
}
