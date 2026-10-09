use agent_sdk::{
    sign_authority_principal, AuthorityCommand, KernelClient, PrincipalProofError, SdkError,
    WireErrorCode,
};
use kernel::syscall_server::SyscallServer;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::sync::Arc;

#[tokio::test]
async fn sdk_uses_own_key_proof_and_never_falls_back_to_node_or_token_authority() {
    let kernel = Arc::new(kernel::AgentKernelImpl::new().unwrap());
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let serving = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(address).await.unwrap();
    let node = client
        .node_info()
        .await
        .unwrap()
        .control
        .expect("current node identity/control");
    let command = AuthorityCommand::ClaimOwnership {
        operation_id: "00000000-0000-0000-0000-000000000010".into(),
        agent_id: "00000000-0000-0000-0000-000000000011".into(),
        owner_node_id: node.identity.node_id.clone(),
        ttl_seconds: 60,
        expected_fencing_token: None,
        actor: format!("system-node:{}", node.identity.node_id),
        reason: "SDK CI proof fixture".into(),
        proposed_at: chrono::Utc::now(),
    };
    assert!(matches!(
        client
            .submit_signed_authority_command(command.clone())
            .await,
        Err(SdkError::Configuration(_))
    ));
    let document = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let independent = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    assert_ne!(
        independent
            .public_key()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        node.identity.public_key
    );
    let signed = sign_authority_principal(
        command.clone(),
        "00000000-0000-0000-0000-000000000100",
        "00000000-0000-0000-0000-000000000900",
        1,
        chrono::Utc::now(),
        |payload| Ok(independent.sign(payload).as_ref().to_vec()),
    )
    .unwrap();
    let principal = agent_sdk::AuthorityPrincipal {
        principal_id: "00000000-0000-0000-0000-000000000900".into(),
        public_key: independent
            .public_key()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        kind: agent_sdk::AuthorityPrincipalKind::Operator,
        tenant_id: None,
        allowed_command_classes: [agent_sdk::AuthorityCommandClass::Ownership]
            .into_iter()
            .collect(),
        generation: 1,
        revoked: false,
        expires_at: None,
    };
    let registry = std::collections::BTreeMap::from([(principal.principal_id.clone(), principal)]);
    assert!(kernel::cluster_principal::verify_authority_principal(
        &signed,
        "00000000-0000-0000-0000-000000000100",
        &registry,
        chrono::Utc::now()
    )
    .is_ok());
    assert_eq!(
        kernel::cluster_principal::verify_authority_principal(
            &signed,
            "00000000-0000-0000-0000-000000000101",
            &registry,
            chrono::Utc::now()
        ),
        Err(PrincipalProofError::InvalidProof)
    );
    match client.submit_signed_authority_command(signed).await {
        Err(SdkError::Wire { code: WireErrorCode::AuthorizationDenied, message, retryable: false }) => assert_eq!(message, PrincipalProofError::Missing.to_string()),
        result => panic!("default authority must not silently accept an independent quorum operation: {result:?}"),
    }
    assert!(matches!(
        client
            .submit_authority_command_with_signer(
                command,
                "00000000-0000-0000-0000-000000000100",
                "00000000-0000-0000-0000-000000000900",
                1,
                |_| Err(PrincipalProofError::InvalidSignature),
            )
            .await,
        Err(SdkError::Configuration(_))
    ));
    assert!(kernel
        .cluster_control
        .agent_ownerships(None, 10)
        .unwrap()
        .is_empty());
    client.close().await.unwrap();
    serving.abort();
    let _ = serving.await;
}
