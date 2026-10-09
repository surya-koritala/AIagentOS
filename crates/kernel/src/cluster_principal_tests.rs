use crate::cluster_principal::{
    fixture_operator, fixture_signed, AuthorityCommandClass, AuthorityPrincipalKind,
    PrincipalProofError, FIXTURE_CLUSTER_ID,
};
use openraft::storage::RaftStateMachine;

fn principal_entry(
    index: u64,
    command: AuthorityCommand,
) -> openraft::Entry<ClusterRaftTypeConfig> {
    openraft::Entry {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
        payload: openraft::EntryPayload::Normal(command),
    }
}

async fn principal_fixture() -> (
    TestPeer,
    ClusterRaftNode,
    Arc<SqliteContextManager>,
    crate::cluster_consensus::ClusterRaftStateMachine,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let peer = test_peer(&test_ca(), 1);
    let context = Arc::new(SqliteContextManager::in_memory().expect("isolated authority storage"));
    let (_, mut state) =
        open_cluster_raft_storage(context.clone()).expect("open authority storage");
    state
        .apply([principal_entry(
            1,
            AuthorityCommand::Initialize {
                operation_id: FIXTURE_CLUSTER_ID.into(),
                genesis: AuthorityGenesis {
                    cluster_id: FIXTURE_CLUSTER_ID.into(),
                    operator_principals: vec![fixture_operator()],
                    members: vec![AuthorityGenesisMember {
                        node_id: peer.application_node_id.clone(),
                        public_key: peer.application_identity_public_key.clone(),
                        fingerprint: crate::cluster_control::sha256_hex(
                            &crate::cluster_control::hex_decode(
                                &peer.application_identity_public_key,
                            )
                            .unwrap(),
                        ),
                        endpoint: "127.0.0.1:7001".into(),
                        tls_server_certificate_fingerprint: None,
                        server_version: env!("CARGO_PKG_VERSION").into(),
                        min_protocol_version: 1,
                        protocol_version: 2,
                    }],
                },
                proposed_at: chrono::Utc::now(),
            },
        )])
        .await
        .expect("initialize replicated fixture");
    let node = ClusterRaftNode {
        identity_public_key: peer.application_identity_public_key.clone(),
        ..Default::default()
    };
    (peer, node, context, state)
}

fn principal_claim(peer: &TestPeer) -> AuthorityCommand {
    AuthorityCommand::ClaimOwnership {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: Uuid::new_v4().to_string(),
        owner_node_id: peer.application_node_id.clone(),
        ttl_seconds: 60,
        expected_fencing_token: None,
        actor: authority_system_actor(&peer.application_node_id),
        reason: "principal CI fixture".into(),
        proposed_at: chrono::Utc::now(),
    }
}

fn proof_rejection(response: &AuthorityResponse, expected: PrincipalProofError) {
    assert!(
        matches!(response, AuthorityResponse::Rejected { reason: crate::cluster_consensus::AuthorityRejection::PrincipalAuthentication(actual), .. } if *actual == expected),
        "unexpected redacted rejection: {response:?}"
    );
}

#[tokio::test]
async fn principal_history_requires_current_reader_and_retains_real_receipt14_before_any_write() {
    let (peer, _, context, mut state) = principal_fixture().await;
    {
        let connection = context.locked_conn();
        let metadata = crate::schema::read_storage_metadata(&connection).unwrap();
        assert_eq!(metadata.schema_version, crate::schema::CURRENT_SCHEMA_VERSION);
        assert_eq!(metadata.min_reader_schema_version, crate::schema::MIN_READER_SCHEMA_VERSION);
        let migration: String = connection.query_row("SELECT name FROM schema_migrations WHERE version=14", [], |row| row.get(0)).unwrap();
        assert_eq!(migration, "retain-actor-bound-cluster-operation-receipts");
        let receipt_table: i64 = connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='cluster_operation_receipts'", [], |row| row.get(0)).unwrap();
        assert_eq!(receipt_table, 1);
        let refusal = crate::schema::preflight_for_reader(&connection, 14).unwrap_err();
        assert!(matches!(refusal, crate::ContextError::DatabaseTooNew { found, supported: 14 } if found == crate::schema::CURRENT_SCHEMA_VERSION));
        connection.pragma_update(None, "user_version", 14).unwrap();
        connection.execute("UPDATE storage_meta SET schema_version=14,min_reader_schema_version=14", []).unwrap();
    }
    let before = read_initialized_authority_view(&context).unwrap();
    let signed = fixture_signed(principal_claim(&peer), FIXTURE_CLUSTER_ID);
    assert!(state.apply([principal_entry(2, signed)]).await.is_err());
    let after = read_initialized_authority_view(&context).unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn compromised_node_keys_cannot_commit_without_an_enrolled_principal() {
    let (peer, node, context, mut state) = principal_fixture().await;
    let command = principal_claim(&peer);
    let delegation = test_authority_delegation(&peer, &command);
    let view = read_initialized_authority_view(&context).unwrap();
    verify_authority_delegation(&command, &delegation, 1, &node, &view, chrono::Utc::now())
        .expect("compromised node still owns both valid node credentials");
    assert_eq!(
        crate::cluster_principal::verify_authority_principal_view(
            &command,
            &view,
            chrono::Utc::now()
        ),
        Err(PrincipalProofError::Missing)
    );
    let result = state.apply([principal_entry(2, command)]).await.unwrap();
    proof_rejection(&result[0], PrincipalProofError::Missing);
    drop(state);
    let (_, reopened) = open_cluster_raft_storage(context.clone()).unwrap();
    assert!(read_initialized_authority_view(&context)
        .unwrap()
        .ownerships
        .is_empty());
    drop(reopened);
}

#[tokio::test]
async fn revoked_principal_signature_is_rejected_at_the_leader() {
    let (peer, node, context, mut state) = principal_fixture().await;
    let document =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let mut principal = fixture_operator();
    principal.principal_id = Uuid::new_v4().to_string();
    principal.public_key = crate::cluster_control::hex_encode(key.public_key().as_ref());
    principal.allowed_command_classes = BTreeSet::from([AuthorityCommandClass::Ownership]);
    let enrollment = fixture_signed(
        AuthorityCommand::EnrollPrincipal {
            operation_id: Uuid::new_v4().to_string(),
            principal: principal.clone(),
            expected_generation: None,
            actor: authority_system_actor(&peer.application_node_id),
            reason: "enroll ephemeral CI principal".into(),
            proposed_at: chrono::Utc::now(),
        },
        FIXTURE_CLUSTER_ID,
    );
    assert!(matches!(
        state.apply([principal_entry(2, enrollment)]).await.unwrap()[0],
        AuthorityResponse::PrincipalUpdated { .. }
    ));
    let signed = crate::cluster_principal::sign_authority_principal(
        principal_claim(&peer),
        FIXTURE_CLUSTER_ID,
        &principal.principal_id,
        1,
        chrono::Utc::now(),
        |payload| Ok(key.sign(payload).as_ref().to_vec()),
    )
    .unwrap();
    crate::cluster_principal::verify_authority_principal_view(
        &signed,
        &read_initialized_authority_view(&context).unwrap(),
        chrono::Utc::now(),
    )
    .unwrap();
    let revoke = fixture_signed(
        AuthorityCommand::RevokePrincipal {
            operation_id: Uuid::new_v4().to_string(),
            principal_id: principal.principal_id.clone(),
            expected_generation: 1,
            actor: authority_system_actor(&peer.application_node_id),
            reason: "revoke ephemeral CI principal".into(),
            proposed_at: chrono::Utc::now(),
        },
        FIXTURE_CLUSTER_ID,
    );
    state.apply([principal_entry(3, revoke)]).await.unwrap();
    let view = read_initialized_authority_view(&context).unwrap();
    let delegation = test_authority_delegation(&peer, &signed);
    verify_authority_delegation(&signed, &delegation, 1, &node, &view, chrono::Utc::now()).unwrap();
    assert_eq!(
        crate::cluster_principal::verify_authority_principal_view(
            &signed,
            &view,
            chrono::Utc::now()
        ),
        Err(PrincipalProofError::Revoked)
    );
    proof_rejection(
        &state.apply([principal_entry(4, signed)]).await.unwrap()[0],
        PrincipalProofError::Revoked,
    );
    assert!(read_initialized_authority_view(&context)
        .unwrap()
        .ownerships
        .is_empty());
}

#[tokio::test]
async fn principal_signature_over_a_different_command_digest_fails_closed() {
    let (peer, node, context, mut state) = principal_fixture().await;
    let mut signed = fixture_signed(principal_claim(&peer), FIXTURE_CLUSTER_ID);
    let AuthorityCommand::Authorized { command, .. } = &mut signed else {
        unreachable!()
    };
    let AuthorityCommand::ClaimOwnership { agent_id, .. } = command.as_mut() else {
        unreachable!()
    };
    *agent_id = Uuid::new_v4().to_string();
    let delegation = test_authority_delegation(&peer, &signed);
    let view = read_initialized_authority_view(&context).unwrap();
    verify_authority_delegation(&signed, &delegation, 1, &node, &view, chrono::Utc::now())
        .expect("node can freshly sign the tampered command");
    assert_eq!(
        crate::cluster_principal::verify_authority_principal_view(
            &signed,
            &view,
            chrono::Utc::now()
        ),
        Err(PrincipalProofError::WrongDigest)
    );
    proof_rejection(
        &state.apply([principal_entry(2, signed)]).await.unwrap()[0],
        PrincipalProofError::WrongDigest,
    );
    assert!(read_initialized_authority_view(&context)
        .unwrap()
        .ownership_audit
        .is_empty());
}

#[tokio::test]
async fn principal_expiry_class_unknown_signature_and_replay_use_current_registry() {
    let (peer, _, context, mut state) = principal_fixture().await;
    let signed = fixture_signed(principal_claim(&peer), FIXTURE_CLUSTER_ID);
    let view = read_initialized_authority_view(&context).unwrap();
    let mut unknown = view.clone();
    unknown.principals.clear();
    assert_eq!(
        crate::cluster_principal::verify_authority_principal_view(
            &signed,
            &unknown,
            chrono::Utc::now()
        ),
        Err(PrincipalProofError::Unknown)
    );
    assert_eq!(
        crate::cluster_principal::verify_authority_principal_view(
            &signed,
            &view,
            chrono::Utc::now() + chrono::TimeDelta::seconds(31)
        ),
        Err(PrincipalProofError::Expired)
    );
    let mut wrong_class = view.clone();
    wrong_class
        .principals
        .get_mut(&fixture_operator().principal_id)
        .unwrap()
        .allowed_command_classes = BTreeSet::from([AuthorityCommandClass::Membership]);
    assert_eq!(
        crate::cluster_principal::verify_authority_principal_view(
            &signed,
            &wrong_class,
            chrono::Utc::now()
        ),
        Err(PrincipalProofError::WrongCommandClass)
    );
    let mut invalid = signed.clone();
    if let AuthorityCommand::Authorized {
        principal_proof, ..
    } = &mut invalid
    {
        principal_proof.signature_hex = "00".repeat(64);
    }
    assert_eq!(
        crate::cluster_principal::verify_authority_principal_view(
            &invalid,
            &view,
            chrono::Utc::now()
        ),
        Err(PrincipalProofError::InvalidSignature)
    );
    let first = state
        .apply([principal_entry(2, signed.clone())])
        .await
        .unwrap();
    assert!(matches!(
        first[0],
        AuthorityResponse::OwnershipUpdated {
            replayed: false,
            ..
        }
    ));
    let AuthorityCommand::Authorized { command, .. } = signed else {
        unreachable!()
    };
    let mut replacement = fixture_operator();
    replacement.generation = 2;
    let enrollment = fixture_signed(
        AuthorityCommand::EnrollPrincipal {
            operation_id: Uuid::new_v4().to_string(),
            principal: replacement,
            expected_generation: Some(1),
            actor: authority_system_actor(&peer.application_node_id),
            reason: "same-principal generation update".into(),
            proposed_at: chrono::Utc::now(),
        },
        FIXTURE_CLUSTER_ID,
    );
    state.apply([principal_entry(3, enrollment)]).await.unwrap();
    let fresh =
        crate::cluster_principal::fixture_signed_generation(*command, FIXTURE_CLUSTER_ID, 2);
    let replay = state.apply([principal_entry(4, fresh)]).await.unwrap();
    assert!(matches!(
        replay[0],
        AuthorityResponse::OwnershipUpdated { replayed: true, .. }
    ));
    let after = read_initialized_authority_view(&context).unwrap();
    assert_eq!(after.ownership_audit.len(), 1);
    assert_eq!(
        after.ownership_audit[0].actor,
        format!("principal:{}", fixture_operator().principal_id)
    );
}

#[tokio::test]
async fn tenant_principal_ownership_scope_survives_release_and_rejects_foreign_and_unscoped_rows() {
    let (peer, _, context, mut state) = principal_fixture().await;
    let document =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let mut principal = fixture_operator();
    principal.principal_id = Uuid::new_v4().to_string();
    principal.public_key = crate::cluster_control::hex_encode(key.public_key().as_ref());
    principal.kind = AuthorityPrincipalKind::Tenant;
    principal.tenant_id = Some(Uuid::new_v4().to_string());
    principal.allowed_command_classes = BTreeSet::from([AuthorityCommandClass::Ownership]);
    let enrollment = fixture_signed(
        AuthorityCommand::EnrollPrincipal {
            operation_id: Uuid::new_v4().to_string(),
            principal: principal.clone(),
            expected_generation: None,
            actor: authority_system_actor(&peer.application_node_id),
            reason: "tenant scope fixture".into(),
            proposed_at: chrono::Utc::now(),
        },
        FIXTURE_CLUSTER_ID,
    );
    state.apply([principal_entry(2, enrollment)]).await.unwrap();
    let claim = principal_claim(&peer);
    let agent = crate::cluster_principal::ownership_agent(&claim)
        .unwrap()
        .to_owned();
    let signed = crate::cluster_principal::sign_authority_principal(
        claim,
        FIXTURE_CLUSTER_ID,
        &principal.principal_id,
        1,
        chrono::Utc::now(),
        |payload| Ok(key.sign(payload).as_ref().to_vec()),
    )
    .unwrap();
    state.apply([principal_entry(3, signed)]).await.unwrap();
    let view = read_initialized_authority_view(&context).unwrap();
    assert_eq!(
        view.ownership_tenant_scopes.get(&agent),
        principal.tenant_id.as_ref()
    );
    let release = AuthorityCommand::ReleaseOwnership {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.clone(),
        owner_node_id: peer.application_node_id.clone(),
        fencing_token: 1,
        actor: authority_system_actor(&peer.application_node_id),
        reason: "release retains tenant scope".into(),
        proposed_at: chrono::Utc::now(),
    };
    let signed = crate::cluster_principal::sign_authority_principal(
        release.clone(),
        FIXTURE_CLUSTER_ID,
        &principal.principal_id,
        1,
        chrono::Utc::now(),
        |payload| Ok(key.sign(payload).as_ref().to_vec()),
    )
    .unwrap();
    state.apply([principal_entry(4, signed)]).await.unwrap();
    assert_eq!(
        read_initialized_authority_view(&context)
            .unwrap()
            .ownership_tenant_scopes
            .get(&agent),
        principal.tenant_id.as_ref()
    );
    let mut foreign = principal.clone();
    foreign.tenant_id = Some(Uuid::new_v4().to_string());
    assert_eq!(
        crate::cluster_principal::verify_tenant_ownership_scope(
            &foreign,
            &release,
            &view.ownership_tenant_scopes,
            true
        ),
        Err(PrincipalProofError::TenantScope)
    );
    assert_eq!(
        crate::cluster_principal::verify_tenant_ownership_scope(
            &principal,
            &release,
            &BTreeMap::new(),
            true
        ),
        Err(PrincipalProofError::TenantScope)
    );
    let mut membership = principal_claim(&peer);
    if let AuthorityCommand::ClaimOwnership {
        expected_fencing_token,
        ..
    } = &mut membership
    {
        *expected_fencing_token = Some(1);
    }
    assert_eq!(
        crate::cluster_principal::verify_tenant_ownership_scope(
            &principal,
            &membership,
            &BTreeMap::new(),
            true
        ),
        Err(PrincipalProofError::TenantScope)
    );
}
