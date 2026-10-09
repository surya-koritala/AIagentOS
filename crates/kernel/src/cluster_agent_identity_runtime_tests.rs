use crate::cluster_agent_identity::{
    AgentIdentityRecord, AgentIdentityScope, AgentIdentityState, DestinationCreationAdmission,
};
use crate::cluster_consensus::AuthorityRejection;
use openraft::storage::RaftStateMachine;
use openraft::RaftSnapshotBuilder;

async fn identity_commit(
    runtimes: &[Option<ClusterRaftRuntime>],
    peers: &[TestPeer],
    source: usize,
    signed: AuthorityCommand,
) -> io::Result<AuthorityResponse> {
    let delegation = test_authority_delegation(&peers[source], &signed);
    tokio::time::timeout(
        Duration::from_secs(10),
        runtimes[source]
            .as_ref()
            .unwrap()
            .authority_handle()
            .commit(signed, delegation),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "identity quorum fixture timed out"))?
}

fn tenant_identity_command(
    command: AuthorityCommand,
    principal: &crate::cluster_principal::AuthorityPrincipal,
    key: &ring::signature::Ed25519KeyPair,
) -> AuthorityCommand {
    crate::cluster_principal::sign_authority_principal(
        command,
        crate::cluster_principal::FIXTURE_CLUSTER_ID,
        &principal.principal_id,
        principal.generation,
        chrono::Utc::now(),
        |payload| Ok(key.sign(payload).as_ref().to_vec()),
    )
    .unwrap()
}

fn updated_identity(
    response: AuthorityResponse,
) -> (AgentIdentityRecord, LogId<ClusterRaftNodeId>, bool) {
    match response {
        AuthorityResponse::AgentIdentityUpdated {
            identity,
            log_id,
            replayed,
            ..
        } => (identity, log_id, replayed),
        other => panic!("expected committed immutable identity, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immutable_identity_real_majority_duplicate_failover_receipt_migration_and_restore() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = test_ca();
    let peers = (1..=3)
        .map(|node_id| test_peer(&ca, node_id))
        .collect::<Vec<_>>();
    let initial_listeners = listeners(3).await;
    let members = member_map(&peers, &initial_listeners);
    let configs = peers
        .iter()
        .zip(&initial_listeners)
        .map(|(peer, listener)| {
            runtime_config(peer, listener, &members, "immutable-identity-majority")
        })
        .collect::<Vec<_>>();
    let directory = TempDir::new().unwrap();
    let contexts = (1..=3)
        .map(|node| if node == 1 {
            Arc::new(SqliteContextManager::new(&directory.path().join("node-1.db")).unwrap())
        } else { context(&directory, node) })
        .collect::<Vec<_>>();
    {
        let connection = contexts[0].locked_conn();
        connection.execute("INSERT INTO cluster_node_identity(singleton,node_id,private_key,public_key,fingerprint,created_at)
            VALUES(1,?1,?2,?3,?4,?5)", rusqlite::params![peers[0].application_node_id,
            peers[0].application_identity_pkcs8, crate::cluster_control::hex_decode(&peers[0].application_identity_public_key).unwrap(),
            crate::cluster_control::sha256_hex(&crate::cluster_control::hex_decode(&peers[0].application_identity_public_key).unwrap()), chrono::Utc::now().to_rfc3339()]).unwrap();
    }
    let security = crate::config::Config::default();
    let kernel = crate::AgentKernelImpl::with_context_manager(
        contexts[0].clone(),
        &security.budgets,
        security.mac_enforcing,
        &security.mac_rules,
    )
    .unwrap();
    let tenant = kernel
        .create_tenant("immutable identity tenant")
        .await
        .unwrap();
    let document =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let principal = crate::cluster_principal::AuthorityPrincipal {
        principal_id: Uuid::new_v4().to_string(),
        public_key: crate::cluster_control::hex_encode(key.public_key().as_ref()),
        kind: crate::cluster_principal::AuthorityPrincipalKind::Tenant,
        tenant_id: Some(tenant.clone()),
        allowed_command_classes: BTreeSet::from([
            crate::cluster_principal::AuthorityCommandClass::Ownership,
        ]),
        generation: 1,
        revoked: false,
        expires_at: None,
    };
    let mut runtimes = Vec::new();
    for ((config, listener), context) in configs
        .iter()
        .cloned()
        .zip(initial_listeners)
        .zip(&contexts)
    {
        runtimes.push(Some(
            ClusterRaftRuntime::start_on_listener(context.clone(), config, listener)
                .await
                .unwrap(),
        ));
    }
    let (first, second, third) = tokio::join!(
        runtimes[0]
            .as_ref()
            .unwrap()
            .ensure_configured_membership(true),
        runtimes[1]
            .as_ref()
            .unwrap()
            .ensure_configured_membership(true),
        runtimes[2]
            .as_ref()
            .unwrap()
            .ensure_configured_membership(true)
    );
    first.unwrap();
    second.unwrap();
    third.unwrap();
    let leader = wait_for_leader(&runtimes, None).await;
    runtimes[(leader - 1) as usize]
        .as_ref()
        .unwrap()
        .ensure_authority_initialized()
        .await
        .unwrap();
    let initialized_log = runtimes[(leader - 1) as usize]
        .as_ref()
        .unwrap()
        .metrics()
        .borrow()
        .last_applied
        .unwrap()
        .index;
    wait_for_applied(&runtimes, initialized_log, 3).await;
    let source = (leader as usize) % 3;
    let enrollment = crate::cluster_principal::fixture_signed(
        AuthorityCommand::EnrollPrincipal {
            operation_id: Uuid::new_v4().to_string(),
            principal: principal.clone(),
            expected_generation: None,
            actor: authority_system_actor(&peers[source].application_node_id),
            reason: "immutable identity tenant enrollment".into(),
            proposed_at: chrono::Utc::now(),
        },
        crate::cluster_principal::FIXTURE_CLUSTER_ID,
    );
    let enrolled = identity_commit(&runtimes, &peers, source, enrollment)
        .await
        .unwrap();
    let AuthorityResponse::PrincipalUpdated {
        log_id: enrollment_log,
        ..
    } = enrolled
    else {
        panic!("tenant enrollment rejected")
    };
    wait_for_applied(&runtimes, enrollment_log.index, 3).await;

    let agent = Uuid::new_v4();
    let creation_operation = Uuid::new_v4().to_string();
    let call = crate::syscall_server::Syscall::CreateAgent {
        agent_id: Some(agent.to_string()),
        ownership_proof: None,
        name: "majority identity".into(),
        task: "retain exact quorum identity".into(),
        provider: "stub".into(),
        profile: "standard".into(),
        priority: 3,
    };
    let prepare = AuthorityCommand::PrepareAgentIdentity {
        operation_id: creation_operation.clone(),
        agent_id: agent.to_string(),
        scope: AgentIdentityScope::Tenant {
            tenant_id: tenant.clone(),
        },
        creator_principal_id: principal.principal_id.clone(),
        creation_operation_id: creation_operation,
        creation_sha256: crate::cluster_agent_identity::creation_command_sha256(&call).unwrap(),
        owner_node_id: peers[0].application_node_id.clone(),
        ttl_seconds: 120,
        actor: authority_system_actor(&peers[source].application_node_id),
        reason: "majority exact creation reservation".into(),
        proposed_at: chrono::Utc::now(),
    };
    let first_signed = tenant_identity_command(prepare.clone(), &principal, &key);
    let second_signed = tenant_identity_command(prepare.clone(), &principal, &key);
    let (first, second) = tokio::join!(
        identity_commit(&runtimes, &peers, source, first_signed),
        identity_commit(&runtimes, &peers, source, second_signed)
    );
    let (identity, allocation_log, first_replay) = updated_identity(first.unwrap());
    let (duplicate, _, second_replay) = updated_identity(second.unwrap());
    assert_eq!(identity, duplicate);
    assert_ne!(first_replay, second_replay);
    wait_for_applied(&runtimes, allocation_log.index, 3).await;
    let initial_reservation = identity.reservation.clone();
    for context in &contexts {
        assert_eq!(
            read_initialized_authority_view(context)
                .unwrap()
                .agent_identities
                .len(),
            1
        );
    }
    let mut changed = prepare.clone();
    if let AuthorityCommand::PrepareAgentIdentity {
        creation_sha256, ..
    } = &mut changed
    {
        *creation_sha256 = "99".repeat(32);
    }
    assert!(matches!(
        identity_commit(
            &runtimes,
            &peers,
            source,
            tenant_identity_command(changed, &principal, &key)
        )
        .await
        .unwrap(),
        AuthorityResponse::Rejected {
            reason: AuthorityRejection::OperationIdConflict,
            ..
        }
    ));
    let mut foreign = prepare;
    if let AuthorityCommand::PrepareAgentIdentity { scope, .. } = &mut foreign {
        *scope = AgentIdentityScope::System;
    }
    assert!(identity_commit(
        &runtimes,
        &peers,
        source,
        tenant_identity_command(foreign, &principal, &key)
    )
    .await
    .is_err());

    assert_eq!(
        crate::cluster_agent_identity::begin_destination_creation(
            &contexts[0],
            &identity,
            &peers[0].application_node_id
        )
        .unwrap(),
        DestinationCreationAdmission::Create
    );
    kernel
        .create_agent_for_tenant_with_id(
            &tenant,
            agent,
            crate::AgentConfig {
                name: "majority identity".into(),
                task: "retain exact quorum identity".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: crate::Priority::default(),
                sandbox_config: None,
            },
        )
        .await
        .unwrap();
    assert!(
        !crate::cluster_agent_identity::destination_agent_is_published(&contexts[0], agent)
            .unwrap()
    );
    assert!(kernel
        .send_message(agent, "unpublished work must fail")
        .await
        .is_err());
    assert!(
        matches!(crate::syscall_server::dispatch(&kernel, crate::syscall_server::Syscall::ListAgents).await,
        crate::syscall_server::SyscallReply::Agents { agents } if agents.is_empty())
    );
    let receipt =
        crate::cluster_agent_identity::destination_creation_receipt(&kernel, &identity).unwrap();
    receipt
        .verify_signature(&peers[0].application_identity_public_key)
        .unwrap();
    let record_command = AuthorityCommand::RecordAgentCreation {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        expected_revision: 1,
        receipt: receipt.clone(),
        actor: authority_system_actor(&peers[source].application_node_id),
        reason: "retain exact destination receipt".into(),
        proposed_at: chrono::Utc::now(),
    };
    let (created, receipt_log, _) = updated_identity(
        identity_commit(
            &runtimes,
            &peers,
            source,
            tenant_identity_command(record_command, &principal, &key),
        )
        .await
        .unwrap(),
    );
    wait_for_applied(&runtimes, receipt_log.index, 3).await;
    assert_eq!(created.state, AgentIdentityState::Created);
    assert!(
        crate::cluster_agent_identity::publish_destination_identity(&contexts[0], &created)
            .is_err()
    );

    // Lose the committing leader between receipt and publication, retaining
    // both independent stores and exactly one immutable identity.
    let old_leader_index = (leader - 1) as usize;
    runtimes[old_leader_index]
        .take()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let replacement_leader = wait_for_leader(&runtimes, Some(leader)).await;
    let survivor_source = runtimes
        .iter()
        .enumerate()
        .find(|(_, runtime)| runtime.is_some())
        .unwrap()
        .0;
    let publish = AuthorityCommand::PublishAgentIdentity {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        expected_revision: 2,
        receipt_sha256: receipt.sha256().unwrap(),
        actor: authority_system_actor(&peers[survivor_source].application_node_id),
        reason: "publish after receipt-boundary leader failover".into(),
        proposed_at: chrono::Utc::now(),
    };
    let (published, publish_log, _) = updated_identity(
        identity_commit(
            &runtimes,
            &peers,
            survivor_source,
            tenant_identity_command(publish.clone(), &principal, &key),
        )
        .await
        .unwrap(),
    );
    assert_eq!(published.state, AgentIdentityState::Published);
    assert_eq!(published.reservation, initial_reservation);
    wait_for_applied(&runtimes, publish_log.index, 2).await;
    crate::cluster_agent_identity::publish_destination_identity(&contexts[0], &published).unwrap();
    assert!(
        crate::cluster_agent_identity::destination_agent_is_published(&contexts[0], agent).unwrap()
    );
    let listener = rebind_test_listener(
        configs[old_leader_index].listen_addr,
        "identity leader restart",
    )
    .await;
    runtimes[old_leader_index] = Some(
        ClusterRaftRuntime::start_on_listener(
            contexts[old_leader_index].clone(),
            configs[old_leader_index].clone(),
            listener,
        )
        .await
        .unwrap(),
    );
    wait_for_applied(&runtimes, publish_log.index, 3).await;
    let (_, _, replayed) = updated_identity(
        identity_commit(
            &runtimes,
            &peers,
            survivor_source,
            tenant_identity_command(publish, &principal, &key),
        )
        .await
        .unwrap(),
    );
    assert!(replayed);

    let backup_root = directory.path().join("identity-backups");
    contexts[0]
        .create_backup(&backup_root, "published")
        .unwrap();
    let release = AuthorityCommand::ReleaseOwnership {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        owner_node_id: peers[0].application_node_id.clone(),
        fencing_token: 1,
        actor: authority_system_actor(&peers[survivor_source].application_node_id),
        reason: "identity migration fencing fixture".into(),
        proposed_at: chrono::Utc::now(),
    };
    let released = identity_commit(
        &runtimes,
        &peers,
        survivor_source,
        tenant_identity_command(release, &principal, &key),
    )
    .await
    .unwrap();
    let AuthorityResponse::OwnershipUpdated {
        log_id: release_log,
        ..
    } = released
    else {
        panic!("release rejected")
    };
    wait_for_applied(&runtimes, release_log.index, 3).await;
    let transfer = AuthorityCommand::ClaimOwnership {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        owner_node_id: peers[1].application_node_id.clone(),
        ttl_seconds: 120,
        expected_fencing_token: Some(1),
        actor: authority_system_actor(&peers[survivor_source].application_node_id),
        reason: "identity migration newer ownership revision".into(),
        proposed_at: chrono::Utc::now(),
    };
    let transferred = identity_commit(
        &runtimes,
        &peers,
        survivor_source,
        tenant_identity_command(transfer, &principal, &key),
    )
    .await
    .unwrap();
    let AuthorityResponse::OwnershipUpdated {
        ownership,
        log_id: transfer_log,
        ..
    } = transferred
    else {
        panic!("transfer rejected")
    };
    assert_eq!(ownership.fencing_token, 2);
    wait_for_applied(&runtimes, transfer_log.index, 3).await;
    for context in &contexts {
        assert_eq!(
            read_initialized_authority_view(context)
                .unwrap()
                .agent_identities[&agent.to_string()]
                .reservation,
            initial_reservation
        );
    }
    assert!(
        crate::cluster_agent_identity::begin_destination_creation(
            &contexts[1],
            &published,
            &peers[1].application_node_id
        )
        .is_err(),
        "migration must not adopt a second destination row under the original creation receipt"
    );

    let delete = AuthorityCommand::DeleteAgentIdentity {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        expected_revision: 3,
        actor: authority_system_actor(&peers[survivor_source].application_node_id),
        reason: "permanent identity deletion tombstone".into(),
        proposed_at: chrono::Utc::now(),
    };
    let (deleted, delete_log, _) = updated_identity(
        identity_commit(
            &runtimes,
            &peers,
            survivor_source,
            tenant_identity_command(delete, &principal, &key),
        )
        .await
        .unwrap(),
    );
    wait_for_applied(&runtimes, delete_log.index, 3).await;
    assert_eq!(deleted.reservation, initial_reservation);
    assert_eq!(deleted.state, AgentIdentityState::Deleted);
    assert!(
        !crate::cluster_agent_identity::destination_agent_is_published(&contexts[0], agent)
            .unwrap()
    );
    assert!(kernel
        .send_message(agent, "deleted work must fail")
        .await
        .is_err());
    contexts[0].create_backup(&backup_root, "deleted").unwrap();
    let restore_path = directory.path().join("deleted-restore.sqlite");
    crate::storage::restore_backup(&backup_root.join("deleted"), &restore_path).unwrap();
    let restored = Arc::new(SqliteContextManager::new(&restore_path).unwrap());
    assert_eq!(
        read_initialized_authority_view(&restored)
            .unwrap()
            .agent_identities[&agent.to_string()],
        deleted
    );
    assert!(
        !crate::cluster_agent_identity::destination_agent_is_published(&restored, agent).unwrap()
    );
    let stale_path = directory.path().join("published-restore.sqlite");
    crate::storage::restore_backup(&backup_root.join("published"), &stale_path).unwrap();
    let stale = Arc::new(SqliteContextManager::new(&stale_path).unwrap());
    let (_, mut incoming) = open_cluster_raft_storage(stale.clone()).unwrap();
    let (_, mut current) = open_cluster_raft_storage(contexts[0].clone()).unwrap();
    let mut builder = current.get_snapshot_builder().await;
    let snapshot = builder.build_snapshot().await.unwrap();
    incoming
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .unwrap();
    assert_eq!(
        read_initialized_authority_view(&stale)
            .unwrap()
            .agent_identities[&agent.to_string()],
        deleted
    );
    assert!(!crate::cluster_agent_identity::destination_agent_is_published(&stale, agent).unwrap());

    // A minority cannot make a newly allocated identity visible or return a
    // successful publication. The interrupted operation remains indeterminate.
    let leader_index = (replacement_leader - 1) as usize;
    for (index, runtime) in runtimes.iter_mut().enumerate() {
        if index != leader_index {
            runtime.take().unwrap().shutdown().await.unwrap();
        }
    }
    let minority_read = tokio::time::timeout(
        Duration::from_secs(2),
        runtimes[leader_index]
            .as_ref()
            .unwrap()
            .authority_handle()
            .linearizable_view(),
    )
    .await;
    assert!(
        !matches!(minority_read, Ok(Ok(_))),
        "minority must not return a fresh majority-backed identity projection"
    );

    kernel.shutdown().await.unwrap();
    for runtime in runtimes.into_iter().flatten() {
        runtime.shutdown().await.unwrap();
    }
    drop(builder);
    drop(incoming);
    drop(current);
    drop(restored);
    drop(stale);
    drop(kernel);
    drop(contexts);
    directory.close().unwrap();
}
