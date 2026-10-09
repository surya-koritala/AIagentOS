use super::*;
use openraft::storage::RaftStateMachine;
use ring::signature::KeyPair;

struct IdentityFixture {
    state: AuthorityState,
    node: String,
    key: ring::signature::Ed25519KeyPair,
    index: u64,
    term: u64,
}

impl IdentityFixture {
    fn new() -> Self {
        let document =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let public_key = key.public_key().as_ref();
        let node = Uuid::new_v4().to_string();
        let mut state = AuthorityState::default();
        let genesis = AuthorityGenesis {
            cluster_id: crate::cluster_principal::FIXTURE_CLUSTER_ID.into(),
            operator_principals: vec![crate::cluster_principal::fixture_operator()],
            members: vec![AuthorityGenesisMember {
                node_id: node.clone(),
                public_key: crate::cluster_control::hex_encode(public_key),
                fingerprint: sha256_hex(public_key),
                tls_server_certificate_fingerprint: None,
                endpoint: "127.0.0.1:7111".into(),
                server_version: "0.4.0-rc.1".into(),
                min_protocol_version: 1,
                protocol_version: 2,
            }],
        };
        assert!(matches!(
            apply_authority_command(
                &mut state,
                AuthorityCommand::Initialize {
                    operation_id: genesis.cluster_id.clone(),
                    genesis,
                    proposed_at: Utc::now(),
                },
                LogId::new(openraft::CommittedLeaderId::new(1, 1), 1)
            ),
            AuthorityResponse::ControlPlaneInitialized { .. }
        ));
        Self {
            state,
            node,
            key,
            index: 1,
            term: 1,
        }
    }

    fn apply(&mut self, command: AuthorityCommand) -> AuthorityResponse {
        self.index += 1;
        let signed = crate::cluster_principal::fixture_signed(
            command,
            crate::cluster_principal::FIXTURE_CLUSTER_ID,
        );
        let response = apply_authority_command(
            &mut self.state,
            signed,
            LogId::new(openraft::CommittedLeaderId::new(self.term, 1), self.index),
        );
        validate_authority_state(&self.state).unwrap();
        response
    }

    fn prepare(&self, agent: &str, operation: &str) -> AuthorityCommand {
        AuthorityCommand::PrepareAgentIdentity {
            operation_id: operation.into(),
            agent_id: agent.into(),
            scope: AgentIdentityScope::System,
            creator_principal_id: crate::cluster_principal::fixture_operator().principal_id,
            creation_operation_id: operation.into(),
            creation_sha256: "31".repeat(32),
            owner_node_id: self.node.clone(),
            ttl_seconds: 60,
            actor: "caller-provided machine label".into(),
            reason: "identity fixture".into(),
            proposed_at: Utc::now(),
        }
    }

    fn record(&self, agent: &str) -> AgentIdentityRecord {
        self.state.control_plane.as_ref().unwrap().agent_identities[agent].clone()
    }

    fn receipt(&self, identity: &AgentIdentityRecord) -> DestinationCreationReceipt {
        let reservation = &identity.reservation;
        let mut receipt = DestinationCreationReceipt {
            version: IDENTITY_VERSION,
            cluster_id: reservation.cluster_id.clone(),
            agent_id: reservation.agent_id.clone(),
            scope: reservation.scope.clone(),
            creator_principal_id: reservation.creator_principal_id.clone(),
            creation_operation_id: reservation.creation_operation_id.clone(),
            creation_sha256: reservation.creation_sha256.clone(),
            reservation_revision: reservation.reservation_revision,
            reservation_sha256: reservation.sha256().unwrap(),
            destination_node_id: self.node.clone(),
            destination_installation_id: Uuid::new_v4().to_string(),
            local_receipt_id: Uuid::new_v4().to_string(),
            created_agent_id: reservation.agent_id.clone(),
            created_row_sha256: "42".repeat(32),
            schema_version: crate::schema::CURRENT_SCHEMA_VERSION,
            min_reader_schema_version: crate::schema::MIN_READER_SCHEMA_VERSION,
            protocol_version: 2,
            created_at: reservation.prepared_at + TimeDelta::microseconds(1),
            signature_hex: String::new(),
        };
        receipt.signature_hex = crate::cluster_control::hex_encode(
            self.key.sign(&receipt.signing_payload().unwrap()).as_ref(),
        );
        receipt
    }

    fn create(&mut self, agent: &str) -> DestinationCreationReceipt {
        let receipt = self.receipt(&self.record(agent));
        assert!(matches!(
            self.apply(AuthorityCommand::RecordAgentCreation {
                operation_id: Uuid::new_v4().to_string(),
                agent_id: agent.into(),
                expected_revision: 1,
                receipt: receipt.clone(),
                actor: "fixture".into(),
                reason: "exact receipt".into(),
                proposed_at: Utc::now(),
            }),
            AuthorityResponse::AgentIdentityUpdated { identity, .. }
                if identity.state == AgentIdentityState::Created
        ));
        receipt
    }

    fn publish(&mut self, agent: &str, receipt: &DestinationCreationReceipt) {
        assert!(matches!(
            self.apply(AuthorityCommand::PublishAgentIdentity {
                operation_id: Uuid::new_v4().to_string(),
                agent_id: agent.into(),
                expected_revision: 2,
                receipt_sha256: receipt.sha256().unwrap(),
                actor: "fixture".into(),
                reason: "publish exact receipt".into(),
                proposed_at: Utc::now(),
            }),
            AuthorityResponse::AgentIdentityUpdated { identity, .. }
                if identity.state == AgentIdentityState::Published
        ));
    }
}

#[test]
fn immutable_identity_allocation_retry_conflicts_and_tombstones_are_permanent() {
    let mut fixture = IdentityFixture::new();
    let agent = Uuid::new_v4().to_string();
    let operation = Uuid::new_v4().to_string();
    let command = fixture.prepare(&agent, &operation);
    let original = fixture.apply(command.clone());
    assert!(matches!(
        original,
        AuthorityResponse::AgentIdentityUpdated { .. }
    ));
    assert!(matches!(
        fixture.apply(command.clone()),
        AuthorityResponse::AgentIdentityUpdated { replayed: true, .. }
    ));
    let mut conflict = command.clone();
    if let AuthorityCommand::PrepareAgentIdentity { scope, .. } = &mut conflict {
        *scope = AgentIdentityScope::Tenant {
            tenant_id: Uuid::new_v4().to_string(),
        };
    }
    assert!(matches!(
        fixture.apply(conflict),
        AuthorityResponse::Rejected {
            reason: AuthorityRejection::OperationIdConflict,
            ..
        }
    ));
    let receipt = fixture.create(&agent);
    fixture.publish(&agent, &receipt);
    let reservation = fixture.record(&agent).reservation;
    let deletion = AuthorityCommand::DeleteAgentIdentity {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.clone(),
        expected_revision: 3,
        actor: "fixture".into(),
        reason: "delete exact identity".into(),
        proposed_at: Utc::now(),
    };
    assert!(matches!(
        fixture.apply(deletion.clone()),
        AuthorityResponse::AgentIdentityUpdated { identity, .. }
            if identity.state == AgentIdentityState::Deleted
    ));
    assert!(matches!(
        fixture.apply(deletion),
        AuthorityResponse::AgentIdentityUpdated { replayed: true, .. }
    ));
    assert_eq!(fixture.record(&agent).reservation, reservation);
    assert!(matches!(
        fixture.apply(command),
        AuthorityResponse::Rejected {
            reason: AuthorityRejection::Conflict,
            ..
        }
    ));
    let replacement = fixture.prepare(&agent, &Uuid::new_v4().to_string());
    assert!(matches!(
        fixture.apply(replacement),
        AuthorityResponse::Rejected {
            reason: AuthorityRejection::Conflict,
            ..
        }
    ));
    assert!(matches!(
        fixture.apply(AuthorityCommand::ClaimOwnership {
            operation_id: Uuid::new_v4().to_string(),
            agent_id: agent.clone(),
            owner_node_id: fixture.node.clone(),
            ttl_seconds: 60,
            expected_fencing_token: Some(1),
            actor: "fixture".into(),
            reason: "reuse deleted identity".into(),
            proposed_at: Utc::now(),
        }),
        AuthorityResponse::Rejected {
            reason: AuthorityRejection::Conflict,
            ..
        }
    ));
}

#[test]
fn immutable_identity_receipt_substitutions_and_wrong_publication_fail_closed() {
    let mut fixture = IdentityFixture::new();
    let agent = Uuid::new_v4().to_string();
    fixture.apply(fixture.prepare(&agent, &Uuid::new_v4().to_string()));
    let original = fixture.record(&agent);
    let good = fixture.receipt(&original);
    for alteration in 0..6 {
        let mut bad = good.clone();
        match alteration {
            0 => {
                bad.scope = AgentIdentityScope::Tenant {
                    tenant_id: Uuid::new_v4().to_string(),
                }
            }
            1 => bad.creator_principal_id = Uuid::new_v4().to_string(),
            2 => bad.created_agent_id = Uuid::new_v4().to_string(),
            3 => bad.reservation_sha256 = "10".repeat(32),
            4 => bad.created_row_sha256 = "11".repeat(32),
            _ => bad.schema_version -= 1,
        }
        assert!(matches!(
            fixture.apply(AuthorityCommand::RecordAgentCreation {
                operation_id: Uuid::new_v4().to_string(),
                agent_id: agent.clone(),
                expected_revision: 1,
                receipt: bad,
                actor: "fixture".into(),
                reason: "mismatched receipt".into(),
                proposed_at: Utc::now(),
            }),
            AuthorityResponse::Rejected { .. }
        ));
        assert_eq!(fixture.record(&agent), original);
    }
    let receipt = fixture.create(&agent);
    assert!(matches!(
        fixture.apply(AuthorityCommand::PublishAgentIdentity {
            operation_id: Uuid::new_v4().to_string(),
            agent_id: agent.clone(),
            expected_revision: 2,
            receipt_sha256: "ff".repeat(32),
            actor: "fixture".into(),
            reason: "foreign receipt".into(),
            proposed_at: Utc::now(),
        }),
        AuthorityResponse::Rejected { .. }
    ));
    fixture.publish(&agent, &receipt);
}

#[test]
fn immutable_identity_history_rejects_foreign_tenant_and_dropped_creation_evidence() {
    let mut fixture = IdentityFixture::new();
    let agent = Uuid::new_v4().to_string();
    fixture.apply(fixture.prepare(&agent, &Uuid::new_v4().to_string()));
    let receipt = fixture.create(&agent);
    fixture.publish(&agent, &receipt);
    let mut corrupt = fixture.state.clone();
    corrupt
        .control_plane
        .as_mut()
        .unwrap()
        .agent_identities
        .get_mut(&agent)
        .unwrap()
        .reservation
        .scope = AgentIdentityScope::Tenant {
        tenant_id: Uuid::new_v4().to_string(),
    };
    assert!(validate_authority_state(&corrupt).is_err());
    let mut corrupt = fixture.state.clone();
    corrupt
        .control_plane
        .as_mut()
        .unwrap()
        .agent_identities
        .clear();
    assert!(validate_authority_state(&corrupt).is_err());
}

#[test]
fn immutable_identity_abort_never_becomes_a_new_creation_or_published_agent() {
    for after_receipt in [false, true] {
        let mut fixture = IdentityFixture::new();
        let agent = Uuid::new_v4().to_string();
        fixture.apply(fixture.prepare(&agent, &Uuid::new_v4().to_string()));
        if after_receipt {
            fixture.create(&agent);
        }
        let identity = fixture.record(&agent);
        assert!(matches!(
            fixture.apply(AuthorityCommand::AbortAgentIdentity {
                operation_id: Uuid::new_v4().to_string(),
                agent_id: agent.clone(),
                expected_revision: identity.revision,
                actor: "fixture".into(),
                reason: "incomplete creation abort".into(),
                proposed_at: Utc::now(),
            }),
            AuthorityResponse::AgentIdentityUpdated { identity, .. }
                if identity.state == AgentIdentityState::Aborted
        ));
        assert_eq!(fixture.record(&agent).reservation, identity.reservation);
        assert!(matches!(
            fixture.apply(fixture.prepare(&agent, &Uuid::new_v4().to_string())),
            AuthorityResponse::Rejected { .. }
        ));
        let receipt = fixture.receipt(&identity);
        assert!(matches!(
            fixture.apply(AuthorityCommand::RecordAgentCreation {
                operation_id: Uuid::new_v4().to_string(),
                agent_id: agent,
                expected_revision: identity.revision + 1,
                receipt,
                actor: "fixture".into(),
                reason: "late receipt".into(),
                proposed_at: Utc::now(),
            }),
            AuthorityResponse::Rejected { .. }
        ));
    }
}

#[test]
fn immutable_identity_expired_ownership_recovers_the_same_exact_receipt_without_reallocation() {
    let mut fixture = IdentityFixture::new();
    let agent = Uuid::new_v4().to_string();
    fixture.apply(fixture.prepare(&agent, &Uuid::new_v4().to_string()));
    let identity = fixture.record(&agent);
    let receipt = fixture.receipt(&identity);
    let after_expiry = identity.reservation.initial_lease_expires_at + TimeDelta::seconds(1);
    fixture.term = 2;
    fixture.index += 1;
    apply_authority_command(
        &mut fixture.state,
        AuthorityCommand::AdvanceTime {
            operation_id: Uuid::new_v4().to_string(),
            proposed_at: after_expiry,
        },
        LogId::new(openraft::CommittedLeaderId::new(2, 1), fixture.index),
    );
    assert!(matches!(
        fixture.apply(AuthorityCommand::RecordAgentCreation {
            operation_id: Uuid::new_v4().to_string(),
            agent_id: agent.clone(),
            expected_revision: 1,
            receipt: receipt.clone(),
            actor: "fixture".into(),
            reason: "expired ownership must reject publication".into(),
            proposed_at: after_expiry,
        }),
        AuthorityResponse::Rejected { .. }
    ));
    let renewed = fixture.apply(AuthorityCommand::ClaimOwnership {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.clone(),
        owner_node_id: fixture.node.clone(),
        ttl_seconds: 60,
        expected_fencing_token: Some(1),
        actor: "fixture".into(),
        reason: "recover exact creation after expired ownership".into(),
        proposed_at: after_expiry,
    });
    assert!(matches!(
        renewed,
        AuthorityResponse::OwnershipUpdated {
            ownership: ClusterAgentOwnership {
                fencing_token: 2,
                ..
            },
            ..
        }
    ));
    let created = fixture.apply(AuthorityCommand::RecordAgentCreation {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.clone(),
        expected_revision: 1,
        receipt: receipt.clone(),
        actor: "fixture".into(),
        reason: "recover retained pre-expiry receipt".into(),
        proposed_at: after_expiry + TimeDelta::seconds(1),
    });
    assert!(matches!(
        created,
        AuthorityResponse::AgentIdentityUpdated { .. }
    ));
    let published = fixture.apply(AuthorityCommand::PublishAgentIdentity {
        operation_id: Uuid::new_v4().to_string(),
        agent_id: agent.clone(),
        expected_revision: 2,
        receipt_sha256: receipt.sha256().unwrap(),
        actor: "fixture".into(),
        reason: "publish recovered exact identity".into(),
        proposed_at: after_expiry + TimeDelta::seconds(2),
    });
    assert!(matches!(
        published,
        AuthorityResponse::AgentIdentityUpdated { .. }
    ));
    assert_eq!(fixture.record(&agent).reservation, identity.reservation);
    assert_eq!(
        fixture.record(&agent).creation_receipt.as_ref(),
        Some(&receipt)
    );
}

#[test]
fn immutable_identity_current_principal_checks_precede_all_receipt_replay() {
    let mut fixture = IdentityFixture::new();
    let agent = Uuid::new_v4().to_string();
    let command = fixture.prepare(&agent, &Uuid::new_v4().to_string());
    fixture.index += 1;
    let unsigned = apply_authority_command(
        &mut fixture.state,
        command.clone(),
        LogId::new(openraft::CommittedLeaderId::new(1, 1), fixture.index),
    );
    assert!(matches!(
        unsigned,
        AuthorityResponse::Rejected {
            reason: AuthorityRejection::PrincipalAuthentication(
                crate::cluster_principal::PrincipalProofError::Missing
            ),
            ..
        }
    ));
    let mut wrong_creator = command.clone();
    if let AuthorityCommand::PrepareAgentIdentity {
        creator_principal_id,
        ..
    } = &mut wrong_creator
    {
        *creator_principal_id = Uuid::new_v4().to_string();
    }
    assert!(matches!(
        fixture.apply(wrong_creator),
        AuthorityResponse::Rejected {
            reason: AuthorityRejection::PrincipalAuthentication(
                crate::cluster_principal::PrincipalProofError::TenantScope
            ),
            ..
        }
    ));
    fixture.apply(command.clone());
    assert!(matches!(
        fixture.apply(command.clone()),
        AuthorityResponse::AgentIdentityUpdated { replayed: true, .. }
    ));
    assert!(matches!(
        fixture.apply(AuthorityCommand::RevokePrincipal {
            operation_id: Uuid::new_v4().to_string(),
            principal_id: crate::cluster_principal::fixture_operator().principal_id,
            expected_generation: 1,
            actor: "fixture".into(),
            reason: "current caller key revocation".into(),
            proposed_at: Utc::now(),
        }),
        AuthorityResponse::PrincipalUpdated { .. }
    ));
    let current = fixture.state.clone();
    assert!(matches!(
        fixture.apply(command),
        AuthorityResponse::Rejected {
            reason: AuthorityRejection::PrincipalAuthentication(
                crate::cluster_principal::PrincipalProofError::Revoked
            ),
            ..
        }
    ));
    assert_eq!(fixture.state, current);
}

#[test]
fn immutable_identity_reserved_nil_uuid_cannot_allocate_an_unerasable_agent() {
    let mut fixture = IdentityFixture::new();
    let nil = Uuid::nil().to_string();
    let command = fixture.prepare(&nil, &Uuid::new_v4().to_string());
    assert!(matches!(
        fixture.apply(command),
        AuthorityResponse::Rejected {
            reason: AuthorityRejection::InvalidCommand,
            ..
        }
    ));
    assert!(fixture
        .state
        .control_plane
        .as_ref()
        .unwrap()
        .agent_identities
        .is_empty());
    assert!(fixture
        .state
        .control_plane
        .as_ref()
        .unwrap()
        .ownerships
        .is_empty());
}

#[tokio::test]
async fn immutable_identity_authority_crash_child() {
    let Ok(path) = std::env::var("AIOS_IDENTITY_AUTHORITY_DATABASE") else {
        return;
    };
    let phase = std::env::var("AIOS_IDENTITY_AUTHORITY_PHASE").unwrap();
    let agent = std::env::var("AIOS_IDENTITY_CRASH_AGENT").unwrap();
    let mut fixture = IdentityFixture::new();
    let context = Arc::new(SqliteContextManager::new(std::path::Path::new(&path)).unwrap());
    let (_, mut store) = open_cluster_raft_storage(context).unwrap();
    let initialization = fixture
        .state
        .receipts
        .values()
        .next()
        .unwrap()
        .command
        .clone();
    store
        .apply([Entry {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
            payload: EntryPayload::Normal(initialization),
        }])
        .await
        .unwrap();
    let prepare = fixture.prepare(&agent, &Uuid::new_v4().to_string());
    let response = fixture.apply(prepare);
    let AuthorityResponse::AgentIdentityUpdated { identity, .. } = response else {
        panic!("fixture preparation failed")
    };
    let command = fixture
        .state
        .receipts
        .get(&identity.reservation.creation_operation_id)
        .unwrap()
        .command
        .clone();
    store
        .apply([Entry {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 2),
            payload: EntryPayload::Normal(command),
        }])
        .await
        .unwrap();
    if phase == "aborted" {
        let command = AuthorityCommand::AbortAgentIdentity {
            operation_id: Uuid::new_v4().to_string(),
            agent_id: agent,
            expected_revision: 1,
            actor: "fixture".into(),
            reason: "exact authority crash abort".into(),
            proposed_at: Utc::now(),
        };
        store
            .apply([Entry {
                log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 3),
                payload: EntryPayload::Normal(crate::cluster_principal::fixture_signed(
                    command,
                    crate::cluster_principal::FIXTURE_CLUSTER_ID,
                )),
            }])
            .await
            .unwrap();
    } else {
        let receipt = fixture.receipt(&identity);
        let record = AuthorityCommand::RecordAgentCreation {
            operation_id: Uuid::new_v4().to_string(),
            agent_id: agent.clone(),
            expected_revision: 1,
            receipt: receipt.clone(),
            actor: "fixture".into(),
            reason: "exact authority crash receipt".into(),
            proposed_at: Utc::now(),
        };
        store
            .apply([Entry {
                log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 3),
                payload: EntryPayload::Normal(crate::cluster_principal::fixture_signed(
                    record,
                    crate::cluster_principal::FIXTURE_CLUSTER_ID,
                )),
            }])
            .await
            .unwrap();
        let publish = AuthorityCommand::PublishAgentIdentity {
            operation_id: Uuid::new_v4().to_string(),
            agent_id: agent.clone(),
            expected_revision: 2,
            receipt_sha256: receipt.sha256().unwrap(),
            actor: "fixture".into(),
            reason: "exact authority crash publication".into(),
            proposed_at: Utc::now(),
        };
        store
            .apply([Entry {
                log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 4),
                payload: EntryPayload::Normal(crate::cluster_principal::fixture_signed(
                    publish,
                    crate::cluster_principal::FIXTURE_CLUSTER_ID,
                )),
            }])
            .await
            .unwrap();
        let delete = AuthorityCommand::DeleteAgentIdentity {
            operation_id: Uuid::new_v4().to_string(),
            agent_id: agent,
            expected_revision: 3,
            actor: "fixture".into(),
            reason: "exact authority crash deletion".into(),
            proposed_at: Utc::now(),
        };
        store
            .apply([Entry {
                log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 5),
                payload: EntryPayload::Normal(crate::cluster_principal::fixture_signed(
                    delete,
                    crate::cluster_principal::FIXTURE_CLUSTER_ID,
                )),
            }])
            .await
            .unwrap();
    }
    panic!("the named authority crash boundary was not reached");
}

#[test]
fn immutable_identity_every_authority_transition_process_crash_retains_one_recoverable_identity() {
    for (phase, previous, committed) in [
        ("prepared", None, AgentIdentityState::Prepared),
        (
            "created",
            Some(AgentIdentityState::Prepared),
            AgentIdentityState::Created,
        ),
        (
            "published",
            Some(AgentIdentityState::Created),
            AgentIdentityState::Published,
        ),
        (
            "aborted",
            Some(AgentIdentityState::Prepared),
            AgentIdentityState::Aborted,
        ),
        (
            "deleted",
            Some(AgentIdentityState::Published),
            AgentIdentityState::Deleted,
        ),
    ] {
        for boundary in ["before_commit", "after_commit"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("identity-authority.sqlite");
            let agent = Uuid::new_v4().to_string();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cluster_consensus::agent_identity_tests::immutable_identity_authority_crash_child", "--nocapture"])
                .env("AIOS_IDENTITY_AUTHORITY_DATABASE", &path).env("AIOS_IDENTITY_AUTHORITY_PHASE", phase)
                .env("AIOS_IDENTITY_CRASH_AGENT", &agent).env("AIOS_IDENTITY_CRASH_STEP", format!("authority_{phase}_{boundary}"))
                .status().unwrap();
            assert_eq!(
                status.code(),
                Some(86),
                "{phase}/{boundary}: exact process boundary was not reached"
            );
            let context = Arc::new(SqliteContextManager::new(&path).unwrap());
            let (_, state) = open_cluster_raft_storage(context.clone()).unwrap();
            let view = read_replicated_authority_view(&context).unwrap().unwrap();
            let expected = if boundary == "before_commit" {
                previous
            } else {
                Some(committed)
            };
            match expected {
                None => {
                    assert!(view.agent_identities.is_empty());
                    assert!(view.ownerships.is_empty());
                }
                Some(expected) => {
                    assert_eq!(view.agent_identities.len(), 1);
                    let identity = &view.agent_identities[&agent];
                    assert_eq!(identity.state, expected);
                    assert_eq!(identity.reservation.agent_id, agent);
                    assert_eq!(identity.reservation.scope, AgentIdentityScope::System);
                    assert_eq!(identity.reservation.initial_fencing_token, 1);
                    assert_eq!(
                        identity.reservation.creator_principal_id,
                        crate::cluster_principal::fixture_operator().principal_id
                    );
                    identity.validate().unwrap();
                }
            }
            drop(state);
            drop(context);
            directory.close().unwrap();
        }
    }
}
