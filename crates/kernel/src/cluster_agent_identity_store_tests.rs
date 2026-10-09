use super::*;
use crate::cluster_agent_identity::{AgentIdentityScope, IDENTITY_VERSION};

fn destination_fixture(
    store: &SqliteContextManager,
    agent: uuid::Uuid,
) -> (AgentIdentityRecord, PersistedAgent) {
    let now = Utc::now();
    let record = PersistedAgent {
        id: agent,
        session_id: uuid::Uuid::new_v4(),
        tenant_id: crate::context::DEFAULT_TENANT.into(),
        name: "exact identity".into(),
        task: "retain immutable creation".into(),
        llm_provider: "stub".into(),
        permission_profile: "standard".into(),
        priority: 3,
        status: "\"Running\"".into(),
        sandbox_config_json: None,
        created_at: now,
        last_activity_at: now,
    };
    let call = crate::syscall_server::Syscall::CreateAgent {
        agent_id: Some(agent.to_string()),
        ownership_proof: None,
        name: record.name.clone(),
        task: record.task.clone(),
        provider: record.llm_provider.clone(),
        profile: record.permission_profile.clone(),
        priority: record.priority,
    };
    let operation = uuid::Uuid::new_v4().to_string();
    let creator = uuid::Uuid::new_v4().to_string();
    let identity = AgentIdentityRecord {
        reservation: AgentIdentityReservation {
            version: IDENTITY_VERSION,
            cluster_id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent.to_string(),
            scope: AgentIdentityScope::System,
            creator_principal_id: creator.clone(),
            creation_operation_id: operation.clone(),
            creation_sha256: crate::cluster_agent_identity::creation_command_sha256(&call).unwrap(),
            initial_owner_node_id: uuid::Uuid::new_v4().to_string(),
            initial_authority_term: 1,
            initial_authority_generation: 1,
            initial_fencing_token: 1,
            initial_lease_expires_at: now + chrono::TimeDelta::seconds(60),
            prepared_at: now,
            reservation_revision: 1,
        },
        state: AgentIdentityState::Prepared,
        revision: 1,
        creation_receipt: None,
        changed_at: now,
        last_operation_id: operation,
        changed_by_principal_id: creator,
        tombstone_reason: None,
    };
    crate::schema::verify(&store.locked_conn()).unwrap();
    (identity, record)
}

#[test]
fn immutable_identity_destination_row_and_unsigned_receipt_commit_together() {
    let store = SqliteContextManager::in_memory().unwrap();
    let agent = uuid::Uuid::new_v4();
    let (identity, record) = destination_fixture(&store, agent);
    assert_eq!(
        begin_destination_creation(
            &store,
            &identity,
            &identity.reservation.initial_owner_node_id
        )
        .unwrap(),
        DestinationCreationAdmission::Create
    );
    assert!(!destination_agent_is_published(&store, agent).unwrap());
    store.save_agent(&record).unwrap();
    let receipt = match begin_destination_creation(
        &store,
        &identity,
        &identity.reservation.initial_owner_node_id,
    )
    .unwrap()
    {
        DestinationCreationAdmission::Receipt(receipt) => receipt,
        other => panic!("expected exact retained receipt, got {other:?}"),
    };
    assert_eq!(receipt.created_agent_id, agent.to_string());
    assert!(receipt.signature_hex.is_empty());
    assert!(!destination_agent_is_published(&store, agent).unwrap());
    assert!(publish_destination_identity(&store, &identity).is_err());
    let mut foreign = record.clone();
    foreign.tenant_id = uuid::Uuid::new_v4().to_string();
    assert!(store.save_agent(&foreign).is_err());
    let connection = store.locked_conn();
    assert_eq!(
        row_sha256(&connection, &agent.to_string())
            .unwrap()
            .as_ref(),
        Some(&receipt.created_row_sha256)
    );
    assert!(connection
        .execute(
            "DELETE FROM cluster_agent_creation_journal WHERE agent_id=?1",
            [agent.to_string()]
        )
        .is_err());
    assert!(connection
        .execute(
            "UPDATE cluster_agent_creation_journal SET reservation_sha256=?1 WHERE agent_id=?2",
            params!["ff".repeat(32), agent.to_string()]
        )
        .is_err());
}

#[test]
fn immutable_identity_destination_never_adopts_an_existing_or_foreign_local_row() {
    let store = SqliteContextManager::in_memory().unwrap();
    let agent = uuid::Uuid::new_v4();
    let (identity, record) = destination_fixture(&store, agent);
    store.save_agent(&record).unwrap();
    let original_row = row_sha256(&store.locked_conn(), &agent.to_string()).unwrap();
    assert!(begin_destination_creation(
        &store,
        &identity,
        &identity.reservation.initial_owner_node_id
    )
    .is_err());
    assert_eq!(
        row_sha256(&store.locked_conn(), &agent.to_string()).unwrap(),
        original_row
    );
    assert_eq!(
        store
            .locked_conn()
            .query_row(
                "SELECT COUNT(*) FROM cluster_agent_creation_journal",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn immutable_identity_destination_request_substitution_rolls_back_the_row() {
    let store = SqliteContextManager::in_memory().unwrap();
    let agent = uuid::Uuid::new_v4();
    let (identity, mut record) = destination_fixture(&store, agent);
    begin_destination_creation(
        &store,
        &identity,
        &identity.reservation.initial_owner_node_id,
    )
    .unwrap();
    record.task = "different creation digest".into();
    assert!(store.save_agent(&record).is_err());
    assert!(row_sha256(&store.locked_conn(), &agent.to_string())
        .unwrap()
        .is_none());
    let local = load_local(&store.locked_conn(), &agent.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(local.state, "preparing");
    assert!(local.receipt.is_none());
}

#[test]
fn immutable_identity_destination_crash_child() {
    let Ok(path) = std::env::var("AIOS_IDENTITY_CRASH_DATABASE") else {
        return;
    };
    let agent: uuid::Uuid = std::env::var("AIOS_IDENTITY_CRASH_AGENT")
        .unwrap()
        .parse()
        .unwrap();
    let store = SqliteContextManager::new(std::path::Path::new(&path)).unwrap();
    let (identity, record) = destination_fixture(&store, agent);
    begin_destination_creation(
        &store,
        &identity,
        &identity.reservation.initial_owner_node_id,
    )
    .unwrap();
    store.save_agent(&record).unwrap();
    panic!("the named crash boundary was not reached");
}

#[test]
fn immutable_identity_destination_exact_process_crash_boundaries_remain_recoverable() {
    for step in [
        "destination_reservation_committed",
        "destination_row_inserted",
        "unsigned_receipt_staged",
        "destination_creation_committed",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity-crash.sqlite");
        let agent = uuid::Uuid::new_v4();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cluster_agent_identity::destination_store::tests::immutable_identity_destination_crash_child", "--nocapture"])
            .env("AIOS_IDENTITY_CRASH_DATABASE", &path).env("AIOS_IDENTITY_CRASH_AGENT", agent.to_string())
            .env("AIOS_IDENTITY_CRASH_STEP", step).status().unwrap();
        assert_eq!(
            status.code(),
            Some(86),
            "{step}: exact named process boundary was not reached"
        );
        let store = SqliteContextManager::new(&path).unwrap();
        let local = load_local(&store.locked_conn(), &agent.to_string())
            .unwrap()
            .unwrap();
        assert!(!destination_agent_is_published(&store, agent).unwrap());
        if step == "destination_creation_committed" {
            assert_eq!(local.state, "created");
            let receipt = local.receipt.as_ref().unwrap();
            assert_eq!(
                row_sha256(&store.locked_conn(), &agent.to_string())
                    .unwrap()
                    .as_ref(),
                Some(&receipt.created_row_sha256)
            );
        } else {
            assert_eq!(local.state, "preparing");
            assert!(local.receipt.is_none());
            assert!(row_sha256(&store.locked_conn(), &agent.to_string())
                .unwrap()
                .is_none());
        }
        let first_local_id = local.local_receipt_id.clone();
        let record = AgentIdentityRecord {
            reservation: local.reservation.clone(),
            state: AgentIdentityState::Prepared,
            revision: 1,
            creation_receipt: None,
            changed_at: local.reservation.prepared_at,
            last_operation_id: local.reservation.creation_operation_id.clone(),
            changed_by_principal_id: local.reservation.creator_principal_id.clone(),
            tombstone_reason: None,
        };
        let admission =
            begin_destination_creation(&store, &record, &record.reservation.initial_owner_node_id)
                .unwrap();
        if step == "destination_creation_committed" {
            assert!(matches!(
                admission,
                DestinationCreationAdmission::Receipt(_)
            ));
        } else {
            assert_eq!(admission, DestinationCreationAdmission::Create);
        }
        assert_eq!(
            load_local(&store.locked_conn(), &agent.to_string())
                .unwrap()
                .unwrap()
                .local_receipt_id,
            first_local_id
        );
        drop(store);
        directory.close().unwrap();
    }
}
