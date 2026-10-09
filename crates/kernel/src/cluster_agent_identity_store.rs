//! Destination SQLite half of immutable quorum identity publication.

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::cluster_agent_identity::{
    AgentIdentityRecord, AgentIdentityReservation, AgentIdentityState, DestinationCreationReceipt,
    IDENTITY_VERSION,
};
use crate::context::{PersistedAgent, SqliteContextManager};
use crate::ContextError;

fn failure(message: &str) -> ContextError {
    ContextError::PersistenceFailed(message.to_owned())
}

fn evidence_error(error: impl std::fmt::Display) -> ContextError {
    failure(&error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationCreationAdmission {
    Create,
    Receipt(Box<DestinationCreationReceipt>),
}

struct LocalCreation {
    reservation: AgentIdentityReservation,
    installation_id: String,
    local_receipt_id: String,
    state: String,
    row_sha256: Option<String>,
    receipt: Option<DestinationCreationReceipt>,
}

fn load_local(connection: &Connection, agent_id: &str) -> Result<Option<LocalCreation>, ContextError> {
    let row = connection.query_row(
        "SELECT reservation_json, reservation_sha256, creation_operation_id,
            installation_id, local_receipt_id, state, created_row_sha256, receipt_json
         FROM cluster_agent_creation_journal WHERE agent_id = ?1",
        [agent_id],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
            row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?, row.get::<_, Option<Vec<u8>>>(7)?)),
    ).optional().map_err(|_| failure("destination creation journal cannot be read"))?;
    let Some((bytes, sha256, operation_id, installation_id, local_receipt_id, state, row_sha256, receipt_bytes)) = row else {
        return Ok(None);
    };
    if bytes.len() > 16384 || receipt_bytes.as_ref().is_some_and(|bytes| bytes.len() > 32768) {
        return Err(failure("destination creation journal exceeds its bounds"));
    }
    let reservation: AgentIdentityReservation = serde_json::from_slice(&bytes)
        .map_err(|_| failure("destination creation reservation is malformed"))?;
    reservation.validate().map_err(evidence_error)?;
    let metadata = crate::schema::read_storage_metadata(connection)?;
    if reservation.agent_id != agent_id || reservation.sha256().map_err(evidence_error)? != sha256
        || reservation.creation_operation_id != operation_id
        || metadata.installation_id != installation_id
        || !crate::cluster_agent_identity::canonical_uuid(&local_receipt_id)
        || !matches!(state.as_str(), "preparing" | "created" | "published" | "aborted" | "deleted")
    {
        return Err(failure("destination creation journal has conflicting identity evidence"));
    }
    let receipt: Option<DestinationCreationReceipt> = receipt_bytes.map(|bytes| {
        serde_json::from_slice(&bytes).map_err(|_| failure("destination creation receipt is malformed"))
    }).transpose()?;
    if let Some(receipt) = &receipt {
        receipt.validate_binding(&reservation).map_err(evidence_error)?;
        if receipt.destination_installation_id != installation_id
            || receipt.local_receipt_id != local_receipt_id || row_sha256.as_ref() != Some(&receipt.created_row_sha256)
        {
            return Err(failure("destination creation receipt conflicts with retained journal evidence"));
        }
    }
    let valid = match state.as_str() {
        "preparing" => receipt.is_none() && row_sha256.is_none(),
        "created" | "published" | "deleted" => receipt.is_some() && row_sha256.is_some(),
        "aborted" => receipt.is_some() == row_sha256.is_some(),
        _ => false,
    };
    if !valid { return Err(failure("destination creation journal phase is inconsistent")); }
    Ok(Some(LocalCreation { reservation, installation_id, local_receipt_id, state, row_sha256, receipt }))
}

fn row_sha256(connection: &Connection, agent_id: &str) -> Result<Option<String>, ContextError> {
    let value = connection.query_row(
        "SELECT id, session_id, tenant_id, name, task, llm_provider, permission_profile,
            priority, sandbox_config_json, created_at, namespace_group, clone_parent_id,
            clone_request_digest, clone_security_json, clone_pending FROM agents WHERE id = ?1",
        [agent_id], |row| {
            Ok(serde_json::json!([
                row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?,
                row.get::<_, String>(6)?, row.get::<_, i64>(7)?, row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?, row.get::<_, Option<String>>(10)?, row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?, row.get::<_, Option<String>>(13)?, row.get::<_, bool>(14)?
            ]))
        },
    ).optional().map_err(|_| failure("destination agent row cannot be verified"))?;
    value.map(|value| serde_json::to_vec(&value).map(|bytes| crate::cluster_control::sha256_hex(&bytes))
        .map_err(|_| failure("destination agent row cannot be digested"))).transpose()
}

/// Called only after the destination independently admits the current signed
/// creator, credential lease and committed reservation. It never adopts an
/// existing row and never creates a different UUID after an interrupted attempt.
pub fn begin_destination_creation(
    store: &SqliteContextManager,
    identity: &AgentIdentityRecord,
    destination_node_id: &str,
) -> Result<DestinationCreationAdmission, ContextError> {
    identity.validate().map_err(evidence_error)?;
    let reservation = &identity.reservation;
    if reservation.initial_owner_node_id != destination_node_id
        || matches!(identity.state, AgentIdentityState::Aborted | AgentIdentityState::Deleted)
    {
        return Err(failure("destination refuses a foreign or terminal immutable identity"));
    }
    let mut connection = store.locked_conn();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| failure("destination reservation transaction cannot start"))?;
    crate::schema::require_current_writer(&transaction)?;
    let existing = load_local(&transaction, &reservation.agent_id)?;
    let row = row_sha256(&transaction, &reservation.agent_id)?;
    if let Some(local) = existing {
        if local.reservation != *reservation || matches!(local.state.as_str(), "aborted" | "deleted") {
            return Err(failure("destination already retains a conflicting or terminal identity"));
        }
        if let Some(receipt) = local.receipt {
            if row.as_ref() != Some(&receipt.created_row_sha256) {
                return Err(failure("destination row differs from its exact creation receipt"));
            }
            if identity.creation_receipt.as_ref().is_some_and(|committed| committed != &receipt) {
                // The local payload can precede deterministic node signing.
                let mut unsigned_committed = identity.creation_receipt.clone().unwrap();
                unsigned_committed.signature_hex.clear();
                let mut unsigned_local = receipt.clone();
                unsigned_local.signature_hex.clear();
                if unsigned_committed != unsigned_local {
                    return Err(failure("destination receipt differs from the committed identity"));
                }
            }
            return Ok(DestinationCreationAdmission::Receipt(Box::new(receipt)));
        }
        if identity.state != AgentIdentityState::Prepared || row.is_some() {
            return Err(failure("destination creation is incomplete and requires exact reconciliation"));
        }
        if Utc::now() >= reservation.initial_lease_expires_at {
            return Err(failure("destination cannot create from an expired immutable reservation"));
        }
        return Ok(DestinationCreationAdmission::Create);
    }
    if identity.state != AgentIdentityState::Prepared || row.is_some()
        || Utc::now() >= reservation.initial_lease_expires_at
    {
        return Err(failure("destination cannot adopt an existing row or expired reservation"));
    }
    let metadata = crate::schema::read_storage_metadata(&transaction)?;
    transaction.execute(
        "INSERT INTO cluster_agent_creation_journal (agent_id, reservation_json, reservation_sha256,
            creation_operation_id, installation_id, local_receipt_id, state, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'preparing', ?7)",
        params![reservation.agent_id, serde_json::to_vec(reservation).map_err(|_| failure("reservation cannot be retained"))?,
            reservation.sha256().map_err(evidence_error)?, reservation.creation_operation_id,
            metadata.installation_id, uuid::Uuid::new_v4().to_string(), Utc::now().to_rfc3339()],
    ).map_err(|_| failure("destination cannot reserve the immutable creation identity"))?;
    transaction.commit().map_err(|_| failure("destination reservation cannot commit"))?;
    crash_identity_after_step_for_test("destination_reservation_committed");
    Ok(DestinationCreationAdmission::Create)
}

/// The caller holds the same actual transaction that inserts/finalizes `agents`.
/// A failure rolls back both the local row and its exact unsigned receipt.
pub(crate) fn commit_agent_creation_evidence(
    connection: &Connection,
    record: &PersistedAgent,
) -> Result<(), ContextError> {
    let Some(local) = load_local(connection, &record.id.to_string())? else { return Ok(()); };
    if local.state != "preparing" || local.reservation.scope.storage_tenant() != record.tenant_id
        || Utc::now() >= local.reservation.initial_lease_expires_at
    {
        return Err(failure("destination creation is fenced by its immutable reservation"));
    }
    let digest = row_sha256(connection, &record.id.to_string())?
        .ok_or_else(|| failure("destination creation has no exact durable agent row"))?;
    let metadata = crate::schema::read_storage_metadata(connection)?;
    let created_at = Utc::now().max(local.reservation.prepared_at);
    let reservation = local.reservation;
    let receipt = DestinationCreationReceipt {
        version: IDENTITY_VERSION, cluster_id: reservation.cluster_id.clone(), agent_id: reservation.agent_id.clone(),
        scope: reservation.scope.clone(), creator_principal_id: reservation.creator_principal_id.clone(),
        creation_operation_id: reservation.creation_operation_id.clone(), creation_sha256: reservation.creation_sha256.clone(),
        reservation_revision: reservation.reservation_revision, reservation_sha256: reservation.sha256().map_err(evidence_error)?,
        destination_node_id: reservation.initial_owner_node_id.clone(), destination_installation_id: local.installation_id,
        local_receipt_id: local.local_receipt_id, created_agent_id: record.id.to_string(), created_row_sha256: digest.clone(),
        schema_version: metadata.schema_version, min_reader_schema_version: metadata.min_reader_schema_version,
        protocol_version: crate::syscall_server::PROTOCOL_VERSION, created_at, signature_hex: String::new(),
    };
    receipt.validate_binding(&reservation).map_err(evidence_error)?;
    connection.execute("UPDATE cluster_agent_creation_journal SET state='created', created_row_sha256=?1,
        receipt_json=?2, updated_at=?3 WHERE agent_id=?4 AND state='preparing'",
        params![digest, serde_json::to_vec(&receipt).map_err(|_| failure("creation receipt cannot be retained"))?,
            created_at.to_rfc3339(), record.id.to_string()],
    ).map_err(|_| failure("exact creation receipt cannot commit with the agent row"))?;
    Ok(())
}

pub(crate) fn validate_creation_write(
    connection: &Connection,
    record: &PersistedAgent,
    creation_sha256: &str,
) -> Result<(), ContextError> {
    let Some(local) = load_local(connection, &record.id.to_string())? else { return Ok(()); };
    if local.state != "preparing" || local.reservation.scope.storage_tenant() != record.tenant_id
        || local.reservation.creation_sha256 != creation_sha256
        || row_sha256(connection, &record.id.to_string())?.is_some()
    {
        return Err(failure("destination cannot replace or adopt a conflicting immutable identity"));
    }
    Ok(())
}

/// Signing is deterministic and occurs after the row/unsigned receipt commit.
/// A crash before/after signing returns the same exact local receipt on retry.
pub fn destination_creation_receipt(
    kernel: &crate::AgentKernelImpl,
    identity: &AgentIdentityRecord,
) -> Result<DestinationCreationReceipt, ContextError> {
    let local = {
        let connection = kernel.context_manager.locked_conn();
        let local = load_local(&connection, &identity.reservation.agent_id)?
            .ok_or_else(|| failure("destination has no retained creation receipt"))?;
        if local.reservation != identity.reservation || matches!(local.state.as_str(), "preparing" | "aborted" | "deleted")
            || row_sha256(&connection, &identity.reservation.agent_id)? != local.row_sha256
        {
            return Err(failure("destination receipt conflicts with the immutable identity or local row"));
        }
        local
    };
    let mut receipt = local.receipt.ok_or_else(|| failure("destination receipt is missing"))?;
    if kernel.cluster_control.identity().node_id != receipt.destination_node_id {
        return Err(failure("destination receipt belongs to a foreign admitted node"));
    }
    if receipt.signature_hex.is_empty() {
        receipt.signature_hex = crate::cluster_control::hex_encode(&kernel.cluster_control.sign_challenge(
            &receipt.signing_payload().map_err(evidence_error)?,
        )?);
        crash_identity_after_step_for_test("destination_signature_created");
        let connection = kernel.context_manager.locked_conn();
        crate::schema::require_current_writer(&connection)?;
        let current = load_local(&connection, &receipt.agent_id)?
            .ok_or_else(|| failure("destination signature has no current creation evidence"))?;
        if !matches!(current.state.as_str(), "created" | "published")
            || current.reservation != identity.reservation
            || row_sha256(&connection, &receipt.agent_id)?.as_ref() != Some(&receipt.created_row_sha256)
        {
            return Err(failure("destination signature crossed a conflicting identity transition"));
        }
        let changed = connection.execute("UPDATE cluster_agent_creation_journal SET receipt_json=?1
            WHERE agent_id=?2 AND state IN ('created', 'published')",
            params![serde_json::to_vec(&receipt).map_err(|_| failure("signed receipt cannot be retained"))?, receipt.agent_id],
        ).map_err(|_| failure("signed destination receipt cannot commit"))?;
        if changed != 1 { return Err(failure("signed destination receipt did not retain its exact identity")); }
        crash_identity_after_step_for_test("destination_signature_committed");
    }
    receipt.validate(&identity.reservation).map_err(evidence_error)?;
    receipt.verify_signature(&kernel.cluster_control.identity().public_key).map_err(evidence_error)?;
    Ok(receipt)
}

/// The caller has just verified this Published record through an online quorum
/// barrier. Marking the exact matching local receipt makes the row visible.
pub fn publish_destination_identity(
    store: &SqliteContextManager,
    identity: &AgentIdentityRecord,
) -> Result<(), ContextError> {
    identity.validate().map_err(evidence_error)?;
    if identity.state != AgentIdentityState::Published {
        return Err(failure("destination exposure requires a published quorum identity"));
    }
    let mut connection = store.locked_conn();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| failure("destination publication transaction cannot start"))?;
    crate::schema::require_current_writer(&transaction)?;
    let local = load_local(&transaction, &identity.reservation.agent_id)?
        .ok_or_else(|| failure("destination publication has no local creation evidence"))?;
    if local.reservation != identity.reservation || !matches!(local.state.as_str(), "created" | "published")
        || local.receipt != identity.creation_receipt
        || row_sha256(&transaction, &identity.reservation.agent_id)? != local.row_sha256
    {
        return Err(failure("destination publication conflicts with exact local creation evidence"));
    }
    transaction.execute("UPDATE cluster_agent_creation_journal SET state='published', updated_at=?1
        WHERE agent_id=?2 AND state IN ('created', 'published')",
        params![identity.changed_at.to_rfc3339(), identity.reservation.agent_id],
    ).map_err(|_| failure("destination publication cannot commit"))?;
    transaction.commit().map_err(|_| failure("destination publication cannot commit"))?;
    crash_identity_after_step_for_test("destination_publication_committed");
    Ok(())
}

pub fn destination_agent_is_published(
    store: &SqliteContextManager,
    agent_id: uuid::Uuid,
) -> Result<bool, ContextError> {
    let connection = store.locked_conn();
    let Some(local) = load_local(&connection, &agent_id.to_string())? else {
        let fenced: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM cluster_agent_mutation_fences WHERE agent_id=?1)",
            [agent_id.to_string()], |row| row.get(0)).map_err(|_| failure("destination legacy fence cannot be verified"))?;
        return Ok(!fenced);
    };
    if local.state != "published" { return Ok(false); }
    if row_sha256(&connection, &agent_id.to_string())? != local.row_sha256 {
        return Err(failure("published destination agent differs from its exact identity receipt"));
    }
    Ok(true)
}

pub(crate) fn retain_identity_tombstones(
    connection: &Connection,
    identities: &std::collections::BTreeMap<String, AgentIdentityRecord>,
) -> Result<(), ContextError> {
    for identity in identities.values().filter(|identity| matches!(identity.state, AgentIdentityState::Aborted | AgentIdentityState::Deleted)) {
        if let Some(local) = load_local(connection, &identity.reservation.agent_id)? {
            if local.reservation != identity.reservation {
                return Err(failure("quorum tombstone conflicts with retained destination identity"));
            }
            connection.execute("UPDATE cluster_agent_creation_journal SET state=?1, updated_at=?2 WHERE agent_id=?3",
                params![if identity.state == AgentIdentityState::Deleted { "deleted" } else { "aborted" },
                    identity.changed_at.to_rfc3339(), identity.reservation.agent_id],
            ).map_err(|_| failure("destination identity tombstone cannot commit"))?;
        }
    }
    Ok(())
}

pub(crate) fn validate_destination_identity_store(connection: &Connection) -> Result<(), ContextError> {
    let ids = {
        let mut statement = connection.prepare("SELECT agent_id FROM cluster_agent_creation_journal ORDER BY agent_id LIMIT 100001")
            .map_err(|_| failure("destination journal inventory cannot be read"))?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| failure("destination journal inventory cannot be read"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|_| failure("destination journal inventory is malformed"))?
    };
    if ids.len() > crate::cluster_agent_identity::MAX_AGENT_IDENTITIES {
        return Err(failure("destination identity directory exceeds bounded capacity"));
    }
    for id in ids {
        let local = load_local(connection, &id)?.ok_or_else(|| failure("destination journal identity disappeared"))?;
        if matches!(local.state.as_str(), "created" | "published")
            && row_sha256(connection, &id)? != local.row_sha256
        {
            return Err(failure("destination identity journal retains mismatched local row evidence"));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn crash_identity_after_step_for_test(step: &str) {
    if std::env::var("AIOS_IDENTITY_CRASH_STEP").as_deref() == Ok(step) {
        std::process::exit(86);
    }
}

#[cfg(not(test))]
#[inline]
pub(crate) fn crash_identity_after_step_for_test(_step: &str) {}

#[cfg(test)]
#[path = "cluster_agent_identity_store_tests.rs"]
mod tests;
