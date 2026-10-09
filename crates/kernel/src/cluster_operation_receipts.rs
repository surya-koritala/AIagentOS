//! Bounded, actor-bound at-most-once admission for operator cluster mutations.
//!
//! A durable pending record is written before dispatch. It is never evicted or
//! automatically retried: interruption between mutation and reply persistence
//! requires explicit operator reconciliation. Completed replies can be replayed
//! after normal current authorization, without executing the mutation again.

use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::auth::Principal;
use crate::context::SqliteContextManager;
use crate::syscall_server::{Syscall, SyscallReply, WireErrorCode};

pub(crate) const FEATURE: &str = "cluster-operation-receipts-v1";
const MAX_RECEIPTS: i64 = 4096;
const MAX_REPLY_BYTES: usize = 128 * 1024;
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_RETAINED_BYTES: i64 = 64 * 1024 * 1024;

pub(crate) struct Prepared {
    operation_id: String,
    actor_digest: String,
    command_digest: String,
    reply_kind: ReplyKind,
}

pub(crate) enum Admission {
    Legacy,
    Prepared(Prepared),
    Replay(SyscallReply),
}

#[derive(Clone, Copy)]
enum ReplyKind {
    NodeControl,
    Challenge,
    Member,
    Certificate,
    Fence,
}

fn mutation(call: &Syscall) -> Option<(Option<&str>, ReplyKind)> {
    match call {
        Syscall::SetNodeAvailability { operation_id, .. }
        | Syscall::SetNodeProfile { operation_id, .. } => {
            Some((operation_id.as_deref(), ReplyKind::NodeControl))
        }
        Syscall::IssueClusterJoinChallenge { operation_id, .. } => {
            Some((operation_id.as_deref(), ReplyKind::Challenge))
        }
        Syscall::RegisterClusterMember { operation_id, .. }
        | Syscall::SetClusterMemberState { operation_id, .. } => {
            Some((operation_id.as_deref(), ReplyKind::Member))
        }
        Syscall::PrepareClusterMemberCertificateRollout { operation_id, .. }
        | Syscall::AbortClusterMemberCertificateRollout { operation_id, .. }
        | Syscall::FinalizeClusterMemberCertificateRollout { operation_id, .. } => {
            Some((operation_id.as_deref(), ReplyKind::Certificate))
        }
        Syscall::InstallAgentMutationFence { operation_id, .. }
        | Syscall::RetireAgentMutationFence { operation_id, .. } => {
            Some((operation_id.as_deref(), ReplyKind::Fence))
        }
        _ => None,
    }
}

fn valid_reply(kind: ReplyKind, reply: &SyscallReply) -> bool {
    matches!(
        reply,
        SyscallReply::Error { .. } | SyscallReply::TypedError { .. }
    ) || matches!(
        (kind, reply),
        (
            ReplyKind::NodeControl,
            SyscallReply::NodeControlUpdated { .. }
        ) | (
            ReplyKind::Challenge,
            SyscallReply::ClusterJoinChallenge { .. }
        ) | (ReplyKind::Member, SyscallReply::ClusterMemberUpdated { .. })
            | (
                ReplyKind::Certificate,
                SyscallReply::ClusterCertificateRolloutUpdated { .. }
            )
            | (ReplyKind::Fence, SyscallReply::AgentMutationFence { .. })
    )
}

fn failure(code: WireErrorCode, message: &str) -> SyscallReply {
    SyscallReply::TypedError {
        code,
        message: message.into(),
        retryable: false,
    }
}

fn storage_failure() -> SyscallReply {
    failure(WireErrorCode::Internal, "cluster operation receipt storage failed; reconcile the mutation outcome before using a new operation id")
}

pub(crate) fn prepare(
    store: &SqliteContextManager,
    node_id: &str,
    call: &Syscall,
    principal: Option<&Principal>,
) -> Result<Admission, SyscallReply> {
    let Some((Some(raw_id), reply_kind)) = mutation(call) else {
        return Ok(Admission::Legacy);
    };
    let operation_id = uuid::Uuid::parse_str(raw_id)
        .map_err(|_| {
            failure(
                WireErrorCode::InvalidArgument,
                "invalid cluster operation UUID",
            )
        })?
        .to_string();
    if operation_id != raw_id {
        return Err(failure(
            WireErrorCode::InvalidArgument,
            "cluster operation UUID must use canonical lowercase form",
        ));
    }
    let command = serde_json::to_vec(call).map_err(|_| storage_failure())?;
    if command.len() > MAX_REQUEST_BYTES {
        return Err(failure(
            WireErrorCode::InvalidArgument,
            "cluster operation request exceeds the receipt bound",
        ));
    }
    let actor = match principal {
        Some(principal) => serde_json::json!([
            "principal",
            node_id,
            principal.tenant_id,
            principal.user_id,
            principal.role.as_str()
        ]),
        None => serde_json::json!(["trusted-system", node_id]),
    };
    let actor_digest = crate::cluster_control::sha256_hex(
        &serde_json::to_vec(&actor).map_err(|_| storage_failure())?,
    );
    let command_digest = crate::cluster_control::sha256_hex(&command);
    let mut connection = store.conn.lock().map_err(|_| storage_failure())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| storage_failure())?;
    let previous: Option<(String, String, String, Option<String>)> = transaction.query_row(
        "SELECT actor_digest, command_digest, phase, reply_json FROM cluster_operation_receipts WHERE operation_id = ?1",
        [&operation_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional().map_err(|_| storage_failure())?;
    if let Some((saved_actor, saved_command, phase, reply_json)) = previous {
        if saved_actor != actor_digest || saved_command != command_digest {
            return Err(failure(
                WireErrorCode::Conflict,
                "cluster operation id conflict: actor or command differs",
            ));
        }
        if phase == "pending" {
            return Err(failure(WireErrorCode::Conflict, "cluster operation receipt is pending; the mutation may have committed; reconcile node state before using any new operation id"));
        }
        let Some(json) =
            reply_json.filter(|json| phase == "complete" && json.len() <= MAX_REPLY_BYTES)
        else {
            return Err(storage_failure());
        };
        let reply = serde_json::from_str(&json).map_err(|_| storage_failure())?;
        if !valid_reply(reply_kind, &reply) {
            return Err(storage_failure());
        }
        return Ok(Admission::Replay(reply));
    }
    let (count, reserved): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(SUM(COALESCE(length(CAST(reply_json AS BLOB)), ?1)), 0) FROM cluster_operation_receipts",
        [MAX_REPLY_BYTES as i64], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| storage_failure())?;
    if count >= MAX_RECEIPTS || reserved > MAX_RETAINED_BYTES - MAX_REPLY_BYTES as i64 {
        return Err(failure(
            WireErrorCode::QuotaExceeded,
            "cluster operation receipt capacity exhausted; unresolved entries are retained",
        ));
    }
    transaction.execute(
        "INSERT INTO cluster_operation_receipts (operation_id, actor_digest, command_digest, phase, reply_json, admitted_at) VALUES (?1, ?2, ?3, 'pending', NULL, ?4)",
        params![operation_id, actor_digest, command_digest, chrono::Utc::now().to_rfc3339()],
    ).map_err(|_| storage_failure())?;
    transaction.commit().map_err(|_| storage_failure())?;
    Ok(Admission::Prepared(Prepared {
        operation_id,
        actor_digest,
        command_digest,
        reply_kind,
    }))
}

pub(crate) fn complete(
    store: &SqliteContextManager,
    prepared: Prepared,
    reply: &SyscallReply,
) -> Result<(), SyscallReply> {
    if !valid_reply(prepared.reply_kind, reply) {
        return Err(storage_failure());
    }
    let error_code = match reply {
        SyscallReply::Error { message } => Some(WireErrorCode::classify(message).0),
        SyscallReply::TypedError { code, .. } => Some(*code),
        _ => None,
    };
    if matches!(
        error_code,
        Some(
            WireErrorCode::Timeout
                | WireErrorCode::Cancelled
                | WireErrorCode::Unavailable
                | WireErrorCode::Internal
                | WireErrorCode::Provider
        )
    ) {
        return Err(failure(WireErrorCode::Conflict, "cluster operation outcome is unresolved; pending receipt retained; reconcile node state before using any new operation id"));
    }
    let json = serde_json::to_string(reply).map_err(|_| storage_failure())?;
    if json.len() > MAX_REPLY_BYTES {
        return Err(storage_failure());
    }
    let connection = store.conn.lock().map_err(|_| storage_failure())?;
    let changed = connection.execute(
        "UPDATE cluster_operation_receipts SET phase = 'complete', reply_json = ?1 WHERE operation_id = ?2 AND actor_digest = ?3 AND command_digest = ?4 AND phase = 'pending'",
        params![json, prepared.operation_id, prepared.actor_digest, prepared.command_digest],
    ).map_err(|_| storage_failure())?;
    if changed != 1 {
        return Err(storage_failure());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;
    use crate::cluster_control::{ClusterControl, NodeAvailability};
    use std::sync::Arc;

    fn call(id: uuid::Uuid) -> Syscall {
        Syscall::SetNodeAvailability {
            operation_id: Some(id.to_string()),
            availability: NodeAvailability::Draining,
            expected_generation: 0,
            reason: "receipt fixture".into(),
        }
    }

    fn prepared(
        store: &SqliteContextManager,
        call: &Syscall,
        principal: Option<&Principal>,
    ) -> Prepared {
        match prepare(store, "receipt-node", call, principal).unwrap() {
            Admission::Prepared(receipt) => receipt,
            _ => panic!("expected a new admitted receipt"),
        }
    }

    fn code(error: SyscallReply, expected: WireErrorCode) {
        assert!(
            matches!(error, SyscallReply::TypedError { code, retryable: false, .. } if code == expected)
        );
    }

    #[test]
    fn receipts_bind_actor_canonical_uuid_and_command_without_storing_raw_payload() {
        let store = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let original = call(id);
        let actor = Principal {
            user_id: "private-user".into(),
            tenant_id: "private-tenant".into(),
            role: Role::Admin,
            credential: None,
        };
        let other = Principal {
            user_id: "another-user".into(),
            ..actor.clone()
        };
        let _receipt = prepared(&store, &original, Some(&actor));
        code(
            prepare(&store, "receipt-node", &original, Some(&other))
                .err()
                .unwrap(),
            WireErrorCode::Conflict,
        );
        let changed = Syscall::SetNodeAvailability {
            operation_id: Some(id.to_string()),
            availability: NodeAvailability::Quarantined,
            expected_generation: 0,
            reason: "receipt fixture".into(),
        };
        code(
            prepare(&store, "receipt-node", &changed, Some(&actor))
                .err()
                .unwrap(),
            WireErrorCode::Conflict,
        );
        let malformed = Syscall::SetNodeAvailability {
            operation_id: Some("not-a-uuid".into()),
            availability: NodeAvailability::Draining,
            expected_generation: 0,
            reason: "receipt fixture".into(),
        };
        code(
            prepare(&store, "receipt-node", &malformed, Some(&actor))
                .err()
                .unwrap(),
            WireErrorCode::InvalidArgument,
        );
        let conn = store.conn.lock().unwrap();
        let retained: (String, String) = conn
            .query_row(
                "SELECT actor_digest, command_digest FROM cluster_operation_receipts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(retained.0.len(), 64);
        assert_eq!(retained.1.len(), 64);
        assert!(!retained.0.contains("private"));
        assert!(!retained.1.contains("receipt fixture"));
    }

    #[test]
    fn completed_receipt_replays_after_restart_without_changing_generation_or_audit() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("receipts.db");
        let original = call(uuid::Uuid::new_v4());
        let saved = {
            let store = Arc::new(SqliteContextManager::new(&path).unwrap());
            let control = ClusterControl::new(store.clone()).unwrap();
            let receipt = prepared(&store, &original, None);
            let changed = control
                .transition(NodeAvailability::Draining, 0, "system", "receipt fixture")
                .unwrap();
            let reply = SyscallReply::NodeControlUpdated { control: changed };
            complete(&store, receipt, &reply).unwrap();
            serde_json::to_value(&reply).unwrap()
        };
        let store = Arc::new(SqliteContextManager::new(&path).unwrap());
        let control = ClusterControl::new(store.clone()).unwrap();
        let Admission::Replay(reply) = prepare(&store, "receipt-node", &original, None).unwrap()
        else {
            panic!("completed operation must replay");
        };
        assert_eq!(serde_json::to_value(reply).unwrap(), saved);
        assert_eq!(control.status().unwrap().generation, 1);
        assert_eq!(control.audit(10).unwrap().len(), 1);
        drop(control);
        drop(store);
        root.close().unwrap();
    }

    #[test]
    fn restart_with_pending_or_committed_before_reply_never_reexecutes() {
        for committed in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("receipts.db");
            let original = call(uuid::Uuid::new_v4());
            {
                let store = Arc::new(SqliteContextManager::new(&path).unwrap());
                let control = ClusterControl::new(store.clone()).unwrap();
                let _pending = prepared(&store, &original, None);
                if committed {
                    control
                        .transition(NodeAvailability::Draining, 0, "system", "receipt fixture")
                        .unwrap();
                }
                // Deliberately omit reply persistence at this durable boundary.
            }
            let store = Arc::new(SqliteContextManager::new(&path).unwrap());
            let control = ClusterControl::new(store.clone()).unwrap();
            code(
                prepare(&store, "receipt-node", &original, None)
                    .err()
                    .unwrap(),
                WireErrorCode::Conflict,
            );
            assert_eq!(
                control.status().unwrap().generation,
                if committed { 1 } else { 0 }
            );
            let phase: String = store
                .conn
                .lock()
                .unwrap()
                .query_row("SELECT phase FROM cluster_operation_receipts", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(phase, "pending");
            drop(control);
            drop(store);
            root.close().unwrap();
        }
    }

    #[test]
    fn receipt_process_boundary_child() {
        use std::io::Write;
        let Some(path) = std::env::var_os("AIAGENTOS_TEST_RECEIPT_BOUNDARY_DB") else {
            return;
        };
        let id =
            uuid::Uuid::parse_str(&std::env::var("AIAGENTOS_TEST_RECEIPT_BOUNDARY_ID").unwrap())
                .unwrap();
        let store = Arc::new(SqliteContextManager::new(std::path::Path::new(&path)).unwrap());
        let control = ClusterControl::new(store.clone()).unwrap();
        let _pending = prepared(&store, &call(id), None);
        if std::env::var("AIAGENTOS_TEST_RECEIPT_BOUNDARY_PHASE").unwrap() == "committed" {
            control
                .transition(NodeAvailability::Draining, 0, "system", "receipt fixture")
                .unwrap();
        }
        println!("RECEIPT_BOUNDARY_DURABLE");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }

    #[tokio::test]
    async fn actual_process_kill_at_pending_and_committed_before_reply_boundaries_requires_reconciliation(
    ) {
        use tokio::io::AsyncBufReadExt;
        for phase in ["pending", "committed"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("receipts.db");
            let id = uuid::Uuid::new_v4();
            let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cluster_operation_receipts::tests::receipt_process_boundary_child",
                    "--nocapture",
                ])
                .env("AIAGENTOS_TEST_RECEIPT_BOUNDARY_DB", &path)
                .env("AIAGENTOS_TEST_RECEIPT_BOUNDARY_ID", id.to_string())
                .env("AIAGENTOS_TEST_RECEIPT_BOUNDARY_PHASE", phase)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let line = stdout
                        .next_line()
                        .await
                        .unwrap()
                        .expect("child exited before durable boundary");
                    if line.ends_with("RECEIPT_BOUNDARY_DURABLE") {
                        break;
                    }
                }
            })
            .await
            .expect("bounded actual durable child boundary");
            child.start_kill().unwrap();
            let status = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
                .await
                .expect("killed child must be reclaimed")
                .unwrap();
            assert!(
                !status.success(),
                "abrupt process termination must not become graceful completion"
            );
            drop(stdout);
            let store = Arc::new(SqliteContextManager::new(&path).unwrap());
            let control = ClusterControl::new(store.clone()).unwrap();
            code(
                prepare(&store, "receipt-node", &call(id), None)
                    .err()
                    .unwrap(),
                WireErrorCode::Conflict,
            );
            assert_eq!(
                control.status().unwrap().generation,
                if phase == "committed" { 1 } else { 0 }
            );
            assert_eq!(
                control.audit(10).unwrap().len(),
                if phase == "committed" { 1 } else { 0 }
            );
            drop(control);
            drop(store);
            root.close().unwrap();
        }
    }

    #[test]
    fn pending_byte_reservations_fail_closed_without_evicting_any_entry() {
        let store = SqliteContextManager::in_memory().unwrap();
        let pending_count = MAX_RETAINED_BYTES / MAX_REPLY_BYTES as i64;
        {
            let mut conn = store.conn.lock().unwrap();
            let tx = conn.transaction().unwrap();
            for _ in 0..pending_count {
                tx.execute("INSERT INTO cluster_operation_receipts VALUES (?1, ?2, ?3, 'pending', NULL, ?4)", params![uuid::Uuid::new_v4().to_string(), "a".repeat(64), "b".repeat(64), chrono::Utc::now().to_rfc3339()]).unwrap();
            }
            tx.commit().unwrap();
        }
        code(
            prepare(&store, "receipt-node", &call(uuid::Uuid::new_v4()), None)
                .err()
                .unwrap(),
            WireErrorCode::QuotaExceeded,
        );
        let count: i64 = store
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM cluster_operation_receipts WHERE phase = 'pending'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, pending_count);
    }

    #[test]
    fn oversized_or_wrong_reply_stays_pending_and_no_payload_is_cached() {
        for reply in [
            SyscallReply::Error {
                message: "x".repeat(MAX_REPLY_BYTES + 1),
            },
            SyscallReply::StorageValue {
                value: Some("foreign payload".into()),
            },
        ] {
            let store = SqliteContextManager::in_memory().unwrap();
            let original = call(uuid::Uuid::new_v4());
            let receipt = prepared(&store, &original, None);
            assert!(complete(&store, receipt, &reply).is_err());
            let pending: bool = store.conn.lock().unwrap().query_row("SELECT phase = 'pending' AND reply_json IS NULL FROM cluster_operation_receipts", [], |row| row.get(0)).unwrap();
            assert!(pending);
            code(
                prepare(&store, "receipt-node", &original, None)
                    .err()
                    .unwrap(),
                WireErrorCode::Conflict,
            );
        }
    }

    #[tokio::test]
    async fn unauthorized_principal_cannot_read_a_cached_operation_or_its_result() {
        let kernel = crate::AgentKernelImpl::new().unwrap();
        let original = call(uuid::Uuid::new_v4());
        let first = crate::syscall_server::dispatch(&kernel, original.clone()).await;
        assert!(matches!(first, SyscallReply::NodeControlUpdated { .. }));
        let actor = Principal {
            user_id: "foreign-user".into(),
            tenant_id: "foreign-tenant".into(),
            role: Role::Admin,
            credential: None,
        };
        let denied = crate::syscall_server::dispatch_scoped(&kernel, original, Some(&actor)).await;
        let encoded = serde_json::to_string(&denied).unwrap();
        assert!(encoded.contains("authorization denied"));
        assert!(!encoded.contains("receipt fixture"));
        assert!(!encoded.contains("draining"));
        assert_eq!(kernel.cluster_control.status().unwrap().generation, 1);
    }
}
