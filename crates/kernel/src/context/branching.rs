//! Immutable conversation prefixes and private branch tails in the context store.

use super::*;
use crate::connector::StandardMessage;
use uuid::Uuid;

pub const EXECUTION_SNAPSHOT_VERSION: u32 = 2;
pub const MAX_EXECUTION_SNAPSHOT_DEPTH: usize = 64;
pub const MAX_EXECUTION_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

/// Non-sensitive metadata for a shared, immutable execution-history prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSnapshotMetadata {
    pub id: Uuid,
    pub version: u32,
    pub message_count: usize,
    pub logical_bytes: u64,
    pub depth: usize,
}

fn failed(message: impl Into<String>) -> ContextError {
    ContextError::PersistenceFailed(message.into())
}
fn sql_error(error: rusqlite::Error) -> ContextError {
    failed(error.to_string())
}
pub(super) fn payload_hash(payload: &str) -> String {
    memory_content_hash(payload)
}
fn node_hash(
    metadata: &ExecutionSnapshotMetadata,
    tenant: &str,
    parent: &Option<String>,
    payload_digest: &str,
    spill_manifest: &str,
) -> Result<String, ContextError> {
    let encoded = serde_json::to_string(&(
        metadata.version,
        metadata.id.to_string(),
        tenant,
        parent,
        payload_digest,
        metadata.message_count,
        metadata.logical_bytes,
        metadata.depth,
        spill_manifest,
    ))
    .map_err(|error| failed(error.to_string()))?;
    Ok(payload_hash(&encoded))
}

pub(super) fn init_schema(conn: &Connection) -> Result<(), ContextError> {
    let old_shape = conn
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE name = 'execution_context_snapshots'",
            [],
            |_| Ok(()),
        )
        .optional()
        .map_err(sql_error)?
        .is_some()
        && !crate::schema::has_column(conn, "execution_context_snapshots", "spill_manifest_hash")?;
    crate::schema::add_column_if_missing(conn, "conversations", "messages_hash", "TEXT")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS execution_context_snapshots (
             id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             parent_id TEXT REFERENCES execution_context_snapshots(id),
             version INTEGER NOT NULL,
             payload_json TEXT NOT NULL,
             payload_hash TEXT NOT NULL,
             node_hash TEXT NOT NULL,
             spill_manifest_hash TEXT NOT NULL,
             message_count INTEGER NOT NULL CHECK(message_count >= 0),
             logical_bytes INTEGER NOT NULL CHECK(logical_bytes >= 2),
             depth INTEGER NOT NULL CHECK(depth BETWEEN 1 AND 64)
         );
         CREATE INDEX IF NOT EXISTS idx_execution_snapshots_tenant
             ON execution_context_snapshots(tenant_id);
         CREATE TABLE IF NOT EXISTS conversation_snapshot_refs (
             conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
             tenant_id TEXT NOT NULL,
             snapshot_id TEXT NOT NULL REFERENCES execution_context_snapshots(id)
         );
         CREATE INDEX IF NOT EXISTS idx_conversation_snapshot_refs_root
             ON conversation_snapshot_refs(snapshot_id);
         CREATE VIRTUAL TABLE IF NOT EXISTS execution_snapshot_fts
             USING fts5(snapshot_id, content);",
    )
    .map_err(sql_error)?;
    let empty_manifest = payload_hash("[]");
    crate::schema::add_column_if_missing(
        conn,
        "execution_context_snapshots",
        "spill_manifest_hash",
        &format!("TEXT NOT NULL DEFAULT '{empty_manifest}'"),
    )?;
    shared_spills::init_schema(conn)?;
    if old_shape {
        let mut statement = conn.prepare("SELECT id, tenant_id, parent_id, version, payload_hash, node_hash, message_count, logical_bytes, depth FROM execution_context_snapshots").map_err(sql_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, usize>(6)?,
                    row.get::<_, u64>(7)?,
                    row.get::<_, usize>(8)?,
                ))
            })
            .map_err(sql_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_error)?;
        drop(statement);
        for (id, tenant, parent, version, digest, old_hash, count, bytes, depth) in rows {
            let old_metadata = serde_json::to_string(&(
                version, &id, &tenant, &parent, &digest, count, bytes, depth,
            ))
            .map_err(|error| failed(error.to_string()))?;
            if version != 1 || payload_hash(&old_metadata) != old_hash {
                return Err(failed("legacy execution snapshot integrity mismatch"));
            }
            let metadata = ExecutionSnapshotMetadata {
                id: Uuid::parse_str(&id).map_err(|error| failed(error.to_string()))?,
                version: EXECUTION_SNAPSHOT_VERSION,
                message_count: count,
                logical_bytes: bytes,
                depth,
            };
            conn.execute(
                "UPDATE execution_context_snapshots SET version = ?1, node_hash = ?2 WHERE id = ?3",
                params![
                    EXECUTION_SNAPSHOT_VERSION,
                    node_hash(&metadata, &tenant, &parent, &digest, &empty_manifest)?,
                    id
                ],
            )
            .map_err(sql_error)?;
        }
    }
    Ok(())
}

struct Node {
    metadata: ExecutionSnapshotMetadata,
    parent: Option<String>,
    payload_digest: String,
}
fn node(conn: &Connection, id: &str, tenant: &str) -> Result<Node, ContextError> {
    let (stored_tenant, parent, version, digest, hash, count, bytes, depth, manifest): (
        String,
        Option<String>,
        u32,
        String,
        String,
        usize,
        u64,
        usize,
        String,
    ) = conn
        .query_row(
            "SELECT tenant_id, parent_id, version, payload_hash, node_hash,
                    message_count, logical_bytes, depth, spill_manifest_hash
             FROM execution_context_snapshots WHERE id = ?1",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .map_err(sql_error)?;
    let metadata = ExecutionSnapshotMetadata {
        id: Uuid::parse_str(id).map_err(|error| failed(error.to_string()))?,
        version,
        message_count: count,
        logical_bytes: bytes,
        depth,
    };
    if stored_tenant != tenant
        || version != EXECUTION_SNAPSHOT_VERSION
        || depth == 0
        || depth > MAX_EXECUTION_SNAPSHOT_DEPTH
        || bytes > MAX_EXECUTION_SNAPSHOT_BYTES
        || hash != node_hash(&metadata, tenant, &parent, &digest, &manifest)?
        || manifest != shared_spills::manifest_digest(conn, id)?
    {
        return Err(failed(
            "execution snapshot ownership, version or integrity mismatch",
        ));
    }
    Ok(Node {
        metadata,
        parent,
        payload_digest: digest,
    })
}
fn reference(
    conn: &Connection,
    conversation: &str,
) -> Result<Option<(String, String)>, ContextError> {
    conn.query_row(
        "SELECT snapshot_id, tenant_id FROM conversation_snapshot_refs WHERE conversation_id = ?1",
        [conversation],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(sql_error)
}
fn load_snapshot(
    conn: &Connection,
    id: &str,
    tenant: &str,
) -> Result<Vec<StandardMessage>, ContextError> {
    let root = node(conn, id, tenant)?;
    let mut cursor = Some(id.to_string());
    let mut seen = BTreeSet::new();
    let mut segments = Vec::new();
    let mut expected_depth = root.metadata.depth;
    while let Some(id) = cursor {
        if seen.len() >= MAX_EXECUTION_SNAPSHOT_DEPTH || !seen.insert(id.clone()) {
            return Err(failed("execution snapshot cycle or depth limit"));
        }
        let current = node(conn, &id, tenant)?;
        if current.metadata.depth != expected_depth {
            return Err(failed("execution snapshot depth mismatch"));
        }
        let payload: Option<String> = conn
            .query_row(
                "SELECT CASE WHEN LENGTH(CAST(payload_json AS BLOB)) <= ?2
                         THEN payload_json ELSE NULL END
                 FROM execution_context_snapshots WHERE id = ?1",
                params![&id, MAX_EXECUTION_SNAPSHOT_BYTES],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        let payload = payload.ok_or_else(|| failed("execution snapshot payload bound exceeded"))?;
        if payload_hash(&payload) != current.payload_digest {
            return Err(failed("execution snapshot payload integrity mismatch"));
        }
        let segment = serde_json::from_str::<Vec<StandardMessage>>(&payload)
            .map_err(|error| failed(error.to_string()))?;
        segments.push(segment);
        cursor = current.parent;
        expected_depth = expected_depth.saturating_sub(1);
    }
    if expected_depth != 0 {
        return Err(failed("execution snapshot ancestor missing"));
    }
    let messages = segments.into_iter().rev().flatten().collect::<Vec<_>>();
    let encoded = serde_json::to_string(&messages).map_err(|error| failed(error.to_string()))?;
    if messages.len() != root.metadata.message_count
        || encoded.len() as u64 != root.metadata.logical_bytes
    {
        return Err(failed("execution snapshot size mismatch"));
    }
    Ok(messages)
}

pub(super) fn validate_owned_roots(
    conn: &Connection,
    agent: AgentId,
    tenant: &str,
) -> Result<(), ContextError> {
    let mut statement = conn.prepare("SELECT r.snapshot_id,r.tenant_id FROM conversation_snapshot_refs r JOIN conversations c ON c.id = r.conversation_id WHERE c.agent_id = ?1").map_err(sql_error)?;
    let roots = statement
        .query_map([agent.to_string()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_error)?;
    drop(statement);
    for (root, owner) in roots {
        if owner != tenant {
            return Err(failed("snapshot spill tenant mismatch"));
        }
        let mut seen = BTreeSet::new();
        let mut cursor = Some(root);
        while let Some(id) = cursor {
            if seen.len() >= MAX_EXECUTION_SNAPSHOT_DEPTH || !seen.insert(id.clone()) {
                return Err(failed("snapshot spill ancestry cycle or limit"));
            }
            cursor = node(conn, &id, tenant)?.parent;
        }
    }
    Ok(())
}

fn seal_tail(
    conn: &Connection,
    conversation: &str,
    agent: AgentId,
    tenant: &str,
    base: Option<&Node>,
) -> Result<ExecutionSnapshotMetadata, ContextError> {
    crate::schema::require_current_writer(conn)?;
    let (count,digest,tail_bytes): (usize,String,u64) = conn.query_row(
        "SELECT json_array_length(messages_json),messages_hash,LENGTH(CAST(messages_json AS BLOB)) FROM conversations WHERE id = ?1",
        [conversation],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))
    ).map_err(sql_error)?;
    let metadata = ExecutionSnapshotMetadata {
        id: Uuid::new_v4(),
        version: EXECUTION_SNAPSHOT_VERSION,
        message_count: count + base.map_or(0, |base| base.metadata.message_count),
        logical_bytes: tail_bytes
            + base.map_or(0, |base| base.metadata.logical_bytes - 2)
            + u64::from(count > 0 && base.is_some_and(|base| base.metadata.message_count > 0)),
        depth: base.map_or(1, |base| base.metadata.depth + 1),
    };
    if metadata.depth > MAX_EXECUTION_SNAPSHOT_DEPTH
        || metadata.logical_bytes > MAX_EXECUTION_SNAPSHOT_BYTES
    {
        return Err(failed("execution snapshot depth or byte bound exceeded"));
    }
    let parent = base.map(|base| base.metadata.id.to_string());
    let empty_manifest = payload_hash("[]");
    let inserted = conn.execute(
        "INSERT INTO execution_context_snapshots(id,tenant_id,parent_id,version,payload_json,payload_hash,node_hash,message_count,logical_bytes,depth,spill_manifest_hash)
         SELECT ?1,?2,?3,?4,messages_json,?5,?6,?7,?8,?9,?10 FROM conversations WHERE id = ?11
           AND messages_hash = agentos_digest(messages_json)",
        params![metadata.id.to_string(),tenant,&parent,metadata.version,&digest,node_hash(&metadata,tenant,&parent,&digest,&empty_manifest)?,metadata.message_count,metadata.logical_bytes,metadata.depth,&empty_manifest,conversation]
    ).map_err(sql_error)?;
    if inserted != 1 {
        return Err(failed("execution history digest mismatch"));
    }
    let manifest =
        shared_spills::attach_tail(conn, &metadata.id.to_string(), agent, tenant, conversation)?;
    conn.execute("UPDATE execution_context_snapshots SET spill_manifest_hash = ?1,node_hash = ?2 WHERE id = ?3",
        params![&manifest,node_hash(&metadata,tenant,&parent,&digest,&manifest)?,metadata.id.to_string()]).map_err(sql_error)?;
    let payload: String = conn.query_row(
        "SELECT payload_json FROM execution_context_snapshots WHERE id = ?1",
        [metadata.id.to_string()],|row|row.get(0)
    ).map_err(sql_error)?;
    let messages: Vec<StandardMessage> = serde_json::from_str(&payload)
        .map_err(|_|failed("invalid execution snapshot content"))?;
    let projection = messages.iter().map(|message|message.content.text_projection()).collect::<Vec<_>>().join(" ");
    conn.execute(
        "INSERT INTO execution_snapshot_fts(snapshot_id,content) VALUES (?1,?2)",
        params![metadata.id.to_string(),projection]
    ).map_err(sql_error)?;
    crash_multi_table_mutation_after_step_for_test("fork.snapshot");
    Ok(metadata)
}

pub(super) fn prepare_tail(
    conn: &Connection,
    conversation: &str,
    agent: AgentId,
    tenant: &str,
    messages: &[StandardMessage],
) -> Result<String, ContextError> {
    if let Some((id, owner)) = reference(conn, conversation)? {
        if owner != tenant || SqliteContextManager::agent_tenant_locked(conn, agent)? != owner {
            return Err(failed("conversation snapshot tenant mismatch"));
        }
        let baseline = load_snapshot(conn, &id, tenant)?;
        if messages.starts_with(&baseline) {
            return serde_json::to_string(&messages[baseline.len()..])
                .map_err(|error| failed(error.to_string()));
        }
        // A summarized or otherwise rewritten history starts a private root.
        // Shared prefixes referenced by other branches remain immutable.
        let json = serde_json::to_string(messages).map_err(|error| failed(error.to_string()))?;
        conn.execute(
            "UPDATE conversations SET messages_json = ?1,messages_hash = ?2 WHERE id = ?3",
            params![&json, payload_hash(&json), conversation],
        )
        .map_err(sql_error)?;
        let snapshot = seal_tail(conn, conversation, agent, tenant, None)?;
        conn.execute(
            "UPDATE conversation_snapshot_refs SET snapshot_id = ?1 WHERE conversation_id = ?2",
            params![snapshot.id.to_string(), conversation],
        )
        .map_err(sql_error)?;
        gc(conn)?;
        return Ok("[]".into());
    }
    serde_json::to_string(messages).map_err(|error| failed(error.to_string()))
}

pub(super) fn logical_bytes(conn: &Connection, conversation: &str) -> Result<u64, ContextError> {
    conn.query_row(
        "SELECT LENGTH(CAST(c.messages_json AS BLOB)) + COALESCE(s.logical_bytes - 2, 0)
                 + CASE WHEN s.message_count > 0 AND json_array_length(c.messages_json) > 0 THEN 1 ELSE 0 END
         FROM conversations c
         LEFT JOIN conversation_snapshot_refs r ON r.conversation_id = c.id
         LEFT JOIN execution_context_snapshots s ON s.id = r.snapshot_id
         WHERE c.id = ?1",
        [conversation],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql_error)
    .map(|value| value.unwrap_or(0))
}

pub(super) fn load_conversation(
    conn: &Connection,
    conversation: &str,
) -> Result<Vec<StandardMessage>, ContextError> {
    let (agent, json, digest): (String, String, Option<String>) = conn
        .query_row(
            "SELECT agent_id, messages_json, messages_hash FROM conversations WHERE id = ?1",
            [conversation],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sql_error)?;
    if digest.is_some_and(|digest| digest != payload_hash(&json)) {
        return Err(failed("conversation payload integrity mismatch"));
    }
    let mut messages = match reference(conn, conversation)? {
        Some((id, tenant)) => {
            let agent = Uuid::parse_str(&agent).map_err(|error| failed(error.to_string()))?;
            if SqliteContextManager::agent_tenant_locked(conn, agent)? != tenant {
                return Err(failed("conversation snapshot tenant mismatch"));
            }
            load_snapshot(conn, &id, &tenant)?
        }
        None => Vec::new(),
    };
    messages.extend(
        serde_json::from_str::<Vec<StandardMessage>>(&json)
            .map_err(|error| failed(error.to_string()))?,
    );
    Ok(messages)
}

/// Delete unreachable immutable prefixes and their search indexes. Call only
/// inside the same write transaction that changes roots or erases owners.
pub(super) fn gc(conn: &Connection) -> Result<(usize, usize), ContextError> {
    const LIVE: &str = "WITH RECURSIVE live(id) AS (
        SELECT snapshot_id FROM conversation_snapshot_refs
        UNION
        SELECT s.parent_id FROM execution_context_snapshots s JOIN live ON s.id = live.id
        WHERE s.parent_id IS NOT NULL
    ) ";
    let search_rows = conn.execute(
        &format!("{LIVE} DELETE FROM execution_snapshot_fts WHERE snapshot_id NOT IN (SELECT id FROM live)"),
        [],
    )
    .map_err(sql_error)?;
    let snapshots = conn.execute(
        &format!("{LIVE} DELETE FROM execution_context_snapshots WHERE id NOT IN (SELECT id FROM live)"),
        [],
    )
    .map_err(sql_error)?;
    shared_spills::gc(conn)?;
    Ok((snapshots, search_rows))
}

impl SqliteContextManager {
    /// Read the latest owned execution conversation under one consistent
    /// SQLite snapshot. Corrupt shared or private history fails before a new
    /// provider session is created.
    pub fn latest_execution_history(
        &self,
        agent: AgentId,
    ) -> Result<Option<(String, Vec<StandardMessage>)>, ContextError> {
        let mut conn = self.locked_conn();
        let tx = conn.transaction().map_err(sql_error)?;
        let id: Option<String> = tx.query_row(
            "SELECT id FROM conversations WHERE agent_id = ?1 ORDER BY updated_at DESC, id DESC LIMIT 1",
            [agent.to_string()], |row| row.get(0)
        ).optional().map_err(sql_error)?;
        let result = id
            .map(|id| load_conversation(&tx, &id).map(|messages| (id, messages)))
            .transpose()?;
        tx.commit().map_err(sql_error)?;
        Ok(result)
    }

    /// Fork an owned conversation over immutable shared prefixes. This is a
    /// storage transaction, not an agent lifecycle operation: kernel callers
    /// must first serialize the parent against execution and teardown.
    /// Both existing agent identities must belong to the same tenant.
    pub fn fork_conversation(
        &self,
        parent: AgentId,
        source: &str,
        child: AgentId,
        target: &str,
    ) -> Result<ExecutionSnapshotMetadata, ContextError> {
        if parent == child || source == target || target.is_empty() || target.len() > 128 {
            return Err(failed("invalid conversation fork identities"));
        }
        let mut conn = self.locked_conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let result = self.fork_conversation_locked(&tx, parent, source, child, target)?;
        tx.commit().map_err(sql_error)?;
        Ok(result)
    }

    pub(super) fn fork_conversation_locked(
        &self,
        tx: &Connection,
        parent: AgentId,
        source: &str,
        child: AgentId,
        target: &str,
    ) -> Result<ExecutionSnapshotMetadata, ContextError> {
        crate::schema::require_current_writer(tx)?;
        let owned_tenant = |agent: AgentId| -> Result<String, ContextError> {
            tx.query_row(
                "SELECT tenant_id FROM agents WHERE id = ?1",
                [agent.to_string()],
                |row| row.get(0),
            )
            .map_err(sql_error)
        };
        let tenant = owned_tenant(parent)?;
        if owned_tenant(child)? != tenant {
            return Err(failed("conversation fork tenant mismatch"));
        }
        let source_owner: String = tx
            .query_row(
                "SELECT agent_id FROM conversations WHERE id = ?1",
                [source],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        if source_owner != parent.to_string() {
            return Err(failed("conversation fork owner mismatch"));
        }
        let existing = tx
            .query_row(
                "SELECT 1 FROM conversations WHERE id = ?1",
                [target],
                |_| Ok(()),
            )
            .optional()
            .map_err(sql_error)?
            .is_some();
        if existing {
            return Err(failed("conversation fork target already exists"));
        }
        let legacy: bool = tx
            .query_row(
                "SELECT messages_hash IS NULL FROM conversations WHERE id = ?1",
                [source],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        if legacy {
            let raw: Option<String> = tx.query_row(
                "SELECT CASE WHEN LENGTH(CAST(messages_json AS BLOB)) <= ?2 THEN messages_json ELSE NULL END
                 FROM conversations WHERE id = ?1", params![source, MAX_EXECUTION_SNAPSHOT_BYTES], |row| row.get(0)
            ).map_err(sql_error)?;
            let raw =
                raw.ok_or_else(|| failed("legacy execution history exceeds the snapshot bound"))?;
            let messages: Vec<StandardMessage> =
                serde_json::from_str(&raw).map_err(|error| failed(error.to_string()))?;
            let canonical =
                serde_json::to_string(&messages).map_err(|error| failed(error.to_string()))?;
            tx.execute(
                "UPDATE conversations SET messages_json = ?1, messages_hash = ?2 WHERE id = ?3",
                params![&canonical, payload_hash(&canonical), source],
            )
            .map_err(sql_error)?;
        }
        let bytes = logical_bytes(tx, source)?;
        if bytes > MAX_EXECUTION_SNAPSHOT_BYTES {
            return Err(failed("execution snapshot logical byte bound exceeded"));
        }
        self.enforce_context_storage_locked(tx, child, &tenant, bytes, 0)?;
        let baseline = match reference(tx, source)? {
            Some((id, owner)) if owner == tenant => Some(node(tx, &id, &tenant)?),
            Some(_) => return Err(failed("conversation snapshot tenant mismatch")),
            None => None,
        };
        let count: usize = tx
            .query_row(
                "SELECT json_array_length(messages_json) FROM conversations WHERE id = ?1",
                [source],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        let snapshot = if let (0, Some(base)) = (count, &baseline) {
            base.metadata.clone()
        } else {
            seal_tail(tx, source, parent, &tenant, baseline.as_ref())?
        };
        tx.execute(
            "UPDATE conversations SET messages_json = '[]', messages_hash = ?1 WHERE id = ?2",
            params![payload_hash("[]"), source],
        )
        .map_err(sql_error)?;
        tx.execute(
            "DELETE FROM conversations_fts WHERE conversation_id = ?1",
            [source],
        )
        .map_err(sql_error)?;
        tx.execute(
            "INSERT INTO conversation_snapshot_refs(conversation_id, tenant_id, snapshot_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(conversation_id) DO UPDATE SET snapshot_id = excluded.snapshot_id",
            params![source, &tenant, snapshot.id.to_string()]
        ).map_err(sql_error)?;
        shared_spills::validate_ownership(tx, parent, &tenant)?;
        let spill_bytes = shared_spills::conversation_bytes(tx, source)?;
        if bytes.saturating_add(spill_bytes) > MAX_EXECUTION_SNAPSHOT_BYTES {
            return Err(failed(
                "execution snapshot including spills exceeds byte bound",
            ));
        }
        self.enforce_context_storage_locked(tx, child, &tenant, bytes + spill_bytes, 0)?;
        crash_multi_table_mutation_after_step_for_test("fork.source_reference");
        let now = Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO conversations(id, agent_id, messages_json, messages_hash, created_at, updated_at)
             VALUES (?1, ?2, '[]', ?3, ?4, ?4)",
            params![target, child.to_string(), payload_hash("[]"), &now]
        ).map_err(sql_error)?;
        crash_multi_table_mutation_after_step_for_test("fork.child_conversation");
        tx.execute(
            "INSERT INTO conversation_snapshot_refs(conversation_id, tenant_id, snapshot_id) VALUES (?1, ?2, ?3)",
            params![target, &tenant, snapshot.id.to_string()]
        ).map_err(sql_error)?;
        crash_multi_table_mutation_after_step_for_test("fork.child_reference");
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn agent(manager: &SqliteContextManager, tenant: &str) -> AgentId {
        let id = Uuid::new_v4();
        let now = Utc::now();
        manager
            .save_agent(&PersistedAgent {
                id,
                session_id: Uuid::new_v4(),
                tenant_id: tenant.into(),
                name: "branch".into(),
                task: "context branching".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: 3,
                status: "\"Running\"".into(),
                sandbox_config_json: None,
                created_at: now,
                last_activity_at: now,
            })
            .unwrap();
        id
    }
    fn history() -> Vec<StandardMessage> {
        vec![
            StandardMessage::system("governed history"),
            StandardMessage::user("immutable needle 🦀"),
            StandardMessage::assistant("completed effect"),
        ]
    }
    fn count(manager: &SqliteContextManager, table: &str) -> usize {
        manager
            .locked_conn()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    #[test]
    fn fork_shares_prefixes_and_stores_only_independent_private_tails() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        let third = agent(&manager, "tenant");
        let original = history();
        manager
            .save_conversation("parent", parent, &original)
            .unwrap();
        let first = manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        assert_eq!(first.message_count, original.len());
        assert_eq!(first.depth, 1);
        assert_eq!(manager.load_conversation("child").unwrap(), original);
        {
            let conn = manager.locked_conn();
            let tails: Vec<String> = conn
                .prepare("SELECT messages_json FROM conversations ORDER BY id")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(tails, ["[]", "[]"]);
        }
        let repeated = manager
            .fork_conversation(parent, "parent", third, "third")
            .unwrap();
        assert_eq!(
            repeated.id, first.id,
            "a clone without new writes reuses the immutable prefix"
        );
        assert_eq!(count(&manager, "execution_context_snapshots"), 1);
        let mut parent_history = original.clone();
        parent_history.push(StandardMessage::user("parent private write"));
        let mut child_history = original.clone();
        child_history.push(StandardMessage::user("child private write"));
        manager
            .save_conversation("parent", parent, &parent_history)
            .unwrap();
        manager
            .save_conversation("child", child, &child_history)
            .unwrap();
        assert_eq!(manager.load_conversation("parent").unwrap(), parent_history);
        assert_eq!(manager.load_conversation("child").unwrap(), child_history);
        assert_eq!(manager.load_conversation("third").unwrap(), original);
        let next = manager
            .fork_conversation(child, "child", third, "grandchild")
            .unwrap();
        assert_eq!(next.depth, 2);
        assert_eq!(
            manager.load_conversation("grandchild").unwrap(),
            child_history
        );
        let bytes: String = manager
            .locked_conn()
            .query_row(
                "SELECT payload_json FROM execution_context_snapshots WHERE id = ?1",
                [next.id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<StandardMessage>>(&bytes).unwrap(),
            vec![StandardMessage::user("child private write")]
        );
    }

    #[test]
    fn shared_and_private_search_indexes_follow_branches_and_erasure() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        manager
            .save_conversation("parent", parent, &history())
            .unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        let found = manager.search_conversations("needle");
        assert_eq!(
            found
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["child", "parent"])
        );
        manager.delete_agent(parent).unwrap();
        assert_eq!(count(&manager, "execution_context_snapshots"), 1);
        assert_eq!(manager.load_conversation("child").unwrap(), history());
        assert_eq!(manager.search_conversations("needle").len(), 1);
        manager.delete_agent(child).unwrap();
        assert_eq!(count(&manager, "execution_context_snapshots"), 0);
        assert_eq!(count(&manager, "conversation_snapshot_refs"), 0);
        assert_eq!(count(&manager, "execution_snapshot_fts"), 0);
        assert!(manager.search_conversations("needle").is_empty());
    }

    #[test]
    fn compaction_detaches_only_the_rewritten_branch_and_reclaims_last_reference() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        manager
            .save_conversation("parent", parent, &history())
            .unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        let compact = vec![StandardMessage::system("private summary")];
        manager
            .save_conversation("parent", parent, &compact)
            .unwrap();
        assert_eq!(manager.load_conversation("parent").unwrap(), compact);
        assert_eq!(manager.load_conversation("child").unwrap(), history());
        assert_eq!(count(&manager, "conversation_snapshot_refs"), 2);
        manager.delete_conversation("child").unwrap();
        assert_eq!(manager.load_conversation("parent").unwrap(), compact);
        assert_eq!(count(&manager, "execution_context_snapshots"), 1);
        manager.delete_conversation("parent").unwrap();
        assert_eq!(count(&manager, "execution_context_snapshots"), 0);
        assert_eq!(count(&manager, "execution_snapshot_fts"), 0);
    }

    #[test]
    fn signed_native_history_survives_shared_fork_restart_and_parent_erasure() {
        let dir = std::env::temp_dir().join(format!("agentos-native-history-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        let (parent, child, expected) = {
            let manager = SqliteContextManager::new(&path).unwrap();
            let parent = agent(&manager, "tenant");
            let child = agent(&manager, "tenant");
            let mut assistant = StandardMessage::assistant("signed answer");
            assistant.provider_metadata = Some(
                crate::connector::ProviderMessageMetadata::new(
                    "gemini".into(),
                    "fixture-model".into(),
                    serde_json::json!({
                        "parts": [{"text": "signed answer", "thoughtSignature": "c2ln"}],
                        "tool_call_ids": []
                    }),
                )
                .unwrap(),
            );
            let messages = vec![StandardMessage::user("task"), assistant];
            manager
                .save_conversation("parent", parent, &messages)
                .unwrap();
            manager
                .fork_conversation(parent, "parent", child, "child")
                .unwrap();
            assert_eq!(manager.load_conversation("child").unwrap(), messages);
            (parent, child, messages)
        };
        let manager = SqliteContextManager::new(&path).unwrap();
        assert_eq!(manager.load_conversation("child").unwrap(), expected);
        manager.delete_agent(parent).unwrap();
        assert_eq!(manager.load_conversation("child").unwrap(), expected);
        manager.delete_agent(child).unwrap();
        assert_eq!(count(&manager, "execution_context_snapshots"), 0);
        drop(manager);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn quota_admission_charges_logical_history_and_rolls_back_failed_forks() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        let third = agent(&manager, "tenant");
        let messages = history();
        let bytes = serde_json::to_vec(&messages).unwrap().len() as u64;
        manager
            .save_conversation("parent", parent, &messages)
            .unwrap();
        let limits = |tenant_bytes| ContextStorageLimits {
            per_agent_bytes: bytes,
            per_tenant_bytes: tenant_bytes,
            global_bytes: bytes * 2,
            ..Default::default()
        };
        manager
            .set_context_storage_limits(limits(bytes * 2 - 1))
            .unwrap();
        assert!(manager
            .fork_conversation(parent, "parent", child, "child")
            .is_err());
        assert_eq!(count(&manager, "execution_context_snapshots"), 0);
        assert_eq!(count(&manager, "conversations"), 1);
        manager
            .set_context_storage_limits(limits(bytes * 2))
            .unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        assert!(manager
            .fork_conversation(parent, "parent", third, "third")
            .is_err());
        assert_eq!(count(&manager, "conversation_snapshot_refs"), 2);
        assert_eq!(manager.load_conversation("parent").unwrap(), messages);
        let mut too_large = messages.clone();
        too_large.push(StandardMessage::user("over budget"));
        assert!(manager
            .save_conversation("child", child, &too_large)
            .is_err());
        assert_eq!(manager.load_conversation("child").unwrap(), messages);
        manager.delete_agent(parent).unwrap();
        manager
            .fork_conversation(child, "child", third, "third")
            .unwrap();
        assert_eq!(count(&manager, "execution_context_snapshots"), 1);
    }

    #[test]
    fn ownership_denials_and_mid_transaction_failure_leave_no_branches() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        let foreign = agent(&manager, "foreign");
        manager
            .save_conversation("parent", parent, &history())
            .unwrap();
        assert!(manager
            .fork_conversation(parent, "parent", foreign, "foreign")
            .is_err());
        assert!(manager
            .fork_conversation(child, "parent", parent, "wrong-owner")
            .is_err());
        assert_eq!(count(&manager, "execution_context_snapshots"), 0);
        manager
            .locked_conn()
            .execute_batch(
                "CREATE TRIGGER reject_branch BEFORE INSERT ON conversations WHEN NEW.id = 'child'
             BEGIN SELECT RAISE(ABORT, 'injected child insert failure'); END;",
            )
            .unwrap();
        assert!(manager
            .fork_conversation(parent, "parent", child, "child")
            .is_err());
        assert_eq!(count(&manager, "execution_context_snapshots"), 0);
        assert_eq!(count(&manager, "execution_snapshot_fts"), 0);
        assert_eq!(count(&manager, "conversation_snapshot_refs"), 0);
        assert_eq!(manager.load_conversation("parent").unwrap(), history());
    }

    #[test]
    fn legacy_payload_is_canonicalized_once_and_corruption_fails_closed() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        manager.locked_conn().execute(
            "INSERT INTO conversations(id, agent_id, messages_json, created_at, updated_at)
             VALUES ('parent', ?1, '[ { \"role\" : \"user\", \"content\" : \"legacy\" } ]', 'now', 'now')", [parent.to_string()]
        ).unwrap();
        let metadata = manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        assert_eq!(
            manager.load_conversation("child").unwrap(),
            vec![StandardMessage::user("legacy")]
        );
        manager
            .locked_conn()
            .execute(
                "UPDATE execution_context_snapshots SET version = 99 WHERE id = ?1",
                [metadata.id.to_string()],
            )
            .unwrap();
        assert!(manager.load_conversation("child").is_err());
        manager.locked_conn().execute("UPDATE execution_context_snapshots SET version = 2, payload_json = '[]' WHERE id = ?1", [metadata.id.to_string()]).unwrap();
        assert!(manager.load_conversation("child").is_err());
    }

    #[test]
    fn concurrent_parent_and_child_writes_remain_independent() {
        let manager = Arc::new(SqliteContextManager::in_memory().unwrap());
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        manager
            .save_conversation("parent", parent, &history())
            .unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers = [(parent, "parent"), (child, "child")]
            .into_iter()
            .map(|(id, name)| {
                let manager = manager.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut messages = history();
                    messages.push(StandardMessage::user(name));
                    barrier.wait();
                    manager.save_conversation(name, id, &messages).unwrap();
                    messages
                })
            })
            .collect::<Vec<_>>();
        for (worker, name) in workers.into_iter().zip(["parent", "child"]) {
            let expected = worker.join().unwrap();
            assert_eq!(manager.load_conversation(name).unwrap(), expected);
        }
    }

    #[test]
    fn restart_and_tenant_erasure_preserve_then_collect_shared_history() {
        let dir = std::env::temp_dir().join(format!("agentos-branch-storage-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        {
            let manager = SqliteContextManager::new(&path).unwrap();
            let parent = agent(&manager, "tenant");
            let child = agent(&manager, "tenant");
            manager
                .save_conversation("parent", parent, &history())
                .unwrap();
            manager
                .fork_conversation(parent, "parent", child, "child")
                .unwrap();
            manager.checkpoint().unwrap();
        }
        {
            let manager = SqliteContextManager::new(&path).unwrap();
            assert_eq!(manager.load_conversation("parent").unwrap(), history());
            assert_eq!(manager.load_conversation("child").unwrap(), history());
            manager.erase_tenant_data("tenant").unwrap();
            assert_eq!(count(&manager, "execution_context_snapshots"), 0);
            assert_eq!(count(&manager, "execution_snapshot_fts"), 0);
            assert_eq!(count(&manager, "conversation_snapshot_refs"), 0);
            assert!(manager.load_conversation("child").is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn encrypted_restart_keeps_shared_history_inside_the_protected_database() {
        use crate::storage_encryption::StorageEncryptionKey;
        let dir = std::env::temp_dir().join(format!("agentos-encrypted-branch-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        {
            let key = StorageEncryptionKey::from_bytes("branch-test", [7; 32]).unwrap();
            let manager = SqliteContextManager::new_encrypted(&path, key).unwrap();
            let parent = agent(&manager, "tenant");
            let child = agent(&manager, "tenant");
            manager
                .save_conversation("parent", parent, &history())
                .unwrap();
            manager
                .fork_conversation(parent, "parent", child, "child")
                .unwrap();
            manager.checkpoint().unwrap();
        }
        assert!(!std::fs::read(&path)
            .unwrap()
            .windows(b"immutable needle".len())
            .any(|bytes| bytes == b"immutable needle"));
        assert!(SqliteContextManager::new(&path).is_err());
        {
            let key = StorageEncryptionKey::from_bytes("branch-test", [7; 32]).unwrap();
            let manager = SqliteContextManager::new_encrypted(&path, key).unwrap();
            assert_eq!(manager.load_conversation("child").unwrap(), history());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn process_exit_between_fork_writes_rolls_back_every_reference() {
        for step in [
            "fork.snapshot",
            "fork.source_reference",
            "fork.child_conversation",
            "fork.child_reference",
        ] {
            let dir = std::env::temp_dir().join(format!("agentos-fork-crash-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("store.db");
            let (parent, child);
            {
                let manager = SqliteContextManager::new(&path).unwrap();
                parent = agent(&manager, "tenant");
                child = agent(&manager, "tenant");
                manager
                    .save_conversation("parent", parent, &history())
                    .unwrap();
            }
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "context::branching::tests::fork_crash_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("AIAGENTOS_FORK_CRASH_DB", &path)
                .env("AIAGENTOS_FORK_PARENT", parent.to_string())
                .env("AIAGENTOS_FORK_CHILD", child.to_string())
                .env("AIAGENTOS_TEST_EXIT_MULTI_TABLE_AFTER_STEP", step)
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(86),
                "crash stage {step} must be reached"
            );
            {
                let manager = SqliteContextManager::new(&path).unwrap();
                assert_eq!(manager.load_conversation("parent").unwrap(), history());
                assert!(manager.load_conversation("child").is_err());
                assert_eq!(count(&manager, "execution_context_snapshots"), 0);
                assert_eq!(count(&manager, "conversation_snapshot_refs"), 0);
                assert_eq!(count(&manager, "execution_snapshot_fts"), 0);
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    #[ignore = "subprocess crash fixture"]
    fn fork_crash_child() {
        let path = std::env::var_os("AIAGENTOS_FORK_CRASH_DB").expect("fixture path");
        let parent = std::env::var("AIAGENTOS_FORK_PARENT")
            .unwrap()
            .parse()
            .unwrap();
        let child = std::env::var("AIAGENTOS_FORK_CHILD")
            .unwrap()
            .parse()
            .unwrap();
        let manager = SqliteContextManager::new(Path::new(&path)).unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        panic!("fork crash stage was not reached");
    }

    proptest! {
        #[test]
        fn arbitrary_branch_tails_preserve_the_exact_shared_prefix(
            contents in prop::collection::vec(".{0,80}", 0..20),
            left in ".{0,80}", right in ".{0,80}"
        ) {
            let manager = SqliteContextManager::in_memory().unwrap();
            let parent = agent(&manager, "tenant");
            let child = agent(&manager, "tenant");
            let base = contents.into_iter().map(StandardMessage::user).collect::<Vec<_>>();
            manager.save_conversation("parent", parent, &base).unwrap();
            manager.fork_conversation(parent, "parent", child, "child").unwrap();
            let mut a = base.clone();
            a.push(StandardMessage::assistant(left));
            let mut b = base.clone();
            b.push(StandardMessage::assistant(right));
            manager.save_conversation("parent", parent, &a).unwrap();
            manager.save_conversation("child", child, &b).unwrap();
            prop_assert_eq!(manager.load_conversation("parent").unwrap(), a);
            prop_assert_eq!(manager.load_conversation("child").unwrap(), b);
            manager.delete_conversation("parent").unwrap();
            prop_assert_eq!(count(&manager, "execution_context_snapshots"), 1);
            manager.delete_conversation("child").unwrap();
            prop_assert_eq!(count(&manager, "execution_context_snapshots"), 0);
        }
    }
}
