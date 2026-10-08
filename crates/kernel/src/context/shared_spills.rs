//! Snapshot-owned spill payloads with bounded transitive page-in references.

use super::*;
use rusqlite::functions::FunctionFlags;

pub(super) const MAX_SHARED_SPILL_NODES: usize = 1024;

fn failed(message: impl Into<String>) -> ContextError {
    ContextError::RestoreFailed(message.into())
}
fn sql_error(error: rusqlite::Error) -> ContextError {
    failed(error.to_string())
}

pub(super) fn init_schema(conn: &Connection) -> Result<(), ContextError> {
    conn.create_scalar_function(
        "agentos_digest",
        1,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let value = context
                .get_raw(0)
                .as_str()
                .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
            Ok(memory_content_hash(value))
        },
    )
    .map_err(sql_error)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS execution_spill_blobs (
             id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             key TEXT NOT NULL,
             version INTEGER NOT NULL,
             payload_json TEXT NOT NULL,
             sha256 TEXT NOT NULL,
             edges_hash TEXT NOT NULL,
             byte_count INTEGER NOT NULL CHECK(byte_count >= 0)
         );
         CREATE TABLE IF NOT EXISTS execution_spill_edges (
             blob_id TEXT NOT NULL REFERENCES execution_spill_blobs(id) ON DELETE CASCADE,
             key TEXT NOT NULL,
             child_id TEXT NOT NULL REFERENCES execution_spill_blobs(id),
             PRIMARY KEY(blob_id, key)
         );
         CREATE TABLE IF NOT EXISTS execution_snapshot_spills (
             snapshot_id TEXT NOT NULL REFERENCES execution_context_snapshots(id) ON DELETE CASCADE,
             key TEXT NOT NULL,
             blob_id TEXT NOT NULL REFERENCES execution_spill_blobs(id),
             PRIMARY KEY(snapshot_id, key)
         );",
    )
    .map_err(sql_error)
}

#[derive(Debug, Clone)]
struct Reference {
    key: String,
    digest_prefix: String,
}
fn references(conn: &Connection, query: &str, id: &str) -> Result<Vec<Reference>, ContextError> {
    // query is a static expression selected by trusted call sites, never wire input.
    let mut statement = conn
        .prepare(&format!(
            "SELECT CASE WHEN LENGTH(CAST(json_extract(value, '$.content') AS BLOB)) <= 2048
                 THEN json_extract(value, '$.content') ELSE NULL END
         FROM json_each(({query}))
         WHERE json_extract(value, '$.role') = 'system'
           AND (substr(json_extract(value, '$.content'), 1, 28) = '[Durable context spill: key='
             OR substr(json_extract(value, '$.content'), 1, 20) = '[Context spill: key=')
         LIMIT {}",
            MAX_SHARED_SPILL_NODES + 1
        ))
        .map_err(sql_error)?;
    let rows = statement
        .query_map([id], |row| row.get::<_, Option<String>>(0))
        .map_err(sql_error)?;
    let mut result = BTreeMap::new();
    for (index, row) in rows.enumerate() {
        if index >= MAX_SHARED_SPILL_NODES {
            return Err(failed("too many context spill references"));
        }
        let message = row
            .map_err(sql_error)?
            .ok_or_else(|| failed("spill reference exceeds its bound"))?;
        let (_, tail) = message
            .split_once("key=")
            .ok_or_else(|| failed("invalid spill reference"))?;
        let (key, tail) = tail
            .split_once(';')
            .ok_or_else(|| failed("invalid spill key reference"))?;
        let (_, tail) = tail
            .split_once("sha256-prefix=")
            .ok_or_else(|| failed("spill digest reference is missing"))?;
        let digest_prefix = tail
            .split(';')
            .next()
            .ok_or_else(|| failed("invalid spill digest reference"))?;
        if !key.starts_with("context_spill:")
            || key.len() > MAX_KV_KEY_BYTES
            || digest_prefix.len() != 16
            || !digest_prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(failed("invalid or oversized spill reference"));
        }
        if result
            .insert(key.to_string(), digest_prefix.to_string())
            .is_some_and(|old| old != digest_prefix)
        {
            return Err(failed("conflicting spill references"));
        }
        if result.len() > MAX_SHARED_SPILL_NODES {
            return Err(failed("too many context spill references"));
        }
    }
    Ok(result
        .into_iter()
        .map(|(key, digest_prefix)| Reference { key, digest_prefix })
        .collect())
}

const REACHABLE: &str = "WITH RECURSIVE snapshots(conversation_id, id) AS (
    SELECT r.conversation_id, r.snapshot_id FROM conversation_snapshot_refs r
    JOIN conversations c ON c.id = r.conversation_id WHERE c.agent_id = ?1
    UNION
    SELECT s.conversation_id, n.parent_id FROM snapshots s
    JOIN execution_context_snapshots n ON n.id = s.id WHERE n.parent_id IS NOT NULL
), blobs(id) AS (
    SELECT r.blob_id FROM execution_snapshot_spills r JOIN snapshots s ON s.id = r.snapshot_id
    UNION
    SELECT e.child_id FROM execution_spill_edges e JOIN blobs b ON b.id = e.blob_id
) ";

pub(super) fn owned_blob(
    conn: &Connection,
    agent: AgentId,
    key: &str,
    tenant: &str,
) -> Result<Option<(String, String)>, ContextError> {
    validate_ownership(conn, agent, tenant)?;
    let mut statement = conn
        .prepare(&format!(
            "{REACHABLE} SELECT b.id, b.sha256 FROM execution_spill_blobs b
         JOIN blobs r ON r.id = b.id WHERE b.key = ?2 AND b.tenant_id = ?3 LIMIT 2"
        ))
        .map_err(sql_error)?;
    let result = statement
        .query_map(params![agent.to_string(), key, tenant], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(sql_error)?
        .collect::<Result<Vec<(String, String)>, _>>()
        .map_err(sql_error)?;
    if result.len() > 1 {
        return Err(failed("ambiguous immutable context spill key"));
    }
    Ok(result.into_iter().next())
}

pub(super) fn validate_ownership(
    conn: &Connection,
    agent: AgentId,
    tenant: &str,
) -> Result<(), ContextError> {
    branching::validate_owned_roots(conn, agent, tenant)?;
    validate_blobs(conn, agent, tenant)
}

fn blob_id(
    tenant: &str,
    key: &str,
    digest: &str,
    edges_hash: &str,
) -> Result<String, ContextError> {
    let metadata = serde_json::to_string(&(1, tenant, key, digest, edges_hash))
        .map_err(|error| failed(error.to_string()))?;
    Ok(memory_content_hash(&metadata))
}

fn promote(
    conn: &Connection,
    actor: AgentId,
    tenant: &str,
    reference: &Reference,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeMap<String, String>,
) -> Result<String, ContextError> {
    if let Some(id) = visited.get(&reference.key) {
        let digest: String = conn
            .query_row(
                "SELECT sha256 FROM execution_spill_blobs WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        if !digest.starts_with(&reference.digest_prefix) {
            return Err(failed("conflicting spill digest references"));
        }
        return Ok(id.clone());
    }
    if visiting.len() >= branching::MAX_EXECUTION_SNAPSHOT_DEPTH
        || visited.len() + visiting.len() >= MAX_SHARED_SPILL_NODES
        || !visiting.insert(reference.key.clone())
    {
        return Err(failed("context spill dependency cycle or node limit"));
    }
    let raw: Option<(String, u64)> = conn.query_row(
        "SELECT s.sha256, s.byte_count FROM context_spills s
         JOIN agent_kv kv ON kv.agent_id = s.agent_id AND kv.key = s.key
         WHERE s.agent_id = ?1 AND s.key = ?2 AND s.tenant_id = ?3 AND s.expires_at > ?4
           AND s.byte_count = LENGTH(CAST(kv.value AS BLOB)) AND s.sha256 = agentos_digest(kv.value)",
        params![actor.to_string(), &reference.key, tenant, Utc::now().to_rfc3339()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(sql_error)?;
    let id = if let Some((digest, bytes)) = raw {
        if bytes > branching::MAX_EXECUTION_SNAPSHOT_BYTES
            || !digest.starts_with(&reference.digest_prefix)
        {
            return Err(failed("context spill digest or byte bound mismatch"));
        }
        let locator = serde_json::to_string(&(actor.to_string(), &reference.key))
            .map_err(|error| failed(error.to_string()))?;
        let nested = references(conn,
            "SELECT value FROM agent_kv WHERE agent_id = json_extract(?1, '$[0]') AND key = json_extract(?1, '$[1]')",
            &locator)?;
        let mut edges = BTreeMap::new();
        for child in nested {
            let child_id = promote(conn, actor, tenant, &child, visiting, visited)?;
            edges.insert(child.key, child_id);
        }
        let edge_entries = edges.iter().collect::<Vec<_>>();
        let edge_metadata =
            serde_json::to_string(&edge_entries).map_err(|error| failed(error.to_string()))?;
        let edges_hash = memory_content_hash(&edge_metadata);
        let id = blob_id(tenant, &reference.key, &digest, &edges_hash)?;
        conn.execute(
            "INSERT OR IGNORE INTO execution_spill_blobs(id, tenant_id, key, version, payload_json, sha256, byte_count, edges_hash)
             SELECT ?1, ?2, key, 1, value, ?3, ?4, ?7 FROM agent_kv WHERE agent_id = ?5 AND key = ?6",
            params![&id, tenant, digest, bytes, actor.to_string(), &reference.key, edges_hash],
        ).map_err(sql_error)?;
        for (key, child_id) in edges {
            conn.execute(
                "INSERT OR IGNORE INTO execution_spill_edges(blob_id, key, child_id) VALUES (?1, ?2, ?3)",
                params![&id, key, child_id],
            ).map_err(sql_error)?;
        }
        // The immutable payload becomes branch-owned. Do not retain a second
        // mutable, expiring copy under the originating agent.
        conn.execute(
            "DELETE FROM context_spills WHERE agent_id = ?1 AND key = ?2",
            params![actor.to_string(), &reference.key],
        )
        .map_err(sql_error)?;
        conn.execute(
            "DELETE FROM agent_kv WHERE agent_id = ?1 AND key = ?2",
            params![actor.to_string(), &reference.key],
        )
        .map_err(sql_error)?;
        id
    } else {
        let private_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agent_kv WHERE agent_id = ?1 AND key = ?2)",
                params![actor.to_string(), &reference.key],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        if private_exists {
            return Err(failed("referenced private spill is expired or corrupt"));
        }
        let (id, digest) = owned_blob(conn, actor, &reference.key, tenant)?
            .ok_or_else(|| failed("referenced context spill is absent, expired or corrupt"))?;
        if !digest.starts_with(&reference.digest_prefix) {
            return Err(failed("immutable context spill digest mismatch"));
        }
        id
    };
    visiting.remove(&reference.key);
    visited.insert(reference.key.clone(), id.clone());
    Ok(id)
}

pub(super) fn attach_tail(
    conn: &Connection,
    snapshot: &str,
    actor: AgentId,
    tenant: &str,
    conversation: &str,
) -> Result<String, ContextError> {
    let references = references(
        conn,
        "SELECT messages_json FROM conversations WHERE id = ?1",
        conversation,
    )?;
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeMap::new();
    for reference in references {
        let id = promote(conn, actor, tenant, &reference, &mut visiting, &mut visited)?;
        conn.execute(
            "INSERT INTO execution_snapshot_spills(snapshot_id, key, blob_id) VALUES (?1, ?2, ?3)",
            params![snapshot, reference.key, id],
        )
        .map_err(sql_error)?;
    }
    manifest_digest(conn, snapshot)
}

pub(super) fn manifest_digest(conn: &Connection, snapshot: &str) -> Result<String, ContextError> {
    let mut statement = conn.prepare("SELECT key, blob_id FROM execution_snapshot_spills WHERE snapshot_id = ?1 ORDER BY key").map_err(sql_error)?;
    let entries = statement
        .query_map([snapshot], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_error)?;
    let metadata = serde_json::to_string(&entries).map_err(|error| failed(error.to_string()))?;
    Ok(memory_content_hash(&metadata))
}

pub(super) fn read(
    conn: &Connection,
    agent: AgentId,
    key: &str,
) -> Result<Option<String>, ContextError> {
    let tenant = SqliteContextManager::agent_tenant_locked(conn, agent)?;
    let Some((id, digest)) = owned_blob(conn, agent, key, &tenant)? else {
        return Ok(None);
    };
    let value: Option<String> = conn.query_row(
        "SELECT CASE WHEN version = 1 AND byte_count <= ?2 AND byte_count = LENGTH(CAST(payload_json AS BLOB))
                       AND sha256 = agentos_digest(payload_json) THEN payload_json ELSE NULL END
         FROM execution_spill_blobs WHERE id = ?1", params![&id, branching::MAX_EXECUTION_SNAPSHOT_BYTES], |row| row.get(0)
    ).map_err(sql_error)?;
    let edges_hash: String = conn
        .query_row(
            "SELECT edges_hash FROM execution_spill_blobs WHERE id = ?1",
            [&id],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if blob_id(&tenant, key, &digest, &edges_hash)? != id {
        return Err(failed("immutable spill identity mismatch"));
    }
    value
        .map(Some)
        .ok_or_else(|| failed("immutable spill integrity or version mismatch"))
}

pub(super) fn gc(conn: &Connection) -> Result<usize, ContextError> {
    conn.execute(
        "WITH RECURSIVE live(id) AS (
             SELECT blob_id FROM execution_snapshot_spills
             UNION SELECT e.child_id FROM execution_spill_edges e JOIN live l ON l.id = e.blob_id
         ) DELETE FROM execution_spill_blobs WHERE id NOT IN (SELECT id FROM live)",
        [],
    )
    .map_err(sql_error)
}

pub(super) fn row_counts(conn: &Connection) -> Result<[usize; 3], ContextError> {
    conn.query_row("SELECT (SELECT COUNT(*) FROM execution_spill_blobs),(SELECT COUNT(*) FROM execution_spill_edges),(SELECT COUNT(*) FROM execution_snapshot_spills)",[],
        |row|Ok([row.get(0)?,row.get(1)?,row.get(2)?])).map_err(sql_error)
}

fn validate_blobs(conn: &Connection, agent: AgentId, tenant: &str) -> Result<(), ContextError> {
    let mut statement = conn
        .prepare(&format!(
            "{REACHABLE} SELECT b.id,b.tenant_id,b.key,b.version,b.sha256,b.edges_hash,b.byte_count
         FROM execution_spill_blobs b JOIN blobs r ON r.id = b.id LIMIT {}",
            MAX_SHARED_SPILL_NODES + 1
        ))
        .map_err(sql_error)?;
    let headers = statement
        .query_map([agent.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, u64>(6)?,
            ))
        })
        .map_err(sql_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_error)?;
    drop(statement);
    if headers.len() > MAX_SHARED_SPILL_NODES {
        return Err(failed("immutable context spill graph exceeds node bound"));
    }
    let depth: usize = conn.query_row(&format!(
        "{REACHABLE}, paths(id,depth) AS (
             SELECT r.blob_id,1 FROM execution_snapshot_spills r JOIN snapshots s ON s.id = r.snapshot_id
             UNION SELECT e.child_id,p.depth + 1 FROM execution_spill_edges e JOIN paths p ON p.id = e.blob_id WHERE p.depth <= {}
         ) SELECT COALESCE(MAX(depth),0) FROM paths",branching::MAX_EXECUTION_SNAPSHOT_DEPTH
    ),[agent.to_string()],|row|row.get(0)).map_err(sql_error)?;
    if depth > branching::MAX_EXECUTION_SNAPSHOT_DEPTH {
        return Err(failed("immutable context spill dependency depth exceeded"));
    }
    for (id, owner, key, version, digest, expected_edges, bytes) in headers {
        if owner != tenant
            || version != 1
            || bytes > branching::MAX_EXECUTION_SNAPSHOT_BYTES
            || blob_id(tenant, &key, &digest, &expected_edges)? != id
        {
            return Err(failed(
                "immutable spill ownership, version or identity mismatch",
            ));
        }
        let mut edges = conn
            .prepare(
                "SELECT key,child_id FROM execution_spill_edges WHERE blob_id = ?1 ORDER BY key",
            )
            .map_err(sql_error)?;
        let entries = edges
            .query_map([&id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_error)?;
        let metadata =
            serde_json::to_string(&entries).map_err(|error| failed(error.to_string()))?;
        if memory_content_hash(&metadata) != expected_edges {
            return Err(failed("immutable spill dependency integrity mismatch"));
        }
    }
    Ok(())
}

pub(super) fn conversation_bytes(
    conn: &Connection,
    conversation: &str,
) -> Result<u64, ContextError> {
    conn.query_row(
        &format!("SELECT COALESCE(SUM(byte_count),0) FROM ({LOGICAL_SPILL_BYTES}) WHERE conversation_id = ?1"),
        [conversation],|row|row.get(0)
    ).map_err(sql_error)
}

pub(super) fn agent_stats(conn: &Connection, agent: AgentId) -> Result<(u64, u64), ContextError> {
    conn.query_row(&format!("{REACHABLE} SELECT COUNT(*),COALESCE(SUM(b.byte_count),0) FROM blobs r JOIN execution_spill_blobs b ON b.id = r.id"),
        [agent.to_string()],|row|Ok((row.get(0)?,row.get(1)?))).map_err(sql_error)
}

pub(super) const LOGICAL_SPILL_BYTES: &str = "WITH RECURSIVE snapshots(conversation_id, id) AS (
    SELECT conversation_id, snapshot_id FROM conversation_snapshot_refs
    UNION SELECT s.conversation_id, n.parent_id FROM snapshots s
          JOIN execution_context_snapshots n ON n.id = s.id WHERE n.parent_id IS NOT NULL
), blobs(conversation_id, id) AS (
    SELECT s.conversation_id, r.blob_id FROM snapshots s JOIN execution_snapshot_spills r ON r.snapshot_id = s.id
    UNION SELECT b.conversation_id, e.child_id FROM blobs b JOIN execution_spill_edges e ON e.blob_id = b.id
) SELECT c.id AS conversation_id,c.agent_id,SUM(v.byte_count + LENGTH(CAST(v.key AS BLOB))) AS byte_count
  FROM blobs b JOIN execution_spill_blobs v ON v.id = b.id JOIN conversations c ON c.id = b.conversation_id
  GROUP BY c.id";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::StandardMessage as Message;
    use uuid::Uuid;

    fn agent(manager: &SqliteContextManager, tenant: &str) -> AgentId {
        let id = Uuid::new_v4();
        let now = Utc::now();
        manager
            .save_agent(&PersistedAgent {
                id,
                session_id: Uuid::new_v4(),
                tenant_id: tenant.into(),
                name: "spill branch".into(),
                task: "spill ownership".into(),
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
    fn spill(
        manager: &SqliteContextManager,
        owner: AgentId,
        key: &str,
        messages: &[Message],
    ) -> (Message, String) {
        let value = serde_json::to_string(messages).unwrap();
        let digest = memory_content_hash(&value);
        manager
            .store_context_spill(owner, key, &value, &digest)
            .unwrap();
        (Message::system(format!("[Durable context spill: key={key}; sha256-prefix={}; messages={}; roles=user. Page in with StorageGet before relying on omitted detail.]",&digest[..16],messages.len())),value)
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
    fn branches_page_in_only_reachable_spills_and_retain_them_after_parent_erasure() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        let foreign = agent(&manager, "foreign");
        let (reference, value) = spill(
            &manager,
            parent,
            "context_spill:reachable",
            &[Message::user("retained secret detail")],
        );
        spill(
            &manager,
            parent,
            "context_spill:unrelated",
            &[Message::user("not in this execution history")],
        );
        manager
            .save_conversation("parent", parent, &[Message::system("base"), reference])
            .unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        assert_eq!(count(&manager, "execution_spill_blobs"), 1);
        assert_eq!(
            manager.kv_get(child, "context_spill:reachable").unwrap(),
            Some(value.clone())
        );
        assert_eq!(
            manager.kv_get(parent, "context_spill:reachable").unwrap(),
            Some(value.clone())
        );
        assert_eq!(
            manager.kv_get(child, "context_spill:unrelated").unwrap(),
            None
        );
        assert_eq!(
            manager.kv_get(foreign, "context_spill:reachable").unwrap(),
            None
        );
        let pressure = manager.context_pressure_stats(child).unwrap();
        assert_eq!(pressure.stored_spills, 1);
        assert_eq!(pressure.stored_spill_bytes, value.len() as u64);
        manager.delete_agent(parent).unwrap();
        assert_eq!(
            manager.kv_get(child, "context_spill:reachable").unwrap(),
            Some(value)
        );
        manager.delete_agent(child).unwrap();
        assert_eq!(count(&manager, "execution_spill_blobs"), 0);
        assert_eq!(count(&manager, "execution_spill_edges"), 0);
        assert_eq!(count(&manager, "execution_snapshot_spills"), 0);
    }

    #[test]
    fn further_compaction_preserves_transitive_spills_without_copying_old_payloads() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        let (old, value) = spill(
            &manager,
            parent,
            "context_spill:old",
            &[Message::user("old omitted detail")],
        );
        manager
            .save_conversation("parent", parent, &[Message::system("base"), old.clone()])
            .unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        let (new, _) = spill(
            &manager,
            parent,
            "context_spill:new",
            &[old, Message::user("new omitted detail")],
        );
        manager
            .save_conversation("parent", parent, &[Message::system("summary"), new])
            .unwrap();
        assert_eq!(count(&manager, "execution_spill_blobs"), 2);
        assert_eq!(count(&manager, "execution_spill_edges"), 1);
        assert_eq!(
            manager.kv_get(parent, "context_spill:old").unwrap(),
            Some(value.clone())
        );
        assert_eq!(manager.kv_get(child, "context_spill:new").unwrap(), None);
        manager.delete_agent(child).unwrap();
        assert_eq!(count(&manager, "execution_spill_blobs"), 2);
        assert_eq!(
            manager.kv_get(parent, "context_spill:old").unwrap(),
            Some(value)
        );
        manager.delete_agent(parent).unwrap();
        assert_eq!(count(&manager, "execution_spill_blobs"), 0);
    }

    #[test]
    fn spill_bytes_are_charged_per_branch_and_failed_admission_restores_private_ownership() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        let (reference, value) = spill(
            &manager,
            parent,
            "context_spill:quota",
            &[Message::user("x".repeat(1024))],
        );
        let history = vec![Message::system("base"), reference];
        manager
            .save_conversation("parent", parent, &history)
            .unwrap();
        let bytes = serde_json::to_vec(&history).unwrap().len() as u64;
        let spill_bytes = (value.len() + "context_spill:quota".len()) as u64;
        manager
            .set_context_storage_limits(ContextStorageLimits {
                per_tenant_bytes: (bytes + spill_bytes) * 2 - 1,
                ..Default::default()
            })
            .unwrap();
        assert!(manager
            .fork_conversation(parent, "parent", child, "child")
            .is_err());
        assert_eq!(count(&manager, "execution_spill_blobs"), 0);
        assert_eq!(count(&manager, "execution_snapshot_spills"), 0);
        assert_eq!(count(&manager, "conversation_snapshot_refs"), 0);
        assert_eq!(count(&manager, "context_spills"), 1);
        assert_eq!(
            manager.kv_get(parent, "context_spill:quota").unwrap(),
            Some(value)
        );
        assert_eq!(manager.load_conversation("parent").unwrap(), history);
    }

    #[test]
    fn inherited_spill_keys_are_immutable_and_payload_corruption_fails_closed() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        let (reference, value) = spill(
            &manager,
            parent,
            "context_spill:immutable",
            &[Message::user("protected")],
        );
        manager
            .save_conversation("parent", parent, &[reference])
            .unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        assert!(manager
            .store_context_spill(
                child,
                "context_spill:immutable",
                "replacement",
                &memory_content_hash("replacement")
            )
            .is_err());
        manager
            .store_context_spill(
                child,
                "context_spill:immutable",
                &value,
                &memory_content_hash(&value),
            )
            .unwrap();
        assert_eq!(count(&manager, "agent_kv"), 0);
        manager
            .locked_conn()
            .execute("UPDATE execution_spill_blobs SET payload_json = '[]'", [])
            .unwrap();
        assert!(manager.kv_get(child, "context_spill:immutable").is_err());
    }

    #[test]
    fn corruption_of_snapshot_attachments_or_dependency_edges_does_not_grant_page_in() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        let (old, _) = spill(
            &manager,
            parent,
            "context_spill:leaf",
            &[Message::user("protected")],
        );
        let (new, _) = spill(&manager, parent, "context_spill:outer", &[old]);
        manager.save_conversation("parent", parent, &[new]).unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        manager
            .locked_conn()
            .execute("UPDATE execution_spill_edges SET child_id = blob_id", [])
            .unwrap();
        assert!(manager.kv_get(child, "context_spill:leaf").is_err());
        manager
            .locked_conn()
            .execute("DELETE FROM execution_snapshot_spills", [])
            .unwrap();
        assert!(manager.load_conversation("child").is_err());
    }

    #[test]
    fn encrypted_restart_and_tenant_erasure_include_shared_spills() {
        use crate::storage_encryption::StorageEncryptionKey;
        let dir = std::env::temp_dir().join(format!("agentos-shared-spill-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        let child;
        let value;
        {
            let manager = SqliteContextManager::new_encrypted(
                &path,
                StorageEncryptionKey::from_bytes("spill-test", [11; 32]).unwrap(),
            )
            .unwrap();
            let parent = agent(&manager, "tenant");
            child = agent(&manager, "tenant");
            let (reference, payload) = spill(
                &manager,
                parent,
                "context_spill:restart",
                &[Message::user("never stored in plaintext")],
            );
            value = payload;
            manager
                .save_conversation("parent", parent, &[reference])
                .unwrap();
            manager
                .fork_conversation(parent, "parent", child, "child")
                .unwrap();
            manager.delete_agent(parent).unwrap();
            manager.checkpoint().unwrap();
        }
        {
            let manager = SqliteContextManager::new_encrypted(
                &path,
                StorageEncryptionKey::from_bytes("spill-test", [11; 32]).unwrap(),
            )
            .unwrap();
            assert_eq!(
                manager.kv_get(child, "context_spill:restart").unwrap(),
                Some(value)
            );
            manager.erase_tenant_data("tenant").unwrap();
            assert_eq!(count(&manager, "execution_spill_blobs"), 0);
            assert_eq!(count(&manager, "execution_spill_edges"), 0);
            assert_eq!(count(&manager, "execution_snapshot_spills"), 0);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn appending_to_a_maximum_depth_shared_spill_graph_rolls_back_the_fork() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let parent = agent(&manager, "tenant");
        let child = agent(&manager, "tenant");
        let third = agent(&manager, "tenant");
        let mut messages = vec![Message::user("oldest detail")];
        let mut last = None;
        for index in 0..branching::MAX_EXECUTION_SNAPSHOT_DEPTH {
            let (reference, _) = spill(
                &manager,
                parent,
                &format!("context_spill:depth:{index}"),
                &messages,
            );
            messages = vec![reference.clone()];
            last = Some(reference);
        }
        let original = vec![last.unwrap()];
        manager
            .save_conversation("parent", parent, &original)
            .unwrap();
        manager
            .fork_conversation(parent, "parent", child, "child")
            .unwrap();
        assert_eq!(
            count(&manager, "execution_spill_blobs"),
            branching::MAX_EXECUTION_SNAPSHOT_DEPTH
        );
        let (extra, _) = spill(&manager, parent, "context_spill:too-deep", &original);
        let mut changed = original.clone();
        changed.push(extra);
        manager
            .save_conversation("parent", parent, &changed)
            .unwrap();
        assert!(manager
            .fork_conversation(parent, "parent", third, "third")
            .is_err());
        assert_eq!(
            count(&manager, "execution_spill_blobs"),
            branching::MAX_EXECUTION_SNAPSHOT_DEPTH
        );
        assert_eq!(count(&manager, "context_spills"), 1);
        assert_eq!(manager.load_conversation("parent").unwrap(), changed);
        assert_eq!(manager.load_conversation("child").unwrap(), original);
        assert!(manager.load_conversation("third").is_err());
    }
}
