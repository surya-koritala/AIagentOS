use super::*;

fn owner(manager: &SqliteContextManager, tenant: &str) -> AgentId {
    let now = Utc::now();
    let id = uuid::Uuid::new_v4();
    manager
        .locked_conn()
        .execute(
            "INSERT OR IGNORE INTO tenants(id,name,created_at) VALUES(?1,?1,?2)",
            params![tenant, now.to_rfc3339()],
        )
        .unwrap();
    manager
        .save_agent(&PersistedAgent {
            id,
            session_id: uuid::Uuid::new_v4(),
            tenant_id: tenant.into(),
            name: "indexed quota fixture".into(),
            task: "exact byte accounting".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: 3,
            status: "\"Stopped\"".into(),
            sandbox_config_json: None,
            created_at: now,
            last_activity_at: now,
        })
        .unwrap();
    id
}

fn raw_fact(
    conn: &Connection,
    agent: AgentId,
    content: &str,
    json: Option<&str>,
    blob: Option<&[u8]>,
) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    conn.execute("INSERT INTO facts(id,agent_id,content,category,created_at,last_accessed_at,embedding_json,embedding_blob)
        VALUES(?1,?2,?3,'\"Fact\"','2026-10-08T00:00:00Z','2026-10-08T00:00:00Z',?4,?5)",
        params![id.to_string(), agent.to_string(), content, json, blob]).unwrap();
    id
}

fn oracle(conn: &Connection, agent: AgentId, tenant: &str) -> (u64, u64, u64) {
    let mut statement = conn.prepare("SELECT f.agent_id,COALESCE(a.tenant_id,'default'),f.content,f.embedding_json,f.embedding_blob
        FROM facts f LEFT JOIN agents a ON a.id=f.agent_id ORDER BY f.rowid").unwrap();
    let mut rows = statement.query([]).unwrap();
    let mut totals = (0, 0, 0);
    while let Some(row) = rows.next().unwrap() {
        let bytes = row.get::<_, String>(2).unwrap().len() as u64
            + row
                .get::<_, Option<String>>(3)
                .unwrap()
                .map_or(0, |value| value.len() as u64)
            + row
                .get::<_, Option<Vec<u8>>>(4)
                .unwrap()
                .map_or(0, |value| value.len() as u64);
        if row.get::<_, String>(0).unwrap() == agent.to_string() {
            totals.0 += bytes;
        }
        if row.get::<_, String>(1).unwrap() == tenant {
            totals.1 += bytes;
        }
        totals.2 += bytes;
    }
    totals
}

fn assert_exact(conn: &Connection, agent: AgentId, tenant: &str) {
    let usage = SqliteContextManager::context_storage_usage_locked(conn, agent, tenant).unwrap();
    assert_eq!(
        (usage.agent_bytes, usage.tenant_bytes, usage.global_bytes),
        oracle(conn, agent, tenant)
    );
}

#[test]
fn fact_storage_index_preserves_exact_bytes_across_raw_writes_and_rollback() {
    let manager = SqliteContextManager::in_memory().unwrap();
    let first = owner(&manager, "quota-a");
    let sibling = owner(&manager, "quota-a");
    let foreign = owner(&manager, "quota-b");
    let mut conn = manager.locked_conn();
    let changing = raw_fact(
        &conn,
        first,
        "résumé 🦦",
        Some("[1,2]"),
        Some(&[0, 1, 0, 255]),
    );
    raw_fact(&conn, sibling, "same tenant", None, Some(&[0; 16]));
    raw_fact(&conn, foreign, "foreign tenant", Some("[]"), None);
    assert_exact(&conn, first, "quota-a");
    conn.execute(
        "UPDATE facts SET content=?1,embedding_json=NULL,embedding_blob=?2 WHERE id=?3",
        params!["updated Unicode λ", vec![9_u8; 257], changing.to_string()],
    )
    .unwrap();
    assert_exact(&conn, first, "quota-a");
    {
        let transaction = conn.transaction().unwrap();
        transaction
            .execute(
                "UPDATE facts SET agent_id=?1,content=?2 WHERE id=?3",
                params![
                    foreign.to_string(),
                    "rolled back transfer",
                    changing.to_string()
                ],
            )
            .unwrap();
        assert_exact(&transaction, first, "quota-a");
        assert_exact(&transaction, foreign, "quota-b");
        // Dropping the transaction rolls back both the row and its index.
    }
    assert_exact(&conn, first, "quota-a");
    conn.execute("DELETE FROM facts WHERE id=?1", [changing.to_string()])
        .unwrap();
    assert_exact(&conn, first, "quota-a");
}

#[test]
fn fact_storage_index_reopens_existing_rows_and_keeps_quota_denial_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.db");
    let id;
    let fact;
    {
        let manager = SqliteContextManager::new(&path).unwrap();
        id = owner(&manager, "quota-a");
        let conn = manager.locked_conn();
        fact = raw_fact(&conn, id, "old", None, None);
        // Simulate an older database with payloads but no accounting index.
        conn.execute_batch("DROP INDEX idx_facts_storage_bytes")
            .unwrap();
    }
    let manager = SqliteContextManager::new(&path).unwrap();
    {
        let conn = manager.locked_conn();
        assert_exact(&conn, id, "quota-a");
        let details = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN SELECT agent_id,SUM({})
            FROM facts INDEXED BY idx_facts_storage_bytes GROUP BY agent_id",
                fact_index::STORAGE_BYTE_EXPRESSION
            ))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("idx_facts_storage_bytes")),
            "quota scan did not use the accounting index: {details:?}"
        );
        let root_page: i64 = conn
            .query_row(
                "SELECT rootpage FROM sqlite_schema WHERE type='table' AND name='facts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let instructions = conn.prepare(&format!("EXPLAIN SELECT agent_id,SUM({}) FROM facts INDEXED BY idx_facts_storage_bytes GROUP BY agent_id", fact_index::STORAGE_BYTE_EXPRESSION))
            .unwrap().query_map([], |row| Ok((row.get::<_, String>(1)?,row.get::<_, i64>(2)?,row.get::<_, i64>(3)?)))
            .unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        let table_cursors = instructions
            .iter()
            .filter(|(opcode, _, page)| opcode == "OpenRead" && *page == root_page)
            .map(|(_, cursor, _)| *cursor)
            .collect::<Vec<_>>();
        assert!(
            !instructions
                .iter()
                .any(|(opcode, cursor, _)| opcode == "Column" && table_cursors.contains(cursor)),
            "quota aggregation must read indexed byte counts without loading fact payload columns"
        );
    }
    manager
        .set_context_storage_limits(ContextStorageLimits {
            per_agent_bytes: 3,
            per_tenant_bytes: 3,
            global_bytes: 3,
            spill_retention_seconds: 60,
        })
        .unwrap();
    assert!(manager.update_fact(id, fact, "larger replacement").is_err());
    {
        let conn = manager.locked_conn();
        assert_eq!(
            conn.query_row(
                "SELECT content FROM facts WHERE id=?1",
                [fact.to_string()],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "old"
        );
        assert_exact(&conn, id, "quota-a");
    }
    drop(manager);
    directory.close().unwrap();
}
