//! Versioned binary embeddings and per-agent retained retrieval state.

use super::*;
use crate::memory_manager::{BruteForceIndex, LshIndex, VectorIndex};
use std::collections::HashMap;

const MAGIC: &[u8; 4] = b"AIE1";
const MAX_DIM: usize = 16_384;
const MAX_CACHE_BYTES: usize = 512 * 1024 * 1024;
const MAX_CACHED_AGENTS: usize = 16;

// SQLite maintains these exact integer byte counts on every row mutation,
// including legacy writers and raw repair transactions. Keep the quota query
// expression identical so it reads the index rather than the fact payloads.
pub(super) const STORAGE_BYTE_EXPRESSION: &str = "LENGTH(CAST(content AS BLOB)) + COALESCE(LENGTH(CAST(embedding_json AS BLOB)), 0) + COALESCE(LENGTH(embedding_blob), 0)";

fn failed(error: impl ToString) -> ContextError {
    ContextError::StorageError(error.to_string())
}

pub(super) fn encode(vector: &[f32]) -> Result<Vec<u8>, ContextError> {
    if vector.is_empty() || vector.len() > MAX_DIM || vector.iter().any(|value| !value.is_finite())
    {
        return Err(failed("invalid embedding vector"));
    }
    let mut bytes = Vec::with_capacity(8 + vector.len() * 4);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(vector.len() as u32).to_le_bytes());
    for value in vector {
        bytes.extend_from_slice(&value.to_bits().to_le_bytes());
    }
    Ok(bytes)
}
pub(super) fn decode(bytes: &[u8]) -> Option<Vec<f32>> {
    if bytes.len() < 8 || &bytes[..4] != MAGIC {
        return None;
    }
    let dimension = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    if dimension == 0 || dimension > MAX_DIM || bytes.len() != 8 + dimension * 4 {
        return None;
    }
    let vector = bytes[8..]
        .chunks_exact(4)
        .map(|chunk| f32::from_bits(u32::from_le_bytes(chunk.try_into().expect("fixed chunk"))))
        .collect::<Vec<_>>();
    vector
        .iter()
        .all(|value| value.is_finite())
        .then_some(vector)
}

pub(crate) const TRIGGERS: &[(&str, &str)] = &[
    (
        "facts_index_insert",
        "CREATE TRIGGER IF NOT EXISTS facts_index_insert AFTER INSERT ON facts BEGIN
          INSERT INTO fact_index_generations VALUES (NEW.agent_id, 1)
          ON CONFLICT(agent_id) DO UPDATE SET generation = generation + 1;
        END;",
    ),
    (
        "facts_index_delete",
        "CREATE TRIGGER IF NOT EXISTS facts_index_delete AFTER DELETE ON facts BEGIN
          INSERT INTO fact_index_generations VALUES (OLD.agent_id, 1)
          ON CONFLICT(agent_id) DO UPDATE SET generation = generation + 1;
        END;",
    ),
    (
        "facts_index_update",
        "CREATE TRIGGER IF NOT EXISTS facts_index_update
        AFTER UPDATE OF agent_id, content, category, created_at, last_accessed_at, embedding_json, embedding_blob,
          embedding_model, embedding_version, embedding_dim, content_hash ON facts BEGIN
          INSERT INTO fact_index_generations VALUES (OLD.agent_id, 1)
          ON CONFLICT(agent_id) DO UPDATE SET generation = generation + 1;
          INSERT INTO fact_index_generations VALUES (NEW.agent_id, 1)
          ON CONFLICT(agent_id) DO UPDATE SET generation = generation + 1;
        END;",
    ),
];

pub(super) fn init_schema(conn: &Connection) -> Result<(), ContextError> {
    crate::schema::add_column_if_missing(conn, "facts", "embedding_blob", "BLOB")?;
    // Convert only structurally valid legacy vectors. Stale/corrupt metadata
    // remains authoritative input to the ordinary rebuild-on-query path.
    let mut statement = conn.prepare("SELECT id, embedding_json FROM facts WHERE embedding_blob IS NULL AND embedding_json IS NOT NULL ORDER BY rowid").map_err(failed)?;
    let mut rows = statement.query([]).map_err(failed)?;
    while let Some(row) = rows.next().map_err(failed)? {
        let id: String = row.get(0).map_err(failed)?;
        let json: String = row.get(1).map_err(failed)?;
        if let Ok(vector) = serde_json::from_str::<Vec<f32>>(&json) {
            if let Ok(blob) = encode(&vector) {
                conn.execute(
                    "UPDATE facts SET embedding_blob = ?1, embedding_json = NULL WHERE id = ?2",
                    params![blob, id],
                )
                .map_err(failed)?;
            }
        }
    }
    drop(rows);
    drop(statement);
    conn.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS idx_facts_storage_bytes
         ON facts(agent_id, ({STORAGE_BYTE_EXPRESSION}));"
    ))
    .map_err(failed)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS fact_index_generations (
        agent_id TEXT PRIMARY KEY, generation INTEGER NOT NULL CHECK(generation >= 0));
        INSERT OR IGNORE INTO fact_index_generations SELECT DISTINCT agent_id, 1 FROM facts;
        ",
    )
    .map_err(failed)?;
    for (_, definition) in TRIGGERS {
        conn.execute_batch(definition).map_err(failed)?;
    }
    Ok(())
}

struct IndexedFact {
    row_id: i64,
    fact: Fact,
}

struct CachedFacts {
    generation: i64,
    index: Box<dyn VectorIndex>,
    facts: Vec<IndexedFact>,
    positions: HashMap<uuid::Uuid, usize>,
    bytes: usize,
    used: u64,
}
#[derive(Default)]
pub(super) struct FactCache {
    agents: HashMap<AgentId, CachedFacts>,
    serial: u64,
    #[cfg(test)]
    pub warm_rows: usize,
}
impl FactCache {
    pub(super) fn clear(&mut self) {
        self.agents.clear();
    }
    pub(super) fn remove(&mut self, agent: AgentId) {
        self.agents.remove(&agent);
    }
    fn publish(&mut self, agent: AgentId, entry: CachedFacts) -> Option<CachedFacts> {
        self.agents.remove(&agent);
        if entry.bytes > MAX_CACHE_BYTES {
            return Some(entry);
        }
        while self.agents.len() >= MAX_CACHED_AGENTS
            || self
                .agents
                .values()
                .map(|cached| cached.bytes)
                .sum::<usize>()
                .saturating_add(entry.bytes)
                > MAX_CACHE_BYTES
        {
            let oldest = self
                .agents
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(id, _)| *id);
            if let Some(oldest) = oldest {
                self.agents.remove(&oldest);
            } else {
                break;
            }
        }
        self.agents.insert(agent, entry);
        None
    }
}

impl SqliteContextManager {
    pub(super) fn cached_query_memory(
        &self,
        agent: AgentId,
        query_vector: &[f32],
    ) -> Result<Vec<Fact>, ContextError> {
        let mut conn = self.locked_conn();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let mut cache = self
            .fact_cache
            .lock()
            .map_err(|_| failed("fact cache lock poisoned"))?;
        let outcome = (|| {
            let current_generation = generation(&transaction, agent)?;
            cache.serial = cache.serial.wrapping_add(1);
            let serial = cache.serial;
            let mut transient = None;
            if cache
                .agents
                .get(&agent)
                .is_none_or(|entry| entry.generation != current_generation)
            {
                cache.remove(agent);
                let facts = self.load_index_facts(&transaction, agent, None)?;
                if generation(&transaction, agent)? != current_generation {
                    let tenant = Self::agent_tenant_locked(&transaction, agent)?;
                    self.enforce_context_storage_locked(&transaction, agent, &tenant, 0, 0)?;
                }
                #[cfg(test)]
                {
                    cache.warm_rows += facts.len();
                }
                let mut index: Box<dyn VectorIndex> = if facts.len() > 64 {
                    Box::new(LshIndex::with_dim(self.embedder.dim()))
                } else {
                    Box::new(BruteForceIndex::new())
                };
                let mut bytes = 0_usize;
                for (position, indexed) in facts.iter().enumerate() {
                    let vector = indexed
                        .fact
                        .embedding
                        .as_ref()
                        .expect("warm validates every embedding");
                    index.add(position as u64, vector.clone());
                    // Both the public fact and index retain a vector. Include
                    // conservative bucket/id/struct overhead in the cache cap.
                    bytes = bytes
                        .saturating_add(indexed.fact.content.len())
                        .saturating_add(vector.len() * 8)
                        .saturating_add(1024);
                }
                let entry = CachedFacts {
                    generation: generation(&transaction, agent)?,
                    index,
                    positions: facts
                        .iter()
                        .enumerate()
                        .map(|(position, indexed)| (indexed.fact.id, position))
                        .collect(),
                    facts,
                    bytes,
                    used: serial,
                };
                transient = cache.publish(agent, entry);
            }
            // Oversized stores preserve retrieval behavior but do not displace
            // the bounded process cache indefinitely.
            let entry = match transient.as_mut() {
                Some(entry) => entry,
                None => cache.agents.get_mut(&agent).expect("published cache entry"),
            };
            entry.used = serial;
            let hits = entry.index.search_with_tiebreak(query_vector, 16, &|a, b| {
                let a = &entry.facts[a as usize];
                let b = &entry.facts[b as usize];
                b.fact
                    .last_accessed_at
                    .cmp(&a.fact.last_accessed_at)
                    .then_with(|| a.row_id.cmp(&b.row_id))
            });
            let now = Utc::now();
            let mut result = Vec::with_capacity(hits.len());
            for (position, _) in hits {
                let stored = &mut entry.facts[position as usize].fact;
                result.push(stored.clone());
                transaction
                    .execute(
                        "UPDATE facts SET last_accessed_at = ?1 WHERE id = ?2 AND agent_id = ?3",
                        params![now.to_rfc3339(), stored.id.to_string(), agent.to_string()],
                    )
                    .map_err(failed)?;
                stored.last_accessed_at = now;
            }
            // Our own access updates are already reflected in this entry;
            // carry their revision forward without another warm pass.
            entry.generation = generation(&transaction, agent)?;
            transaction.commit().map_err(failed)?;
            Ok(result)
        })();
        if outcome.is_err() {
            cache.remove(agent);
        }
        outcome
    }

    /// Network-only work can outlive an abandoned async request; database work
    /// stays on the owning request after revision verification, never on a
    /// detached blocking task. Warm caches skip this entire scan.
    pub(super) async fn prepare_remote_embeddings(
        &self,
        agent: AgentId,
    ) -> Result<(), ContextError> {
        let (captured, pending) = {
            let conn = self.locked_conn();
            let captured = generation(&conn, agent)?;
            if self
                .fact_cache
                .lock()
                .map_err(|_| failed("fact cache lock poisoned"))?
                .agents
                .get(&agent)
                .is_some_and(|entry| entry.generation == captured)
            {
                return Ok(());
            }
            let mut statement=conn.prepare("SELECT id,content,embedding_model,embedding_version,embedding_dim,content_hash,embedding_blob,embedding_json FROM facts WHERE agent_id=?1 ORDER BY rowid").map_err(failed)?;
            let rows = statement
                .query_map([agent.to_string()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                })
                .map_err(failed)?;
            let mut pending = Vec::new();
            let mut old_bytes = 0_u64;
            for row in rows {
                let (id, content, model, version, dim, stored_hash, blob, legacy) =
                    row.map_err(failed)?;
                let valid = model == self.embedder.model_id()
                    && version == i64::from(self.embedder.version())
                    && dim == self.embedder.dim() as i64
                    && stored_hash == memory_content_hash(&content)
                    && legacy.is_none()
                    && blob
                        .as_deref()
                        .and_then(decode)
                        .is_some_and(|vector| vector.len() == self.embedder.dim());
                if !valid {
                    old_bytes = old_bytes
                        .saturating_add(blob.as_ref().map_or(0, |blob| blob.len()) as u64)
                        .saturating_add(legacy.as_ref().map_or(0, |json| json.len()) as u64);
                    pending.push((id, content));
                }
            }
            if !pending.is_empty() {
                let tenant = Self::agent_tenant_locked(&conn, agent)?;
                let new_bytes = pending
                    .len()
                    .saturating_mul(8 + self.embedder.dim().saturating_mul(4))
                    as u64;
                self.enforce_context_storage_locked(&conn, agent, &tenant, new_bytes, old_bytes)?;
            }
            (captured, pending)
        };
        if pending.is_empty() {
            return Ok(());
        }
        let mut repaired = Vec::with_capacity(pending.len());
        for batch in pending.chunks(32) {
            let embedder = Arc::clone(&self.embedder);
            let texts = batch
                .iter()
                .map(|(_, text)| text.clone())
                .collect::<Vec<_>>();
            let vectors = tokio::task::spawn_blocking(move || {
                let refs = texts.iter().map(String::as_str).collect::<Vec<_>>();
                embedder.embed_batch(&refs)
            })
            .await
            .map_err(|_| crate::memory_manager::EmbeddingError::Transport)??;
            if vectors.len() != batch.len() {
                return Err(crate::memory_manager::EmbeddingError::InvalidResponse(
                    "batch count mismatch",
                )
                .into());
            }
            for ((id, content), vector) in batch.iter().zip(vectors) {
                if vector.len() != self.embedder.dim() {
                    return Err(crate::memory_manager::EmbeddingError::InvalidResponse(
                        "dimension mismatch",
                    )
                    .into());
                }
                repaired.push((id.clone(), memory_content_hash(content), encode(&vector)?));
            }
        }
        let mut conn = self.locked_conn();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        if generation(&transaction, agent)? != captured {
            return Err(crate::memory_manager::EmbeddingError::StoreChanged.into());
        }
        for (id, content_hash, blob) in repaired {
            transaction.execute("UPDATE facts SET embedding_blob=?1,embedding_json=NULL,embedding_model=?2,embedding_version=?3,embedding_dim=?4,content_hash=?5 WHERE id=?6 AND agent_id=?7",params![blob,self.embedder.model_id(),self.embedder.version(),self.embedder.dim() as i64,content_hash,id,agent.to_string()]).map_err(failed)?;
        }
        let tenant = Self::agent_tenant_locked(&transaction, agent)?;
        self.enforce_context_storage_locked(&transaction, agent, &tenant, 0, 0)?;
        transaction.commit().map_err(failed)?;
        self.fact_cache
            .lock()
            .map_err(|_| failed("fact cache lock poisoned"))?
            .remove(agent);
        Ok(())
    }

    /// Reconcile a normal committed-intent write while the store transaction
    /// owns the connection. An intervening external revision still invalidates
    /// the whole entry. A failed commit has a different durable generation and
    /// therefore cannot expose the staged cache state on a later query.
    pub(super) fn sync_cached_fact(
        &self,
        conn: &Connection,
        agent: AgentId,
        previous_generation: i64,
        fact_id: uuid::Uuid,
    ) -> Result<(), ContextError> {
        let mut cache = self
            .fact_cache
            .lock()
            .map_err(|_| failed("fact cache lock poisoned"))?;
        let Some(mut entry) = cache.agents.remove(&agent) else {
            return Ok(());
        };
        if entry.generation != previous_generation {
            return Ok(());
        }
        let mut changed = self.load_index_facts(conn, agent, Some(fact_id))?;
        let Some(changed) = changed.pop() else {
            return Err(failed("written fact vanished before cache synchronization"));
        };
        let position = entry
            .positions
            .get(&fact_id)
            .copied()
            .unwrap_or(entry.facts.len());
        if position == entry.facts.len() && entry.facts.len() == 64 {
            // Transition from exact to ANN; the small store warms once next time.
            return Ok(());
        }
        let vector = changed
            .fact
            .embedding
            .as_ref()
            .expect("validated changed embedding");
        if let Some(old) = entry.facts.get(position) {
            entry.bytes = entry.bytes.saturating_sub(
                old.fact.content.len() + old.fact.embedding.as_ref().map_or(0, |v| v.len() * 8),
            );
        } else {
            entry.bytes = entry.bytes.saturating_add(1024);
        }
        entry.bytes = entry
            .bytes
            .saturating_add(changed.fact.content.len())
            .saturating_add(vector.len() * 8);
        entry.index.add(position as u64, vector.clone());
        if position == entry.facts.len() {
            entry.positions.insert(fact_id, position);
            entry.facts.push(changed);
        } else {
            entry.facts[position] = changed;
        }
        entry.generation = generation(conn, agent)?;
        cache.serial = cache.serial.wrapping_add(1);
        entry.used = cache.serial;
        // Publish applies the same combined-byte and agent-count LRU bounds.
        drop(cache.publish(agent, entry));
        Ok(())
    }

    fn load_index_facts(
        &self,
        conn: &Connection,
        agent: AgentId,
        fact_id: Option<uuid::Uuid>,
    ) -> Result<Vec<IndexedFact>, ContextError> {
        // Keep point refreshes on the primary-key path; a nullable OR predicate
        // would force a scan of the entire agent store for every update.
        let filter = if fact_id.is_some() {
            "AND id = ?2"
        } else {
            "AND ?2 IS NULL"
        };
        let mut statement=conn.prepare(&format!("SELECT id,content,category,created_at,last_accessed_at,embedding_blob,embedding_json,embedding_model,embedding_version,embedding_dim,content_hash,rowid FROM facts WHERE agent_id=?1 {filter} ORDER BY last_accessed_at DESC,rowid ASC")).map_err(failed)?;
        let rows = statement
            .query_map(
                params![agent.to_string(), fact_id.map(|id| id.to_string())],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, i64>(11)?,
                    ))
                },
            )
            .map_err(failed)?;
        let mut facts = Vec::new();
        for row in rows {
            let (
                id,
                content,
                category,
                created,
                accessed,
                blob,
                legacy,
                model,
                version,
                dim,
                stored_hash,
                row_id,
            ) = row.map_err(failed)?;
            let expected_hash = memory_content_hash(&content);
            let vector = blob.as_deref().and_then(decode);
            let valid = model == self.embedder.model_id()
                && version == i64::from(self.embedder.version())
                && dim == self.embedder.dim() as i64
                && stored_hash == expected_hash
                && legacy.is_none()
                && vector
                    .as_ref()
                    .is_some_and(|vector| vector.len() == self.embedder.dim());
            let embedding = if valid { vector } else { None };
            facts.push(IndexedFact {
                row_id,
                fact: Fact {
                    id: id.parse().map_err(failed)?,
                    content,
                    category: serde_json::from_str(&category).map_err(failed)?,
                    created_at: DateTime::parse_from_rfc3339(&created)
                        .map_err(failed)?
                        .with_timezone(&Utc),
                    last_accessed_at: DateTime::parse_from_rfc3339(&accessed)
                        .map_err(failed)?
                        .with_timezone(&Utc),
                    embedding,
                },
            });
        }
        drop(statement);
        let pending = facts
            .iter()
            .enumerate()
            .filter_map(|(position, indexed)| indexed.fact.embedding.is_none().then_some(position))
            .collect::<Vec<_>>();
        if self.embedder.is_remote() && !pending.is_empty() {
            return Err(crate::memory_manager::EmbeddingError::StoreChanged.into());
        }
        for batch in pending.chunks(32) {
            let texts = batch
                .iter()
                .map(|position| facts[*position].fact.content.as_str())
                .collect::<Vec<_>>();
            let vectors = self.embedder.embed_batch(&texts)?;
            if vectors.len() != batch.len() {
                return Err(crate::memory_manager::EmbeddingError::InvalidResponse(
                    "batch count mismatch",
                )
                .into());
            }
            for (&position, vector) in batch.iter().zip(vectors) {
                if vector.len() != self.embedder.dim() {
                    return Err(crate::memory_manager::EmbeddingError::InvalidResponse(
                        "dimension mismatch",
                    )
                    .into());
                }
                let fact = &mut facts[position].fact;
                conn.execute("UPDATE facts SET embedding_blob=?1,embedding_json=NULL,embedding_model=?2,embedding_version=?3,embedding_dim=?4,content_hash=?5 WHERE id=?6 AND agent_id=?7",params![encode(&vector)?,self.embedder.model_id(),self.embedder.version(),self.embedder.dim() as i64,memory_content_hash(&fact.content),fact.id.to_string(),agent.to_string()]).map_err(failed)?;
                fact.embedding = Some(vector);
            }
        }
        Ok(facts)
    }
}
pub(super) fn generation(conn: &Connection, agent: AgentId) -> Result<i64, ContextError> {
    conn.query_row(
        "SELECT generation FROM fact_index_generations WHERE agent_id=?1",
        [agent.to_string()],
        |row| row.get(0),
    )
    .optional()
    .map_err(failed)
    .map(|value| value.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_manager::{BlendedEmbedder, Embedder};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fact(id: u128, content: &str) -> Fact {
        let now = DateTime::parse_from_rfc3339("2026-10-08T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        Fact {
            id: uuid::Uuid::from_u128(id),
            content: content.into(),
            category: FactCategory::Fact,
            created_at: now,
            last_accessed_at: now,
            embedding: None,
        }
    }

    struct CountingEmbedder(Arc<AtomicUsize>);
    impl Embedder for CountingEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, crate::memory_manager::EmbeddingError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            BlendedEmbedder::default().embed(text)
        }
        fn dim(&self) -> usize {
            crate::memory_manager::EMBED_DIM
        }
        fn model_id(&self) -> &str {
            "blended-feature-hash"
        }
    }

    #[test]
    fn binary_codec_preserves_bits_and_rejects_corrupt_shapes() {
        let vector = vec![0.0, -0.0, 1.23456, f32::MIN_POSITIVE, f32::MAX];
        let blob = encode(&vector).unwrap();
        let decoded = decode(&blob).unwrap();
        assert_eq!(
            decoded.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
            vector.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
        );
        assert_eq!(blob.len(), 8 + vector.len() * 4);
        for vector in [
            vec![],
            vec![f32::NAN],
            vec![f32::INFINITY],
            vec![0.; MAX_DIM + 1],
        ] {
            assert!(encode(&vector).is_err());
        }
        for bytes in [
            vec![],
            b"BAD1\x01\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            blob[..blob.len() - 1].to_vec(),
            b"AIE1\x00\x00\x00\x00".to_vec(),
            b"AIE1\x01\x00\x00\x00\x00\x00\x80\x7f".to_vec(),
        ] {
            assert!(decode(&bytes).is_none());
        }
    }

    #[tokio::test]
    async fn warm_query_does_not_reload_rows_or_reembed_facts() {
        let calls = Arc::new(AtomicUsize::new(0));
        let manager = SqliteContextManager::in_memory()
            .unwrap()
            .with_embedder(Arc::new(CountingEmbedder(calls.clone())));
        let agent = uuid::Uuid::new_v4();
        for id in 1..=80 {
            manager
                .store_fact(agent, fact(id, &format!("retrieval service incident {id}")))
                .await
                .unwrap();
        }
        let first = manager.query_memory(agent, "incident 13").await.unwrap();
        let warmed = manager.fact_cache.lock().unwrap().warm_rows;
        let embedded = calls.load(Ordering::SeqCst);
        let second = manager.query_memory(agent, "incident 13").await.unwrap();
        assert_eq!(
            first.iter().map(|f| f.id).collect::<Vec<_>>(),
            second.iter().map(|f| f.id).collect::<Vec<_>>()
        );
        assert_eq!(warmed, 80);
        assert_eq!(manager.fact_cache.lock().unwrap().warm_rows, warmed);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            embedded + 1,
            "only the query is embedded on a warm cache hit"
        );
        assert_eq!(manager.locked_conn().query_row("SELECT count(*) FROM facts WHERE embedding_json IS NULL AND length(embedding_blob)=1032",[],|r|r.get::<_,i64>(0)).unwrap(),80);
    }

    #[tokio::test]
    async fn retained_cache_reflects_mutations_and_authoritative_corruption() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        let foreign = uuid::Uuid::new_v4();
        let first = fact(1, "cobalt deployment");
        manager.store_fact(owner, first.clone()).await.unwrap();
        manager.query_memory(owner, "cobalt").await.unwrap();
        assert!(!manager.update_fact(foreign, first.id, "foreign").unwrap());
        assert!(manager
            .query_memory(foreign, "cobalt")
            .await
            .unwrap()
            .is_empty());
        manager
            .store_fact(owner, fact(2, "violet service"))
            .await
            .unwrap();
        assert_eq!(
            manager.query_memory(owner, "violet service").await.unwrap()[0].id,
            uuid::Uuid::from_u128(2)
        );
        assert!(manager
            .update_fact(owner, first.id, "violet service exact fix")
            .unwrap());
        assert_eq!(
            manager
                .query_memory(owner, "violet service exact fix")
                .await
                .unwrap()[0]
                .content,
            "violet service exact fix"
        );
        for assignment in [
            "embedding_blob=x'00'",
            "embedding_model='stale'",
            "embedding_version=0",
            "embedding_dim=1",
            "content_hash='wrong'",
            "embedding_json='not-json'",
        ] {
            manager
                .locked_conn()
                .execute(
                    &format!("UPDATE facts SET {assignment} WHERE id=?1"),
                    [first.id.to_string()],
                )
                .unwrap();
            let before = manager.fact_cache.lock().unwrap().warm_rows;
            let result = manager
                .query_memory(owner, "violet service exact fix")
                .await
                .unwrap();
            assert_eq!(
                result[0].embedding.as_ref().unwrap(),
                &manager.embedder.embed(&result[0].content).unwrap()
            );
            assert_eq!(manager.fact_cache.lock().unwrap().warm_rows, before + 2);
        }
        assert_eq!(manager.reindex_memory(owner).unwrap(), 2);
        let before = manager.fact_cache.lock().unwrap().warm_rows;
        manager.query_memory(owner, "violet").await.unwrap();
        assert_eq!(manager.fact_cache.lock().unwrap().warm_rows, before + 2);
        assert!(manager.delete_fact(owner, first.id).unwrap());
        assert!(
            !manager
                .fact_cache
                .lock()
                .unwrap()
                .agents
                .contains_key(&owner),
            "deleted private content must leave process cache immediately"
        );
        assert_eq!(
            manager.query_memory(owner, "violet").await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn equal_scores_follow_durable_recency_and_row_order_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let owner = uuid::Uuid::new_v4();
        let manager = SqliteContextManager::new(&path).unwrap();
        for id in 1..=24 {
            manager
                .store_fact(owner, fact(id, "identical score"))
                .await
                .unwrap();
        }
        manager
            .locked_conn()
            .execute(
                "UPDATE facts SET last_accessed_at='2026-10-08T02:00:00Z' WHERE id=?1",
                [uuid::Uuid::from_u128(24).to_string()],
            )
            .unwrap();
        let expected = std::iter::once(uuid::Uuid::from_u128(24))
            .chain((1..16).map(uuid::Uuid::from_u128))
            .collect::<Vec<_>>();
        let first = manager
            .query_memory(owner, "identical score")
            .await
            .unwrap();
        assert_eq!(first.iter().map(|f| f.id).collect::<Vec<_>>(), expected);
        // Returned facts receive one shared timestamp; the next query uses the
        // same stable row-id tie break that a fresh database read would use.
        let second = manager
            .query_memory(owner, "identical score")
            .await
            .unwrap();
        drop(manager);
        let reopened = SqliteContextManager::new(&path).unwrap();
        let third = reopened
            .query_memory(owner, "identical score")
            .await
            .unwrap();
        assert_eq!(
            second.iter().map(|f| f.id).collect::<Vec<_>>(),
            third.iter().map(|f| f.id).collect::<Vec<_>>()
        );
    }

    fn legacy_database(path: &Path, owner: AgentId, count: usize) -> Vec<Fact> {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("CREATE TABLE facts(id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,content TEXT NOT NULL,category TEXT NOT NULL,created_at TEXT NOT NULL,last_accessed_at TEXT NOT NULL,embedding_json TEXT,embedding_model TEXT NOT NULL,embedding_version INTEGER NOT NULL,embedding_dim INTEGER NOT NULL,content_hash TEXT NOT NULL);").unwrap();
        let embedder = BlendedEmbedder::default();
        (1..=count)
            .map(|id| {
                let mut fact = fact(
                    id as u128,
                    &format!(
                        "project p{} deployment incident i{id} service timeout worker remediation",
                        id % 11
                    ),
                );
                fact.embedding = Some(embedder.embed(&fact.content).unwrap());
                conn.execute(
                    "INSERT INTO facts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![
                        fact.id.to_string(),
                        owner.to_string(),
                        fact.content,
                        serde_json::to_string(&fact.category).unwrap(),
                        fact.created_at.to_rfc3339(),
                        fact.last_accessed_at.to_rfc3339(),
                        serde_json::to_string(&fact.embedding).unwrap(),
                        embedder.model_id(),
                        embedder.version(),
                        embedder.dim() as i64,
                        memory_content_hash(&fact.content)
                    ],
                )
                .unwrap();
                fact
            })
            .collect()
    }

    #[tokio::test]
    async fn json_database_migrates_without_changing_top_k_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.db");
        let owner = uuid::Uuid::new_v4();
        let mut oracle = legacy_database(&path, owner, 96);
        let manager = SqliteContextManager::new(&path).unwrap();
        {
            let conn = manager.locked_conn();
            assert_eq!(conn.query_row("SELECT COUNT(*) FROM facts WHERE embedding_json IS NULL AND embedding_blob IS NOT NULL",[],|r|r.get::<_,i64>(0)).unwrap(),96);
            assert_eq!(
                conn.query_row(
                    "SELECT min_reader_schema_version FROM storage_meta",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                crate::schema::MIN_READER_SCHEMA_VERSION
            );
        }
        for query in [
            "deployment incident i13",
            "project p4 timeout",
            "worker remediation",
            "deployment incident i13",
        ] {
            oracle.sort_by(|a, b| {
                b.last_accessed_at
                    .cmp(&a.last_accessed_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
            let expected = crate::memory_manager::rank_topk(
                &manager.embedder.embed(query).unwrap(),
                oracle
                    .iter()
                    .map(|f| (f.id, f.embedding.clone().unwrap()))
                    .collect(),
                16,
                64,
            )
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
            let actual = manager.query_memory(owner, query).await.unwrap();
            assert_eq!(actual.iter().map(|f| f.id).collect::<Vec<_>>(), expected);
            let now = manager
                .locked_conn()
                .query_row(
                    "SELECT last_accessed_at FROM facts WHERE id=?1",
                    [actual[0].id.to_string()],
                    |r| r.get::<_, String>(0),
                )
                .unwrap();
            let now = DateTime::parse_from_rfc3339(&now)
                .unwrap()
                .with_timezone(&Utc);
            for item in &mut oracle {
                if expected.contains(&item.id) {
                    item.last_accessed_at = now;
                }
            }
        }
    }

    #[test]
    fn late_binary_migration_failure_rolls_back_every_converted_row() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rollback.db");
        legacy_database(&path, uuid::Uuid::new_v4(), 4);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TRIGGER abort_migration BEFORE UPDATE ON facts WHEN OLD.rowid=3 BEGIN SELECT RAISE(ABORT,'injected late migration failure'); END;").unwrap();
        drop(conn);
        assert!(SqliteContextManager::new(&path).is_err());
        let conn = Connection::open(&path).unwrap();
        assert!(!crate::schema::has_column(&conn, "facts", "embedding_blob").unwrap());
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM facts WHERE embedding_json IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            4
        );
        assert_eq!(
            conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn cache_is_bounded_and_agent_erasure_drops_retained_private_rows() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let agents = (0..MAX_CACHED_AGENTS + 2)
            .map(|_| uuid::Uuid::new_v4())
            .collect::<Vec<_>>();
        for (i, owner) in agents.iter().enumerate() {
            manager
                .store_fact(*owner, fact(i as u128 + 1, "private cache content"))
                .await
                .unwrap();
            manager.query_memory(*owner, "private").await.unwrap();
        }
        assert_eq!(
            manager.fact_cache.lock().unwrap().agents.len(),
            MAX_CACHED_AGENTS
        );
        assert!(!manager
            .fact_cache
            .lock()
            .unwrap()
            .agents
            .contains_key(&agents[0]));
        let owner = *agents.last().unwrap();
        manager.erase_agent_data(owner).unwrap();
        assert!(!manager
            .fact_cache
            .lock()
            .unwrap()
            .agents
            .contains_key(&owner));
        assert_eq!(generation(&manager.locked_conn(), owner).unwrap(), 0);
        assert!(manager
            .query_memory(owner, "private")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            manager
                .query_memory(agents[2], "private")
                .await
                .unwrap()
                .len(),
            1
        );
    }
    #[tokio::test]
    async fn schema_nine_json_upgrade_and_trigger_tampering_are_checked_on_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("schema-nine.db");
        let owner = uuid::Uuid::new_v4();
        let manager = SqliteContextManager::new(&path).unwrap();
        manager
            .store_fact(owner, fact(1, "schema nine preserved content"))
            .await
            .unwrap();
        {
            let conn = manager.locked_conn();
            for (name, _) in TRIGGERS {
                conn.execute(&format!("DROP TRIGGER {name}"), []).unwrap();
            }
            conn.execute(
                "UPDATE facts SET embedding_json=?1",
                [serde_json::to_string(
                    &manager
                        .embedder
                        .embed("schema nine preserved content")
                        .unwrap(),
                )
                .unwrap()],
            )
            .unwrap();
            conn.execute_batch("DROP INDEX idx_facts_storage_bytes; DROP TABLE fact_index_generations; ALTER TABLE facts DROP COLUMN embedding_blob; DELETE FROM schema_migrations WHERE version=10; UPDATE storage_meta SET schema_version=9,min_reader_schema_version=9; PRAGMA user_version=9;").unwrap();
        }
        drop(manager);
        let reopened = SqliteContextManager::new(&path).unwrap();
        assert_eq!(
            reopened.query_memory(owner, "preserved").await.unwrap()[0].content,
            "schema nine preserved content"
        );
        let conn = reopened.locked_conn();
        conn.execute_batch("DROP TRIGGER facts_index_insert; CREATE TRIGGER facts_index_insert AFTER INSERT ON facts BEGIN SELECT 1; END;").unwrap();
        drop(conn);
        drop(reopened);
        let error = SqliteContextManager::new(&path)
            .err()
            .expect("tampered trigger must fail closed");
        assert!(
            error.to_string().contains("canonical definition"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn tenant_erasure_invalidates_warmed_content_and_preserves_other_tenant() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        for (owner, tenant, id) in [(first, "tenant-a", 1), (second, "tenant-b", 2)] {
            manager.locked_conn().execute("INSERT INTO agents(id,session_id,name,task,llm_provider,permission_profile,priority,status,created_at,last_activity_at,tenant_id) VALUES(?1,?2,'cache','test','fixture','standard',3,'\"Running\"',?3,?3,?4)",params![owner.to_string(),uuid::Uuid::new_v4().to_string(),Utc::now().to_rfc3339(),tenant]).unwrap();
            manager
                .store_fact(owner, fact(id, &format!("secret for {tenant}")))
                .await
                .unwrap();
            manager
                .query_memory_for_tenant(tenant, owner, "secret")
                .await
                .unwrap();
        }
        assert!(manager
            .query_memory_for_tenant("tenant-b", first, "secret")
            .await
            .unwrap()
            .is_empty());
        assert!(manager
            .fact_cache
            .lock()
            .unwrap()
            .agents
            .contains_key(&first));
        manager.erase_tenant_data("tenant-a").unwrap();
        assert!(!manager
            .fact_cache
            .lock()
            .unwrap()
            .agents
            .contains_key(&first));
        assert_eq!(generation(&manager.locked_conn(), first).unwrap(), 0);
        assert!(manager
            .query_memory(first, "secret")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            manager
                .query_memory_for_tenant("tenant-b", second, "secret")
                .await
                .unwrap()[0]
                .content,
            "secret for tenant-b"
        );
    }
    #[tokio::test]
    async fn normal_updates_and_inserts_refresh_one_row_without_rewarming() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        for id in 1..=80 {
            manager
                .store_fact(owner, fact(id, &format!("service incident {id}")))
                .await
                .unwrap();
        }
        manager.query_memory(owner, "incident").await.unwrap();
        let before = manager.fact_cache.lock().unwrap().warm_rows;
        assert!(manager
            .update_fact(owner, uuid::Uuid::from_u128(3), "unique violet remediation")
            .unwrap());
        assert_eq!(
            manager
                .query_memory(owner, "unique violet remediation")
                .await
                .unwrap()[0]
                .id,
            uuid::Uuid::from_u128(3)
        );
        manager
            .store_fact(owner, fact(81, "unique cobalt repair"))
            .await
            .unwrap();
        assert_eq!(
            manager
                .query_memory(owner, "unique cobalt repair")
                .await
                .unwrap()[0]
                .id,
            uuid::Uuid::from_u128(81)
        );
        manager
            .store_fact(owner, fact(3, "replacement gold repair"))
            .await
            .unwrap();
        assert_eq!(
            manager
                .query_memory(owner, "replacement gold repair")
                .await
                .unwrap()[0]
                .content,
            "replacement gold repair"
        );
        assert_eq!(
            manager.fact_cache.lock().unwrap().warm_rows,
            before,
            "ordinary writes must not reload the whole store"
        );
        assert_eq!(
            manager
                .locked_conn()
                .query_row(
                    "SELECT COUNT(*) FROM facts WHERE agent_id=?1",
                    [owner.to_string()],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            81
        );
    }

    #[tokio::test]
    async fn incremental_refresh_does_not_hide_intervening_authoritative_changes() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        manager.store_fact(owner, fact(1, "first")).await.unwrap();
        manager.store_fact(owner, fact(2, "second")).await.unwrap();
        manager.query_memory(owner, "first").await.unwrap();
        manager
            .locked_conn()
            .execute(
                "UPDATE facts SET content='external important marker' WHERE id=?1",
                [uuid::Uuid::from_u128(1).to_string()],
            )
            .unwrap();
        manager
            .update_fact(owner, uuid::Uuid::from_u128(2), "ordinary update")
            .unwrap();
        assert_eq!(
            manager
                .query_memory(owner, "external important marker")
                .await
                .unwrap()[0]
                .content,
            "external important marker"
        );
    }

    #[tokio::test]
    async fn failed_commit_cannot_publish_staged_cached_fact_content() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        manager
            .store_fact(owner, fact(1, "original"))
            .await
            .unwrap();
        manager.query_memory(owner, "original").await.unwrap();
        manager.locked_conn().execute_batch("CREATE TABLE commit_parent(id INTEGER PRIMARY KEY); CREATE TABLE commit_guard(id INTEGER, FOREIGN KEY(id) REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_fact_commit AFTER UPDATE ON facts WHEN NEW.content='blocked' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
        assert!(manager
            .update_fact(owner, uuid::Uuid::from_u128(1), "blocked")
            .is_err());
        let result = manager.query_memory(owner, "original").await.unwrap();
        assert_eq!(result[0].content, "original");
        assert_eq!(
            result[0].embedding.as_ref().unwrap(),
            &manager.embedder.embed("original").unwrap()
        );
    }

    #[tokio::test]
    async fn fact_replacements_and_updates_enforce_utf8_logical_byte_limits() {
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        let limit = encode(&manager.embedder.embed("seed").unwrap())
            .unwrap()
            .len() as u64
            + 4;
        manager
            .set_context_storage_limits(ContextStorageLimits {
                per_agent_bytes: limit,
                per_tenant_bytes: limit,
                global_bytes: limit,
                spill_retention_seconds: 60,
            })
            .unwrap();
        manager.store_fact(owner, fact(1, "seed")).await.unwrap();
        manager.query_memory(owner, "seed").await.unwrap();
        assert!(manager
            .update_fact(owner, uuid::Uuid::from_u128(1), &"🌲".repeat(50))
            .is_err());
        assert_eq!(
            manager.query_memory(owner, "seed").await.unwrap()[0].content,
            "seed"
        );
        assert!(manager
            .update_fact(owner, uuid::Uuid::from_u128(1), "tiny")
            .unwrap());
        manager.store_fact(owner, fact(1, "seed")).await.unwrap();
        assert!(manager.store_fact(owner, fact(2, "x")).await.is_err());
    }
}
