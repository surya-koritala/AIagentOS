//! Context Manager — handles agent short-term and long-term memory.
//!
//! Provides SQLite-backed persistence for conversation history, working state,
//! tasks, results, and long-term facts with retry logic and summarization.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::memory_manager::Embedder;
use crate::{AgentId, ContextError};

/// A message in the agent's conversation history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub role: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

/// A task assigned to or created by an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task {
    pub id: uuid::Uuid,
    pub description: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Result of a completed task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskResult {
    pub task_id: uuid::Uuid,
    pub success: bool,
    pub output: serde_json::Value,
    pub completed_at: DateTime<Utc>,
}

/// Category for long-term memory facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactCategory {
    Preference,
    LearnedPattern,
    Fact,
    Instruction,
}

/// A fact stored in long-term memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fact {
    pub id: uuid::Uuid,
    pub content: String,
    pub category: FactCategory,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: DateTime<Utc>,
    pub embedding: Option<Vec<f32>>,
}

/// Agent's working context — short-term memory for the current session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentContext {
    pub conversation_history: Vec<Message>,
    pub working_state: serde_json::Value,
    pub active_tasks: Vec<Task>,
    pub intermediate_results: Vec<TaskResult>,
    pub token_count: u32,
}

impl Default for AgentContext {
    fn default() -> Self {
        Self {
            conversation_history: Vec::new(),
            working_state: serde_json::Value::Null,
            active_tasks: Vec::new(),
            intermediate_results: Vec::new(),
            token_count: 0,
        }
    }
}

/// The Context Manager trait.
#[async_trait::async_trait]
pub trait ContextManager: Send + Sync {
    async fn create_context(&self, agent_id: AgentId) -> Result<(), ContextError>;
    async fn get_context(&self, agent_id: AgentId) -> Result<AgentContext, ContextError>;
    async fn persist_context(
        &self,
        agent_id: AgentId,
        context: &AgentContext,
    ) -> Result<(), ContextError>;
    async fn restore_context(&self, agent_id: AgentId) -> Result<AgentContext, ContextError>;
    async fn summarize_overflow(
        &self,
        context: &AgentContext,
        token_limit: u32,
    ) -> Result<AgentContext, ContextError>;
    async fn store_fact(&self, agent_id: AgentId, fact: Fact) -> Result<(), ContextError>;
    async fn query_memory(&self, agent_id: AgentId, query: &str)
        -> Result<Vec<Fact>, ContextError>;
}

/// Maximum retry attempts for persistence operations.
const MAX_RETRIES: u32 = 3;

/// SQLite-backed context manager implementation.
pub struct SqliteContextManager {
    conn: Mutex<Connection>,
    /// Pluggable embedder used for the long-term-memory store/query/ranking
    /// path. Defaults to [`crate::memory_manager::default_embedder`]; swap it
    /// via [`SqliteContextManager::with_embedder`] to change embedding strategy
    /// without touching persistence.
    embedder: Arc<dyn Embedder>,
}

impl SqliteContextManager {
    /// Create a new SqliteContextManager with the given database path.
    pub fn new(db_path: &Path) -> Result<Self, ContextError> {
        let conn =
            Connection::open(db_path).map_err(|e| ContextError::StorageError(e.to_string()))?;
        let mgr = Self {
            conn: Mutex::new(conn),
            embedder: crate::memory_manager::default_embedder(),
        };
        mgr.init_schema()?;
        Ok(mgr)
    }

    /// Create an in-memory context manager (for testing).
    pub fn in_memory() -> Result<Self, ContextError> {
        let conn =
            Connection::open_in_memory().map_err(|e| ContextError::StorageError(e.to_string()))?;
        let mgr = Self {
            conn: Mutex::new(conn),
            embedder: crate::memory_manager::default_embedder(),
        };
        mgr.init_schema()?;
        Ok(mgr)
    }

    /// Swap the embedder used by the long-term-memory store/query path. Returns
    /// `self` for builder-style chaining. The seam where a different
    /// [`Embedder`] can drop in without changing persistence.
    pub fn with_embedder(mut self, embedder: Arc<dyn Embedder>) -> Self {
        self.embedder = embedder;
        self
    }

    fn init_schema(&self) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS contexts (
                agent_id TEXT PRIMARY KEY,
                context_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS facts (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_accessed_at TEXT NOT NULL,
                embedding_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_facts_agent ON facts(agent_id);
            CREATE INDEX IF NOT EXISTS idx_facts_category ON facts(agent_id, category);
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                messages_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_conv_agent ON conversations(agent_id);
            CREATE INDEX IF NOT EXISTS idx_conv_updated ON conversations(updated_at);
            CREATE TABLE IF NOT EXISTS usage_log (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                tokens_used INTEGER NOT NULL,
                model TEXT,
                estimated_cost_usd REAL
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS conversations_fts USING fts5(conversation_id, content);
            CREATE TABLE IF NOT EXISTS agent_kv (
                agent_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(agent_id, key)
            );
            CREATE INDEX IF NOT EXISTS idx_agent_kv_agent ON agent_kv(agent_id);
            CREATE TABLE IF NOT EXISTS context_snapshots (
                agent_id TEXT NOT NULL,
                label TEXT NOT NULL,
                context_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(agent_id, label)
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_agent ON context_snapshots(agent_id);",
        ).map_err(|e| ContextError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn persist_with_retry(
        &self,
        agent_id: AgentId,
        context: &AgentContext,
    ) -> Result<(), ContextError> {
        let json = serde_json::to_string(context)
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        let now = Utc::now().to_rfc3339();
        let id_str = agent_id.to_string();

        for attempt in 0..MAX_RETRIES {
            let conn = self.conn.lock().unwrap();
            let result = conn.execute(
                "INSERT OR REPLACE INTO contexts (agent_id, context_json, updated_at) VALUES (?1, ?2, ?3)",
                params![id_str, json, now],
            );
            match result {
                Ok(_) => return Ok(()),
                Err(e) if attempt < MAX_RETRIES - 1 => {
                    tracing::warn!("Persist attempt {} failed: {}", attempt + 1, e);
                    continue;
                }
                Err(e) => {
                    return Err(ContextError::PersistenceFailed(format!(
                        "Failed after {} attempts: {}",
                        MAX_RETRIES, e
                    )))
                }
            }
        }
        unreachable!()
    }
}

#[async_trait::async_trait]
impl ContextManager for SqliteContextManager {
    async fn create_context(&self, agent_id: AgentId) -> Result<(), ContextError> {
        let context = AgentContext::default();
        self.persist_with_retry(agent_id, &context)
    }

    async fn get_context(&self, agent_id: AgentId) -> Result<AgentContext, ContextError> {
        let conn = self.conn.lock().unwrap();
        let id_str = agent_id.to_string();
        let result = conn.query_row(
            "SELECT context_json FROM contexts WHERE agent_id = ?1",
            params![id_str],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(json) => {
                serde_json::from_str(&json).map_err(|e| ContextError::RestoreFailed(e.to_string()))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(ContextError::RestoreFailed(format!(
                "No context for agent {}",
                agent_id
            ))),
            Err(e) => Err(ContextError::StorageError(e.to_string())),
        }
    }

    async fn persist_context(
        &self,
        agent_id: AgentId,
        context: &AgentContext,
    ) -> Result<(), ContextError> {
        self.persist_with_retry(agent_id, context)
    }

    async fn restore_context(&self, agent_id: AgentId) -> Result<AgentContext, ContextError> {
        self.get_context(agent_id).await
    }

    async fn summarize_overflow(
        &self,
        context: &AgentContext,
        token_limit: u32,
    ) -> Result<AgentContext, ContextError> {
        if context.token_count <= token_limit {
            return Ok(context.clone());
        }

        // Summarize by keeping the most recent messages that fit within 80% of limit
        let target_tokens = (token_limit as f64 * 0.8) as u32;
        let mut new_context = context.clone();

        // Estimate ~4 chars per token, keep recent messages
        let mut kept_messages = Vec::new();
        let mut running_tokens: u32 = 0;

        for msg in context.conversation_history.iter().rev() {
            let msg_tokens = (msg.content.len() as u32) / 4 + 1;
            if running_tokens + msg_tokens > target_tokens {
                break;
            }
            running_tokens += msg_tokens;
            kept_messages.push(msg.clone());
        }
        kept_messages.reverse();

        // Add a summary message at the beginning if we dropped messages
        if kept_messages.len() < context.conversation_history.len() {
            let dropped = context.conversation_history.len() - kept_messages.len();
            let summary = Message {
                role: "system".to_string(),
                content: format!("[Summary: {} earlier messages condensed]", dropped),
                timestamp: Utc::now(),
            };
            kept_messages.insert(0, summary);
        }

        new_context.conversation_history = kept_messages;
        new_context.token_count = running_tokens;
        Ok(new_context)
    }

    async fn store_fact(&self, agent_id: AgentId, fact: Fact) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        // Every stored fact gets a deterministic embedding. If the caller didn't
        // supply one, compute it from the content via the Memory Manager so
        // query_memory can rank by semantic (cosine) similarity later.
        let embedding = match &fact.embedding {
            Some(e) => e.clone(),
            None => self.embedder.embed(&fact.content),
        };
        let embedding_json = Some(serde_json::to_string(&embedding).unwrap_or_default());
        let category_str = serde_json::to_string(&fact.category)
            .map_err(|e| ContextError::StorageError(e.to_string()))?;

        conn.execute(
            "INSERT OR REPLACE INTO facts (id, agent_id, content, category, created_at, last_accessed_at, embedding_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                fact.id.to_string(),
                agent_id.to_string(),
                fact.content,
                category_str,
                fact.created_at.to_rfc3339(),
                fact.last_accessed_at.to_rfc3339(),
                embedding_json,
            ],
        ).map_err(|e| ContextError::StorageError(e.to_string()))?;
        Ok(())
    }

    async fn query_memory(
        &self,
        agent_id: AgentId,
        query: &str,
    ) -> Result<Vec<Fact>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let id_str = agent_id.to_string();

        // Fetch the agent's candidate facts. We pull all of the agent's facts
        // (rather than a substring `LIKE` prefilter) so that semantic ranking
        // can surface relevant facts that don't share literal tokens with the
        // query — that's the whole point of vector retrieval.
        let mut stmt = conn
            .prepare(
                "SELECT id, content, category, created_at, last_accessed_at, embedding_json
             FROM facts WHERE agent_id = ?1
             ORDER BY last_accessed_at DESC",
            )
            .map_err(|e| ContextError::StorageError(e.to_string()))?;

        let facts = stmt
            .query_map(params![id_str], |row| {
                let id_str: String = row.get(0)?;
                let content: String = row.get(1)?;
                let category_str: String = row.get(2)?;
                let created_str: String = row.get(3)?;
                let accessed_str: String = row.get(4)?;
                let embedding_str: Option<String> = row.get(5)?;
                Ok((
                    id_str,
                    content,
                    category_str,
                    created_str,
                    accessed_str,
                    embedding_str,
                ))
            })
            .map_err(|e| ContextError::StorageError(e.to_string()))?;

        let mut result = Vec::new();
        for row in facts {
            let (id_str, content, category_str, created_str, accessed_str, embedding_str) =
                row.map_err(|e| ContextError::StorageError(e.to_string()))?;

            let id = uuid::Uuid::parse_str(&id_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let category: FactCategory = serde_json::from_str(&category_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?;
            let created_at = DateTime::parse_from_rfc3339(&created_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?
                .with_timezone(&Utc);
            let last_accessed_at = DateTime::parse_from_rfc3339(&accessed_str)
                .map_err(|e| ContextError::StorageError(e.to_string()))?
                .with_timezone(&Utc);
            let embedding = embedding_str.and_then(|s| serde_json::from_str(&s).ok());

            result.push(Fact {
                id,
                content,
                category,
                created_at,
                last_accessed_at,
                embedding,
            });
        }

        // Semantic ranking: embed the query and sort facts by cosine similarity
        // (best-first). A fact missing a stored embedding falls back to embedding
        // its content on the fly; an empty/unparseable embedding scores 0.
        let query_vec = self.embedder.embed(query);
        let scored: Vec<(Fact, Vec<f32>)> = result
            .into_iter()
            .map(|fact| {
                let emb = match &fact.embedding {
                    Some(e) if !e.is_empty() => e.clone(),
                    _ => self.embedder.embed(&fact.content),
                };
                (fact, emb)
            })
            .collect();
        let result: Vec<Fact> = crate::memory_manager::rank(&query_vec, scored)
            .into_iter()
            .map(|(fact, _score)| fact)
            .collect();

        // Update last_accessed_at for returned facts
        let now = Utc::now().to_rfc3339();
        for fact in &result {
            let _ = conn.execute(
                "UPDATE facts SET last_accessed_at = ?1 WHERE id = ?2",
                params![now, fact.id.to_string()],
            );
        }

        Ok(result)
    }
}

/// Conversation persistence methods.
impl SqliteContextManager {
    /// Save a conversation (messages as JSON).
    pub fn save_conversation(
        &self,
        id: &str,
        agent_id: AgentId,
        messages: &[crate::connector::StandardMessage],
    ) -> Result<(), ContextError> {
        let json = serde_json::to_string(messages)
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO conversations (id, agent_id, messages_json, created_at, updated_at) VALUES (?1, ?2, ?3, COALESCE((SELECT created_at FROM conversations WHERE id=?1), ?4), ?4)",
            rusqlite::params![id, agent_id.to_string(), json, now],
        ).map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        let text_content: String = messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        conn.execute(
            "INSERT OR REPLACE INTO conversations_fts (conversation_id, content) VALUES (?1, ?2)",
            rusqlite::params![id, text_content],
        )
        .ok();
        Ok(())
    }

    /// Load a conversation's messages.
    pub fn load_conversation(
        &self,
        id: &str,
    ) -> Result<Vec<crate::connector::StandardMessage>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let json: String = conn
            .query_row(
                "SELECT messages_json FROM conversations WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .map_err(|e| ContextError::RestoreFailed(e.to_string()))?;
        serde_json::from_str(&json).map_err(|e| ContextError::RestoreFailed(e.to_string()))
    }

    /// List all conversations, sorted by most recently updated.
    pub fn list_conversations(&self) -> Vec<(String, String, String)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, agent_id, updated_at FROM conversations ORDER BY updated_at DESC")
            .unwrap_or_else(|_| conn.prepare("SELECT 1, 2, 3 WHERE 0").unwrap());
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Delete a conversation.
    pub fn delete_conversation(&self, id: &str) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM conversations WHERE id = ?1",
            rusqlite::params![id],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Export a conversation as JSON.
    pub fn export_conversation(&self, id: &str) -> Result<String, ContextError> {
        let messages = self.load_conversation(id)?;
        let export = serde_json::json!({
            "version": 1,
            "conversation_id": id,
            "messages": messages,
            "exported_at": chrono::Utc::now().to_rfc3339(),
        });
        serde_json::to_string_pretty(&export)
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))
    }

    /// Import a conversation from JSON.
    pub fn import_conversation(&self, json: &str) -> Result<String, ContextError> {
        let data: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| ContextError::RestoreFailed(format!("Invalid JSON: {}", e)))?;
        let messages: Vec<crate::connector::StandardMessage> =
            serde_json::from_value(data["messages"].clone())
                .map_err(|e| ContextError::RestoreFailed(format!("Invalid messages: {}", e)))?;
        let id = uuid::Uuid::new_v4().to_string();
        let agent_id = uuid::Uuid::nil();
        self.save_conversation(&id, agent_id, &messages)?;
        Ok(id)
    }

    pub fn log_usage(&self, agent_id: AgentId, tokens: u32, model: &str, cost_per_1k: f64) {
        let cost = (tokens as f64 / 1000.0) * cost_per_1k;
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO usage_log (id, agent_id, timestamp, tokens_used, model, estimated_cost_usd) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![uuid::Uuid::new_v4().to_string(), agent_id.to_string(), chrono::Utc::now().to_rfc3339(), tokens, model, cost],
        );
    }

    pub fn get_total_usage(&self) -> (u64, f64) {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(SUM(tokens_used), 0), COALESCE(SUM(estimated_cost_usd), 0.0) FROM usage_log",
            [], |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, f64>(1)?)),
        ).unwrap_or((0, 0.0))
    }

    pub fn search_conversations(&self, query: &str) -> Vec<(String, String)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT conversation_id, snippet(conversations_fts, 1, '**', '**', '...', 32) FROM conversations_fts WHERE content MATCH ?1 LIMIT 20"
        ).unwrap_or_else(|_| conn.prepare("SELECT 1, 2 WHERE 0").unwrap());
        stmt.query_map(rusqlite::params![query], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }
}

/// Per-agent durable key/value store ("storage manager").
///
/// A simple persistent KV namespace scoped per agent — distinct from the
/// long-term-memory facts table (which is semantic / queryable). Values are
/// opaque strings (callers may JSON-encode structured data). Backed by the same
/// single SQLite handle as the rest of the context manager (no separate db).
impl SqliteContextManager {
    /// Put (insert-or-overwrite) a value for `key` under `agent_id`.
    pub fn kv_put(&self, agent_id: AgentId, key: &str, value: &str) -> Result<(), ContextError> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO agent_kv (agent_id, key, value, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![agent_id.to_string(), key, value, now],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Get the value for `key` under `agent_id`, or `None` if absent.
    pub fn kv_get(&self, agent_id: AgentId, key: &str) -> Result<Option<String>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT value FROM agent_kv WHERE agent_id = ?1 AND key = ?2",
            params![agent_id.to_string(), key],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ContextError::StorageError(e.to_string())),
        }
    }

    /// List the keys stored under `agent_id` (sorted ascending).
    pub fn kv_list(&self, agent_id: AgentId) -> Result<Vec<String>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT key FROM agent_kv WHERE agent_id = ?1 ORDER BY key ASC")
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let rows = stmt
            .query_map(params![agent_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| ContextError::StorageError(e.to_string()))?);
        }
        Ok(keys)
    }

    /// Delete the value for `key` under `agent_id`. Returns `true` if a row was
    /// removed, `false` if no such key existed.
    pub fn kv_delete(&self, agent_id: AgentId, key: &str) -> Result<bool, ContextError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "DELETE FROM agent_kv WHERE agent_id = ?1 AND key = ?2",
                params![agent_id.to_string(), key],
            )
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(affected > 0)
    }
}

/// Named context snapshots — point-in-time copies of an agent's working context.
///
/// A snapshot captures the agent's current [`AgentContext`] under a `label` so a
/// turn can pause/resume or you can branch/rewind. Snapshots live in the
/// `context_snapshots` table on the same single SQLite handle as everything else
/// (no separate db). Restoring a snapshot writes it back as the agent's current
/// context via the same persist path `get_context`/`persist_context` use.
impl SqliteContextManager {
    /// Capture the agent's current context under `label` (insert-or-overwrite).
    ///
    /// Fetches the live context the same way [`get_context`](ContextManager::get_context)
    /// does, then serializes it into the snapshots table keyed by
    /// `(agent_id, label)`. Errors with [`ContextError::RestoreFailed`] if the
    /// agent has no current context to snapshot.
    pub fn snapshot_context(&self, agent_id: AgentId, label: &str) -> Result<(), ContextError> {
        let conn = self.conn.lock().unwrap();
        let id_str = agent_id.to_string();
        // Read the agent's current context (mirrors get_context's query path).
        let json = match conn.query_row(
            "SELECT context_json FROM contexts WHERE agent_id = ?1",
            params![id_str],
            |row| row.get::<_, String>(0),
        ) {
            Ok(json) => json,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(ContextError::RestoreFailed(format!(
                    "No context for agent {} to snapshot",
                    agent_id
                )))
            }
            Err(e) => return Err(ContextError::StorageError(e.to_string())),
        };
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO context_snapshots (agent_id, label, context_json, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id_str, label, json, now],
        )
        .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(())
    }

    /// Restore a snapshot, making it the agent's current context.
    ///
    /// Loads the snapshot stored under `(agent_id, label)`, writes it back as the
    /// agent's current context (via the same persist path), and returns the
    /// restored [`AgentContext`]. Errors with [`ContextError::RestoreFailed`] if
    /// no such snapshot exists.
    pub fn restore_snapshot(
        &self,
        agent_id: AgentId,
        label: &str,
    ) -> Result<AgentContext, ContextError> {
        let json = {
            let conn = self.conn.lock().unwrap();
            match conn.query_row(
                "SELECT context_json FROM context_snapshots WHERE agent_id = ?1 AND label = ?2",
                params![agent_id.to_string(), label],
                |row| row.get::<_, String>(0),
            ) {
                Ok(json) => json,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Err(ContextError::RestoreFailed(format!(
                        "No snapshot '{}' for agent {}",
                        label, agent_id
                    )))
                }
                Err(e) => return Err(ContextError::StorageError(e.to_string())),
            }
        };
        let context: AgentContext =
            serde_json::from_str(&json).map_err(|e| ContextError::RestoreFailed(e.to_string()))?;
        // Make the snapshot the agent's current context via the persist path.
        self.persist_with_retry(agent_id, &context)?;
        Ok(context)
    }

    /// List the snapshot labels stored for `agent_id`, newest first.
    pub fn list_snapshots(&self, agent_id: AgentId) -> Result<Vec<String>, ContextError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT label FROM context_snapshots WHERE agent_id = ?1 ORDER BY created_at DESC, label DESC",
            )
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let rows = stmt
            .query_map(params![agent_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(|e| ContextError::StorageError(e.to_string()))?;
        let mut labels = Vec::new();
        for row in rows {
            labels.push(row.map_err(|e| ContextError::StorageError(e.to_string()))?);
        }
        Ok(labels)
    }

    /// Delete the snapshot stored under `(agent_id, label)`. Returns `true` if a
    /// row was removed, `false` if no such snapshot existed.
    pub fn delete_snapshot(&self, agent_id: AgentId, label: &str) -> Result<bool, ContextError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "DELETE FROM context_snapshots WHERE agent_id = ?1 AND label = ?2",
                params![agent_id.to_string(), label],
            )
            .map_err(|e| ContextError::PersistenceFailed(e.to_string()))?;
        Ok(affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_get_context() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        mgr.create_context(id).await.unwrap();
        let ctx = mgr.get_context(id).await.unwrap();
        assert_eq!(ctx, AgentContext::default());
    }

    #[tokio::test]
    async fn persist_and_restore_context() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        mgr.create_context(id).await.unwrap();

        let mut ctx = AgentContext::default();
        ctx.conversation_history.push(Message {
            role: "user".to_string(),
            content: "hello".to_string(),
            timestamp: Utc::now(),
        });
        ctx.token_count = 10;

        mgr.persist_context(id, &ctx).await.unwrap();
        let restored = mgr.restore_context(id).await.unwrap();
        assert_eq!(restored.conversation_history.len(), 1);
        assert_eq!(restored.conversation_history[0].content, "hello");
        assert_eq!(restored.token_count, 10);
    }

    #[tokio::test]
    async fn summarize_overflow_reduces_tokens() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let mut ctx = AgentContext::default();
        // Add many messages to exceed token limit
        for i in 0..100 {
            ctx.conversation_history.push(Message {
                role: "user".to_string(),
                content: format!("message number {} with some content", i),
                timestamp: Utc::now(),
            });
        }
        ctx.token_count = 5000;

        let summarized = mgr.summarize_overflow(&ctx, 1000).await.unwrap();
        assert!(summarized.token_count <= 1000);
        assert!(summarized.conversation_history.len() < ctx.conversation_history.len());
    }

    #[tokio::test]
    async fn summarize_within_limit_unchanged() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let ctx = AgentContext {
            token_count: 500,
            ..Default::default()
        };
        let result = mgr.summarize_overflow(&ctx, 1000).await.unwrap();
        assert_eq!(result.token_count, 500);
    }

    #[tokio::test]
    async fn store_and_query_fact() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let fact = Fact {
            id: uuid::Uuid::new_v4(),
            content: "The user prefers dark mode".to_string(),
            category: FactCategory::Preference,
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
            embedding: None,
        };
        mgr.store_fact(id, fact.clone()).await.unwrap();

        let results = mgr.query_memory(id, "dark mode").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, fact.content);
    }

    #[tokio::test]
    async fn query_memory_empty_when_no_facts() {
        // With semantic ranking, query_memory ranks an agent's facts rather than
        // substring-filtering them, so it only returns empty when there are no
        // facts stored for the agent.
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let results = mgr.query_memory(id, "tea").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_fact_persists_computed_embedding() {
        // store_fact should compute an embedding when none is supplied, so the
        // round-tripped fact comes back with a populated embedding vector.
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let fact = Fact {
            id: uuid::Uuid::new_v4(),
            content: "likes coffee in the morning".to_string(),
            category: FactCategory::Preference,
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
            embedding: None,
        };
        mgr.store_fact(id, fact).await.unwrap();
        let results = mgr.query_memory(id, "coffee").await.unwrap();
        assert_eq!(results.len(), 1);
        let emb = results[0].embedding.as_ref().expect("embedding persisted");
        assert_eq!(emb.len(), crate::memory_manager::EMBED_DIM);
    }

    #[tokio::test]
    async fn query_memory_ranks_semantically_closest_first() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();

        let facts = [
            "the user prefers dark mode in the editor",
            "the spacecraft reached orbital velocity at dawn",
            "the user enjoys drinking coffee every morning",
        ];
        for content in facts {
            mgr.store_fact(
                id,
                Fact {
                    id: uuid::Uuid::new_v4(),
                    content: content.to_string(),
                    category: FactCategory::Fact,
                    created_at: Utc::now(),
                    last_accessed_at: Utc::now(),
                    embedding: None,
                },
            )
            .await
            .unwrap();
        }

        let results = mgr
            .query_memory(id, "what theme does the user like in their editor")
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
        // The dark-mode/editor fact is semantically closest to the query.
        assert_eq!(
            results[0].content,
            "the user prefers dark mode in the editor"
        );
    }

    #[test]
    fn kv_put_get_list_delete_roundtrip() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();

        // Missing key → None.
        assert_eq!(mgr.kv_get(id, "color").unwrap(), None);

        // Put then get.
        mgr.kv_put(id, "color", "blue").unwrap();
        mgr.kv_put(id, "size", "large").unwrap();
        assert_eq!(mgr.kv_get(id, "color").unwrap().as_deref(), Some("blue"));

        // List returns both keys, sorted.
        assert_eq!(
            mgr.kv_list(id).unwrap(),
            vec!["color".to_string(), "size".to_string()]
        );

        // Overwrite an existing key.
        mgr.kv_put(id, "color", "green").unwrap();
        assert_eq!(mgr.kv_get(id, "color").unwrap().as_deref(), Some("green"));
        assert_eq!(
            mgr.kv_list(id).unwrap().len(),
            2,
            "overwrite must not add a row"
        );

        // Delete an existing key returns true; deleting again returns false.
        assert!(mgr.kv_delete(id, "color").unwrap());
        assert!(!mgr.kv_delete(id, "color").unwrap());
        assert_eq!(mgr.kv_get(id, "color").unwrap(), None);
        assert_eq!(mgr.kv_list(id).unwrap(), vec!["size".to_string()]);
    }

    #[test]
    fn kv_is_isolated_between_agents() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();

        mgr.kv_put(a, "shared", "a-value").unwrap();
        mgr.kv_put(b, "shared", "b-value").unwrap();

        assert_eq!(mgr.kv_get(a, "shared").unwrap().as_deref(), Some("a-value"));
        assert_eq!(mgr.kv_get(b, "shared").unwrap().as_deref(), Some("b-value"));

        // Agent A's keys don't leak into agent B's listing.
        assert_eq!(mgr.kv_list(a).unwrap(), vec!["shared".to_string()]);
        assert_eq!(mgr.kv_list(b).unwrap(), vec!["shared".to_string()]);

        // Deleting from A leaves B untouched.
        assert!(mgr.kv_delete(a, "shared").unwrap());
        assert_eq!(mgr.kv_get(a, "shared").unwrap(), None);
        assert_eq!(mgr.kv_get(b, "shared").unwrap().as_deref(), Some("b-value"));
    }

    #[tokio::test]
    async fn snapshot_restore_list_delete_roundtrip() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        mgr.create_context(id).await.unwrap();

        // Establish an initial context and snapshot it.
        let mut ctx = AgentContext::default();
        ctx.conversation_history.push(Message {
            role: "user".to_string(),
            content: "first".to_string(),
            timestamp: Utc::now(),
        });
        ctx.token_count = 7;
        mgr.persist_context(id, &ctx).await.unwrap();
        mgr.snapshot_context(id, "checkpoint-a").unwrap();

        // Mutate the live context away from the snapshot.
        let mut mutated = ctx.clone();
        mutated.conversation_history.push(Message {
            role: "assistant".to_string(),
            content: "second".to_string(),
            timestamp: Utc::now(),
        });
        mutated.token_count = 42;
        mgr.persist_context(id, &mutated).await.unwrap();
        assert_eq!(mgr.get_context(id).await.unwrap().token_count, 42);

        // A second snapshot (created later) should sort newest-first.
        mgr.snapshot_context(id, "checkpoint-b").unwrap();
        assert_eq!(
            mgr.list_snapshots(id).unwrap(),
            vec!["checkpoint-b".to_string(), "checkpoint-a".to_string()]
        );

        // Restoring the first snapshot returns the original and makes it current.
        let restored = mgr.restore_snapshot(id, "checkpoint-a").unwrap();
        assert_eq!(restored, ctx);
        let current = mgr.get_context(id).await.unwrap();
        assert_eq!(current, ctx);
        assert_eq!(current.token_count, 7);
        assert_eq!(current.conversation_history.len(), 1);

        // Delete is idempotent: true once, false after.
        assert!(mgr.delete_snapshot(id, "checkpoint-a").unwrap());
        assert!(!mgr.delete_snapshot(id, "checkpoint-a").unwrap());
        assert_eq!(
            mgr.list_snapshots(id).unwrap(),
            vec!["checkpoint-b".to_string()]
        );

        // Restoring or snapshotting unknown things errors rather than panics.
        assert!(mgr.restore_snapshot(id, "missing").is_err());
        let no_ctx = uuid::Uuid::new_v4();
        assert!(mgr.snapshot_context(no_ctx, "x").is_err());
    }

    #[test]
    fn snapshots_are_isolated_between_agents() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        mgr.persist_with_retry(a, &AgentContext::default()).unwrap();
        mgr.persist_with_retry(b, &AgentContext::default()).unwrap();

        mgr.snapshot_context(a, "shared").unwrap();
        mgr.snapshot_context(b, "shared").unwrap();

        // Agent A's snapshot listing doesn't include agent B's, and deleting
        // from A leaves B's untouched.
        assert_eq!(mgr.list_snapshots(a).unwrap(), vec!["shared".to_string()]);
        assert!(mgr.delete_snapshot(a, "shared").unwrap());
        assert!(mgr.list_snapshots(a).unwrap().is_empty());
        assert_eq!(mgr.list_snapshots(b).unwrap(), vec!["shared".to_string()]);
    }

    #[tokio::test]
    async fn get_nonexistent_context_fails() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let result = mgr.get_context(id).await;
        assert!(result.is_err());
    }
}
