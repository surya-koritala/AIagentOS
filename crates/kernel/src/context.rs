//! Context Manager — handles agent short-term and long-term memory.
//!
//! Provides SQLite-backed persistence for conversation history, working state,
//! tasks, results, and long-term facts with retry logic and summarization.

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

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
}

impl SqliteContextManager {
    /// Create a new SqliteContextManager with the given database path.
    pub fn new(db_path: &Path) -> Result<Self, ContextError> {
        let conn =
            Connection::open(db_path).map_err(|e| ContextError::StorageError(e.to_string()))?;
        let mgr = Self {
            conn: Mutex::new(conn),
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
        };
        mgr.init_schema()?;
        Ok(mgr)
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
            CREATE VIRTUAL TABLE IF NOT EXISTS conversations_fts USING fts5(conversation_id, content);",
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
        let embedding_json = fact
            .embedding
            .as_ref()
            .map(|e| serde_json::to_string(e).unwrap_or_default());
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
        let pattern = format!("%{}%", query);

        let mut stmt = conn
            .prepare(
                "SELECT id, content, category, created_at, last_accessed_at, embedding_json
             FROM facts WHERE agent_id = ?1 AND content LIKE ?2
             ORDER BY last_accessed_at DESC",
            )
            .map_err(|e| ContextError::StorageError(e.to_string()))?;

        let facts = stmt
            .query_map(params![id_str, pattern], |row| {
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
    async fn query_memory_no_match() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let fact = Fact {
            id: uuid::Uuid::new_v4(),
            content: "likes coffee".to_string(),
            category: FactCategory::Preference,
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
            embedding: None,
        };
        mgr.store_fact(id, fact).await.unwrap();
        let results = mgr.query_memory(id, "tea").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn get_nonexistent_context_fails() {
        let mgr = SqliteContextManager::in_memory().unwrap();
        let id = uuid::Uuid::new_v4();
        let result = mgr.get_context(id).await;
        assert!(result.is_err());
    }
}
