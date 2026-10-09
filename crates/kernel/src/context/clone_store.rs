//! Durable staging and atomic publication for agent clones.

use super::*;
use crate::cloning::{CloneResult, CloneSecurity};

pub(crate) fn clone_request_digest(
    parent: AgentId,
    name: &str,
    dropped: &BTreeSet<u64>,
) -> Result<String, ContextError> {
    let value = serde_json::to_string(&(1, parent, name, dropped))
        .map_err(|error| ContextError::PersistenceFailed(error.to_string()))?;
    Ok(memory_content_hash(&value))
}
fn failed(message: impl Into<String>) -> ContextError {
    ContextError::PersistenceFailed(message.into())
}

type StoredClone = (Option<String>, Option<String>, bool, Option<String>, String);

impl SqliteContextManager {
    pub(crate) fn latest_execution_conversation_id(
        &self,
        agent: AgentId,
    ) -> Result<Option<String>, ContextError> {
        self.locked_conn().query_row("SELECT id FROM conversations WHERE agent_id = ?1 ORDER BY updated_at DESC,id DESC LIMIT 1",[agent.to_string()],|row|row.get(0))
            .optional().map_err(|error|failed(error.to_string()))
    }

    pub(crate) fn reserve_clone(
        &self,
        record: &PersistedAgent,
        parent: AgentId,
        request_digest: &str,
        group: Option<&str>,
        security: &CloneSecurity,
        max_agents: u64,
        dropped: &BTreeSet<u64>,
    ) -> Result<(), ContextError> {
        let mut conn = self.locked_conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| failed(error.to_string()))?;
        crate::schema::require_current_writer(&tx)?;
        let creation_digest = crate::cluster_agent_identity::clone_creation_sha256(
            &parent.to_string(), &record.id.to_string(), &record.name, dropped,
        ).map_err(|error| failed(error.to_string()))?;
        crate::cluster_agent_identity::validate_creation_write(&tx, record, &creation_digest)?;
        let count: u64 = tx
            .query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))
            .map_err(|error| failed(error.to_string()))?;
        if max_agents > 0 && count >= max_agents {
            return Err(failed(
                "agent admission quota exceeded during clone reservation",
            ));
        }
        let existing: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE id = ?1)",
                [record.id.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| failed(error.to_string()))?;
        if existing {
            return Err(failed("clone child identity already exists"));
        }
        let owner = Self::agent_tenant_locked(&tx, parent)?;
        if owner != record.tenant_id {
            return Err(failed("clone tenant identity cannot change"));
        }
        let constraints =
            serde_json::to_string(security).map_err(|error| failed(error.to_string()))?;
        tx.execute(
            "INSERT INTO agents(id,session_id,tenant_id,name,task,llm_provider,permission_profile,priority,status,sandbox_config_json,created_at,last_activity_at,namespace_group,clone_pending,clone_parent_id,clone_request_digest,clone_security_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,?10,?10,?11,1,?12,?13,?14)",
            params![record.id.to_string(),record.session_id.to_string(),record.tenant_id,record.name,record.task,record.llm_provider,record.permission_profile,record.priority,record.status,record.created_at.to_rfc3339(),group,parent.to_string(),request_digest,constraints],
        ).map_err(|error|failed(error.to_string()))?;
        tx.commit().map_err(|error| failed(error.to_string()))
    }

    pub(crate) fn commit_clone(
        &self,
        record: &PersistedAgent,
        config: &crate::AgentConfig,
        source: Option<&str>,
        parent: AgentId,
        child: AgentId,
    ) -> Result<Option<ExecutionSnapshotMetadata>, ContextError> {
        let mut conn = self.locked_conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| failed(error.to_string()))?;
        let pending: bool = tx
            .query_row(
                "SELECT clone_pending FROM agents WHERE id = ?1 AND clone_parent_id = ?2",
                params![child.to_string(), parent.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| failed(error.to_string()))?;
        if !pending {
            return Err(failed("clone reservation is not pending"));
        }
        let context = serde_json::to_string(&AgentContext::default())
            .map_err(|error| failed(error.to_string()))?;
        tx.execute(
            "INSERT INTO contexts(agent_id,context_json,updated_at) VALUES (?1,?2,?3)",
            params![child.to_string(), context, Utc::now().to_rfc3339()],
        )
        .map_err(|error| failed(error.to_string()))?;
        let snapshot = source
            .map(|source| {
                self.fork_conversation_locked(&tx, parent, source, child, &format!("clone:{child}"))
            })
            .transpose()?;
        self.enforce_context_storage_locked(&tx, child, &record.tenant_id, 0, 0)?;
        let result = CloneResult {
            parent_id: parent,
            child_id: child,
            state: crate::AgentState::Running,
            snapshot: snapshot.clone(),
            inherited_handles: 0,
        };
        let sandbox = config
            .sandbox_config
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| failed(error.to_string()))?;
        tx.execute("UPDATE agents SET status = ?1,sandbox_config_json = ?2,clone_pending = 0,clone_result_json = ?3 WHERE id = ?4",
            params![serde_json::to_string(&crate::AgentState::Running).map_err(|error|failed(error.to_string()))?,sandbox,serde_json::to_string(&result).map_err(|error|failed(error.to_string()))?,child.to_string()]).map_err(|error|failed(error.to_string()))?;
        crate::cluster_agent_identity::commit_agent_creation_evidence(&tx, record)?;
        tx.commit().map_err(|error| failed(error.to_string()))?;
        Ok(snapshot)
    }

    pub(crate) fn completed_clone(
        &self,
        parent: AgentId,
        child: AgentId,
        request_digest: &str,
    ) -> Result<Option<CloneResult>, ContextError> {
        let conn = self.locked_conn();
        let existing: Option<StoredClone> = conn.query_row(
            "SELECT clone_parent_id,clone_request_digest,clone_pending,clone_result_json,status FROM agents WHERE id = ?1",
            [child.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))
        ).optional().map_err(|error|failed(error.to_string()))?;
        let Some((origin, digest, pending, result, status)) = existing else {
            return Ok(None);
        };
        if origin != Some(parent.to_string()) || digest.as_deref() != Some(request_digest) {
            return Err(failed(
                "clone child identity conflicts with another creation",
            ));
        }
        if pending {
            return Err(failed("clone child creation is still pending"));
        }
        let mut result: CloneResult = serde_json::from_str(
            result
                .as_deref()
                .ok_or_else(|| failed("clone result metadata is absent"))?,
        )
        .map_err(|error| failed(error.to_string()))?;
        result.state = serde_json::from_str(&status).map_err(|error| failed(error.to_string()))?;
        Ok(Some(result))
    }

    pub(crate) fn clone_security(
        &self,
        child: AgentId,
    ) -> Result<Option<CloneSecurity>, ContextError> {
        let value: Option<String> = self
            .locked_conn()
            .query_row(
                "SELECT clone_security_json FROM agents WHERE id = ?1",
                [child.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| failed(error.to_string()))?;
        value
            .map(|value| {
                serde_json::from_str::<CloneSecurity>(&value)
                    .map_err(|error| failed(error.to_string()))
            })
            .transpose()
    }

    pub(crate) fn reconcile_pending_clones(&self) -> Result<(), ContextError> {
        let ids = {
            let conn = self.locked_conn();
            let mut statement = conn
                .prepare("SELECT id FROM agents WHERE clone_pending = 1")
                .map_err(|error| failed(error.to_string()))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| failed(error.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| failed(error.to_string()))?
        };
        for id in ids {
            self.purge_agent_data(
                id.parse()
                    .map_err(|error: uuid::Error| failed(error.to_string()))?,
            )?;
        }
        Ok(())
    }
}
