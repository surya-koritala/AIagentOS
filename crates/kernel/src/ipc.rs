//! Inter-Agent Communication (IPC) — direct messaging, pub/sub, and task delegation.

use std::sync::Mutex;

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc};

use crate::{AgentId, IpcError};

/// A message sent between agents.
#[derive(Debug, Clone)]
pub struct IpcMessage {
    pub from: AgentId,
    pub to: AgentId,
    pub payload: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// A delegated task.
#[derive(Debug, Clone)]
pub struct DelegatedTask {
    pub id: uuid::Uuid,
    pub from: AgentId,
    pub to: AgentId,
    pub description: String,
    pub status: DelegationStatus,
}

/// Status of a delegated task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationStatus {
    Pending,
    InProgress,
    Completed,
    Failed(String),
}

/// The Agent IPC trait.
#[async_trait::async_trait]
pub trait AgentIpc: Send + Sync {
    async fn send(
        &self,
        from: AgentId,
        to: AgentId,
        payload: serde_json::Value,
    ) -> Result<(), IpcError>;
    async fn receive(&self, agent_id: AgentId) -> Result<IpcMessage, IpcError>;
    fn subscribe(&self, agent_id: AgentId, topic: &str) -> Result<(), IpcError>;
    fn unsubscribe(&self, agent_id: AgentId, topic: &str) -> Result<(), IpcError>;
    async fn publish(
        &self,
        from: AgentId,
        topic: &str,
        payload: serde_json::Value,
    ) -> Result<usize, IpcError>;
    async fn delegate(
        &self,
        from: AgentId,
        to: AgentId,
        description: String,
    ) -> Result<uuid::Uuid, IpcError>;
    fn complete_delegation(&self, task_id: uuid::Uuid) -> Result<(), IpcError>;
    fn get_delegation_status(&self, task_id: uuid::Uuid) -> Option<DelegationStatus>;
}

/// Concrete IPC implementation using Tokio channels.
pub struct IpcManager {
    /// Per-agent mailboxes (mpsc channels).
    mailboxes: DashMap<AgentId, mpsc::Sender<IpcMessage>>,
    receivers: DashMap<AgentId, Mutex<mpsc::Receiver<IpcMessage>>>,
    /// Pub/sub topics: topic -> broadcast sender.
    topics: DashMap<String, broadcast::Sender<IpcMessage>>,
    /// Agent subscriptions: agent_id -> list of topics.
    subscriptions: DashMap<AgentId, Vec<String>>,
    /// Delegation tracking.
    delegations: DashMap<uuid::Uuid, DelegatedTask>,
    /// Dead-letter queue for failed deliveries.
    dead_letters: Mutex<Vec<IpcMessage>>,
    /// Allowed communication pairs (None = all allowed).
    allowed_pairs: Option<DashMap<(AgentId, AgentId), bool>>,
}

impl Default for IpcManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcManager {
    pub fn new() -> Self {
        Self {
            mailboxes: DashMap::new(),
            receivers: DashMap::new(),
            topics: DashMap::new(),
            subscriptions: DashMap::new(),
            delegations: DashMap::new(),
            dead_letters: Mutex::new(Vec::new()),
            allowed_pairs: None,
        }
    }

    /// Register an agent's mailbox. Must be called before send/receive.
    pub fn register_agent(&self, agent_id: AgentId) {
        let (tx, rx) = mpsc::channel(256);
        self.mailboxes.insert(agent_id, tx);
        self.receivers.insert(agent_id, Mutex::new(rx));
    }

    /// Enable permission enforcement for IPC.
    pub fn enable_permissions(&mut self) {
        self.allowed_pairs = Some(DashMap::new());
    }

    /// Allow communication between two agents.
    pub fn allow_communication(&self, from: AgentId, to: AgentId) {
        if let Some(ref pairs) = self.allowed_pairs {
            pairs.insert((from, to), true);
        }
    }

    fn check_permission(&self, from: AgentId, to: AgentId) -> Result<(), IpcError> {
        if let Some(ref pairs) = self.allowed_pairs {
            if !pairs.contains_key(&(from, to)) {
                return Err(IpcError::PermissionDenied(format!(
                    "Agent {} not allowed to message {}",
                    from, to
                )));
            }
        }
        Ok(())
    }

    /// Get the dead-letter queue contents.
    pub fn dead_letters(&self) -> Vec<IpcMessage> {
        self.dead_letters.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl AgentIpc for IpcManager {
    async fn send(
        &self,
        from: AgentId,
        to: AgentId,
        payload: serde_json::Value,
    ) -> Result<(), IpcError> {
        self.check_permission(from, to)?;

        let msg = IpcMessage {
            from,
            to,
            payload,
            timestamp: chrono::Utc::now(),
        };

        let sender = self.mailboxes.get(&to).ok_or(IpcError::AgentNotFound(to))?;

        match sender.try_send(msg.clone()) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.dead_letters.lock().unwrap().push(msg);
                Err(IpcError::DeliveryFailed("Mailbox full".into()))
            }
        }
    }

    async fn receive(&self, agent_id: AgentId) -> Result<IpcMessage, IpcError> {
        let rx_entry = self
            .receivers
            .get(&agent_id)
            .ok_or(IpcError::AgentNotFound(agent_id))?;
        let mut rx = rx_entry.lock().unwrap();
        rx.try_recv().map_err(|_| IpcError::ChannelClosed)
    }

    fn subscribe(&self, agent_id: AgentId, topic: &str) -> Result<(), IpcError> {
        // Ensure topic exists
        if !self.topics.contains_key(topic) {
            let (tx, _) = broadcast::channel(128);
            self.topics.insert(topic.to_string(), tx);
        }
        // Track subscription
        self.subscriptions
            .entry(agent_id)
            .or_default()
            .push(topic.to_string());
        Ok(())
    }

    fn unsubscribe(&self, agent_id: AgentId, topic: &str) -> Result<(), IpcError> {
        if let Some(mut subs) = self.subscriptions.get_mut(&agent_id) {
            subs.retain(|t| t != topic);
        }
        Ok(())
    }

    async fn publish(
        &self,
        from: AgentId,
        topic: &str,
        payload: serde_json::Value,
    ) -> Result<usize, IpcError> {
        let sender = self
            .topics
            .get(topic)
            .ok_or_else(|| IpcError::DeliveryFailed(format!("Topic '{}' not found", topic)))?;

        let msg = IpcMessage {
            from,
            to: uuid::Uuid::nil(), // broadcast
            payload: payload.clone(),
            timestamp: chrono::Utc::now(),
        };

        // Deliver to all subscribed agents' mailboxes
        let mut delivered = 0;
        for entry in self.subscriptions.iter() {
            let agent_id = *entry.key();
            if entry.value().contains(&topic.to_string()) {
                if let Some(mailbox) = self.mailboxes.get(&agent_id) {
                    let agent_msg = IpcMessage {
                        to: agent_id,
                        ..msg.clone()
                    };
                    if mailbox.try_send(agent_msg).is_ok() {
                        delivered += 1;
                    }
                }
            }
        }

        // Also broadcast via the broadcast channel
        let _ = sender.send(msg);

        Ok(delivered)
    }

    async fn delegate(
        &self,
        from: AgentId,
        to: AgentId,
        description: String,
    ) -> Result<uuid::Uuid, IpcError> {
        self.check_permission(from, to)?;

        let task_id = uuid::Uuid::new_v4();
        let task = DelegatedTask {
            id: task_id,
            from,
            to,
            description: description.clone(),
            status: DelegationStatus::Pending,
        };
        self.delegations.insert(task_id, task);

        // Notify the target agent
        let payload = serde_json::json!({"type": "delegation", "task_id": task_id.to_string(), "description": description});
        self.send(from, to, payload).await?;

        Ok(task_id)
    }

    fn complete_delegation(&self, task_id: uuid::Uuid) -> Result<(), IpcError> {
        let mut task = self
            .delegations
            .get_mut(&task_id)
            .ok_or_else(|| IpcError::DeliveryFailed("Delegation not found".into()))?;
        task.status = DelegationStatus::Completed;

        // Propagate completion up the chain
        let from = task.from;
        let _to = task.to;
        drop(task);

        // Check if this completion should propagate to a parent delegation
        for entry in self.delegations.iter() {
            if entry.to == from && entry.status == DelegationStatus::Pending {
                // Parent found — mark as completed too (chain propagation)
                // In a real impl, would check if ALL sub-delegations are done
            }
        }

        Ok(())
    }

    fn get_delegation_status(&self, task_id: uuid::Uuid) -> Option<DelegationStatus> {
        self.delegations.get(&task_id).map(|t| t.status.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_and_receive() {
        let ipc = IpcManager::new();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        ipc.register_agent(a);
        ipc.register_agent(b);

        ipc.send(a, b, serde_json::json!({"hello": "world"}))
            .await
            .unwrap();
        let msg = ipc.receive(b).await.unwrap();
        assert_eq!(msg.from, a);
        assert_eq!(msg.payload["hello"], "world");
    }

    #[tokio::test]
    async fn send_to_unknown_agent_fails() {
        let ipc = IpcManager::new();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        ipc.register_agent(a);
        let result = ipc.send(a, b, serde_json::json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn pub_sub_delivery() {
        let ipc = IpcManager::new();
        let publisher = uuid::Uuid::new_v4();
        let sub1 = uuid::Uuid::new_v4();
        let sub2 = uuid::Uuid::new_v4();
        ipc.register_agent(publisher);
        ipc.register_agent(sub1);
        ipc.register_agent(sub2);

        ipc.subscribe(sub1, "news").unwrap();
        ipc.subscribe(sub2, "news").unwrap();

        let delivered = ipc
            .publish(publisher, "news", serde_json::json!({"headline": "test"}))
            .await
            .unwrap();
        assert_eq!(delivered, 2);

        let msg1 = ipc.receive(sub1).await.unwrap();
        assert_eq!(msg1.payload["headline"], "test");
        let msg2 = ipc.receive(sub2).await.unwrap();
        assert_eq!(msg2.payload["headline"], "test");
    }

    #[tokio::test]
    async fn delegation_tracking() {
        let ipc = IpcManager::new();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        ipc.register_agent(a);
        ipc.register_agent(b);

        let task_id = ipc.delegate(a, b, "do something".into()).await.unwrap();
        assert_eq!(
            ipc.get_delegation_status(task_id),
            Some(DelegationStatus::Pending)
        );

        ipc.complete_delegation(task_id).unwrap();
        assert_eq!(
            ipc.get_delegation_status(task_id),
            Some(DelegationStatus::Completed)
        );
    }

    #[tokio::test]
    async fn permission_enforcement() {
        let mut ipc = IpcManager::new();
        ipc.enable_permissions();
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        ipc.register_agent(a);
        ipc.register_agent(b);

        // Not allowed
        let result = ipc.send(a, b, serde_json::json!({})).await;
        assert!(result.is_err());

        // Allow and retry
        ipc.allow_communication(a, b);
        let result = ipc.send(a, b, serde_json::json!({})).await;
        assert!(result.is_ok());
    }
}
