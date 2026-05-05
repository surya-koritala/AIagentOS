//! Agent Connector — manages LLM provider connections and sessions.
//!
//! Provides provider registration, session creation, failover, and
//! unavailability detection.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::{AgentId, ConnectorError, ProviderId};

/// Type of LLM provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderType {
    Cloud,
    Local,
}

/// Information about a registered provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub id: ProviderId,
    pub name: String,
    pub provider_type: ProviderType,
    pub available: bool,
}

/// A standard message format for LLM communication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandardMessage {
    pub role: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

impl StandardMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self { role: "user".into(), content: content.into(), tool_call_id: None, tool_calls: None }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self { role: "assistant".into(), content: content.into(), tool_call_id: None, tool_calls: None }
    }
    pub fn system(content: impl Into<String>) -> Self {
        Self { role: "system".into(), content: content.into(), tool_call_id: None, tool_calls: None }
    }
    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self { role: "tool".into(), content: content.into(), tool_call_id: Some(tool_call_id.into()), tool_calls: None }
    }
}

/// A tool call requested by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// A tool definition provided to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Response from an LLM provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub finish_reason: Option<String>,
    pub tokens_used: u32,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
}

/// An LLM session for an agent.
#[async_trait::async_trait]
pub trait LlmSession: Send + Sync {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError>;
    async fn send_with_tools(&self, messages: Vec<StandardMessage>, tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError>;
    fn provider_id(&self) -> &ProviderId;

    /// Send with streaming support. Default falls back to non-streaming.
    async fn send_streaming(&self, messages: Vec<StandardMessage>, tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, tools).await
    }
}

/// An LLM provider adapter.
#[async_trait::async_trait]
pub trait LlmProviderAdapter: Send + Sync {
    fn id(&self) -> &ProviderId;
    fn name(&self) -> &str;
    fn provider_type(&self) -> ProviderType;
    async fn is_available(&self) -> bool;
    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError>;
    /// Translate standard messages to provider format and back (for testing round-trip).
    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value;
    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage>;
}

/// The Agent Connector trait.
#[async_trait::async_trait]
pub trait AgentConnector: Send + Sync {
    fn register_provider(&self, adapter: Arc<dyn LlmProviderAdapter>) -> Result<(), ConnectorError>;
    async fn connect(&self, agent_id: AgentId, provider_id: &ProviderId) -> Result<Box<dyn LlmSession>, ConnectorError>;
    fn list_providers(&self) -> Vec<ProviderInfo>;
}

/// Concrete agent connector implementation.
pub struct AgentConnectorImpl {
    providers: DashMap<ProviderId, Arc<dyn LlmProviderAdapter>>,
    /// Optional backup provider for failover.
    backup_provider: DashMap<ProviderId, ProviderId>,
    /// Active sessions per agent.
    sessions: DashMap<AgentId, ProviderId>,
}

impl AgentConnectorImpl {
    pub fn new() -> Self {
        Self {
            providers: DashMap::new(),
            backup_provider: DashMap::new(),
            sessions: DashMap::new(),
        }
    }

    /// Set a backup provider for failover.
    pub fn set_backup(&self, primary: &ProviderId, backup: &ProviderId) {
        self.backup_provider.insert(primary.clone(), backup.clone());
    }
}

#[async_trait::async_trait]
impl AgentConnector for AgentConnectorImpl {
    fn register_provider(&self, adapter: Arc<dyn LlmProviderAdapter>) -> Result<(), ConnectorError> {
        let id = adapter.id().clone();
        self.providers.insert(id, adapter);
        Ok(())
    }

    async fn connect(&self, agent_id: AgentId, provider_id: &ProviderId) -> Result<Box<dyn LlmSession>, ConnectorError> {
        let provider = self.providers.get(provider_id)
            .ok_or_else(|| ConnectorError::ProviderUnavailable(provider_id.clone()))?;

        // Check availability
        if !provider.is_available().await {
            // Try failover
            if let Some(backup_id) = self.backup_provider.get(provider_id) {
                if let Some(backup) = self.providers.get(backup_id.value()) {
                    if backup.is_available().await {
                        let session = backup.create_session().await?;
                        self.sessions.insert(agent_id, backup_id.value().clone());
                        return Ok(session);
                    }
                }
            }
            return Err(ConnectorError::ProviderUnavailable(
                format!("{} is unavailable and no backup available", provider_id)
            ));
        }

        let session = provider.create_session().await?;
        self.sessions.insert(agent_id, provider_id.clone());
        Ok(session)
    }

    fn list_providers(&self) -> Vec<ProviderInfo> {
        self.providers.iter().map(|entry| {
            let adapter = entry.value();
            ProviderInfo {
                id: adapter.id().clone(),
                name: adapter.name().to_string(),
                provider_type: adapter.provider_type(),
                available: true, // Async check not possible in sync method
            }
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAdapter {
        id: ProviderId,
        available: bool,
    }

    struct MockSession { provider_id: ProviderId }

    #[async_trait::async_trait]
    impl LlmSession for MockSession {
        async fn send(&self, _messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
            Ok(LlmResponse { content: "response".into(), finish_reason: Some("stop".into()), tokens_used: 10, tool_calls: vec![] })
        }
        async fn send_with_tools(&self, messages: Vec<StandardMessage>, _tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
            self.send(messages).await
        }
        fn provider_id(&self) -> &ProviderId { &self.provider_id }
    }

    #[async_trait::async_trait]
    impl LlmProviderAdapter for MockAdapter {
        fn id(&self) -> &ProviderId { &self.id }
        fn name(&self) -> &str { "Mock" }
        fn provider_type(&self) -> ProviderType { ProviderType::Cloud }
        async fn is_available(&self) -> bool { self.available }
        async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
            Ok(Box::new(MockSession { provider_id: self.id.clone() }))
        }
        fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
            serde_json::json!({"role": msg.role, "content": msg.content})
        }
        fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
            Some(StandardMessage::user(value.get("content")?.as_str()?.to_string()))
        }
    }

    #[tokio::test]
    async fn register_and_connect() {
        let connector = AgentConnectorImpl::new();
        let adapter = Arc::new(MockAdapter { id: "openai".into(), available: true });
        connector.register_provider(adapter).unwrap();

        let agent_id = uuid::Uuid::new_v4();
        let session = connector.connect(agent_id, &"openai".into()).await.unwrap();
        let resp = session.send(vec![StandardMessage::user("hi")]).await.unwrap();
        assert_eq!(resp.content, "response");
    }

    #[tokio::test]
    async fn connect_unavailable_fails() {
        let connector = AgentConnectorImpl::new();
        let adapter = Arc::new(MockAdapter { id: "openai".into(), available: false });
        connector.register_provider(adapter).unwrap();

        let agent_id = uuid::Uuid::new_v4();
        let result = connector.connect(agent_id, &"openai".into()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn failover_to_backup() {
        let connector = AgentConnectorImpl::new();
        let primary = Arc::new(MockAdapter { id: "openai".into(), available: false });
        let backup = Arc::new(MockAdapter { id: "anthropic".into(), available: true });
        connector.register_provider(primary).unwrap();
        connector.register_provider(backup).unwrap();
        connector.set_backup(&"openai".into(), &"anthropic".into());

        let agent_id = uuid::Uuid::new_v4();
        let session = connector.connect(agent_id, &"openai".into()).await.unwrap();
        assert_eq!(session.provider_id(), "anthropic");
    }

    #[tokio::test]
    async fn list_providers_returns_registered() {
        let connector = AgentConnectorImpl::new();
        connector.register_provider(Arc::new(MockAdapter { id: "openai".into(), available: true })).unwrap();
        connector.register_provider(Arc::new(MockAdapter { id: "local".into(), available: true })).unwrap();
        let providers = connector.list_providers();
        assert_eq!(providers.len(), 2);
    }
}
