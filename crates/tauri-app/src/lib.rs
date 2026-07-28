//! Backend client for the AI Agent OS desktop application.
//!
//! The desktop UI is a client of the public syscall service. Even though the
//! packaged application hosts its kernel in the same process, it reaches that
//! kernel through an authenticated loopback server so lifecycle and tool calls
//! cannot bypass the canonical authorization path.

use std::sync::Arc;

use agent_sdk::{
    AgentEnforcementInfo, ConnectionProfile, KernelClient, MessageResult, OperatorSnapshot,
    SdkError,
};
use kernel::{syscall_server::SyscallServer, AgentKernelImpl};
use serde::Serialize;
use tokio::sync::Mutex;

#[cfg(feature = "desktop-shell")]
pub mod commands;
#[cfg(feature = "desktop-shell")]
pub mod credentials;

/// Serializable agent row consumed by the Svelte UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopAgent {
    pub id: String,
    pub name: String,
    pub state: String,
    pub priority: u8,
}

/// Non-secret global metrics shown by the desktop dashboard.
///
/// The capture timestamp and telemetry contract version make it explicit
/// which raw operator snapshot the values came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopMetricsView {
    pub captured_at: String,
    pub telemetry_contract_version: u32,
    pub tokens_consumed: u64,
    pub api_calls_made: u64,
    pub time_elapsed_ms: u64,
}

/// One atomic desktop refresh payload with explicit scope omissions and the
/// SDK reconnect generation that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopOperatorView {
    pub captured_at: String,
    pub agents: Vec<DesktopAgent>,
    pub metrics: Option<DesktopMetricsView>,
    pub warnings: Vec<String>,
    pub reconnect_generation: u64,
}

impl DesktopOperatorView {
    fn from_operator_snapshot(snapshot: OperatorSnapshot, reconnect_generation: u64) -> Self {
        let metrics = DesktopMetricsView::try_from_operator_snapshot(&snapshot).ok();
        let mut warnings = Vec::new();
        if metrics.is_none() {
            warnings.push(
                "Global metrics are unavailable for this caller scope; agent data is current."
                    .to_string(),
            );
        }
        Self {
            captured_at: snapshot.captured_at,
            agents: snapshot
                .agents
                .into_iter()
                .map(|agent| DesktopAgent {
                    id: agent.id,
                    name: agent.name,
                    state: agent.state,
                    priority: agent.priority,
                })
                .collect(),
            metrics,
            warnings,
            reconnect_generation,
        }
    }
}

impl DesktopMetricsView {
    pub fn try_from_operator_snapshot(snapshot: &OperatorSnapshot) -> Result<Self, &'static str> {
        let metrics = snapshot
            .system_metrics
            .as_ref()
            .ok_or("global metrics are unavailable for this caller scope")?;
        Ok(Self {
            captured_at: snapshot.captured_at.clone(),
            telemetry_contract_version: metrics.telemetry_contract_version,
            tokens_consumed: metrics.tokens_consumed,
            api_calls_made: metrics.api_calls_made,
            time_elapsed_ms: metrics.uptime_seconds.saturating_mul(1_000),
        })
    }
}

/// A serialized, single-connection desktop session.
///
/// Tauri commands may run concurrently, while one wire connection is ordered
/// request/reply. The mutex preserves that protocol invariant.
pub struct DesktopClient {
    inner: Mutex<KernelClient>,
}

impl DesktopClient {
    /// Connect to an existing syscall service and optionally authenticate.
    pub async fn connect(addr: &str, token: Option<&str>) -> Result<Self, SdkError> {
        Self::connect_profile(&ConnectionProfile::plaintext(addr), token).await
    }

    pub async fn connect_profile(
        profile: &ConnectionProfile,
        token: Option<&str>,
    ) -> Result<Self, SdkError> {
        let inner = profile.connect(token).await?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Expose an in-process kernel only through an authenticated ephemeral
    /// loopback service, then connect the desktop client to that service.
    pub async fn connect_embedded(kernel: Arc<AgentKernelImpl>) -> Result<Self, String> {
        let token = format!("desktop-{}", uuid::Uuid::new_v4());
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .map_err(|error| format!("failed to bind desktop kernel service: {error}"))?
            .with_auth_token(token.clone());
        let addr = server
            .local_addr()
            .map_err(|error| format!("failed to read desktop service address: {error}"))?;
        tokio::spawn(async move {
            if let Err(error) = server.serve().await {
                tracing::error!("desktop kernel service stopped: {error}");
            }
        });
        Self::connect(&addr.to_string(), Some(&token))
            .await
            .map_err(|error| format!("failed to connect desktop kernel client: {error}"))
    }

    pub async fn ping(&self) -> Result<(), SdkError> {
        self.inner.lock().await.ping().await
    }

    pub async fn authenticate(&self, token: impl Into<String>) -> Result<(), SdkError> {
        self.inner.lock().await.authenticate(token).await
    }

    pub async fn create_agent(
        &self,
        name: impl Into<String>,
        task: impl Into<String>,
        provider: Option<String>,
    ) -> Result<String, SdkError> {
        self.inner
            .lock()
            .await
            .create_agent(
                name,
                task,
                Some(provider.unwrap_or_else(|| "openai".to_string())),
                None,
                None,
            )
            .await
    }

    pub async fn send_message(
        &self,
        agent_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<MessageResult, SdkError> {
        self.inner
            .lock()
            .await
            .send_message(agent_id, message)
            .await
    }

    pub async fn pause_agent(&self, agent_id: impl Into<String>) -> Result<(), SdkError> {
        self.inner
            .lock()
            .await
            .pause_agent(agent_id)
            .await
            .map(|_| ())
    }

    pub async fn resume_agent(&self, agent_id: impl Into<String>) -> Result<(), SdkError> {
        self.inner
            .lock()
            .await
            .resume_agent(agent_id)
            .await
            .map(|_| ())
    }

    pub async fn stop_agent(&self, agent_id: impl Into<String>) -> Result<(), SdkError> {
        self.inner
            .lock()
            .await
            .stop_agent(agent_id)
            .await
            .map(|_| ())
    }

    pub async fn operator_snapshot(&self) -> Result<OperatorSnapshot, SdkError> {
        self.inner.lock().await.operator_snapshot().await
    }

    pub async fn operator_view(&self) -> Result<DesktopOperatorView, SdkError> {
        let mut client = self.inner.lock().await;
        let snapshot = client.operator_snapshot().await?;
        Ok(DesktopOperatorView::from_operator_snapshot(
            snapshot,
            client.reconnect_generation(),
        ))
    }

    pub async fn list_agents(&self) -> Result<Vec<DesktopAgent>, SdkError> {
        Ok(self
            .operator_snapshot()
            .await?
            .agents
            .into_iter()
            .map(|agent| DesktopAgent {
                id: agent.id,
                name: agent.name,
                state: agent.state,
                priority: agent.priority,
            })
            .collect())
    }

    pub async fn agent_info(
        &self,
        agent_id: impl Into<String>,
    ) -> Result<AgentEnforcementInfo, SdkError> {
        self.inner.lock().await.agent_info(agent_id).await
    }

    pub async fn call_tool(
        &self,
        agent_id: impl Into<String>,
        tool: impl Into<String>,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        self.inner
            .lock()
            .await
            .call_tool(agent_id, tool, args)
            .await
    }
}

/// State managed by Tauri for every backend command.
pub struct AppState {
    pub client: DesktopClient,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn embedded_desktop_reaches_the_kernel_only_through_its_wire_client() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
        let client = DesktopClient::connect_embedded(kernel)
            .await
            .expect("embedded desktop");

        client.ping().await.expect("authenticated ping");
        assert!(client.list_agents().await.expect("initial list").is_empty());
        let id = client
            .create_agent("desktop-test", "wire boundary", Some("stub".to_string()))
            .await
            .expect("create over wire");
        assert!(client
            .list_agents()
            .await
            .expect("updated list")
            .iter()
            .any(|agent| agent.id == id));
    }

    #[test]
    fn scoped_operator_view_is_partial_instead_of_inventing_global_zeroes() {
        let snapshot = OperatorSnapshot {
            captured_at: "2026-07-28T00:00:00Z".into(),
            consistency: "atomic".into(),
            scope: "tenant".into(),
            kernel_version: "test".into(),
            protocol_version: 2,
            agents: Vec::new(),
            total_visible_agents: 0,
            agents_truncated: false,
            providers: Vec::new(),
            packages: Vec::new(),
            scoped_gate_decisions: Default::default(),
            tunables: None,
            services: None,
            system_metrics: None,
            global_spend_usd: None,
        };

        let view = DesktopOperatorView::from_operator_snapshot(snapshot, 3);
        assert_eq!(view.reconnect_generation, 3);
        assert!(view.metrics.is_none());
        assert_eq!(view.warnings.len(), 1);
    }
}
