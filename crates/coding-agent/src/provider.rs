//! Proposal-only provider boundary: responses cannot become executable tools.

use crate::types::{Proposal, MAX_PROPOSAL_BYTES};
use async_trait::async_trait;
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, LlmUsage, ProviderCapabilities,
    ProviderType, StandardMessage, ToolDefinition,
};
use kernel::ConnectorError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct ProviderAudit {
    calls: AtomicU64,
}
impl ProviderAudit {
    pub fn api_calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

const BAD: &str =
    include_str!("../../../fixtures/coding-agent/utf8-budget/bad-character-budget.json");
const GOOD: &str =
    include_str!("../../../fixtures/coding-agent/utf8-budget/good-utf8-boundaries.json");

pub struct ProposalProvider {
    id: String,
    inner: Option<Arc<dyn LlmProviderAdapter>>,
    budget: Option<Arc<kernel::budget::BudgetEnforcer>>,
    audit: Arc<ProviderAudit>,
}
impl ProposalProvider {
    pub fn fixture() -> Self {
        Self {
            id: "coding".into(),
            inner: None,
            budget: None,
            audit: Arc::new(ProviderAudit::default()),
        }
    }
    pub fn real(
        adapter: Arc<dyn LlmProviderAdapter>,
        budget: Arc<kernel::budget::BudgetEnforcer>,
    ) -> Self {
        Self {
            id: "coding".into(),
            inner: Some(adapter),
            budget: Some(budget),
            audit: Arc::new(ProviderAudit::default()),
        }
    }
    pub fn with_audit(mut self, audit: Arc<ProviderAudit>) -> Self {
        self.audit = audit;
        self
    }
}
struct ProposalSession {
    id: String,
    inner: Option<Box<dyn LlmSession>>,
    budget: Option<Arc<kernel::budget::BudgetEnforcer>>,
    audit: Arc<ProviderAudit>,
}

#[async_trait]
impl LlmSession for ProposalSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_options(messages, &[], LlmRequestOptions::default())
            .await
    }
    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send(messages).await
    }
    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        let mut response = if let Some(inner) = &self.inner {
            let allowance = options.max_output_tokens.ok_or_else(|| {
                ConnectorError::ProtocolError(
                    "coding provider requires a bounded completion".into(),
                )
            })?;
            if let Some(budget) = &self.budget {
                // Charge admission conservatively using input bytes plus
                // envelope allowance, with no cached-input discount. The
                // retained report names these configured prices explicitly.
                let input_bound = messages
                    .iter()
                    .map(|message| message.content.len().saturating_add(1024))
                    .sum::<usize>() as f64;
                let prices = budget.token_pricing_for(&self.id, inner.model_id());
                let configured_bound = (input_bound * prices.input_usd_per_1k_tokens
                    + f64::from(allowance) * prices.output_usd_per_1k_tokens)
                    / 1000.0;
                if !configured_bound.is_finite() || configured_bound > budget.remaining() {
                    return Err(ConnectorError::ProtocolError(
                        "coding task budget exhausted before provider request".into(),
                    ));
                }
            }
            // The upstream receives no executable tool declarations. Reject
            // native calls as well as text-shim calls before executor parsing.
            self.audit.calls.fetch_add(1, Ordering::Relaxed);
            inner.send_with_options(messages, &[], options).await?
        } else {
            let last = messages
                .last()
                .map_or("", |message| message.content.as_str());
            let content = if last.contains("candidate=0") {
                BAD
            } else if last.contains("candidate=1") {
                GOOD
            } else {
                "{\"edits\":[]}"
            };
            let output = (content.len() / 4 + 1) as u32;
            if options
                .max_output_tokens
                .is_some_and(|limit| output > limit)
            {
                return Err(ConnectorError::ProtocolError(
                    "fixture completion allowance is too small".into(),
                ));
            }
            let input = (messages
                .iter()
                .map(|message| message.content.len())
                .sum::<usize>()
                / 4
                + 1) as u32;
            LlmResponse {
                provider_metadata: None,
                content: content.into(),
                finish_reason: Some("stop".into()),
                tokens_used: input + output,
                usage: LlmUsage::reported(input, output, 0),
                tool_calls: vec![],
            }
        };
        if response.content.len() > MAX_PROPOSAL_BYTES
            || !response.tool_calls.is_empty()
            || !kernel::function_calling::parse_tool_calls(&response.content).is_empty()
        {
            return Err(ConnectorError::ProtocolError(
                "coding provider attempted an executable or oversized response".into(),
            ));
        }
        let proposal = Proposal::parse(&response.content).map_err(|_| {
            ConnectorError::ProtocolError("coding provider returned an invalid proposal".into())
        })?;
        response.content = serde_json::to_string(&proposal)
            .map_err(|_| ConnectorError::ProtocolError("proposal encoding failed".into()))?;
        Ok(response)
    }
    fn provider_id(&self) -> &String {
        &self.id
    }
    fn model_id(&self) -> &str {
        self.inner
            .as_ref()
            .map_or("coding-fixture", |session| session.model_id())
    }
    fn enforces_max_output_tokens(&self) -> bool {
        self.inner
            .as_ref()
            .is_none_or(|session| session.enforces_max_output_tokens())
    }
}
#[async_trait]
impl LlmProviderAdapter for ProposalProvider {
    fn id(&self) -> &String {
        &self.id
    }
    fn name(&self) -> &str {
        "bounded coding proposal provider"
    }
    fn provider_type(&self) -> ProviderType {
        self.inner
            .as_ref()
            .map_or(ProviderType::Cloud, |adapter| adapter.provider_type())
    }
    async fn is_available(&self) -> bool {
        if let Some(adapter) = &self.inner {
            adapter.is_available().await
        } else {
            true
        }
    }
    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        let inner = if let Some(adapter) = &self.inner {
            Some(adapter.create_session().await?)
        } else {
            None
        };
        Ok(Box::new(ProposalSession {
            id: self.id.clone(),
            inner,
            budget: self.budget.clone(),
            audit: self.audit.clone(),
        }))
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            tool_calls: true,
            ..Default::default()
        }
    }
    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::to_value(message).expect("standard message encoding")
    }
    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        serde_json::from_value(value.clone()).ok()
    }
}
