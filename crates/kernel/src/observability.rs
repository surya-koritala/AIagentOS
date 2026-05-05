//! Observability Engine — logging, metrics, reasoning chains, and plan deviation detection.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::AgentId;
use crate::scheduler::ResourceMetrics;

/// An action performed by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    pub id: uuid::Uuid,
    pub action_type: String,
    pub description: String,
    pub resources_accessed: Vec<String>,
    pub reasoning: Option<String>,
    pub plan_context: Option<PlanStep>,
    pub timestamp: DateTime<Utc>,
}

/// Aggregated metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metrics {
    pub tokens_consumed: u64,
    pub api_calls_made: u64,
    pub files_modified: Vec<String>,
    pub time_elapsed_ms: u64,
    pub resource_usage: ResourceMetrics,
}

/// A step in an agent's execution plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub step_number: u32,
    pub description: String,
    pub status: PlanStepStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanStepStatus {
    Pending,
    InProgress,
    Completed,
    Skipped,
}

/// A step in an agent's reasoning chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    pub thought: String,
    pub evidence: Option<String>,
    pub conclusion: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Filter for activity log queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilter {
    pub action_type: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
}

/// Scope for metrics queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricScope {
    Agent(AgentId),
    System,
}

/// The Observability Engine trait.
pub trait ObservabilityEngine: Send + Sync {
    fn log_action(&self, agent_id: AgentId, action: AgentAction);
    fn get_activity_log(&self, agent_id: AgentId, filter: Option<&LogFilter>) -> Vec<AgentAction>;
    fn get_reasoning_chain(&self, agent_id: AgentId, action_id: uuid::Uuid) -> Option<Vec<ReasoningStep>>;
    fn get_agent_plan(&self, agent_id: AgentId) -> Vec<PlanStep>;
    fn set_agent_plan(&self, agent_id: AgentId, plan: Vec<PlanStep>);
    fn get_metrics(&self, scope: MetricScope) -> Metrics;
    fn record_metrics(&self, agent_id: AgentId, tokens: u64, api_calls: u64);
    fn add_reasoning_step(&self, agent_id: AgentId, action_id: uuid::Uuid, step: ReasoningStep);
    fn on_deviation(&self, handler: Box<dyn Fn(AgentId, &AgentAction) + Send + Sync>);
}

/// Concrete observability engine implementation.
pub struct ObservabilityEngineImpl {
    /// Per-agent action logs.
    action_logs: DashMap<AgentId, Vec<AgentAction>>,
    /// Per-action reasoning chains.
    reasoning_chains: DashMap<(AgentId, uuid::Uuid), Vec<ReasoningStep>>,
    /// Per-agent plans.
    agent_plans: DashMap<AgentId, Vec<PlanStep>>,
    /// Per-agent metrics.
    agent_metrics: DashMap<AgentId, Metrics>,
    /// Deviation handlers.
    deviation_handlers: Mutex<Vec<Arc<dyn Fn(AgentId, &AgentAction) + Send + Sync>>>,
}

impl ObservabilityEngineImpl {
    pub fn new() -> Self {
        Self {
            action_logs: DashMap::new(),
            reasoning_chains: DashMap::new(),
            agent_plans: DashMap::new(),
            agent_metrics: DashMap::new(),
            deviation_handlers: Mutex::new(Vec::new()),
        }
    }

    fn check_deviation(&self, agent_id: AgentId, action: &AgentAction) {
        if let Some(plan) = self.agent_plans.get(&agent_id) {
            // Find the next pending/in-progress step
            let next_step = plan.iter().find(|s| s.status == PlanStepStatus::Pending || s.status == PlanStepStatus::InProgress);
            if let Some(step) = next_step {
                // Simple deviation check: if action description doesn't contain plan step keywords
                if !action.description.to_lowercase().contains(&step.description.to_lowercase())
                    && !step.description.to_lowercase().contains(&action.action_type.to_lowercase()) {
                    let handlers = self.deviation_handlers.lock().unwrap();
                    for handler in handlers.iter() {
                        handler(agent_id, action);
                    }
                }
            }
        }
    }
}

impl ObservabilityEngine for ObservabilityEngineImpl {
    fn log_action(&self, agent_id: AgentId, action: AgentAction) {
        self.check_deviation(agent_id, &action);
        self.action_logs.entry(agent_id).or_insert_with(Vec::new).push(action);
    }

    fn get_activity_log(&self, agent_id: AgentId, filter: Option<&LogFilter>) -> Vec<AgentAction> {
        let logs = self.action_logs.get(&agent_id).map(|l| l.clone()).unwrap_or_default();
        match filter {
            None => logs,
            Some(f) => {
                let mut filtered: Vec<_> = logs.into_iter().filter(|a| {
                    if let Some(ref at) = f.action_type {
                        if &a.action_type != at { return false; }
                    }
                    if let Some(from) = f.from {
                        if a.timestamp < from { return false; }
                    }
                    if let Some(to) = f.to {
                        if a.timestamp > to { return false; }
                    }
                    true
                }).collect();
                if let Some(limit) = f.limit {
                    filtered.truncate(limit);
                }
                filtered
            }
        }
    }

    fn get_reasoning_chain(&self, agent_id: AgentId, action_id: uuid::Uuid) -> Option<Vec<ReasoningStep>> {
        self.reasoning_chains.get(&(agent_id, action_id)).map(|r| r.clone())
    }

    fn get_agent_plan(&self, agent_id: AgentId) -> Vec<PlanStep> {
        self.agent_plans.get(&agent_id).map(|p| p.clone()).unwrap_or_default()
    }

    fn set_agent_plan(&self, agent_id: AgentId, plan: Vec<PlanStep>) {
        self.agent_plans.insert(agent_id, plan);
    }

    fn get_metrics(&self, scope: MetricScope) -> Metrics {
        match scope {
            MetricScope::Agent(id) => {
                self.agent_metrics.get(&id).map(|m| m.clone()).unwrap_or_default()
            }
            MetricScope::System => {
                let mut total = Metrics::default();
                for entry in self.agent_metrics.iter() {
                    total.tokens_consumed += entry.tokens_consumed;
                    total.api_calls_made += entry.api_calls_made;
                    total.time_elapsed_ms += entry.time_elapsed_ms;
                }
                total
            }
        }
    }

    fn record_metrics(&self, agent_id: AgentId, tokens: u64, api_calls: u64) {
        let mut metrics = self.agent_metrics.entry(agent_id).or_insert_with(Metrics::default);
        metrics.tokens_consumed += tokens;
        metrics.api_calls_made += api_calls;
    }

    fn add_reasoning_step(&self, agent_id: AgentId, action_id: uuid::Uuid, step: ReasoningStep) {
        self.reasoning_chains.entry((agent_id, action_id)).or_insert_with(Vec::new).push(step);
    }

    fn on_deviation(&self, handler: Box<dyn Fn(AgentId, &AgentAction) + Send + Sync>) {
        self.deviation_handlers.lock().unwrap().push(Arc::from(handler));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_and_retrieve_action() {
        let engine = ObservabilityEngineImpl::new();
        let id = uuid::Uuid::new_v4();
        let action = AgentAction {
            id: uuid::Uuid::new_v4(),
            action_type: "tool_call".into(),
            description: "Read file".into(),
            resources_accessed: vec!["filesystem".into()],
            reasoning: None,
            plan_context: None,
            timestamp: Utc::now(),
        };
        engine.log_action(id, action.clone());
        let log = engine.get_activity_log(id, None);
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action_type, "tool_call");
    }

    #[test]
    fn metrics_monotonically_increase() {
        let engine = ObservabilityEngineImpl::new();
        let id = uuid::Uuid::new_v4();
        engine.record_metrics(id, 100, 1);
        engine.record_metrics(id, 200, 2);
        let m = engine.get_metrics(MetricScope::Agent(id));
        assert_eq!(m.tokens_consumed, 300);
        assert_eq!(m.api_calls_made, 3);
    }

    #[test]
    fn reasoning_chain_storage() {
        let engine = ObservabilityEngineImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let action_id = uuid::Uuid::new_v4();
        engine.add_reasoning_step(agent_id, action_id, ReasoningStep {
            thought: "Need to read file".into(),
            evidence: Some("User asked for file contents".into()),
            conclusion: Some("Will use filesystem.read".into()),
            timestamp: Utc::now(),
        });
        let chain = engine.get_reasoning_chain(agent_id, action_id).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].thought, "Need to read file");
    }

    #[test]
    fn deviation_detection() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let engine = ObservabilityEngineImpl::new();
        let agent_id = uuid::Uuid::new_v4();

        // Set a plan
        engine.set_agent_plan(agent_id, vec![
            PlanStep { step_number: 1, description: "Read config file".into(), status: PlanStepStatus::Pending },
        ]);

        // Register deviation handler
        let deviated = Arc::new(AtomicBool::new(false));
        let deviated_clone = deviated.clone();
        engine.on_deviation(Box::new(move |_id, _action| {
            deviated_clone.store(true, Ordering::SeqCst);
        }));

        // Log an action that doesn't match the plan
        engine.log_action(agent_id, AgentAction {
            id: uuid::Uuid::new_v4(),
            action_type: "network_call".into(),
            description: "Send HTTP request to API".into(),
            resources_accessed: vec![],
            reasoning: None,
            plan_context: None,
            timestamp: Utc::now(),
        });

        assert!(deviated.load(Ordering::SeqCst));
    }
}
