//! Multi-step planning & execution.
//!
//! Agents create explicit plans before acting, execute steps sequentially,
//! and can revise plans when steps fail.

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::connector::{LlmSession, StandardMessage};
use crate::execution::AgentExecutor;
use crate::KernelError;

// ─── Data Model ──────────────────────────────────────────────────────────────

/// Status of a plan step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanStepStatus {
    Pending,
    Running,
    Done,
    Failed(String),
    Skipped,
    NeedsApproval,
}

/// A single step in an agent's plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub number: usize,
    pub description: String,
    pub status: PlanStepStatus,
    pub output: Option<String>,
    pub risk_level: RiskLevel,
}

/// Risk level determines whether approval is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// A complete execution plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub task: String,
    pub steps: Vec<PlanStep>,
    pub revision: usize,
    pub status: PlanStatus,
}

/// Overall plan status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanStatus {
    Planning,
    Executing,
    Completed,
    Failed,
    Revised,
}

/// Events emitted during plan execution.
#[derive(Debug, Clone)]
pub enum PlanEvent {
    PlanCreated(Plan),
    StepStarted {
        step: usize,
        description: String,
    },
    StepCompleted {
        step: usize,
        output: String,
    },
    StepFailed {
        step: usize,
        error: String,
    },
    PlanRevised {
        revision: usize,
        new_steps: Vec<PlanStep>,
    },
    ApprovalRequired {
        step: usize,
        description: String,
    },
    PlanCompleted {
        total_steps: usize,
    },
}

// ─── Plan Generator ──────────────────────────────────────────────────────────

const PLAN_SYSTEM_PROMPT: &str = r#"You are a planning agent. Given a task, create a numbered plan of concrete steps.

Rules:
- Each step must be a single, actionable action
- Steps should be ordered by dependency
- Mark steps that delete files or run destructive commands as [HIGH RISK]
- Keep plans concise (3-10 steps)
- Format: one step per line, numbered: "1. Do X\n2. Do Y"
- Do NOT include explanations, just the steps"#;

pub const MAX_PLAN_TASK_BYTES: usize = 8 * 1024;
pub const MAX_PLAN_RESPONSE_BYTES: usize = 32 * 1024;
pub const MAX_PLAN_STEPS: usize = 10;
pub const MAX_PLAN_STEP_BYTES: usize = 1_024;

pub fn validate_plan_task(task: &str) -> Result<(), KernelError> {
    if task.trim().is_empty() || task.len() > MAX_PLAN_TASK_BYTES || task.contains('\0') {
        return Err(KernelError::Policy("plan task must contain 1..=8192 UTF-8 bytes without NUL".into()));
    }
    Ok(())
}

/// Generate a plan from a task description using the LLM.
pub async fn generate_plan(session: &dyn LlmSession, task: &str) -> Result<Plan, KernelError> {
    generate_plan_with(task, |messages| async move {
        session.send(messages).await.map_err(KernelError::Connector)
    }).await
}

/// The production executor supplies its governed sender here. No tool
/// definitions are offered and generation never executes returned calls.
pub(crate) async fn generate_plan_with<F, Fut>(task: &str, send: F) -> Result<Plan, KernelError>
where
    F: FnOnce(Vec<StandardMessage>) -> Fut,
    Fut: std::future::Future<Output = Result<crate::connector::LlmResponse, KernelError>>,
{
    validate_plan_task(task)?;
    let messages = vec![
        StandardMessage::system(PLAN_SYSTEM_PROMPT),
        StandardMessage::user(format!("Create a plan for: {}", task)),
    ];

    let response = send(messages).await?;
    if !response.tool_calls.is_empty() || response.content.len() > MAX_PLAN_RESPONSE_BYTES {
        return Err(KernelError::Policy("plan response must be bounded text without executable tool calls".into()));
    }

    let steps = parse_plan_steps(&response.content);
    if steps.is_empty() || steps.len() > MAX_PLAN_STEPS || steps.iter().any(|step| step.description.len() > MAX_PLAN_STEP_BYTES || step.description.chars().any(char::is_control)) {
        return Err(KernelError::Policy("plan must have 1..=10 numbered steps of at most 1024 UTF-8 bytes each".into()));
    }

    Ok(Plan {
        task: task.to_string(),
        steps,
        revision: 0,
        status: PlanStatus::Planning,
    })
}

/// Parse numbered steps from LLM response.
pub fn parse_plan_steps(text: &str) -> Vec<PlanStep> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // Match "1. Do something" or "1) Do something"
            let number_end = trimmed.find(|c: char| !c.is_ascii_digit())?;
            if number_end == 0 { return None; }
            trimmed[..number_end].parse::<usize>().ok().filter(|number| *number > 0)?;
            let content = trimmed[number_end..].strip_prefix('.').or_else(|| trimmed[number_end..].strip_prefix(')'))?
                .trim().to_string();
            if content.is_empty() {
                return None;
            }
            Some(content)
        })
        .enumerate()
        .map(|(i, description)| {
            let risk_level = if description.contains("[HIGH RISK]")
                || description.to_lowercase().contains("delete")
                || description.to_lowercase().contains("remove")
            {
                RiskLevel::High
            } else if description.to_lowercase().contains("modify")
                || description.to_lowercase().contains("overwrite")
            {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            };
            PlanStep {
                number: i + 1,
                description: description.replace("[HIGH RISK]", "").trim().to_string(),
                status: PlanStepStatus::Pending,
                output: None,
                risk_level,
            }
        })
        .collect()
}

// ─── Plan Executor ───────────────────────────────────────────────────────────

/// Execute a plan step-by-step using an AgentExecutor.
pub struct PlanExecutor {
    plan: Plan,
    executor: AgentExecutor,
    event_tx: Option<mpsc::Sender<PlanEvent>>,
    require_approval_for_high_risk: bool,
    approval_rx: Option<mpsc::Receiver<bool>>,
}

impl PlanExecutor {
    pub fn new(plan: Plan, executor: AgentExecutor) -> Self {
        Self {
            plan,
            executor,
            event_tx: None,
            require_approval_for_high_risk: true,
            approval_rx: None,
        }
    }

    /// Set event channel for plan progress.
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<PlanEvent>) {
        self.event_tx = Some(tx);
    }

    /// Set approval channel (for high-risk steps).
    pub fn set_approval_channel(&mut self, rx: mpsc::Receiver<bool>) {
        self.approval_rx = Some(rx);
    }

    /// Disable approval requirement (for testing).
    pub fn disable_approval(&mut self) {
        self.require_approval_for_high_risk = false;
    }

    /// Get the current plan.
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    async fn emit(&self, event: PlanEvent) {
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(event).await;
        }
    }

    /// Execute the entire plan.
    pub async fn execute(&mut self) -> Result<Plan, KernelError> {
        self.plan.status = PlanStatus::Executing;
        self.emit(PlanEvent::PlanCreated(self.plan.clone())).await;

        let step_count = self.plan.steps.len();
        let mut i = 0;

        while i < self.plan.steps.len() {
            // Check if approval needed
            let risk = self.plan.steps[i].risk_level.clone();
            let desc = self.plan.steps[i].description.clone();
            let num = self.plan.steps[i].number;

            if self.require_approval_for_high_risk && risk == RiskLevel::High {
                self.plan.steps[i].status = PlanStepStatus::NeedsApproval;
                self.emit(PlanEvent::ApprovalRequired {
                    step: num,
                    description: desc.clone(),
                })
                .await;

                if let Some(ref mut rx) = self.approval_rx {
                    match rx.recv().await {
                        Some(true) => {}
                        _ => {
                            self.plan.steps[i].status = PlanStepStatus::Skipped;
                            i += 1;
                            continue;
                        }
                    }
                }
            }

            // Execute step
            self.plan.steps[i].status = PlanStepStatus::Running;
            self.emit(PlanEvent::StepStarted {
                step: num,
                description: desc.clone(),
            })
            .await;

            let prompt = format!(
                "Execute this step of the plan: {}\n\nContext: You are executing step {} of {} for the task: '{}'",
                desc, i + 1, step_count, self.plan.task
            );

            match self.executor.run(&prompt).await {
                Ok(output) => {
                    self.plan.steps[i].status = PlanStepStatus::Done;
                    self.plan.steps[i].output = Some(output.content.clone());
                    self.emit(PlanEvent::StepCompleted {
                        step: i + 1,
                        output: output.content.chars().take(200).collect(),
                    })
                    .await;
                }
                Err(e) => {
                    let error = e.to_string();
                    self.plan.steps[i].status = PlanStepStatus::Failed(error.clone());
                    self.emit(PlanEvent::StepFailed {
                        step: i + 1,
                        error: error.clone(),
                    })
                    .await;

                    // Try to revise the plan
                    if let Ok(revised) = self.revise_plan(i, &error).await {
                        self.plan.steps = revised;
                        self.plan.revision += 1;
                        self.plan.status = PlanStatus::Revised;
                        self.emit(PlanEvent::PlanRevised {
                            revision: self.plan.revision,
                            new_steps: self.plan.steps.clone(),
                        })
                        .await;
                        // Don't increment i — retry from current position with new step
                        continue;
                    } else {
                        self.plan.status = PlanStatus::Failed;
                        return Ok(self.plan.clone());
                    }
                }
            }
            i += 1;
        }

        self.plan.status = PlanStatus::Completed;
        self.emit(PlanEvent::PlanCompleted {
            total_steps: step_count,
        })
        .await;
        Ok(self.plan.clone())
    }

    /// Revise the plan after a step failure.
    async fn revise_plan(
        &mut self,
        failed_step: usize,
        error: &str,
    ) -> Result<Vec<PlanStep>, KernelError> {
        let completed: Vec<String> = self.plan.steps[..failed_step]
            .iter()
            .filter(|s| s.status == PlanStepStatus::Done)
            .map(|s| format!("✓ {}", s.description))
            .collect();

        let prompt = format!(
            "Step {} failed with error: {}\n\nCompleted steps:\n{}\n\nRevise the remaining plan to work around this failure. Give me new numbered steps starting from {}.",
            failed_step + 1, error, completed.join("\n"), failed_step + 1
        );

        let output = self.executor.run(&prompt).await?;
        let mut new_steps: Vec<PlanStep> = self.plan.steps[..failed_step].to_vec();
        let revised = parse_plan_steps(&output.content);
        for (j, mut step) in revised.into_iter().enumerate() {
            step.number = failed_step + j + 1;
            new_steps.push(step);
        }
        Ok(new_steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_numbered_steps() {
        let text = "1. Read the config file\n2. Modify the database URL\n3. Delete the old backup [HIGH RISK]\n4. Restart the service";
        let steps = parse_plan_steps(text);
        assert_eq!(steps.len(), 4);
        assert_eq!(steps[0].description, "Read the config file");
        assert_eq!(steps[0].risk_level, RiskLevel::Low);
        assert_eq!(steps[2].risk_level, RiskLevel::High);
        assert_eq!(steps[2].description, "Delete the old backup");
    }

    #[test]
    fn parse_with_parentheses() {
        let text = "1) First step\n2) Second step";
        let steps = parse_plan_steps(text);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].description, "First step");
    }

    #[tokio::test]
    async fn planning_rejects_overflow_empty_and_oversized_steps() {
        for text in [
            "not numbered".to_string(),
            (1..=MAX_PLAN_STEPS + 1).map(|number| format!("{number}. step\n")).collect(),
            format!("1. {}", "a".repeat(MAX_PLAN_STEP_BYTES + 1)),
            format!("1. {}", "a".repeat(MAX_PLAN_RESPONSE_BYTES + 1)),
        ] {
            let result = generate_plan_with("bounded task", |_| async {
                Ok(serde_json::from_value(serde_json::json!({
                    "content": text, "finish_reason":"stop", "tokens_used": 1, "tool_calls": []
                })).unwrap())
            }).await;
            assert!(result.is_err());
        }
        assert!(validate_plan_task("").is_err());
        assert!(validate_plan_task(&"x".repeat(MAX_PLAN_TASK_BYTES + 1)).is_err());
        assert_eq!(parse_plan_steps("10. Last step")[0].description, "Last step");
        assert!(parse_plan_steps("0. Invalid step").is_empty());
    }

    #[test]
    fn parse_ignores_non_numbered_lines() {
        let text = "Here's my plan:\n1. Do A\n2. Do B\nThat's it!";
        let steps = parse_plan_steps(text);
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn plan_initial_state() {
        let plan = Plan {
            task: "test".into(),
            steps: vec![PlanStep {
                number: 1,
                description: "step 1".into(),
                status: PlanStepStatus::Pending,
                output: None,
                risk_level: RiskLevel::Low,
            }],
            revision: 0,
            status: PlanStatus::Planning,
        };
        assert_eq!(plan.status, PlanStatus::Planning);
        assert_eq!(plan.steps[0].status, PlanStepStatus::Pending);
    }
}
