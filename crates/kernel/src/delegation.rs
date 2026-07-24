//! Multi-agent delegation — agents can delegate tasks to other agents.

use crate::execution::AgentOutput;
use crate::{AgentConfig, AgentId, AgentKernelImpl, KernelError, Priority};

/// Maximum delegation depth to prevent infinite recursion.
const MAX_DELEGATION_DEPTH: usize = 3;

/// Delegate a task to a sub-agent and return its response.
pub async fn delegate_to_agent(
    kernel: &AgentKernelImpl,
    parent_agent_id: AgentId,
    agent_name: &str,
    task: &str,
    depth: usize,
) -> Result<AgentOutput, KernelError> {
    if depth >= MAX_DELEGATION_DEPTH {
        return Ok(AgentOutput {
            content: format!(
                "Delegation depth limit ({}) reached. Cannot delegate further.",
                MAX_DELEGATION_DEPTH
            ),
            tool_calls_made: 0,
            tokens_used: 0,
            provider_id: "none".into(),
            model_id: "none".into(),
            estimated_cost_usd: 0.0,
            usage: Default::default(),
        });
    }

    // Get parent's provider
    let provider = kernel
        .agent_manager
        .get_agent_provider(parent_agent_id)
        .unwrap_or_else(|| "azure-openai".to_string());

    // Create sub-agent
    let config = AgentConfig {
        name: format!("{}-delegate", agent_name),
        task: task.to_string(),
        llm_provider: provider,
        permission_profile: "standard".to_string(),
        priority: Priority::default(),
        sandbox_config: None,
    };

    let handle = kernel.create_agent_full(config).await?;

    // Delegates use the same coordinated cleanup path as every public
    // lifecycle entry surface, including when their turn fails.
    let output = kernel.send_message(handle.id, task).await;
    let cleanup = kernel.stop_agent(handle.id).await;
    match (output, cleanup) {
        (Ok(output), Ok(_)) => Ok(output),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(turn_error), Ok(_)) => Err(turn_error),
        (Err(turn_error), Err(_)) => {
            // A graceful cleanup fault is retryable. Make one forced attempt
            // before preserving the original turn error for the caller.
            let _ = kernel.kill_agent(handle.id).await;
            Err(turn_error)
        }
    }
}

/// Predefined specialist agent types.
pub enum Specialist {
    Researcher,
    Coder,
    Reviewer,
}

impl Specialist {
    pub fn system_prompt(&self) -> &'static str {
        match self {
            Self::Researcher => "You are a research specialist. Search the web, read documentation, and synthesize findings into clear summaries with citations.",
            Self::Coder => "You are a coding specialist. Write clean, tested, well-documented code. Always include error handling.",
            Self::Reviewer => "You are a code reviewer. Analyze code for bugs, security issues, performance problems, and style. Be specific and actionable.",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Researcher => "researcher",
            Self::Coder => "coder",
            Self::Reviewer => "reviewer",
        }
    }
}
