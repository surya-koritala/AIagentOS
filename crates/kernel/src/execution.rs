//! Agent Execution Loop — the think→act→observe cycle.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::connector::{LlmSession, StandardMessage};
use crate::context::{ContextManager, Fact, FactCategory, SqliteContextManager};
use crate::resources::ResourceBroker;
use crate::tools::ToolRegistry;
use crate::{AgentId, KernelError};

/// Maximum tool call rounds before forcing termination.
const MAX_ITERATIONS: usize = 10;

/// Maximum LLM retry attempts on transient failures.
const LLM_RETRIES: usize = 3;

/// Events streamed during agent execution.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// A text token from the LLM.
    Token(String),
    /// A tool call is starting.
    ToolCallStarted { name: String, arguments: String },
    /// A tool call completed.
    ToolCallResult { name: String, result: String },
    /// Execution complete.
    Done(AgentOutput),
    /// Execution was cancelled.
    Cancelled { tool_calls_made: usize },
    /// Execution was paused at a safe boundary; the accumulated work is
    /// preserved in a checkpoint (see [`GenerationCheckpoint`]) rather than
    /// discarded. Distinct from `Cancelled`, which drops progress.
    Paused { tool_calls_made: usize },
    /// The active prompt was compacted without discarding history: omitted
    /// messages were written to the durable per-agent spill namespace.
    ContextPressure {
        active_tokens: u32,
        budget_tokens: u32,
        evicted_messages: usize,
        spill_key: String,
    },
    /// An error occurred.
    Error(String),
}

/// A checkpoint of an in-flight turn, captured when a running turn is paused at
/// a safe boundary (a "mid-generation context switch"). It carries everything a
/// fresh executor needs to continue the turn to completion.
///
/// # Pause granularity — honest about the approximation
///
/// A pause is taken at a *cooperative boundary*, not at an arbitrary point in
/// the model's decode:
///
/// - **Between tool iterations** — after the accumulated messages (assistant
///   turn + tool results) are appended, before the next LLM round. This is the
///   only boundary that is real for every backend.
/// - **Between streamed tokens** — for local/streaming backends that surface
///   per-token events, a pause here approaches *true* mid-decode switching:
///   tokens emitted so far are kept in `partial_content`.
///
/// For hosted request/response APIs there is **no token-level pause**: a single
/// `send` call is atomic from the kernel's point of view, so the finest real
/// boundary is the turn/iteration boundary. Resuming such a turn is a
/// *continuation* — the executor re-issues the request with the accumulated
/// context (the prior assistant turn + tool results already in `messages`). We
/// do not claim to interrupt a hosted decode in flight; `partial_content` for
/// those backends is only ever populated at a completed-message boundary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct GenerationCheckpoint {
    /// The agent this turn belongs to (kernel UUID).
    pub agent_id: AgentId,
    /// The conversation this turn belongs to, so a resuming executor can
    /// persist back to the same SQLite conversation.
    pub conversation_id: String,
    /// The original user message that started the turn.
    pub user_message: String,
    /// The full accumulated conversation at the pause boundary — system prompt,
    /// memories, the user message, and any assistant/tool turns completed so
    /// far. A fresh executor seeded with this can continue without replaying.
    pub messages: Vec<StandardMessage>,
    /// Any partial assistant text accumulated but not yet committed as a final
    /// message (only ever non-empty for streaming backends that pause
    /// mid-token; empty for hosted request/response APIs — see type docs).
    pub partial_content: String,
    /// Tool calls executed before the pause — carried so the resumed turn's
    /// final `AgentOutput.tool_calls_made` reflects the whole turn.
    pub tool_calls_made: usize,
    /// Tokens consumed before the pause — carried so the resumed turn's final
    /// `AgentOutput.tokens_used` reflects the whole turn.
    pub tokens_used: u32,
    /// Detailed request accounting accumulated before the pause.
    #[serde(default)]
    pub usage: UsageTelemetry,
}

/// The result of a pause-aware turn: either it ran to completion, or it stopped
/// at a safe boundary with a checkpoint to resume from.
#[derive(Debug, Clone)]
pub enum TurnResult {
    /// The turn finished; the output reflects the whole turn.
    Completed(AgentOutput),
    /// The turn was paused at a boundary; resume with
    /// [`AgentExecutor::resume`] to finish it.
    Paused(GenerationCheckpoint),
}

/// Output from the agent execution loop.
#[derive(Debug, Clone)]
pub struct AgentOutput {
    pub content: String,
    pub tool_calls_made: usize,
    pub tokens_used: u32,
    pub provider_id: String,
    pub model_id: String,
    pub estimated_cost_usd: f64,
    pub usage: UsageTelemetry,
}

/// Detailed per-turn provider accounting. `estimated_requests` is non-zero
/// when an adapter omitted usage and the executor used its documented
/// conservative prompt/output estimate.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct UsageTelemetry {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cached_tokens: u32,
    pub llm_requests: u32,
    pub retries: u32,
    pub provider_latency_ms: u64,
    pub provider_reported_requests: u32,
    pub estimated_requests: u32,
}

impl UsageTelemetry {
    fn record(&mut self, call: &ProviderCall) {
        self.input_tokens = self.input_tokens.saturating_add(call.usage.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(call.usage.output_tokens);
        self.cached_tokens = self.cached_tokens.saturating_add(call.usage.cached_tokens);
        self.llm_requests = self.llm_requests.saturating_add(call.attempts);
        self.retries = self.retries.saturating_add(call.retries);
        self.provider_latency_ms = self.provider_latency_ms.saturating_add(call.latency_ms);
        if call.usage.provider_reported {
            self.provider_reported_requests = self.provider_reported_requests.saturating_add(1);
        } else {
            self.estimated_requests = self.estimated_requests.saturating_add(1);
        }
    }
}

struct ProviderCall {
    response: crate::connector::LlmResponse,
    usage: crate::connector::LlmUsage,
    attempts: u32,
    retries: u32,
    latency_ms: u64,
}

/// The agent executor — drives the think→act→observe loop.
pub struct AgentExecutor {
    pub agent_id: AgentId,
    pub conversation_id: String,
    session: Box<dyn LlmSession>,
    resource_broker: Arc<dyn ResourceBroker>,
    tool_registry: Arc<ToolRegistry>,
    context_manager: Arc<SqliteContextManager>,
    rule_store: Option<Arc<crate::learning::RuleStore>>,
    /// The syscall gate every tool call is checked against. **Mandatory** — it is
    /// a required constructor argument, so an executor cannot exist in an
    /// ungoverned state. Running without enforcement requires an explicit
    /// [`crate::syscall_gate::SyscallGate::unconfined`] gate, never the absence
    /// of one.
    syscall_gate: Arc<crate::syscall_gate::SyscallGate>,
    budget_enforcer: Option<Arc<crate::budget::BudgetEnforcer>>,
    /// Optional per-request LLM-core scheduler installed by the kernel.
    llm_scheduler: Option<(Arc<crate::llm_sched::LlmScheduler>, u64, i8)>,
    /// Shared RPM/TPM/provider-concurrency limiter, acquired for each actual
    /// provider attempt rather than for the whole agent turn.
    rate_limiter: Option<Arc<crate::rate_limit::RateLimiter>>,
    /// Max active-context tokens; older non-system messages are paged out (via
    /// the context pager) when exceeded. 0 = disabled (no token bound).
    context_budget_tokens: u32,
    messages: Vec<StandardMessage>,
    cancel_token: CancellationToken,
    event_tx: Option<mpsc::Sender<StreamEvent>>,
    #[allow(dead_code)]
    system_prompt: String,
}

impl AgentExecutor {
    fn output(
        &self,
        content: String,
        tool_calls_made: usize,
        tokens_used: u32,
        usage: UsageTelemetry,
    ) -> AgentOutput {
        let provider_id = self.session.provider_id().clone();
        let estimated_cost_usd = self
            .budget_enforcer
            .as_ref()
            .map(|budget| budget.cost_of(&provider_id, tokens_used))
            .unwrap_or(0.0);
        AgentOutput {
            content,
            tool_calls_made,
            tokens_used,
            provider_id,
            model_id: self.session.model_id().to_string(),
            estimated_cost_usd,
            usage,
        }
    }

    pub fn new(
        agent_id: AgentId,
        session: Box<dyn LlmSession>,
        resource_broker: Arc<dyn ResourceBroker>,
        tool_registry: Arc<ToolRegistry>,
        context_manager: Arc<SqliteContextManager>,
        syscall_gate: Arc<crate::syscall_gate::SyscallGate>,
        system_prompt: String,
    ) -> Self {
        Self {
            agent_id,
            conversation_id: uuid::Uuid::new_v4().to_string(),
            session,
            resource_broker,
            tool_registry,
            context_manager,
            rule_store: None,
            syscall_gate,
            budget_enforcer: None,
            llm_scheduler: None,
            rate_limiter: None,
            context_budget_tokens: 0,
            messages: vec![StandardMessage::system(&system_prompt)],
            cancel_token: CancellationToken::new(),
            event_tx: None,
            system_prompt,
        }
    }

    /// Test-only constructor that wires an explicitly *unconfined* gate, for
    /// unit tests that exercise the think→act loop without OS enforcement. It is
    /// `#[cfg(test)]` so it can never be reached from production code: the only
    /// way to build an ungoverned executor is to ask for one by name, in a test.
    #[cfg(test)]
    pub fn new_unconfined(
        agent_id: AgentId,
        session: Box<dyn LlmSession>,
        resource_broker: Arc<dyn ResourceBroker>,
        tool_registry: Arc<ToolRegistry>,
        context_manager: Arc<SqliteContextManager>,
        system_prompt: String,
    ) -> Self {
        // Tool-call concurrency accounting still needs an agent→cgroup record,
        // even though the explicit unconfined gate bypasses authorization.
        // Register the test agent in the unlimited root cgroup so the bypass is
        // confined to policy checks rather than accidentally disabling resource
        // lifecycle accounting as well.
        let gate = Arc::new(crate::syscall_gate::SyscallGate::unconfined());
        gate.register_agent(agent_id, crate::CapabilitySet::all(), None);
        Self::new(
            agent_id,
            session,
            resource_broker,
            tool_registry,
            context_manager,
            gate,
            system_prompt,
        )
    }

    /// Install a budget enforcer. Once set, the loop refuses to make a further
    /// LLM call once the cumulative USD ceiling is reached, and prices each
    /// response against the agent's provider. Without one, no cost is tracked.
    pub fn set_budget_enforcer(&mut self, enforcer: Arc<crate::budget::BudgetEnforcer>) {
        self.budget_enforcer = Some(enforcer);
    }

    /// Install per-provider-request LLM scheduling metadata. A permit is held
    /// only while `send_streaming` is in flight, not during tool execution or
    /// retry backoff.
    pub fn set_llm_scheduler(
        &mut self,
        scheduler: Arc<crate::llm_sched::LlmScheduler>,
        pid: u64,
        nice: i8,
    ) {
        self.llm_scheduler = Some((scheduler, pid, nice));
    }

    pub fn set_rate_limiter(&mut self, limiter: Arc<crate::rate_limit::RateLimiter>) {
        self.rate_limiter = Some(limiter);
    }

    /// Set the active-context token budget. When > 0, the loop pages out the
    /// oldest non-system messages before each LLM call so the working set stays
    /// within the budget (the context-paging / virtual-memory analogue). 0
    /// disables it (unbounded — prior behavior).
    pub fn set_context_budget(&mut self, max_tokens: u32) {
        self.context_budget_tokens = max_tokens;
    }

    fn estimate_prompt_tokens(&self, messages: &[StandardMessage]) -> u32 {
        self.session
            .estimate_prompt_tokens(messages)
            .unwrap_or_else(|| {
                // Conservative fallback: UTF-8 bytes / 3 plus per-message framing.
                // This intentionally overestimates typical English relative to the
                // old chars/4 heuristic and is deterministic across platforms.
                messages.iter().fold(0u32, |total, message| {
                    total.saturating_add(
                        (message.content.len() as u32)
                            .saturating_add(2)
                            .saturating_div(3)
                            .saturating_add(4),
                    )
                })
            })
    }

    /// Bound the active prompt without silently discarding state. The root
    /// system instruction and latest tool-call state are pinned. Evicted
    /// messages are serialized into the durable agent KV store and replaced by
    /// a compact reference that can be paged in with `StorageGet`.
    async fn compact_to_token_budget(&mut self) -> Result<(), KernelError> {
        let budget = self.context_budget_tokens;
        if budget == 0 || self.messages.len() <= 1 {
            return Ok(());
        }
        let original_tokens = self.estimate_prompt_tokens(&self.messages);
        if original_tokens <= budget {
            return Ok(());
        }

        let latest_tool_state = self
            .messages
            .iter()
            .rposition(|message| message.tool_calls.is_some());
        let pinned: Vec<bool> = (0..self.messages.len())
            .map(|index| index == 0 || latest_tool_state.is_some_and(|start| index >= start))
            .collect();
        let pinned_messages: Vec<_> = self
            .messages
            .iter()
            .zip(&pinned)
            .filter(|(_, pinned)| **pinned)
            .map(|(message, _)| message.clone())
            .collect();
        let pinned_tokens = self.estimate_prompt_tokens(&pinned_messages);
        if pinned_tokens > budget {
            let message = format!(
                "context pressure: pinned system/tool state requires {pinned_tokens} tokens but the active budget is {budget}; increase max_context_tokens or shorten required state"
            );
            let _ = self.context_manager.record_context_pressure(
                self.agent_id,
                original_tokens,
                budget,
                0,
                Some(&message),
            );
            return Err(KernelError::Policy(message));
        }

        // Reserve room for a compact durable-spill reference, then keep the
        // newest non-pinned messages that fit.
        let reference_reserve = 36u32.min(budget.saturating_sub(pinned_tokens));
        let mut remaining = budget
            .saturating_sub(pinned_tokens)
            .saturating_sub(reference_reserve);
        let mut keep = pinned.clone();
        for index in (0..self.messages.len()).rev() {
            if keep[index] {
                continue;
            }
            let tokens = self.estimate_prompt_tokens(std::slice::from_ref(&self.messages[index]));
            if tokens <= remaining {
                keep[index] = true;
                remaining -= tokens;
            }
        }
        if keep.iter().all(|keep| *keep) {
            let message =
                "context pressure: active prompt exceeds its budget but no state is safely evictable"
                    .to_string();
            let _ = self.context_manager.record_context_pressure(
                self.agent_id,
                original_tokens,
                budget,
                0,
                Some(&message),
            );
            return Err(KernelError::Policy(message));
        }

        let key = format!(
            "context_spill:{}:{}",
            self.conversation_id,
            uuid::Uuid::new_v4()
        );

        // The compact reference itself has a variable size (conversation IDs,
        // hashes and message counts all contribute). Recompute it while
        // evicting the oldest safe message until the *actual* active prompt
        // fits. Nothing is persisted or mutated until a fitting representation
        // has been found, so a failed compaction cannot leave orphan spills.
        loop {
            let evicted: Vec<_> = self
                .messages
                .iter()
                .zip(&keep)
                .filter(|(_, keep)| !**keep)
                .map(|(message, _)| message.clone())
                .collect();
            let spill_json = match serde_json::to_string(&evicted) {
                Ok(encoded) => encoded,
                Err(error) => {
                    let message = format!("context spill encoding failed: {error}");
                    let _ = self.context_manager.record_context_pressure(
                        self.agent_id,
                        original_tokens,
                        budget,
                        0,
                        Some(&message),
                    );
                    return Err(KernelError::Policy(message));
                }
            };
            let digest = ring::digest::digest(&ring::digest::SHA256, spill_json.as_bytes());
            let digest = digest
                .as_ref()
                .iter()
                .take(8)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let roles = evicted
                .iter()
                .map(|message| message.role.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(",");
            let mut reference = StandardMessage::system(format!(
                "[Durable context spill: key={key}; sha256-prefix={digest}; messages={}; roles={roles}. Page in with StorageGet before relying on omitted detail.]",
                evicted.len()
            ));
            if self.estimate_prompt_tokens(std::slice::from_ref(&reference)) > reference_reserve {
                reference = StandardMessage::system(format!(
                    "[Context spill: key={key}; sha256-prefix={digest}; n={}]",
                    evicted.len()
                ));
            }

            let mut compacted = Vec::with_capacity(keep.iter().filter(|keep| **keep).count() + 1);
            for (index, message) in self.messages.iter().enumerate() {
                if index == 1 {
                    compacted.push(reference.clone());
                }
                if keep[index] {
                    compacted.push(message.clone());
                }
            }
            let active_tokens = self.estimate_prompt_tokens(&compacted);
            if active_tokens <= budget {
                if let Err(error) = self
                    .context_manager
                    .kv_put(self.agent_id, &key, &spill_json)
                {
                    let message = format!("context spill persistence failed: {error}");
                    let _ = self.context_manager.record_context_pressure(
                        self.agent_id,
                        original_tokens,
                        budget,
                        0,
                        Some(&message),
                    );
                    return Err(KernelError::Context(error));
                }
                let _ = self.context_manager.record_context_pressure(
                    self.agent_id,
                    active_tokens,
                    budget,
                    evicted.len(),
                    None,
                );
                self.messages = compacted;
                self.emit(StreamEvent::ContextPressure {
                    active_tokens,
                    budget_tokens: budget,
                    evicted_messages: evicted.len(),
                    spill_key: key,
                })
                .await;
                return Ok(());
            }

            if let Some(index) = (0..keep.len()).find(|index| keep[*index] && !pinned[*index]) {
                keep[index] = false;
                continue;
            }
            let message = format!(
                "context pressure: durable reference plus pinned state requires {active_tokens} tokens but budget is {budget}"
            );
            let _ = self.context_manager.record_context_pressure(
                self.agent_id,
                original_tokens,
                budget,
                0,
                Some(&message),
            );
            return Err(KernelError::Policy(message));
        }
    }

    /// Resume from a saved conversation.
    pub fn with_conversation(mut self, conversation_id: &str) -> Self {
        self.conversation_id = conversation_id.to_string();
        if let Ok(messages) = self.context_manager.load_conversation(conversation_id) {
            self.messages = messages;
        }
        self
    }

    /// Set an event channel for streaming events to the caller.
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<StreamEvent>) {
        self.event_tx = Some(tx);
    }

    /// Set a rule store for learning from corrections.
    pub fn set_rule_store(&mut self, store: Arc<crate::learning::RuleStore>) {
        self.rule_store = Some(store);
    }

    /// Get a cancellation token for this executor.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    pub fn provider_id(&self) -> &str {
        self.session.provider_id()
    }

    pub fn model_id(&self) -> &str {
        self.session.model_id()
    }

    /// Cancel the running execution.
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Install a fresh token before a new turn after an earlier pause/cancel.
    pub fn renew_cancel_token(&mut self) -> CancellationToken {
        self.cancel_token = CancellationToken::new();
        self.cancel_token.clone()
    }

    async fn emit(&self, event: StreamEvent) {
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(event).await;
        }
    }

    /// Run the execution loop for a user message.
    ///
    /// This is the original, pause-unaware entry point and its behavior is
    /// unchanged: if the `cancel_token` fires at a boundary it returns a
    /// `"Cancelled."` output and discards in-flight progress. It delegates to
    /// the pause-aware [`AgentExecutor::run_resumable`]; a `Paused` outcome
    /// (which `run` itself can only reach via cancellation) is collapsed back
    /// into the legacy cancelled output so existing callers see no change.
    pub async fn run(&mut self, user_message: &str) -> Result<AgentOutput, KernelError> {
        match self.run_resumable(user_message).await? {
            TurnResult::Completed(output) => Ok(output),
            TurnResult::Paused(checkpoint) => {
                // Preserve `run`'s historical contract: a cancellation surfaces
                // as a "Cancelled." output. The accumulated work still lives in
                // the checkpoint for callers that use `run_resumable` directly.
                self.emit(StreamEvent::Cancelled {
                    tool_calls_made: checkpoint.tool_calls_made,
                })
                .await;
                Ok(self.output(
                    "Cancelled.".into(),
                    checkpoint.tool_calls_made,
                    checkpoint.tokens_used,
                    checkpoint.usage,
                ))
            }
        }
    }

    /// Prepare a fresh turn: inject memories + correction rules, append the user
    /// message, and auto-summarize if over the overflow threshold. Shared by
    /// `run`/`run_resumable`; not called on the resume path (the checkpoint
    /// already carries the prepared `messages`).
    async fn prepare_turn(&mut self, user_message: &str) {
        // Query long-term memory for relevant facts
        if let Ok(facts) = self
            .context_manager
            .query_memory(self.agent_id, user_message)
            .await
        {
            if !facts.is_empty() {
                let memory_text = facts
                    .iter()
                    .map(|f| f.content.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                self.messages.push(StandardMessage::system(format!(
                    "Relevant memories:\n{}",
                    memory_text
                )));
            }
        }

        // Inject applicable correction rules
        if let Some(ref store) = self.rule_store {
            if let Some(rules_prompt) = store.rules_as_prompt(user_message) {
                self.messages.push(StandardMessage::system(rules_prompt));
            }
        }

        self.messages.push(StandardMessage::user(user_message));

        // Message-count-only auto-summarization used to replace old content
        // with a count placeholder, silently losing semantics. Pressure is now
        // handled in `compact_to_token_budget`: full evicted messages are durably
        // spilled and a retrievable reference remains in the active prompt.
    }

    /// Pause-aware run of a turn for `user_message`.
    ///
    /// Behaves exactly like [`AgentExecutor::run`] (think→act→observe to
    /// completion) but, instead of discarding progress when the `cancel_token`
    /// fires at a safe boundary, it stops at the boundary and returns
    /// `TurnResult::Paused(checkpoint)` capturing the accumulated messages,
    /// tool-call count, and token count. Resume later with
    /// [`AgentExecutor::resume`] — even into a *different* executor instance.
    ///
    /// The pause is cooperative and taken at the same boundaries the legacy
    /// cancel path checked: at the top of each iteration (between LLM rounds)
    /// and before each tool execution (between tool iterations). See
    /// [`GenerationCheckpoint`] for the honest note on token-level vs
    /// turn-boundary granularity across local and hosted backends.
    pub async fn run_resumable(&mut self, user_message: &str) -> Result<TurnResult, KernelError> {
        self.prepare_turn(user_message).await;
        self.drive_loop(user_message.to_string(), 0, 0, UsageTelemetry::default())
            .await
    }

    /// Resume a turn from a checkpoint and drive it to completion (it can itself
    /// be paused again). The executor's `messages`/`conversation_id` are seeded
    /// from the checkpoint, so the final `AgentOutput` reflects the whole turn —
    /// both the pre-pause and post-pause work (tool calls and tokens are carried
    /// forward). The prologue (memory/rules/user-message/summarize) is *not*
    /// re-run: the checkpoint already encodes that state.
    ///
    /// This may be called on a fresh executor backed by a new session — the
    /// continuation re-issues against the accumulated context, which is exactly
    /// the turn-boundary continuation semantics for hosted APIs described on
    /// [`GenerationCheckpoint`].
    pub async fn resume(
        &mut self,
        checkpoint: GenerationCheckpoint,
    ) -> Result<TurnResult, KernelError> {
        self.conversation_id = checkpoint.conversation_id;
        self.messages = checkpoint.messages;
        // If a streaming backend paused mid-token, the partial assistant text is
        // re-seeded as context so the continuation can build on it. Hosted APIs
        // never populate this (see GenerationCheckpoint docs), so this is a
        // no-op for them.
        if !checkpoint.partial_content.is_empty() {
            self.messages
                .push(StandardMessage::assistant(&checkpoint.partial_content));
        }
        self.drive_loop(
            checkpoint.user_message,
            checkpoint.tool_calls_made,
            checkpoint.tokens_used,
            checkpoint.usage,
        )
        .await
    }

    /// The core think→act→observe loop, shared by the fresh and resume paths.
    ///
    /// `tool_calls_made` / `total_tokens` are seeded (0 for a fresh turn, or the
    /// carried-forward counts for a resume) so a completed `AgentOutput` always
    /// reflects the entire turn. A cancellation at a boundary returns
    /// `TurnResult::Paused(checkpoint)` with the accumulated state preserved.
    async fn drive_loop(
        &mut self,
        user_message: String,
        seed_tool_calls: usize,
        seed_tokens: u32,
        mut usage: UsageTelemetry,
    ) -> Result<TurnResult, KernelError> {
        let tools = self.tool_registry.definitions();
        let mut total_tokens: u32 = seed_tokens;
        let mut tool_calls_made: usize = seed_tool_calls;

        // A pause can land after an assistant response declared several tool
        // calls but before all of them ran. Completed results are already in
        // `messages`; execute only the missing ids before asking the model
        // again. This is exactly-once within a persisted checkpoint. A process
        // crash inside an external side effect is necessarily at-least-once
        // unless that tool implements its own idempotency key.
        for tool_call in self.pending_tool_calls() {
            if self.cancel_token.is_cancelled() {
                return Ok(TurnResult::Paused(
                    self.checkpoint(
                        &user_message,
                        tool_calls_made,
                        total_tokens,
                        usage,
                        String::new(),
                    )
                    .await,
                ));
            }
            tool_calls_made += 1;
            self.emit(StreamEvent::ToolCallStarted {
                name: tool_call.name.clone(),
                arguments: tool_call.arguments.to_string(),
            })
            .await;
            let result = self.execute_tool(&tool_call).await;
            self.emit(StreamEvent::ToolCallResult {
                name: tool_call.name.clone(),
                result: result.chars().take(200).collect(),
            })
            .await;
            self.messages
                .push(StandardMessage::tool_result(&tool_call.id, &result));
        }

        for _ in 0..MAX_ITERATIONS {
            // Pause boundary: between LLM rounds. Capture a checkpoint of the
            // work so far instead of discarding it.
            if self.cancel_token.is_cancelled() {
                return Ok(TurnResult::Paused(
                    self.checkpoint(
                        &user_message,
                        tool_calls_made,
                        total_tokens,
                        usage,
                        String::new(),
                    )
                    .await,
                ));
            }

            // Page out old context to keep the active window within the token
            // budget before each LLM call (no-op when the budget is 0).
            self.compact_to_token_budget().await?;

            // Atomically check configured cumulative USD ceilings and hold each
            // relevant scope through provider accounting. This prevents two
            // concurrent agents/tenants from both passing the same remaining
            // budget check.
            let budget_call = if let Some(ref budget) = self.budget_enforcer {
                match budget.begin_call(self.agent_id).await {
                    Ok(guard) => Some(guard),
                    Err(exceeded) => {
                        let output = self.output(
                            format!("Stopped before LLM call: {}.", exceeded.message()),
                            tool_calls_made,
                            total_tokens,
                            usage,
                        );
                        self.emit(StreamEvent::Done(output.clone())).await;
                        self.save_conversation();
                        return Ok(TurnResult::Completed(output));
                    }
                }
            } else {
                None
            };

            // Think: send to LLM with retry
            let call = match self.send_with_retry(&tools).await {
                Ok(call) => call,
                Err(_error) if self.cancel_token.is_cancelled() => {
                    drop(budget_call);
                    return Ok(TurnResult::Paused(
                        self.checkpoint(
                            &user_message,
                            tool_calls_made,
                            total_tokens,
                            usage,
                            String::new(),
                        )
                        .await,
                    ));
                }
                Err(error) => return Err(error),
            };
            usage.record(&call);
            let call_tokens = call.usage.total();
            let response = call.response;
            total_tokens = total_tokens.saturating_add(call_tokens);

            // Price this response against the agent's provider and accrue spend.
            if let Some(ref budget) = self.budget_enforcer {
                budget.record(self.agent_id, self.session.provider_id(), call_tokens);
            }
            drop(budget_call);

            // Function-calling shim: models without native structured
            // tool-calling return their tool requests as plaintext. Only when
            // the response carries no native tool_calls do we scan the content
            // for shim-encoded call(s) and recover them — the native FC path is
            // untouched (this fallback only runs when it would otherwise end).
            let mut tool_calls = response.tool_calls.clone();
            if tool_calls.is_empty() {
                tool_calls = crate::function_calling::parse_tool_calls(&response.content);
            }

            // If no tool calls (native or shim-recovered), we're done — return content
            if tool_calls.is_empty() {
                self.messages
                    .push(StandardMessage::assistant(&response.content));

                // Store as fact if response is substantial (>100 chars)
                if response.content.len() > 100 {
                    let fact = Fact {
                        id: uuid::Uuid::new_v4(),
                        content: response.content.clone(),
                        category: FactCategory::Fact,
                        created_at: chrono::Utc::now(),
                        last_accessed_at: chrono::Utc::now(),
                        embedding: None,
                    };
                    let _ = self.context_manager.store_fact(self.agent_id, fact).await;
                }

                let output = self.output(response.content, tool_calls_made, total_tokens, usage);
                self.emit(StreamEvent::Done(output.clone())).await;
                self.save_conversation();
                return Ok(TurnResult::Completed(output));
            }

            // Act: execute tool calls (native, or shim-recovered from plaintext).
            // For shim-recovered calls the model's prose is preserved as the
            // assistant content; the structured calls are attached so the tool
            // results that follow are correctly paired with this turn.
            let mut assistant_msg = StandardMessage::assistant(&response.content);
            assistant_msg.tool_calls = Some(tool_calls.clone());
            self.messages.push(assistant_msg);

            for tool_call in &tool_calls {
                // Pause boundary: between tool iterations. The assistant turn is
                // already committed to `messages`; the as-yet-unexecuted call is
                // re-issued on resume (its result simply isn't in `messages`
                // yet), so no progress is lost.
                if self.cancel_token.is_cancelled() {
                    return Ok(TurnResult::Paused(
                        self.checkpoint(
                            &user_message,
                            tool_calls_made,
                            total_tokens,
                            usage,
                            String::new(),
                        )
                        .await,
                    ));
                }
                tool_calls_made += 1;
                self.emit(StreamEvent::ToolCallStarted {
                    name: tool_call.name.clone(),
                    arguments: tool_call.arguments.to_string(),
                })
                .await;
                let result = self.execute_tool(tool_call).await;
                self.emit(StreamEvent::ToolCallResult {
                    name: tool_call.name.clone(),
                    result: result.chars().take(200).collect(),
                })
                .await;
                self.messages
                    .push(StandardMessage::tool_result(&tool_call.id, &result));
            }
        }

        // Max iterations reached
        Ok(TurnResult::Completed(self.output(
            "I've reached the maximum number of tool call iterations. Here's what I've done so far."
                .to_string(),
            tool_calls_made,
            total_tokens,
            usage,
        )))
    }

    /// Build a checkpoint of the in-flight turn at a pause boundary and emit a
    /// `Paused` stream event. The accumulated `messages` are snapshotted so a
    /// resuming executor can continue without replaying the prologue.
    async fn checkpoint(
        &self,
        user_message: &str,
        tool_calls_made: usize,
        tokens_used: u32,
        usage: UsageTelemetry,
        partial_content: String,
    ) -> GenerationCheckpoint {
        self.emit(StreamEvent::Paused { tool_calls_made }).await;
        GenerationCheckpoint {
            agent_id: self.agent_id,
            conversation_id: self.conversation_id.clone(),
            user_message: user_message.to_string(),
            messages: self.messages.clone(),
            partial_content,
            tool_calls_made,
            tokens_used,
            usage,
        }
    }

    /// Return tool calls from the most recent assistant tool-call turn that do
    /// not yet have a matching tool-result message in the checkpoint.
    fn pending_tool_calls(&self) -> Vec<crate::connector::ToolCall> {
        let Some((index, calls)) = self
            .messages
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, message)| message.tool_calls.clone().map(|calls| (index, calls)))
        else {
            return Vec::new();
        };
        let completed: std::collections::HashSet<&str> = self.messages[index + 1..]
            .iter()
            .filter_map(|message| message.tool_call_id.as_deref())
            .collect();
        calls
            .into_iter()
            .filter(|call| !completed.contains(call.id.as_str()))
            .collect()
    }

    /// Send to LLM with retry (3 attempts, exponential backoff).
    /// Send to LLM with retry. Filters orphaned tool messages to prevent API errors.
    async fn send_with_retry(
        &self,
        tools: &[crate::connector::ToolDefinition],
    ) -> Result<ProviderCall, KernelError> {
        // Filter messages: remove tool results that don't have a preceding tool_calls message
        let clean_messages = self.clean_messages();
        let estimated_input_tokens = clean_messages
            .iter()
            .map(|message| (message.content.len() as u32 / 4).saturating_add(1))
            .chain(tools.iter().map(|tool| {
                ((tool.name.len() + tool.description.len() + tool.parameters.to_string().len())
                    as u32
                    / 4)
                .saturating_add(1)
            }))
            .fold(0u32, u32::saturating_add);

        let mut last_err = None;
        let mut provider_latency_ms = 0u64;
        for attempt in 0..LLM_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(500 * (1 << attempt))).await;
            }
            let rate_guard = match &self.rate_limiter {
                Some(limiter) => Some(
                    limiter
                        .acquire_tokens(u64::from(estimated_input_tokens))
                        .await
                        .map_err(|error| KernelError::Policy(error.to_string()))?,
                ),
                None => None,
            };
            let _llm_core = match &self.llm_scheduler {
                Some((scheduler, pid, nice)) => Some(
                    scheduler
                        .acquire_cancellable(*pid, *nice, &self.cancel_token)
                        .await
                        .map_err(KernelError::Scheduler)?,
                ),
                None => None,
            };
            let started = std::time::Instant::now();
            let result = tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    return Err(KernelError::Policy("execution cancelled by lifecycle coordinator".into()));
                }
                result = self.session.send_streaming(clean_messages.clone(), tools) => result,
            };
            provider_latency_ms = provider_latency_ms
                .saturating_add(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            drop(_llm_core);
            match result {
                Ok(response) => {
                    let usage = if response.usage.provider_reported && response.usage.total() > 0 {
                        response.usage
                    } else {
                        // Conservative fallback: count the full serialized
                        // request estimate plus the adapter's token count as
                        // output. This may over-count providers that return only
                        // a total, which is safer for quota enforcement.
                        crate::connector::LlmUsage {
                            input_tokens: estimated_input_tokens,
                            output_tokens: response.tokens_used,
                            cached_tokens: 0,
                            provider_reported: false,
                        }
                    };
                    if let Some(guard) = rate_guard {
                        guard.reconcile(u64::from(usage.total()));
                    }
                    return Ok(ProviderCall {
                        response,
                        usage,
                        attempts: (attempt + 1) as u32,
                        retries: attempt as u32,
                        latency_ms: provider_latency_ms,
                    });
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        Err(KernelError::Connector(last_err.unwrap()))
    }

    /// Execute a tool call, returning the result string (or error message for LLM recovery).
    ///
    /// When a `SyscallGate` is installed, every call is screened: capability →
    /// MAC → cgroup quota. A denial is surfaced to the LLM as a tool error so
    /// the model can recover (try another tool, ask the user, etc.) without
    /// the kernel trusting the LLM to obey policy.
    async fn execute_tool(&self, tool_call: &crate::connector::ToolCall) -> String {
        // Estimate token cost: arguments + tool name. Conservative ratio of 4
        // chars per token plus a 10-token floor so trivial calls still count.
        let est_tokens: u64 = (tool_call.arguments.to_string().len() as u64 / 4)
            .saturating_add(tool_call.name.len() as u64 / 4)
            .saturating_add(10);

        // Resolve action, capabilities, and resource using the binding's
        // validated declaration. Unknown tools and malformed resource arguments
        // fail before policy evaluation or provider execution.
        let (security, resource) = match self
            .tool_registry
            .security_context(&tool_call.name, &tool_call.arguments)
        {
            Ok(context) => context,
            Err(error) if error.starts_with("unknown tool") => {
                return format!(
                    "Unknown tool '{}'. Available tools: {}",
                    tool_call.name,
                    self.tool_registry
                        .definitions()
                        .iter()
                        .map(|tool| tool.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Err(error) => return format!("Tool '{}' denied by kernel: {error}", tool_call.name),
        };

        // Mandatory enforcement: every tool call is checked against the gate
        // (namespace → capability → MAC → cgroup). There is no ungoverned path —
        // an unconfined gate is the only bypass and must be requested by name.
        match self
            .syscall_gate
            .check_tool_call_declared(
                self.agent_id,
                &tool_call.name,
                &resource,
                est_tokens,
                &security,
            )
            .await
        {
            Ok(_) => { /* proceed */ }
            Err(denial) => {
                return format!(
                    "Tool '{}' denied by kernel: {}",
                    tool_call.name,
                    denial.message()
                );
            }
        }

        let _tool_slot = match self.syscall_gate.acquire_tool_call(self.agent_id) {
            Ok(slot) => slot,
            Err(denial) => {
                return format!(
                    "Tool '{}' denied by kernel: {}",
                    tool_call.name,
                    denial.message()
                );
            }
        };

        let result = match self.tool_registry.resolve(self.agent_id, tool_call) {
            Some(request) => match self.resource_broker.execute(request).await {
                Ok(resp) if resp.success => serde_json::to_string(&resp.data).unwrap_or_default(),
                Ok(resp) => {
                    format!(
                        "Tool '{}' failed: {}. Try a different approach.",
                        tool_call.name,
                        resp.error.unwrap_or_default()
                    )
                }
                Err(e) => {
                    format!(
                        "Tool '{}' error: {}. Try a different approach or tool.",
                        tool_call.name, e
                    )
                }
            },
            None => format!(
                "Unknown tool '{}'. Available tools: {}",
                tool_call.name,
                self.tool_registry
                    .definitions()
                    .iter()
                    .map(|t| t.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };

        result
    }

    /// Get the current message history.
    pub fn messages(&self) -> &[StandardMessage] {
        &self.messages
    }

    /// Save the current conversation to SQLite.
    fn save_conversation(&self) {
        let _ = self.context_manager.save_conversation(
            &self.conversation_id,
            self.agent_id,
            &self.messages,
        );
    }

    /// Clean messages: remove orphaned tool results (tool messages without preceding tool_calls).
    fn clean_messages(&self) -> Vec<StandardMessage> {
        let mut clean = Vec::new();
        let mut last_had_tool_calls = false;

        for msg in &self.messages {
            if msg.role == "tool" {
                // Only include tool messages if the previous assistant message had tool_calls
                if last_had_tool_calls {
                    clean.push(msg.clone());
                }
                // Don't update last_had_tool_calls for tool messages
            } else {
                last_had_tool_calls = msg
                    .tool_calls
                    .as_ref()
                    .map(|tc| !tc.is_empty())
                    .unwrap_or(false);
                clean.push(msg.clone());
            }
        }
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::{LlmResponse, LlmUsage, ToolCall, ToolDefinition};
    use crate::permissions::PermissionManager;
    use crate::resources::ResourceProvider;
    use crate::{ConnectorError, ResourceError};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn mock_context_manager() -> Arc<SqliteContextManager> {
        Arc::new(SqliteContextManager::in_memory().unwrap())
    }

    /// Mock LLM session that returns tool calls on first call, then content.
    struct MockToolSession {
        call_count: AtomicUsize,
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for MockToolSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(
            &self,
            _messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                Ok(LlmResponse {
                    content: "".into(),
                    finish_reason: Some("tool_calls".into()),
                    tokens_used: 20,
                    usage: LlmUsage::reported(0, 20, 0),
                    tool_calls: vec![ToolCall {
                        id: "call_1".into(),
                        name: "read_file".into(),
                        arguments: serde_json::json!({"path": "/tmp/test.txt"}),
                    }],
                })
            } else {
                Ok(LlmResponse {
                    content: "The file contains: hello world".into(),
                    finish_reason: Some("stop".into()),
                    tokens_used: 15,
                    usage: LlmUsage::reported(0, 15, 0),
                    tool_calls: vec![],
                })
            }
        }
        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    /// Mock session that always returns tool calls (for testing max iterations).
    struct InfiniteToolSession {
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for InfiniteToolSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(
            &self,
            _messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            Ok(LlmResponse {
                content: "".into(),
                finish_reason: Some("tool_calls".into()),
                tokens_used: 5,
                usage: LlmUsage::reported(0, 5, 0),
                tool_calls: vec![ToolCall {
                    id: "call_x".into(),
                    name: "read_file".into(),
                    arguments: serde_json::json!({"path": "/x"}),
                }],
            })
        }
        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    fn mock_broker() -> Arc<dyn ResourceBroker> {
        use crate::resources::ResourceBrokerImpl;
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new_unconfined(perms.clone());
        // Register a mock filesystem provider
        struct MockFs;
        #[async_trait::async_trait]
        impl ResourceProvider for MockFs {
            fn resource_type(&self) -> crate::resources::ResourceType {
                crate::resources::ResourceType::Filesystem
            }
            fn supported_operations(&self) -> Vec<String> {
                vec!["read".into(), "write".into(), "list".into()]
            }
            async fn execute(
                &self,
                _op: &str,
                _params: &serde_json::Value,
            ) -> Result<serde_json::Value, ResourceError> {
                Ok(serde_json::json!({"content": "hello world"}))
            }
        }
        broker.register_provider(Box::new(MockFs));
        Arc::new(broker)
    }

    // Regression guard for the CLI wiring fix: once a syscall gate is installed
    // on the executor (as the `agent` CLI now does via `set_syscall_gate`), tool
    // calls must be enforced against the agent's capabilities. A tool requiring a
    // missing capability is denied by the kernel; a tool requiring none passes.
    #[tokio::test]
    async fn executor_with_gate_enforces_capabilities() {
        use crate::agent_struct::CapabilitySet;
        use crate::cgroups::CgroupManager;
        use crate::syscall_gate::SyscallGate;

        let agent_id = uuid::Uuid::new_v4();

        // Register the agent with the gate WITHOUT CAP_FILE_WRITE (net only),
        // mirroring a restricted permission profile rather than full-access.
        let gate = Arc::new(SyscallGate::new(Arc::new(CgroupManager::new())));
        let mut caps = CapabilitySet::none();
        caps.grant(CapabilitySet::CAP_NET_ACCESS);
        gate.register_agent(agent_id, caps, None);

        let session = Box::new(MockToolSession {
            call_count: AtomicUsize::new(0),
            id: "mock".into(),
        });
        let executor = AgentExecutor::new(
            agent_id,
            session,
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            gate,
            "test".into(),
        );

        // write_file requires CAP_FILE_WRITE, which this agent lacks → denied.
        let denied = executor
            .execute_tool(&ToolCall {
                id: "c1".into(),
                name: "write_file".into(),
                arguments: serde_json::json!({"path": "/tmp/x", "content": "y"}),
            })
            .await;
        assert!(
            denied.contains("denied by kernel"),
            "write_file should be denied by the gate, got: {denied}"
        );

        // read_file needs no capability → passes the gate (no kernel denial).
        let allowed = executor
            .execute_tool(&ToolCall {
                id: "c2".into(),
                name: "read_file".into(),
                arguments: serde_json::json!({"path": "/tmp/x"}),
            })
            .await;
        assert!(
            !allowed.contains("denied by kernel"),
            "read_file should pass the gate, got: {allowed}"
        );
    }

    // Structural guarantee: an executor built the normal way (`new`, with a real
    // non-unconfined gate) is ungoverned for *no one*. An agent that was never
    // registered with the gate is denied (UnknownAgent), NOT silently allowed —
    // the inverse of the old footgun where a missing gate meant "skip all checks".
    // Production code cannot reach an ungoverned executor: `new` requires a gate
    // and the only bypass, `SyscallGate::unconfined`, is `#[cfg(test)]`-gated at
    // the executor (`new_unconfined`) and must be named explicitly.
    #[tokio::test]
    async fn unregistered_agent_is_denied_not_unconfined() {
        use crate::cgroups::CgroupManager;
        use crate::syscall_gate::SyscallGate;

        // A real (enforcing-capable) gate with NO agent registered.
        let gate = Arc::new(SyscallGate::new(Arc::new(CgroupManager::new())));
        let agent_id = uuid::Uuid::new_v4();
        let session = Box::new(MockToolSession {
            call_count: AtomicUsize::new(0),
            id: "mock".into(),
        });
        let executor = AgentExecutor::new(
            agent_id,
            session,
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            gate,
            "test".into(),
        );

        // read_file needs no capability, but the agent is unknown to the gate, so
        // the call must be denied rather than reaching the broker unchecked.
        let result = executor
            .execute_tool(&ToolCall {
                id: "c1".into(),
                name: "read_file".into(),
                arguments: serde_json::json!({"path": "/tmp/x"}),
            })
            .await;
        assert!(
            result.contains("denied by kernel"),
            "an unregistered agent must be denied by the gate, got: {result}"
        );
    }

    // The explicit escape hatch behaves as documented: an unconfined executor
    // allows a call for an unregistered agent (the only sanctioned ungoverned
    // path), proving `new_unconfined` is wired to the short-circuiting gate.
    #[tokio::test]
    async fn unconfined_executor_allows_unregistered_agent() {
        let agent_id = uuid::Uuid::new_v4();
        let session = Box::new(MockToolSession {
            call_count: AtomicUsize::new(0),
            id: "mock".into(),
        });
        let executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        let result = executor
            .execute_tool(&ToolCall {
                id: "c1".into(),
                name: "read_file".into(),
                arguments: serde_json::json!({"path": "/tmp/x"}),
            })
            .await;
        assert!(
            !result.contains("denied by kernel"),
            "an unconfined executor should not deny, got: {result}"
        );
    }

    // #44: a cumulative USD ceiling hard-stops the think→act loop. The
    // InfiniteToolSession would otherwise run all MAX_ITERATIONS rounds; with a
    // budget priced so one response exhausts the ceiling, the loop refuses the
    // *next* LLM call and returns a budget message instead.
    // #4: the context pager bounds the active window by token budget — older
    // non-system messages are paged out, the system prompt is always retained.
    #[tokio::test]
    async fn context_pager_bounds_active_window_by_tokens() {
        let agent_id = uuid::Uuid::new_v4();
        let context = mock_context_manager();
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            Box::new(InfiniteToolSession { id: "x".into() }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            context.clone(),
            "SYSTEM PROMPT".into(),
        );
        executor.set_context_budget(100);
        let (event_tx, mut event_rx) = mpsc::channel(4);
        executor.set_event_channel(event_tx);

        // 10 user messages of ~40 chars each (~11 tokens apiece).
        for _ in 0..10 {
            executor
                .messages
                .push(StandardMessage::user("x".repeat(40)));
        }
        let before = executor.messages.len();
        executor.compact_to_token_budget().await.unwrap();
        let after = executor.messages.len();

        assert!(
            after < before,
            "should page out old messages (was {before})"
        );
        // System prompt is always kept at index 0.
        assert_eq!(executor.messages[0].role, "system");
        assert_eq!(executor.messages[0].content, "SYSTEM PROMPT");
        assert!(executor.estimate_prompt_tokens(&executor.messages) <= 100);
        assert!(executor.messages.iter().any(|message| {
            message.role == "system" && message.content.contains("Context spill")
        }));
        let spills = context.kv_list(agent_id).unwrap();
        assert_eq!(spills.len(), 1);
        assert!(spills[0].starts_with("context_spill:"));
        assert!(context
            .kv_get(agent_id, &spills[0])
            .unwrap()
            .unwrap()
            .contains(&"x".repeat(40)));
        let stats = context.context_pressure_stats(agent_id).unwrap();
        assert_eq!(
            stats.active_tokens,
            executor.estimate_prompt_tokens(&executor.messages)
        );
        assert_eq!(stats.budget_tokens, 100);
        assert_eq!(stats.spill_count, 1);
        assert!(stats.evicted_messages > 0);
        assert_eq!(stats.stored_spills, 1);
        assert!(stats.stored_spill_bytes > 0);
        assert_eq!(stats.error_count, 0);
        assert!(matches!(
            event_rx.try_recv().unwrap(),
            StreamEvent::ContextPressure {
                budget_tokens: 100,
                ..
            }
        ));

        // Disabling the budget is a no-op even with a large history.
        executor.set_context_budget(0);
        for _ in 0..5 {
            executor
                .messages
                .push(StandardMessage::user("y".repeat(40)));
        }
        let n = executor.messages.len();
        executor.compact_to_token_budget().await.unwrap();
        assert_eq!(executor.messages.len(), n, "budget 0 must not trim");
    }

    #[tokio::test]
    async fn impossible_pinned_budget_fails_closed_without_mutating_context() {
        let context = mock_context_manager();
        let agent_id = uuid::Uuid::new_v4();
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            Box::new(InfiniteToolSession { id: "x".into() }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            context.clone(),
            "required system instruction that cannot fit".repeat(10),
        );
        executor.set_context_budget(5);
        executor
            .messages
            .push(StandardMessage::user("ordinary history"));
        let before = executor.messages.clone();
        let error = executor.compact_to_token_budget().await.unwrap_err();
        assert!(error.to_string().contains("pinned system/tool state"));
        assert_eq!(executor.messages, before);
        let stats = context.context_pressure_stats(agent_id).unwrap();
        assert_eq!(stats.error_count, 1);
        assert_eq!(stats.stored_spills, 0);
        assert!(stats
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("pinned system/tool state")));
    }

    #[tokio::test]
    async fn execution_loop_stops_at_budget_ceiling() {
        use crate::budget::BudgetEnforcer;

        let agent_id = uuid::Uuid::new_v4();
        let session = Box::new(InfiniteToolSession {
            id: "infinite".into(),
        });
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        // $1 per 1k tokens; each response is 5 tokens = $0.005. A $0.004 ceiling
        // is exhausted by the first response, so the 2nd iteration is refused.
        let budget = Arc::new(BudgetEnforcer::with_pricing(1.0, 0.004, 0.0));
        executor.set_budget_enforcer(budget.clone());

        let output = executor.run("go").await.unwrap();

        assert!(
            output.content.contains("budget exhausted"),
            "loop should stop with a budget message, got: {}",
            output.content
        );
        // Exactly one LLM round happened (one tool call), not all 10 iterations.
        assert_eq!(output.tool_calls_made, 1);
        // One response was priced: 5 tokens × $1/1k = $0.005.
        assert!((budget.global_spent_usd() - 0.005).abs() < 1e-6);
    }

    /// Mock session that emits a shim-style plaintext tool call (no native
    /// `tool_calls`), then plain content — exercises the function-calling shim.
    struct PlaintextShimSession {
        call_count: AtomicUsize,
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for PlaintextShimSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(
            &self,
            _messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                // Plaintext reply with a fenced shim call and NO native tool_calls.
                Ok(LlmResponse {
                    content: "I'll read it.\n```json\n{\"tool\": \"read_file\", \"arguments\": {\"path\": \"/tmp/test.txt\"}}\n```".into(),
                    finish_reason: Some("stop".into()),
                    tokens_used: 12,
                    usage: Default::default(),
                    tool_calls: vec![],
                })
            } else {
                Ok(LlmResponse {
                    content: "The file contains: hello world".into(),
                    finish_reason: Some("stop".into()),
                    tokens_used: 8,
                    usage: Default::default(),
                    tool_calls: vec![],
                })
            }
        }
        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    // The function-calling shim is load-bearing: a model that emits a tool call
    // as plaintext (no native `tool_calls`) still drives the tool-execution path.
    #[tokio::test]
    async fn execution_loop_recovers_plaintext_tool_call() {
        let session = Box::new(PlaintextShimSession {
            call_count: AtomicUsize::new(0),
            id: "mock".into(),
        });
        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            session,
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );

        let output = executor.run("Read /tmp/test.txt").await.unwrap();
        // The plaintext call was recovered and executed (one tool call made).
        assert_eq!(output.tool_calls_made, 1);
        assert_eq!(output.content, "The file contains: hello world");
    }

    #[tokio::test]
    async fn execution_loop_with_tool_call() {
        let session = Box::new(MockToolSession {
            call_count: AtomicUsize::new(0),
            id: "mock".into(),
        });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            session,
            broker,
            registry,
            mock_context_manager(),
            "You are a helpful assistant.".into(),
        );

        let output = executor.run("Read /tmp/test.txt").await.unwrap();
        assert_eq!(output.content, "The file contains: hello world");
        assert_eq!(output.tool_calls_made, 1);
        assert_eq!(output.tokens_used, 35);
    }

    #[tokio::test]
    async fn execution_loop_caps_at_max_iterations() {
        let session = Box::new(InfiniteToolSession { id: "mock".into() });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            session,
            broker,
            registry,
            mock_context_manager(),
            "You are a helpful assistant.".into(),
        );

        let output = executor.run("Do something forever").await.unwrap();
        assert_eq!(output.tool_calls_made, MAX_ITERATIONS);
        assert!(output.content.contains("maximum"));
    }

    /// Mock session that fails twice then succeeds (tests LLM retry).
    struct FailThenSucceedSession {
        call_count: AtomicUsize,
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for FailThenSucceedSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(
            &self,
            _messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err(ConnectorError::ConnectionFailed("server error".into()))
            } else {
                Ok(LlmResponse {
                    content: "recovered!".into(),
                    finish_reason: Some("stop".into()),
                    tokens_used: 10,
                    usage: Default::default(),
                    tool_calls: vec![],
                })
            }
        }
        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    #[tokio::test]
    async fn llm_retry_recovers_from_transient_failure() {
        let session = Box::new(FailThenSucceedSession {
            call_count: AtomicUsize::new(0),
            id: "mock".into(),
        });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            session,
            broker,
            registry,
            mock_context_manager(),
            "test".into(),
        );

        let output = executor.run("test").await.unwrap();
        assert_eq!(output.content, "recovered!");
        assert_eq!(output.usage.llm_requests, 3);
        assert_eq!(output.usage.retries, 2);
        assert_eq!(output.usage.provider_reported_requests, 0);
        assert_eq!(output.usage.estimated_requests, 1);
        assert!(output.usage.input_tokens > 0);
        assert_eq!(output.usage.output_tokens, 10);
    }

    /// Mock session that calls a nonexistent tool — tests error recovery message to LLM.
    struct BadToolSession {
        call_count: AtomicUsize,
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for BadToolSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(
            &self,
            messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                // First call: return a bad tool call
                Ok(LlmResponse {
                    content: "".into(),
                    finish_reason: Some("tool_calls".into()),
                    tokens_used: 10,
                    usage: Default::default(),
                    tool_calls: vec![ToolCall {
                        id: "c1".into(),
                        name: "nonexistent_tool".into(),
                        arguments: serde_json::json!({}),
                    }],
                })
            } else {
                // Second call: LLM sees the error and responds with content
                // Verify the error message was passed back
                let last_msg = messages.last().unwrap();
                assert!(last_msg.content.contains("Unknown tool"));
                assert!(last_msg.content.contains("read_file")); // suggests available tools
                Ok(LlmResponse {
                    content: "Sorry, let me try differently.".into(),
                    finish_reason: Some("stop".into()),
                    tokens_used: 8,
                    usage: Default::default(),
                    tool_calls: vec![],
                })
            }
        }
        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    #[tokio::test]
    async fn tool_failure_sends_error_back_to_llm() {
        let session = Box::new(BadToolSession {
            call_count: AtomicUsize::new(0),
            id: "mock".into(),
        });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            session,
            broker,
            registry,
            mock_context_manager(),
            "test".into(),
        );

        let output = executor.run("use a bad tool").await.unwrap();
        assert_eq!(output.content, "Sorry, let me try differently.");
        assert_eq!(output.tool_calls_made, 1);
    }

    #[tokio::test]
    async fn memory_stored_and_queried_across_runs() {
        let ctx_mgr = mock_context_manager();
        let agent_id = uuid::Uuid::new_v4();

        // Store a fact manually
        let fact = Fact {
            id: uuid::Uuid::new_v4(),
            content: "User prefers dark mode theme".to_string(),
            category: FactCategory::Preference,
            created_at: chrono::Utc::now(),
            last_accessed_at: chrono::Utc::now(),
            embedding: None,
        };
        ctx_mgr.store_fact(agent_id, fact).await.unwrap();

        // Query and verify it appears
        let results = ctx_mgr.query_memory(agent_id, "dark mode").await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].content.contains("dark mode"));
    }

    /// Mock session that returns a long response (>100 chars) to trigger fact storage.
    struct LongResponseSession {
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for LongResponseSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(
            &self,
            _messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            Ok(LlmResponse {
                content: "This is a very long response that exceeds one hundred characters in length so it will be stored as a fact in long-term memory for future reference.".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 30,
                usage: Default::default(),
                tool_calls: vec![],
            })
        }
        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    #[tokio::test]
    async fn long_response_stored_as_fact() {
        let ctx_mgr = mock_context_manager();
        let agent_id = uuid::Uuid::new_v4();
        let session = Box::new(LongResponseSession { id: "mock".into() });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            broker,
            registry,
            ctx_mgr.clone(),
            "test".into(),
        );

        executor.run("tell me something").await.unwrap();

        // Verify fact was stored
        let facts = ctx_mgr
            .query_memory(agent_id, "long-term memory")
            .await
            .unwrap();
        assert_eq!(facts.len(), 1);
    }

    /// Mock session for summarization test — tracks messages received.
    struct SummarizationSession {
        id: String,
        msg_count: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl LlmSession for SummarizationSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(
            &self,
            messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            self.msg_count.store(messages.len(), Ordering::SeqCst);
            Ok(LlmResponse {
                content: "ok".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 5,
                usage: Default::default(),
                tool_calls: vec![],
            })
        }
        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    #[tokio::test]
    async fn pressure_spills_instead_of_message_count_summarization() {
        let ctx_mgr = mock_context_manager();
        let agent_id = uuid::Uuid::new_v4();
        let session = Box::new(SummarizationSession {
            id: "mock".into(),
            msg_count: AtomicUsize::new(0),
        });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            broker,
            registry,
            ctx_mgr.clone(),
            "test".into(),
        );
        executor.set_context_budget(120);

        // Manually fill enough history to exceed the active prompt budget.
        for i in 0..30 {
            executor
                .messages
                .push(StandardMessage::user(format!("message {}", i)));
        }

        // Run should durably spill rather than silently count-summarize.
        executor.run("final message").await.unwrap();
        assert!(executor.messages().len() < 33);
        assert!(!ctx_mgr.kv_list(agent_id).unwrap().is_empty());
    }

    // ---- Mid-generation context switch (#56) ----

    /// A no-pause `run_resumable` runs to completion just like `run`.
    #[tokio::test]
    async fn run_resumable_completes_when_not_paused() {
        let session = Box::new(MockToolSession {
            call_count: AtomicUsize::new(0),
            id: "mock".into(),
        });
        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            session,
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );

        match executor.run_resumable("Read /tmp/test.txt").await.unwrap() {
            TurnResult::Completed(output) => {
                assert_eq!(output.content, "The file contains: hello world");
                assert_eq!(output.tool_calls_made, 1);
                assert_eq!(output.tokens_used, 35);
            }
            TurnResult::Paused(_) => panic!("should have completed, not paused"),
        }
    }

    /// Cancelling before the first LLM round pauses at the boundary and returns
    /// a checkpoint carrying the accumulated (prologue) messages — the user
    /// message is present, so a fresh executor can continue the turn. This is
    /// deterministic: the cancel token is set before `run_resumable`, so the
    /// very first boundary check trips.
    #[tokio::test]
    async fn run_resumable_pauses_at_boundary_with_checkpoint() {
        let agent_id = uuid::Uuid::new_v4();
        let session = Box::new(InfiniteToolSession { id: "x".into() });
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "SYSTEM".into(),
        );

        // Deterministic pause: signal cancel up front so the first boundary
        // check (top of the loop) trips — no wall-clock timing involved.
        executor.cancel();

        let checkpoint = match executor.run_resumable("do work").await.unwrap() {
            TurnResult::Paused(cp) => cp,
            TurnResult::Completed(_) => panic!("should have paused, not completed"),
        };

        // No LLM round ran, but the prologue is captured: system + user message.
        assert_eq!(checkpoint.agent_id, agent_id);
        assert_eq!(checkpoint.user_message, "do work");
        assert_eq!(checkpoint.tool_calls_made, 0);
        assert!(
            checkpoint.messages.iter().any(|m| m.role == "system"),
            "checkpoint should retain the system prompt"
        );
        assert!(
            checkpoint
                .messages
                .iter()
                .any(|m| m.role == "user" && m.content == "do work"),
            "checkpoint should retain the user message"
        );
    }

    /// A broker whose filesystem provider trips a shared cancel token as a side
    /// effect of executing the tool. This makes the pause boundary
    /// *deterministic*: the first tool runs to completion (so `tool_calls_made`
    /// is 1), and by the time the executor reaches iteration 2's top-of-loop
    /// check the token is already set — no event-channel race, no wall clock.
    fn cancel_on_tool_broker(
        agent_id: AgentId,
        cancel: CancellationToken,
    ) -> Arc<dyn ResourceBroker> {
        use crate::resources::ResourceBrokerImpl;
        let perms = Arc::new(PermissionManager::new());
        crate::permissions::PermissionSystem::assign_profile(
            perms.as_ref(),
            agent_id,
            &"full-access".to_string(),
        );
        let broker = ResourceBrokerImpl::new_unconfined(perms);
        struct CancelFs {
            cancel: CancellationToken,
        }
        #[async_trait::async_trait]
        impl ResourceProvider for CancelFs {
            fn resource_type(&self) -> crate::resources::ResourceType {
                crate::resources::ResourceType::Filesystem
            }
            fn supported_operations(&self) -> Vec<String> {
                vec!["read".into(), "write".into(), "list".into()]
            }
            async fn execute(
                &self,
                _op: &str,
                _params: &serde_json::Value,
            ) -> Result<serde_json::Value, ResourceError> {
                self.cancel.cancel();
                Ok(serde_json::json!({"content": "hello world"}))
            }
        }
        broker.register_provider(Box::new(CancelFs { cancel }));
        Arc::new(broker)
    }

    /// Resuming a checkpoint into a *fresh* executor (new mock session) finishes
    /// the turn, and the completed output reflects both phases: the tool call
    /// made before the pause is carried forward, and tokens accumulate across
    /// the pre- and post-pause work.
    #[tokio::test]
    async fn resume_from_checkpoint_reflects_both_phases() {
        let agent_id = uuid::Uuid::new_v4();

        // Phase 1: run exactly one tool round, then pause at the next boundary.
        // `MockToolSession` returns a tool call on call 0; the broker trips the
        // cancel token while executing that tool, so the pause is taken at the
        // top of iteration 2 — deterministic, gated on the cancel flag being set
        // before the boundary check, not on timing.
        let shared_cancel = CancellationToken::new();
        let mut exec1 = AgentExecutor::new_unconfined(
            agent_id,
            Box::new(MockToolSession {
                call_count: AtomicUsize::new(0),
                id: "phase1".into(),
            }),
            cancel_on_tool_broker(agent_id, shared_cancel.clone()),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "SYSTEM".into(),
        );
        exec1.cancel_token = shared_cancel;

        let checkpoint = match exec1.run_resumable("Read /tmp/test.txt").await.unwrap() {
            TurnResult::Paused(cp) => cp,
            TurnResult::Completed(_) => panic!("phase 1 should pause after one tool round"),
        };
        assert_eq!(checkpoint.tool_calls_made, 1, "one tool call before pause");
        assert!(checkpoint.tokens_used >= 20, "phase-1 tokens accumulated");
        // The assistant turn + tool result are in the checkpoint.
        assert!(checkpoint.messages.iter().any(|m| m.role == "tool"));

        // Phase 2: resume into a FRESH executor with a session that returns the
        // remainder (final content, no tool calls).
        let resume_session = Box::new(LongResponseSession {
            id: "phase2".into(),
        });
        let mut exec2 = AgentExecutor::new_unconfined(
            agent_id,
            resume_session,
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "SYSTEM".into(),
        );
        let phase1_tokens = checkpoint.tokens_used;

        let output = match exec2.resume(checkpoint).await.unwrap() {
            TurnResult::Completed(out) => out,
            TurnResult::Paused(_) => panic!("phase 2 should complete"),
        };

        // The final output reflects the WHOLE turn: the pre-pause tool call is
        // carried forward, and tokens are the sum of both phases.
        assert_eq!(output.tool_calls_made, 1, "pre-pause tool call carried");
        assert!(
            output.tokens_used > phase1_tokens,
            "tokens accumulate across pause ({} should exceed {})",
            output.tokens_used,
            phase1_tokens
        );
        assert!(output.content.contains("long response"));
    }

    /// A paused turn can be paused again on resume: resuming with the cancel
    /// token already set re-pauses immediately, preserving the carried-forward
    /// counts (idempotent re-checkpointing).
    #[tokio::test]
    async fn resume_can_pause_again() {
        let agent_id = uuid::Uuid::new_v4();
        let checkpoint = GenerationCheckpoint {
            agent_id,
            conversation_id: "conv".into(),
            user_message: "keep going".into(),
            messages: vec![
                StandardMessage::system("SYSTEM"),
                StandardMessage::user("keep going"),
            ],
            partial_content: String::new(),
            tool_calls_made: 2,
            tokens_used: 42,
            usage: UsageTelemetry::default(),
        };

        let session = Box::new(InfiniteToolSession { id: "x".into() });
        let mut exec = AgentExecutor::new_unconfined(
            agent_id,
            session,
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "SYSTEM".into(),
        );
        exec.cancel(); // re-pause at the first boundary on resume

        match exec.resume(checkpoint).await.unwrap() {
            TurnResult::Paused(cp) => {
                // Carried-forward counts are preserved across the re-pause.
                assert_eq!(cp.tool_calls_made, 2);
                assert_eq!(cp.tokens_used, 42);
                assert_eq!(cp.user_message, "keep going");
                assert_eq!(cp.conversation_id, "conv");
            }
            TurnResult::Completed(_) => panic!("should re-pause, not complete"),
        }
    }

    /// A `GenerationCheckpoint` round-trips through serde unchanged.
    #[test]
    fn checkpoint_serde_round_trip() {
        let mut assistant = StandardMessage::assistant("calling a tool");
        assistant.tool_calls = Some(vec![ToolCall {
            id: "call_1".into(),
            name: "read_file".into(),
            arguments: serde_json::json!({"path": "/tmp/x"}),
        }]);

        let checkpoint = GenerationCheckpoint {
            agent_id: uuid::Uuid::new_v4(),
            conversation_id: "conv-123".into(),
            user_message: "do the thing".into(),
            messages: vec![
                StandardMessage::system("SYSTEM"),
                StandardMessage::user("do the thing"),
                assistant,
                StandardMessage::tool_result("call_1", "hello world"),
            ],
            partial_content: "partial assistant text".into(),
            tool_calls_made: 3,
            tokens_used: 123,
            usage: UsageTelemetry {
                input_tokens: 70,
                output_tokens: 53,
                llm_requests: 2,
                ..Default::default()
            },
        };

        let json = serde_json::to_string(&checkpoint).unwrap();
        let restored: GenerationCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(checkpoint, restored);
    }
}
