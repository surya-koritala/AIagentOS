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
    /// A request-scoped execution stream is registered and cancellable.
    Started { request_id: String },
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
    /// Exact micro-USD charged to the durable budget ledger for this turn.
    /// Stored as an integer so persisted/replayed telemetry reconciles without
    /// floating-point drift. Older checkpoints deserialize this as zero.
    #[serde(default)]
    pub charged_cost_micros: u64,
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
    provider_id: crate::ProviderId,
    model_id: String,
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
    /// Shared active-prompt admission. The tenant id is immutable for the
    /// executor lifetime and restored with the owning agent.
    context_admission: Option<(Arc<crate::context_paging::ActiveContextManager>, String)>,
    /// Max active-context tokens; older non-system messages are paged out (via
    /// the context pager) when exceeded. 0 = disabled (no token bound).
    context_budget_tokens: u32,
    /// Maximum cumulative tool calls in one logical turn. Unlike the cgroup
    /// slot limit, this is not a concurrency control: it counts calls across
    /// response batches and LLM rounds, and is carried by checkpoints. 0 means
    /// unlimited.
    max_tool_calls_per_turn: usize,
    /// Provider-enforced completion allowance reserved with each prompt. `0`
    /// preserves the source-compatible direct-executor behavior; production
    /// kernel wiring always installs a positive validated value.
    max_output_tokens_per_request: u32,
    /// Per-attempt provider timeout. `None` preserves direct-executor
    /// compatibility; production kernel wiring installs a finite bound.
    provider_request_timeout: Option<std::time::Duration>,
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
        let (provider_id, model_id) = self.session.last_attribution().unwrap_or_else(|| {
            (
                self.session.provider_id().clone(),
                self.session.model_id().to_string(),
            )
        });
        let estimated_cost_usd = usage.charged_cost_micros as f64 / 1_000_000.0;
        AgentOutput {
            content,
            tool_calls_made,
            tokens_used,
            provider_id,
            model_id,
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
            context_admission: None,
            context_budget_tokens: 0,
            max_tool_calls_per_turn: 0,
            max_output_tokens_per_request: 0,
            provider_request_timeout: None,
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

    pub fn set_context_admission(
        &mut self,
        manager: Arc<crate::context_paging::ActiveContextManager>,
        tenant_id: impl Into<String>,
    ) {
        self.context_admission = Some((manager, tenant_id.into()));
    }

    /// Set the active-context token budget. When > 0, the loop pages out the
    /// oldest non-system messages before each LLM call so the working set stays
    /// within the budget (the context-paging / virtual-memory analogue). 0
    /// disables it (unbounded — prior behavior).
    pub fn set_context_budget(&mut self, max_tokens: u32) {
        self.context_budget_tokens = max_tokens;
    }

    /// Set the cumulative tool-call ceiling for each logical user turn.
    ///
    /// The count spans every tool call in a response, subsequent LLM rounds,
    /// and pause/resume continuations. A fresh [`run`](Self::run) or
    /// [`run_resumable`](Self::run_resumable) starts at zero. `0` disables the
    /// ceiling. Concurrent tool execution remains independently controlled by
    /// the cgroup's `max_concurrent_tool_calls` setting.
    pub fn set_max_tool_calls(&mut self, max_tool_calls: u32) {
        self.max_tool_calls_per_turn = max_tool_calls as usize;
    }

    /// Set the provider-enforced completion allowance reserved with each
    /// prompt before quota admission.
    pub fn set_max_output_tokens_per_request(&mut self, max_output_tokens: u32) {
        self.max_output_tokens_per_request = max_output_tokens;
    }

    pub fn set_provider_request_timeout(&mut self, timeout: std::time::Duration) {
        self.provider_request_timeout = Some(timeout);
    }

    fn estimate_prompt_tokens(&self, messages: &[StandardMessage]) -> u32 {
        // Serialize the complete standardized wire shape, not just content.
        // Assistant tool-call ids/names/arguments, tool result ids, roles, and
        // framing all become provider input on the next round. The structural
        // floor prevents an incomplete provider hook from under-reserving a
        // known prompt; a more accurate provider estimate can only raise it.
        let structural_floor = Self::conservative_serialized_tokens(messages)
            .saturating_add((messages.len() as u32).saturating_mul(4));
        self.session
            .estimate_prompt_tokens(messages)
            .map_or(structural_floor, |estimate| estimate.max(structural_floor))
    }

    fn conservative_serialized_tokens<T: serde::Serialize + ?Sized>(value: &T) -> u32 {
        let bytes = serde_json::to_vec(value)
            .map(|serialized| serialized.len())
            .unwrap_or(usize::MAX);
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        // One token per serialized UTF-8 byte is a tokenizer-independent
        // upper bound for byte-backed production tokenizers. It deliberately
        // over-reserves ordinary prose so adversarial ASCII, identifiers, code,
        // and structured tool arguments cannot slip below the kernel's local
        // context/TPM safety floor.
        bytes
    }

    fn conservative_tool_tokens(tools: &[crate::connector::ToolDefinition]) -> u32 {
        if tools.is_empty() {
            0
        } else {
            Self::conservative_serialized_tokens(tools)
        }
    }

    /// Bound the active prompt without silently discarding state. The root
    /// system instruction and latest tool-call state are pinned. Evicted
    /// messages are serialized into the durable agent KV store and replaced by
    /// a compact reference that can be paged in with `StorageGet`.
    async fn compact_to_token_budget(
        &mut self,
        tools: &[crate::connector::ToolDefinition],
    ) -> Result<(), KernelError> {
        let budget = self.context_budget_tokens;
        if budget == 0 {
            return Ok(());
        }
        let tool_tokens = Self::conservative_tool_tokens(tools);
        let original_message_tokens = self.estimate_prompt_tokens(&self.messages);
        let original_tokens = original_message_tokens.saturating_add(tool_tokens);
        if original_tokens <= budget {
            return Ok(());
        }
        let message_budget = budget.saturating_sub(tool_tokens);
        if tool_tokens >= budget {
            let message = format!(
                "context pressure: tool definitions require {tool_tokens} tokens but the active budget is {budget}; increase max_context_tokens or reduce registered tool schemas"
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

        let latest_tool_state = self
            .messages
            .iter()
            .rposition(|message| message.tool_calls.is_some());
        let pinned: Vec<bool> = (0..self.messages.len())
            .map(|index| {
                let message = &self.messages[index];
                let required_system = message.role == "system"
                    && !message.content.starts_with("[Durable context spill:")
                    && !message.content.starts_with("[Context spill:");
                required_system || latest_tool_state.is_some_and(|start| index >= start)
            })
            .collect();
        let pinned_messages: Vec<_> = self
            .messages
            .iter()
            .zip(&pinned)
            .filter(|(_, pinned)| **pinned)
            .map(|(message, _)| message.clone())
            .collect();
        let pinned_tokens = self.estimate_prompt_tokens(&pinned_messages);
        if pinned_tokens > message_budget {
            let message = format!(
                "context pressure: pinned system/tool state requires {pinned_tokens} tokens plus {tool_tokens} tool-definition tokens but the active budget is {budget}; increase max_context_tokens or shorten required state"
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
        let reference_reserve = 36u32.min(message_budget.saturating_sub(pinned_tokens));
        let mut remaining = message_budget
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
            let digest = ring::digest::digest(&ring::digest::SHA256, spill_json.as_bytes())
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let digest_prefix = &digest[..16];
            let roles = evicted
                .iter()
                .map(|message| message.role.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(",");
            let mut reference = StandardMessage::system(format!(
                "[Durable context spill: key={key}; sha256-prefix={digest_prefix}; messages={}; roles={roles}. Page in with StorageGet before relying on omitted detail.]",
                evicted.len()
            ));
            if self.estimate_prompt_tokens(std::slice::from_ref(&reference)) > reference_reserve {
                reference = StandardMessage::system(format!(
                    "[Context spill: key={key}; sha256-prefix={digest_prefix}; n={}]",
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
            let active_message_tokens = self.estimate_prompt_tokens(&compacted);
            let active_tokens = active_message_tokens.saturating_add(tool_tokens);
            if active_message_tokens <= message_budget {
                if let Err(error) = self.context_manager.store_context_spill(
                    self.agent_id,
                    &key,
                    &spill_json,
                    &digest,
                ) {
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
                "context pressure: durable reference plus pinned state requires {active_message_tokens} tokens plus {tool_tokens} tool-definition tokens but budget is {budget}"
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

    /// Remove the current event channel after a request-scoped stream ends.
    pub fn clear_event_channel(&mut self) {
        self.event_tx = None;
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
        let tools = self
            .tool_registry
            .definitions_for_agent(&self.syscall_gate, self.agent_id);
        let mut total_tokens: u32 = seed_tokens;
        let mut tool_calls_made: usize = seed_tool_calls;

        // A pause can land after an assistant response declared several tool
        // calls but before all of them ran. Completed results are already in
        // `messages`; execute only the missing ids before asking the model
        // again. This is exactly-once within a persisted checkpoint. A process
        // crash inside an external side effect is necessarily at-least-once
        // unless that tool implements its own idempotency key.
        let pending_tool_calls = self.pending_tool_calls();
        for (index, tool_call) in pending_tool_calls.iter().enumerate() {
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
            if self.tool_call_limit_reached(tool_calls_made) {
                return self
                    .stop_at_tool_call_limit(
                        &pending_tool_calls[index..],
                        tool_calls_made,
                        total_tokens,
                        usage,
                    )
                    .await;
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
            self.compact_to_token_budget(&tools).await?;

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
                        self.save_conversation()?;
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
                let (_charged_usd, charged_micros) = budget.record_usage_charge(
                    self.agent_id,
                    &call.provider_id,
                    &call.model_id,
                    call.usage,
                );
                usage.charged_cost_micros =
                    usage.charged_cost_micros.saturating_add(charged_micros);
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
                self.save_conversation()?;
                return Ok(TurnResult::Completed(output));
            }

            // Act: execute tool calls (native, or shim-recovered from plaintext).
            // For shim-recovered calls the model's prose is preserved as the
            // assistant content; the structured calls are attached so the tool
            // results that follow are correctly paired with this turn.
            let mut assistant_msg = StandardMessage::assistant(&response.content);
            assistant_msg.tool_calls = Some(tool_calls.clone());
            self.messages.push(assistant_msg);

            for (index, tool_call) in tool_calls.iter().enumerate() {
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
                if self.tool_call_limit_reached(tool_calls_made) {
                    return self
                        .stop_at_tool_call_limit(
                            &tool_calls[index..],
                            tool_calls_made,
                            total_tokens,
                            usage,
                        )
                        .await;
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

    fn tool_call_limit_reached(&self, tool_calls_made: usize) -> bool {
        self.max_tool_calls_per_turn > 0 && tool_calls_made >= self.max_tool_calls_per_turn
    }

    /// Finish a logical turn before any over-limit tool reaches authorization
    /// or a resource provider. Every skipped call receives an explicit tool
    /// result so it cannot be mistaken for unfinished checkpoint work and
    /// executed at the beginning of the next turn.
    async fn stop_at_tool_call_limit(
        &mut self,
        skipped_calls: &[crate::connector::ToolCall],
        tool_calls_made: usize,
        tokens_used: u32,
        usage: UsageTelemetry,
    ) -> Result<TurnResult, KernelError> {
        let content = format!(
            "Stopped before tool call: per-turn tool-call limit of {} reached.",
            self.max_tool_calls_per_turn
        );
        for tool_call in skipped_calls {
            self.messages.push(StandardMessage::tool_result(
                &tool_call.id,
                format!("Tool '{}' was not executed: {content}", tool_call.name),
            ));
        }
        let output = self.output(content, tool_calls_made, tokens_used, usage);
        self.emit(StreamEvent::Done(output.clone())).await;
        self.save_conversation()?;
        Ok(TurnResult::Completed(output))
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

    /// Send to the LLM with transient-only retry and filter orphaned tool
    /// messages before provider I/O.
    async fn send_with_retry(
        &self,
        tools: &[crate::connector::ToolDefinition],
    ) -> Result<ProviderCall, KernelError> {
        if self.max_output_tokens_per_request > 0 && !self.session.enforces_max_output_tokens() {
            return Err(KernelError::Policy(format!(
                "provider session {}/{} does not enforce the configured max_output_tokens_per_request={}; bounded token admission refuses to call it",
                self.session.provider_id(),
                self.session.model_id(),
                self.max_output_tokens_per_request
            )));
        }
        // Filter messages: remove tool results that don't have a preceding tool_calls message
        let clean_messages = self.clean_messages();
        let estimated_input_tokens = self
            .estimate_prompt_tokens(&clean_messages)
            .saturating_add(Self::conservative_tool_tokens(tools));
        let estimated_admission_tokens =
            estimated_input_tokens.saturating_add(self.max_output_tokens_per_request);
        let provider_attempt_budget = self.session.max_provider_attempts().max(1);
        let estimated_attempt_tokens = u64::from(estimated_admission_tokens)
            .saturating_mul(u64::from(provider_attempt_budget));

        let mut last_err = None;
        let mut provider_latency_ms = 0u64;
        let mut completed_provider_attempts = 0u32;
        let max_attempts = if self.session.handles_retries() {
            1
        } else {
            LLM_RETRIES
        };
        for attempt in 0..max_attempts {
            if attempt > 0 {
                let delay = tokio::time::Duration::from_millis(500 * (1 << attempt));
                tokio::select! {
                    _ = self.cancel_token.cancelled() => {
                        return Err(KernelError::Policy(
                            "execution cancelled during provider retry backoff".into(),
                        ));
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            let _context_admission = match &self.context_admission {
                Some((manager, tenant_id)) => match manager.try_admit(
                    self.agent_id,
                    tenant_id,
                    u64::from(estimated_input_tokens),
                ) {
                    Ok(admission) => Some(admission),
                    Err(message) => {
                        let _ = self.context_manager.record_context_pressure(
                            self.agent_id,
                            estimated_input_tokens,
                            self.context_budget_tokens,
                            0,
                            Some(&message),
                        );
                        return Err(KernelError::Policy(message));
                    }
                },
                None => None,
            };
            // A cgroup can be reassigned while quota admission waits. Snapshot,
            // reserve every stable scope atomically, then verify and mark the
            // receipt in flight under the gate's membership-mutation lock. A
            // stale snapshot is fully refunded and retried without consuming a
            // provider retry attempt.
            let mut membership_retries = 0u8;
            let (rate_guard, _llm_core) = loop {
                let (quota_snapshot, mut membership_changes) = match &self.rate_limiter {
                    Some(_) => {
                        // Subscribe first. The receiver carries the exact
                        // per-agent revision, so a move before, during, or
                        // after the snapshot cannot be lost.
                        let changes = self
                            .syscall_gate
                            .cgroup_quota_changes(self.agent_id)
                            .map_err(|denial| KernelError::Policy(denial.message()))?;
                        let snapshot = self
                            .syscall_gate
                            .cgroup_quota_constraints(self.agent_id)
                            .map_err(|denial| KernelError::Policy(denial.message()))?;
                        (Some(snapshot), Some(changes))
                    }
                    None => (None, None),
                };
                let admission = match (&self.rate_limiter, quota_snapshot.as_ref()) {
                    (Some(limiter), Some(snapshot)) => limiter
                        .try_acquire_attempts_with_cgroups_cancellable(
                            u64::from(provider_attempt_budget),
                            estimated_attempt_tokens,
                            &snapshot.constraints,
                            Some((
                                membership_changes
                                    .as_mut()
                                    .expect("a quota snapshot always has a revision receiver"),
                                snapshot.membership_revision,
                            )),
                            &self.cancel_token,
                        )
                        .await
                        .map(Some),
                    _ => Ok(None),
                };
                let mut guard = match admission {
                    Ok(guard) => guard,
                    Err(crate::rate_limit::RateLimitError::CgroupMembershipChanged) => {
                        membership_retries = membership_retries.saturating_add(1);
                        if membership_retries >= 8 {
                            return Err(KernelError::Policy(
                                "cgroup membership changed repeatedly during provider admission"
                                    .into(),
                            ));
                        }
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let llm_core = match &self.llm_scheduler {
                    Some((scheduler, pid, nice)) => {
                        if let Some(changes) = membership_changes.as_mut() {
                            let core = tokio::select! {
                                biased;
                                changed = changes.changed() => {
                                    let _ = changed;
                                    guard
                                        .expect(
                                            "membership changes are watched only with a quota guard",
                                        )
                                        .refund()?;
                                    membership_retries = membership_retries.saturating_add(1);
                                    if membership_retries >= 8 {
                                        return Err(KernelError::Policy(
                                            "cgroup membership changed repeatedly during provider admission"
                                                .into(),
                                        ));
                                    }
                                    continue;
                                }
                                core = scheduler.acquire_cancellable(
                                    *pid,
                                    *nice,
                                    &self.cancel_token,
                                ) => core.map_err(KernelError::Scheduler)?,
                            };
                            Some(core)
                        } else {
                            Some(
                                scheduler
                                    .acquire_cancellable(*pid, *nice, &self.cancel_token)
                                    .await
                                    .map_err(KernelError::Scheduler)?,
                            )
                        }
                    }
                    None => None,
                };
                if self.cancel_token.is_cancelled() {
                    return Err(KernelError::Policy(
                        "execution cancelled before provider invocation".into(),
                    ));
                }

                let Some(snapshot) = quota_snapshot else {
                    break (guard, llm_core);
                };
                let mark_result = self.syscall_gate.with_verified_cgroup_quota_snapshot(
                    self.agent_id,
                    snapshot.membership_revision,
                    || {
                        guard
                            .as_mut()
                            .expect("a quota snapshot always has a rate-limit guard")
                            .mark_invoked()
                    },
                );
                match mark_result {
                    Ok(Ok(())) => break (guard, llm_core),
                    Ok(Err(error)) => return Err(error.into()),
                    Err(crate::syscall_gate::GateDenial::CgroupMembershipChanged) => {
                        guard
                            .expect("a stale quota snapshot always has a rate-limit guard")
                            .refund()?;
                        drop(llm_core);
                        membership_retries = membership_retries.saturating_add(1);
                        if membership_retries >= 8 {
                            return Err(KernelError::Policy(
                                "cgroup membership changed repeatedly during provider admission"
                                    .into(),
                            ));
                        }
                    }
                    Err(denial) => {
                        guard
                            .expect("a rejected quota snapshot always has a rate-limit guard")
                            .refund()?;
                        return Err(KernelError::Policy(denial.message()));
                    }
                }
            };
            let started = std::time::Instant::now();
            let (provider_events_tx, mut provider_events_rx) =
                mpsc::channel(crate::wire_io::STREAM_EVENT_BUFFER_CAPACITY);
            let send = self.session.send_streaming_events_controlled(
                clean_messages.clone(),
                tools,
                crate::connector::LlmRequestOptions {
                    max_output_tokens: (self.max_output_tokens_per_request > 0)
                        .then_some(self.max_output_tokens_per_request),
                    timeout: self.provider_request_timeout,
                },
                &self.cancel_token,
                crate::connector::ProviderEventSink::new(provider_events_tx),
            );
            tokio::pin!(send);
            let mut provider_events_open = true;
            let result = loop {
                tokio::select! {
                    biased;
                    event = provider_events_rx.recv(), if provider_events_open => {
                        match event {
                            Some(crate::connector::ProviderStreamEvent::TextDelta(delta)) => {
                                self.emit(StreamEvent::Token(delta)).await;
                            }
                            None => provider_events_open = false,
                        }
                    }
                    result = &mut send => {
                        while let Ok(crate::connector::ProviderStreamEvent::TextDelta(delta)) =
                            provider_events_rx.try_recv()
                        {
                            self.emit(StreamEvent::Token(delta)).await;
                        }
                        break result;
                    }
                }
            };
            provider_latency_ms = provider_latency_ms
                .saturating_add(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            drop(_llm_core);
            match result {
                Ok(response) => {
                    let usage = if response.usage.provider_reported && response.usage.total() > 0 {
                        let cached_tokens = response
                            .usage
                            .cached_tokens
                            .min(response.usage.input_tokens);
                        crate::connector::LlmUsage {
                            input_tokens: response.usage.input_tokens,
                            output_tokens: response.usage.output_tokens,
                            cached_tokens,
                            // Malformed cached>input data is clamped before
                            // billing and marked as hybrid estimated usage.
                            provider_reported: cached_tokens == response.usage.cached_tokens,
                        }
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
                    let current_send_attempts = self.session.last_attempts().unwrap_or(1).max(1);
                    if let Some(guard) = rate_guard {
                        // Quota enforcement is deliberately stricter than
                        // invoice accounting. A provider cannot refund below
                        // the kernel's complete serialized-prompt floor, while
                        // billing and user-facing telemetry retain the
                        // provider-reported usage used by the invoice.
                        let successful_attempt_tokens = usage
                            .total()
                            .max(estimated_input_tokens.saturating_add(usage.output_tokens));
                        let failed_attempt_tokens = u64::from(estimated_admission_tokens)
                            .saturating_mul(u64::from(current_send_attempts.saturating_sub(1)));
                        let quota_tokens = u64::from(successful_attempt_tokens)
                            .saturating_add(failed_attempt_tokens);
                        guard.reconcile_attempts(u64::from(current_send_attempts), quota_tokens)?;
                    }
                    let (provider_id, model_id) =
                        self.session.last_attribution().unwrap_or_else(|| {
                            (
                                self.session.provider_id().clone(),
                                self.session.model_id().to_string(),
                            )
                        });
                    let attempts =
                        completed_provider_attempts.saturating_add(current_send_attempts);
                    return Ok(ProviderCall {
                        response,
                        usage,
                        provider_id,
                        model_id,
                        attempts,
                        retries: attempts.saturating_sub(1),
                        latency_ms: provider_latency_ms,
                    });
                }
                Err(e) => {
                    let observed_attempts = self.session.last_attempts().unwrap_or(1);
                    if let Some(guard) = rate_guard {
                        if observed_attempts > 0 {
                            let conservative_tokens = u64::from(estimated_admission_tokens)
                                .saturating_mul(u64::from(observed_attempts));
                            guard.reconcile_attempts(
                                u64::from(observed_attempts),
                                conservative_tokens,
                            )?;
                        } else {
                            guard.retain_estimate()?;
                        }
                    }
                    completed_provider_attempts =
                        completed_provider_attempts.saturating_add(observed_attempts);
                    if !crate::connector::is_transient(&e) {
                        return Err(KernelError::Connector(e));
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(KernelError::Connector(last_err.unwrap()))
    }

    /// Execute a tool call, returning the result string (or error message for LLM recovery).
    ///
    /// When a `SyscallGate` is installed, every call is screened for namespace
    /// visibility, capabilities, MAC, exact approval, valid cgroup membership,
    /// and concurrent-tool capacity. A denial is surfaced to the LLM as a tool
    /// error so the model can recover without the kernel trusting it to obey
    /// policy.
    async fn execute_tool(&self, tool_call: &crate::connector::ToolCall) -> String {
        // Resolve action, capabilities, and resource using the binding's
        // validated declaration. Unknown tools and malformed resource arguments
        // fail before policy evaluation or provider execution.
        let (prepared_tool, _tool_slot) = match self
            .tool_registry
            .authorize_and_acquire_call(
                &self.syscall_gate,
                self.agent_id,
                &tool_call.name,
                &tool_call.arguments,
            )
            .await
        {
            Ok((prepared, slot)) => (prepared, slot),
            Err(crate::tools::ToolAuthorizationError::InvalidDeclaration(error))
                if error == crate::tools::TOOL_NOT_FOUND_ERROR =>
            {
                return format!(
                    "Tool not found. Available tools: {}",
                    self.tool_registry
                        .definitions_for_agent(&self.syscall_gate, self.agent_id)
                        .iter()
                        .map(|tool| tool.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Err(error) => return format!("Tool '{}' denied by kernel: {error}", tool_call.name),
        };

        let result = match self.resource_broker.execute(prepared_tool.request).await {
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
        };

        result
    }

    /// Get the current message history.
    pub fn messages(&self) -> &[StandardMessage] {
        &self.messages
    }

    /// Save the current conversation to SQLite.
    fn save_conversation(&self) -> Result<(), KernelError> {
        self.context_manager
            .save_conversation(&self.conversation_id, self.agent_id, &self.messages)
            .map_err(KernelError::Context)
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

    struct ToolCatalogSession {
        seen_tools: Arc<std::sync::Mutex<Vec<String>>>,
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for ToolCatalogSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }

        async fn send_with_tools(
            &self,
            _messages: Vec<StandardMessage>,
            tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            *self.seen_tools.lock().unwrap() = tools.iter().map(|tool| tool.name.clone()).collect();
            Ok(LlmResponse {
                content: "done".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 1,
                usage: LlmUsage::reported(0, 1, 0),
                tool_calls: Vec::new(),
            })
        }

        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
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

    fn counting_broker(agent_id: AgentId, executions: Arc<AtomicUsize>) -> Arc<dyn ResourceBroker> {
        use crate::resources::ResourceBrokerImpl;
        let perms = Arc::new(PermissionManager::new());
        crate::permissions::PermissionSystem::assign_profile(
            perms.as_ref(),
            agent_id,
            &"full-access".to_string(),
        );
        let broker = ResourceBrokerImpl::new_unconfined(perms);
        struct CountingFs {
            executions: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl ResourceProvider for CountingFs {
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
                self.executions.fetch_add(1, Ordering::SeqCst);
                Ok(serde_json::json!({"content": "counted"}))
            }
        }
        broker.register_provider(Box::new(CountingFs { executions }));
        Arc::new(broker)
    }

    struct SequencedSession {
        responses: Vec<LlmResponse>,
        calls: Arc<AtomicUsize>,
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for SequencedSession {
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
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.responses.get(index).cloned().unwrap_or(LlmResponse {
                content: "done".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 1,
                usage: LlmUsage::reported(0, 1, 0),
                tool_calls: Vec::new(),
            }))
        }

        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    fn tool_response(ids: &[&str]) -> LlmResponse {
        LlmResponse {
            content: String::new(),
            finish_reason: Some("tool_calls".into()),
            tokens_used: 1,
            usage: LlmUsage::reported(0, 1, 0),
            tool_calls: ids
                .iter()
                .map(|id| ToolCall {
                    id: (*id).into(),
                    name: "read_file".into(),
                    arguments: serde_json::json!({"path": format!("/tmp/{id}")}),
                })
                .collect(),
        }
    }

    fn content_response(content: &str) -> LlmResponse {
        LlmResponse {
            content: content.into(),
            finish_reason: Some("stop".into()),
            tokens_used: 1,
            usage: LlmUsage::reported(0, 1, 0),
            tool_calls: Vec::new(),
        }
    }

    #[tokio::test]
    async fn executor_does_not_advertise_foreign_namespace_tools_to_the_llm() {
        use crate::agent_struct::CapabilitySet;
        use crate::cgroups::CgroupManager;
        use crate::syscall_gate::SyscallGate;

        let agent_id = uuid::Uuid::new_v4();
        let gate = Arc::new(SyscallGate::with_mac(
            Arc::new(CgroupManager::new()),
            false,
            Vec::new(),
        ));
        gate.register_agent(agent_id, CapabilitySet::all(), None);
        gate.register_tool_namespace("read_file", 42);
        let seen_tools = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut executor = AgentExecutor::new(
            agent_id,
            Box::new(ToolCatalogSession {
                seen_tools: seen_tools.clone(),
                id: "catalog".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            gate,
            "test".into(),
        );

        let output = executor.run("list visible tools").await.unwrap();
        assert_eq!(output.content, "done");
        let seen_tools = seen_tools.lock().unwrap();
        assert!(!seen_tools.iter().any(|tool| tool == "read_file"));
        assert!(
            seen_tools.iter().any(|tool| tool == "write_file"),
            "global tools should remain visible to the registered agent"
        );
    }

    #[tokio::test]
    async fn missing_and_foreign_tool_errors_are_indistinguishable() {
        use crate::agent_struct::CapabilitySet;
        use crate::cgroups::CgroupManager;
        use crate::syscall_gate::SyscallGate;

        let agent_id = uuid::Uuid::new_v4();
        let gate = Arc::new(SyscallGate::with_mac(
            Arc::new(CgroupManager::new()),
            false,
            Vec::new(),
        ));
        gate.register_agent(agent_id, CapabilitySet::all(), None);
        gate.register_tool_namespace("read_file", 42);
        let executor = AgentExecutor::new(
            agent_id,
            Box::new(ToolCatalogSession {
                seen_tools: Arc::new(std::sync::Mutex::new(Vec::new())),
                id: "catalog".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            gate,
            "test".into(),
        );

        let missing = executor
            .execute_tool(&ToolCall {
                id: "adversarial-guess".into(),
                name: "does_not_exist".into(),
                arguments: serde_json::json!({}),
            })
            .await;
        let foreign = executor
            .execute_tool(&ToolCall {
                id: "foreign-exact-guess".into(),
                name: "read_file".into(),
                arguments: serde_json::json!({"path": "/tmp/foreign"}),
            })
            .await;
        assert_eq!(missing, foreign);
        assert!(missing.starts_with("Tool not found."));
        assert!(
            !missing.contains("read_file")
                && !missing.contains("does_not_exist")
                && !missing.contains("ns="),
            "tool lookup errors must not reflect guessed or foreign catalog data: {missing}"
        );
        assert!(
            missing.contains("write_file"),
            "visible global tools should remain useful recovery suggestions: {missing}"
        );
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
        let gate = Arc::new(SyscallGate::with_mac(
            Arc::new(CgroupManager::new()),
            false,
            Vec::new(),
        ));
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
    #[test]
    fn structural_prompt_floor_never_counts_less_than_serialized_bytes() {
        let executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(InfiniteToolSession { id: "x".into() }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "SYSTEM".into(),
        );
        let high_entropy = (0..2_048)
            .map(|index| {
                const ASCII: &[u8] =
                    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()[]{}";
                ASCII[(index * 37 + 11) % ASCII.len()] as char
            })
            .collect::<String>();
        let messages = vec![StandardMessage::user(high_entropy)];
        let serialized_bytes = u32::try_from(serde_json::to_vec(&messages).unwrap().len()).unwrap();

        assert!(
            executor.estimate_prompt_tokens(&messages) >= serialized_bytes,
            "the structural floor must never assume fewer than one token per serialized byte"
        );
    }

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
        const CONTEXT_BUDGET: u32 = 300;
        executor.set_context_budget(CONTEXT_BUDGET);
        let (event_tx, mut event_rx) = mpsc::channel(4);
        executor.set_event_channel(event_tx);

        // Ten user messages exceed the byte-conservative structural budget.
        for _ in 0..10 {
            executor
                .messages
                .push(StandardMessage::user("x".repeat(40)));
        }
        let before = executor.messages.len();
        executor.compact_to_token_budget(&[]).await.unwrap();
        let after = executor.messages.len();

        assert!(
            after < before,
            "should page out old messages (was {before})"
        );
        // System prompt is always kept at index 0.
        assert_eq!(executor.messages[0].role, "system");
        assert_eq!(executor.messages[0].content, "SYSTEM PROMPT");
        assert!(executor.estimate_prompt_tokens(&executor.messages) <= CONTEXT_BUDGET);
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
        assert_eq!(stats.budget_tokens, CONTEXT_BUDGET);
        assert_eq!(stats.spill_count, 1);
        assert!(stats.evicted_messages > 0);
        assert_eq!(stats.stored_spills, 1);
        assert!(stats.stored_spill_bytes > 0);
        assert_eq!(stats.error_count, 0);
        assert!(matches!(
            event_rx.try_recv().unwrap(),
            StreamEvent::ContextPressure {
                budget_tokens: CONTEXT_BUDGET,
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
        executor.compact_to_token_budget(&[]).await.unwrap();
        assert_eq!(executor.messages.len(), n, "budget 0 must not trim");
    }

    #[tokio::test]
    async fn context_budget_includes_complete_tool_schema_overhead() {
        let agent_id = uuid::Uuid::new_v4();
        let context = mock_context_manager();
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            Box::new(InfiniteToolSession { id: "x".into() }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            context.clone(),
            "SYSTEM".into(),
        );
        let tools = vec![ToolDefinition {
            name: "large_schema".into(),
            description: "d".repeat(90),
            parameters: serde_json::json!({
                "type": "object",
                "description": "s".repeat(120),
            }),
        }];
        let tool_tokens = AgentExecutor::conservative_serialized_tokens(&tools);
        let budget = tool_tokens.saturating_add(300);
        executor.set_context_budget(budget);
        for _ in 0..12 {
            executor
                .messages
                .push(StandardMessage::user("history".repeat(20)));
        }

        executor.compact_to_token_budget(&tools).await.unwrap();
        let total = executor
            .estimate_prompt_tokens(&executor.messages)
            .saturating_add(tool_tokens);
        assert!(total <= budget, "{total} must fit within {budget}");
        assert_eq!(
            context
                .context_pressure_stats(agent_id)
                .unwrap()
                .active_tokens,
            total
        );

        let mut one_message = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(InfiniteToolSession { id: "x".into() }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "SYSTEM".into(),
        );
        one_message.set_context_budget(tool_tokens.saturating_sub(1));
        let error = one_message
            .compact_to_token_budget(&tools)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("tool definitions require"));
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
        let error = executor.compact_to_token_budget(&[]).await.unwrap_err();
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
    async fn compaction_is_lossless_and_keeps_required_system_and_tool_state_active() {
        let context = mock_context_manager();
        let agent_id = uuid::Uuid::new_v4();
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            Box::new(InfiniteToolSession { id: "x".into() }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            context.clone(),
            "ROOT INSTRUCTION".into(),
        );
        executor
            .messages
            .push(StandardMessage::system("REQUIRED POLICY"));
        executor.messages.push(StandardMessage {
            role: "assistant".into(),
            content: "earlier tool transaction".into(),
            tool_call_id: None,
            tool_calls: Some(vec![ToolCall {
                id: "earlier-call".into(),
                name: "search".into(),
                arguments: serde_json::json!({"query": "history"}),
            }]),
        });
        executor.messages.push(StandardMessage::tool_result(
            "earlier-call",
            "earlier-result",
        ));
        for index in 0..20 {
            executor.messages.push(StandardMessage::user(format!(
                "historical-message-{index}-{}",
                "x".repeat(80)
            )));
        }
        executor.messages.push(StandardMessage {
            role: "assistant".into(),
            content: "calling tool".into(),
            tool_call_id: None,
            tool_calls: Some(vec![ToolCall {
                id: "required-call".into(),
                name: "read_file".into(),
                arguments: serde_json::json!({"path": "/required"}),
            }]),
        });
        executor.messages.push(StandardMessage::tool_result(
            "required-call",
            "required-result",
        ));
        let original = executor.messages.clone();
        executor.set_context_budget(900);
        executor.compact_to_token_budget(&[]).await.unwrap();

        assert!(executor
            .messages
            .iter()
            .any(|message| message.content == "ROOT INSTRUCTION"));
        assert!(executor
            .messages
            .iter()
            .any(|message| message.content == "REQUIRED POLICY"));
        assert!(executor.messages.iter().any(|message| {
            message
                .tool_calls
                .as_ref()
                .is_some_and(|calls| calls.iter().any(|call| call.id == "required-call"))
        }));
        assert!(executor.messages.iter().any(|message| {
            message.tool_call_id.as_deref() == Some("required-call")
                && message.content == "required-result"
        }));

        let key = context
            .kv_list(agent_id)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let spilled: Vec<StandardMessage> =
            serde_json::from_str(&context.kv_get(agent_id, &key).unwrap().unwrap()).unwrap();
        let active_without_reference = executor
            .messages
            .iter()
            .filter(|message| !message.content.starts_with("[Durable context spill:"))
            .filter(|message| !message.content.starts_with("[Context spill:"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            active_without_reference.len() + spilled.len(),
            original.len(),
            "compaction must not drop or synthesize source messages"
        );
        for message in original {
            assert!(
                active_without_reference.contains(&message) || spilled.contains(&message),
                "every source message must remain active or round-trip from the durable spill"
            );
        }
    }

    #[tokio::test]
    async fn compaction_quality_regression_measures_recall_loss_and_page_in_recovery() {
        const REQUIRED_FACT: &str = "deployment-codeword=ORCHID-731";
        let context = mock_context_manager();
        let agent_id = uuid::Uuid::new_v4();
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            Box::new(InfiniteToolSession { id: "x".into() }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            context.clone(),
            "ROOT".into(),
        );
        executor.messages.push(StandardMessage::user(REQUIRED_FACT));
        for index in 0..20 {
            executor.messages.push(StandardMessage::user(format!(
                "later-history-{index}-{}",
                "x".repeat(80)
            )));
        }
        let recalls_fact = |messages: &[StandardMessage]| {
            u64::from(
                messages
                    .iter()
                    .any(|message| message.content.contains(REQUIRED_FACT)),
            )
        };
        let baseline_score = recalls_fact(&executor.messages);
        executor.set_context_budget(300);
        executor.compact_to_token_budget(&[]).await.unwrap();
        let active_score = recalls_fact(&executor.messages);
        let key = context.kv_list(agent_id).unwrap().remove(0);
        let paged_in: Vec<StandardMessage> =
            serde_json::from_str(&context.kv_get(agent_id, &key).unwrap().unwrap()).unwrap();
        let page_in_score = recalls_fact(&paged_in);

        assert_eq!(baseline_score, 1);
        assert_eq!(
            active_score, 0,
            "the suite must detect the known active-recall penalty of explicit compaction"
        );
        assert_eq!(
            page_in_score, 1,
            "verified page-in must restore exact recall for the evicted fact"
        );
    }

    #[tokio::test]
    async fn live_provider_path_applies_and_releases_active_prompt_admission() {
        let agent_id = uuid::Uuid::new_v4();
        let manager = Arc::new(crate::context_paging::ActiveContextManager::new(
            crate::context_paging::ActiveContextLimits {
                per_agent_tokens: 1,
                per_tenant_tokens: 0,
                global_tokens: 0,
            },
        ));
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            Box::new(InfiniteToolSession { id: "x".into() }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "required system prompt".into(),
        );
        executor.set_context_admission(manager.clone(), "tenant-a");
        let error = match executor.send_with_retry(&[]).await {
            Ok(_) => panic!("oversized active prompt must be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("active prompt admission would use"));
        let rejected = manager.usage(agent_id, "tenant-a");
        assert_eq!(rejected.agent_tokens, 0);
        assert_eq!(rejected.rejection_count, 1);

        let permissive = Arc::new(crate::context_paging::ActiveContextManager::new(
            crate::context_paging::ActiveContextLimits {
                per_agent_tokens: 10_000,
                per_tenant_tokens: 10_000,
                global_tokens: 10_000,
            },
        ));
        executor.set_context_admission(permissive.clone(), "tenant-a");
        executor.send_with_retry(&[]).await.unwrap();
        let released = permissive.usage(agent_id, "tenant-a");
        assert_eq!(released.agent_tokens, 0);
        assert_eq!(released.tenant_tokens, 0);
        assert_eq!(released.global_tokens, 0);
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
        // The response is priced from the byte-conservative input floor plus
        // provider output, so the charged amount is exact but intentionally
        // larger than the old output-only fixture value.
        assert!(budget.global_spent_usd() > 0.004);
        assert!((budget.global_spent_usd() - output.estimated_cost_usd).abs() < f64::EPSILON);
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
        assert_eq!(output.usage.output_tokens, 35);
        assert_eq!(
            output.tokens_used,
            output
                .usage
                .input_tokens
                .saturating_add(output.usage.output_tokens)
        );
    }

    #[tokio::test]
    async fn per_turn_limit_stops_multi_call_response_without_extra_side_effects() {
        let agent_id = uuid::Uuid::new_v4();
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let tool_executions = Arc::new(AtomicUsize::new(0));
        let session = Box::new(SequencedSession {
            responses: vec![
                tool_response(&["multi-1", "multi-2"]),
                content_response("must not be requested"),
            ],
            calls: provider_calls.clone(),
            id: "mock".into(),
        });
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            counting_broker(agent_id, tool_executions.clone()),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        executor.set_max_tool_calls(1);

        let output = executor.run("make two calls").await.unwrap();

        assert_eq!(output.tool_calls_made, 1);
        assert!(output.content.contains("tool-call limit of 1"));
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(tool_executions.load(Ordering::SeqCst), 1);
        assert!(executor.messages().iter().any(|message| {
            message.tool_call_id.as_deref() == Some("multi-2")
                && message.content.contains("was not executed")
        }));
    }

    #[tokio::test]
    async fn per_turn_limit_accumulates_across_llm_rounds() {
        let agent_id = uuid::Uuid::new_v4();
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let tool_executions = Arc::new(AtomicUsize::new(0));
        let session = Box::new(SequencedSession {
            responses: vec![
                tool_response(&["round-1"]),
                tool_response(&["round-2"]),
                content_response("must not be requested"),
            ],
            calls: provider_calls.clone(),
            id: "mock".into(),
        });
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            counting_broker(agent_id, tool_executions.clone()),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        executor.set_max_tool_calls(1);

        let output = executor.run("keep calling").await.unwrap();

        assert_eq!(output.tool_calls_made, 1);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
        assert_eq!(tool_executions.load(Ordering::SeqCst), 1);
        assert!(executor.messages().iter().any(|message| {
            message.tool_call_id.as_deref() == Some("round-2")
                && message.content.contains("was not executed")
        }));
    }

    #[tokio::test]
    async fn zero_per_turn_limit_means_unlimited() {
        let agent_id = uuid::Uuid::new_v4();
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let tool_executions = Arc::new(AtomicUsize::new(0));
        let session = Box::new(SequencedSession {
            responses: vec![
                tool_response(&["round-1"]),
                tool_response(&["round-2"]),
                content_response("finished"),
            ],
            calls: provider_calls.clone(),
            id: "mock".into(),
        });
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            counting_broker(agent_id, tool_executions.clone()),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        executor.set_max_tool_calls(0);

        let output = executor.run("keep calling").await.unwrap();

        assert_eq!(output.content, "finished");
        assert_eq!(output.tool_calls_made, 2);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 3);
        assert_eq!(tool_executions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn per_turn_limit_resets_for_each_new_user_turn() {
        let agent_id = uuid::Uuid::new_v4();
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let tool_executions = Arc::new(AtomicUsize::new(0));
        let session = Box::new(SequencedSession {
            responses: vec![
                tool_response(&["turn-1"]),
                content_response("first done"),
                tool_response(&["turn-2"]),
                content_response("second done"),
            ],
            calls: provider_calls,
            id: "mock".into(),
        });
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            counting_broker(agent_id, tool_executions.clone()),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        executor.set_max_tool_calls(1);

        let first = executor.run("first turn").await.unwrap();
        let second = executor.run("second turn").await.unwrap();

        assert_eq!(first.content, "first done");
        assert_eq!(first.tool_calls_made, 1);
        assert_eq!(second.content, "second done");
        assert_eq!(second.tool_calls_made, 1);
        assert_eq!(tool_executions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn checkpoint_resume_preserves_per_turn_tool_count_at_limit() {
        let agent_id = uuid::Uuid::new_v4();
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let tool_executions = Arc::new(AtomicUsize::new(0));
        let mut assistant = StandardMessage::assistant("another call");
        assistant.tool_calls = Some(tool_response(&["resume-blocked"]).tool_calls);
        let checkpoint = GenerationCheckpoint {
            agent_id,
            conversation_id: "resume-limit".into(),
            user_message: "continue".into(),
            messages: vec![
                StandardMessage::system("SYSTEM"),
                StandardMessage::user("continue"),
                assistant,
            ],
            partial_content: String::new(),
            tool_calls_made: 1,
            tokens_used: 3,
            usage: UsageTelemetry::default(),
        };
        let session = Box::new(SequencedSession {
            responses: vec![content_response("must not be requested")],
            calls: provider_calls.clone(),
            id: "mock".into(),
        });
        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            counting_broker(agent_id, tool_executions.clone()),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        executor.set_max_tool_calls(1);

        let output = match executor.resume(checkpoint).await.unwrap() {
            TurnResult::Completed(output) => output,
            TurnResult::Paused(_) => panic!("limit should complete the turn"),
        };

        assert_eq!(output.tool_calls_made, 1);
        assert!(output.content.contains("tool-call limit of 1"));
        assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
        assert_eq!(tool_executions.load(Ordering::SeqCst), 0);
        assert!(executor.messages().iter().any(|message| {
            message.tool_call_id.as_deref() == Some("resume-blocked")
                && message.content.contains("was not executed")
        }));
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

    struct PermanentFailSession {
        call_count: Arc<AtomicUsize>,
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for PermanentFailSession {
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
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Err(ConnectorError::ProtocolError(
                "permanent authentication failure".into(),
            ))
        }

        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
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
        let limiter = execution_rate_limiter();
        executor.set_rate_limiter(limiter.clone());

        let output = executor.run("test").await.unwrap();
        assert_eq!(output.content, "recovered!");
        assert_eq!(output.usage.llm_requests, 3);
        assert_eq!(output.usage.retries, 2);
        assert_eq!(output.usage.provider_reported_requests, 0);
        assert_eq!(output.usage.estimated_requests, 1);
        assert!(output.usage.input_tokens > 0);
        assert_eq!(output.usage.output_tokens, 10);
        assert_eq!(
            limiter.try_stats().unwrap().requests_this_minute,
            3,
            "one durable request receipt must exist for each outbound attempt"
        );
    }

    #[tokio::test]
    async fn permanent_provider_failure_is_not_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let limiter = execution_rate_limiter();
        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(PermanentFailSession {
                call_count: calls.clone(),
                id: "mock".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        executor.set_rate_limiter(limiter.clone());

        let error = executor.run("test").await.unwrap_err();

        assert!(matches!(
            error,
            KernelError::Connector(ConnectorError::ProtocolError(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            limiter.try_stats().unwrap().requests_this_minute,
            1,
            "a permanent failure must burn exactly one durable request receipt"
        );
    }

    struct CountingContentSession {
        calls: Arc<AtomicUsize>,
        entered: Option<Arc<tokio::sync::Notify>>,
        release: Option<Arc<tokio::sync::Notify>>,
        fail: bool,
        id: String,
    }

    struct UnderreportingSession {
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for UnderreportingSession {
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
                content: "done".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 2,
                usage: LlmUsage {
                    input_tokens: 1,
                    output_tokens: 2,
                    cached_tokens: 99,
                    provider_reported: true,
                },
                tool_calls: Vec::new(),
            })
        }

        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    struct BoundedOutputSession {
        id: String,
        observed_limit: Arc<std::sync::atomic::AtomicU32>,
    }

    #[async_trait::async_trait]
    impl LlmSession for BoundedOutputSession {
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
                content: "bounded".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 2,
                usage: LlmUsage::reported(1, 2, 0),
                tool_calls: Vec::new(),
            })
        }

        async fn send_with_options(
            &self,
            messages: Vec<StandardMessage>,
            tools: &[ToolDefinition],
            options: crate::connector::LlmRequestOptions,
        ) -> Result<LlmResponse, ConnectorError> {
            self.observed_limit.store(
                options.max_output_tokens.unwrap_or(0),
                std::sync::atomic::Ordering::SeqCst,
            );
            self.send_with_tools(messages, tools).await
        }

        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }

        fn enforces_max_output_tokens(&self) -> bool {
            true
        }
    }

    #[async_trait::async_trait]
    impl LlmSession for CountingContentSession {
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
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(entered) = &self.entered {
                entered.notify_waiters();
            }
            if let Some(release) = &self.release {
                release.notified().await;
            }
            if self.fail {
                Err(ConnectorError::ConnectionFailed(
                    "deterministic provider failure".into(),
                ))
            } else {
                Ok(LlmResponse {
                    content: "done".into(),
                    finish_reason: Some("stop".into()),
                    tokens_used: 7,
                    usage: LlmUsage::reported(5, 7, 0),
                    tool_calls: Vec::new(),
                })
            }
        }

        fn provider_id(&self) -> &crate::ProviderId {
            &self.id
        }
    }

    fn execution_rate_limiter() -> Arc<crate::rate_limit::RateLimiter> {
        Arc::new(
            crate::rate_limit::RateLimiter::with_store(
                crate::rate_limit::RateLimitConfig {
                    rpm: 100,
                    tpm: 10_000,
                    max_concurrent: 4,
                },
                mock_context_manager(),
                Arc::new(crate::quota_clock::ManualQuotaClock::new(0)),
            )
            .expect("the deterministic execution rate limiter must initialize"),
        )
    }

    #[tokio::test]
    async fn provider_usage_cannot_refund_below_the_structural_prompt_floor() {
        let registry = Arc::new(ToolRegistry::new());
        let user_message = "high-entropy:".to_string() + &"A1!z9$".repeat(400);
        let prompt = vec![
            StandardMessage::system("system"),
            StandardMessage::user(&user_message),
        ];
        let structural_floor = AgentExecutor::conservative_serialized_tokens(&prompt)
            .saturating_add((prompt.len() as u32).saturating_mul(4))
            .saturating_add(AgentExecutor::conservative_tool_tokens(
                &registry.definitions(),
            ));
        let limiter = Arc::new(crate::rate_limit::RateLimiter::new(
            crate::rate_limit::RateLimitConfig {
                rpm: 10,
                tpm: 100_000,
                max_concurrent: 2,
            },
        ));
        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(UnderreportingSession { id: "mock".into() }),
            mock_broker(),
            registry,
            mock_context_manager(),
            "system".into(),
        );
        executor.set_rate_limiter(limiter.clone());

        let output = executor.run(&user_message).await.unwrap();

        assert_eq!(output.usage.input_tokens, 1);
        assert_eq!(output.usage.output_tokens, 2);
        assert_eq!(output.usage.cached_tokens, 1);
        assert_eq!(output.usage.provider_reported_requests, 0);
        assert_eq!(output.usage.estimated_requests, 1);
        assert_eq!(
            limiter.try_stats().unwrap().tokens_this_minute,
            u64::from(structural_floor.saturating_add(2))
        );
    }

    #[tokio::test]
    async fn bounded_execution_rejects_sessions_that_ignore_output_options() {
        let limiter = execution_rate_limiter();
        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(UnderreportingSession {
                id: "custom".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "system".into(),
        );
        executor.set_rate_limiter(limiter.clone());
        executor.set_max_output_tokens_per_request(32);

        let error = executor
            .run("must fail before provider admission")
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("does not enforce the configured max_output_tokens_per_request"));
        assert_eq!(limiter.try_stats().unwrap().requests_this_minute, 0);
    }

    #[tokio::test]
    async fn output_allowance_is_reserved_before_io_and_forwarded_to_session() {
        let user_message = "reserve completion room";
        let registry = Arc::new(ToolRegistry::new());
        let prompt = vec![
            StandardMessage::system("system"),
            StandardMessage::user(user_message),
        ];
        let input_floor = AgentExecutor::conservative_serialized_tokens(&prompt)
            .saturating_add((prompt.len() as u32).saturating_mul(4))
            .saturating_add(AgentExecutor::conservative_tool_tokens(
                &registry.definitions(),
            ));
        let output_allowance = 50;
        let observed = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let limiter = Arc::new(crate::rate_limit::RateLimiter::new(
            crate::rate_limit::RateLimitConfig {
                rpm: 10,
                tpm: u64::from(input_floor.saturating_add(output_allowance - 1)),
                max_concurrent: 1,
            },
        ));
        let mut denied = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(BoundedOutputSession {
                id: "bounded".into(),
                observed_limit: observed.clone(),
            }),
            mock_broker(),
            registry.clone(),
            mock_context_manager(),
            "system".into(),
        );
        denied.set_rate_limiter(limiter);
        denied.set_max_output_tokens_per_request(output_allowance);

        assert!(matches!(
            denied.run(user_message).await,
            Err(KernelError::RateLimit(
                crate::rate_limit::RateLimitError::RequestExceedsTpm { .. }
            ))
        ));
        assert_eq!(
            observed.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "provider I/O must not begin when the completion allowance cannot fit"
        );

        let admitted_limiter = Arc::new(crate::rate_limit::RateLimiter::new(
            crate::rate_limit::RateLimitConfig {
                rpm: 10,
                tpm: u64::from(input_floor.saturating_add(output_allowance)),
                max_concurrent: 1,
            },
        ));
        let mut admitted = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(BoundedOutputSession {
                id: "bounded".into(),
                observed_limit: observed.clone(),
            }),
            mock_broker(),
            registry,
            mock_context_manager(),
            "system".into(),
        );
        admitted.set_rate_limiter(admitted_limiter);
        admitted.set_max_output_tokens_per_request(output_allowance);
        admitted.run(user_message).await.unwrap();
        assert_eq!(
            observed.load(std::sync::atomic::Ordering::SeqCst),
            output_allowance
        );
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_llm_core_refunds_quota_without_provider_io() {
        let scheduler = Arc::new(crate::llm_sched::LlmScheduler::new(1));
        let held_core = scheduler.acquire(999, 0).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let limiter = execution_rate_limiter();
        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(CountingContentSession {
                calls: calls.clone(),
                entered: None,
                release: None,
                fail: false,
                id: "mock".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        executor.set_rate_limiter(limiter.clone());
        executor.set_llm_scheduler(scheduler.clone(), 1, 0);
        let cancellation = executor.cancel_token();

        let run = tokio::spawn(async move { executor.run("wait for a core").await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while scheduler.waiting() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("executor should wait for the occupied LLM core");
        cancellation.cancel();
        let output = run.await.unwrap().unwrap();
        drop(held_core);

        assert_eq!(output.content, "Cancelled.");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let stats = limiter.try_stats().unwrap();
        assert_eq!(stats.requests_this_minute, 0);
        assert_eq!(stats.tokens_this_minute, 0);
        assert_eq!(stats.reserved_receipts, 0);
        assert_eq!(stats.in_flight_receipts, 0);
    }

    #[tokio::test]
    async fn cgroup_move_after_reservation_refunds_stale_snapshot_before_provider_io() {
        let scheduler = Arc::new(crate::llm_sched::LlmScheduler::new(1));
        let held_core = scheduler.acquire(999, 0).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let context = mock_context_manager();
        let limiter = Arc::new(
            crate::rate_limit::RateLimiter::with_store(
                crate::rate_limit::RateLimitConfig {
                    rpm: 100,
                    tpm: 100_000,
                    max_concurrent: 4,
                },
                context.clone(),
                Arc::new(crate::quota_clock::SystemQuotaClock::new()),
            )
            .unwrap(),
        );
        let cgroups = Arc::new(crate::cgroups::CgroupManager::new());
        let first_group = cgroups.create(
            "first".into(),
            cgroups.root(),
            crate::cgroups::CgroupLimits {
                tokens_per_min: 10_000,
                ..Default::default()
            },
        );
        let second_group = cgroups.create(
            "second".into(),
            cgroups.root(),
            crate::cgroups::CgroupLimits {
                tokens_per_min: 10_000,
                ..Default::default()
            },
        );
        let gate = Arc::new(crate::syscall_gate::SyscallGate::with_mac(
            cgroups,
            false,
            Vec::new(),
        ));
        let agent_id = uuid::Uuid::new_v4();
        gate.try_register_agent(agent_id, crate::CapabilitySet::all(), Some(first_group))
            .unwrap();
        let mut executor = AgentExecutor::new(
            agent_id,
            Box::new(CountingContentSession {
                calls: calls.clone(),
                entered: None,
                release: None,
                fail: false,
                id: "mock".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            context,
            gate.clone(),
            "test".into(),
        );
        executor.set_rate_limiter(limiter.clone());
        executor.set_llm_scheduler(scheduler.clone(), 1, 0);

        let run = tokio::spawn(async move { executor.run("move while admitted").await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while scheduler.waiting() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("executor should reserve quota before waiting for the core");
        gate.try_set_cgroup(agent_id, second_group).unwrap();
        drop(held_core);

        let output = run.await.unwrap().unwrap();
        assert_eq!(output.content, "done");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let stats = limiter.try_stats().unwrap();
        assert_eq!(
            stats.requests_this_minute, 1,
            "the stale hierarchy reservation must be fully refunded"
        );
        assert_eq!(stats.reconciled_receipts, 1);
        assert_eq!(stats.reserved_receipts, 0);
        assert_eq!(stats.in_flight_receipts, 0);
    }

    #[tokio::test]
    async fn exhausted_cgroup_returns_backpressure_without_epoch_wait_or_provider_io() {
        let clock = Arc::new(crate::quota_clock::ManualQuotaClock::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let context = mock_context_manager();
        let limiter = Arc::new(
            crate::rate_limit::RateLimiter::with_store(
                crate::rate_limit::RateLimitConfig {
                    rpm: 100,
                    tpm: 100_000,
                    max_concurrent: 4,
                },
                context.clone(),
                clock.clone(),
            )
            .unwrap(),
        );
        let cgroups = Arc::new(crate::cgroups::CgroupManager::new());
        let old_group = cgroups.create(
            "old".into(),
            cgroups.root(),
            crate::cgroups::CgroupLimits {
                tokens_per_min: 64,
                ..Default::default()
            },
        );
        let gate = Arc::new(crate::syscall_gate::SyscallGate::with_mac(
            cgroups,
            false,
            Vec::new(),
        ));
        let agent_id = uuid::Uuid::new_v4();
        gate.try_register_agent(agent_id, crate::CapabilitySet::all(), Some(old_group))
            .unwrap();

        let old_constraints = gate.cgroup_quota_constraints(agent_id).unwrap();
        let cancellation = CancellationToken::new();
        let mut fill = limiter
            .acquire_tokens_with_cgroups_cancellable(
                64,
                &old_constraints.constraints,
                None,
                &cancellation,
            )
            .await
            .unwrap();
        fill.mark_invoked().unwrap();
        fill.reconcile(64).unwrap();

        let mut executor = AgentExecutor::new(
            agent_id,
            Box::new(CountingContentSession {
                calls: calls.clone(),
                entered: None,
                release: None,
                fail: false,
                id: "mock".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            context,
            gate.clone(),
            "test".into(),
        );
        executor.set_rate_limiter(limiter.clone());
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            executor.send_with_retry(&[]),
        )
        .await
        .expect("execution admission must return without an epoch wait");
        let Err(error) = result else {
            panic!("exhausted cgroup unexpectedly reached the provider");
        };
        assert!(matches!(
            error,
            KernelError::RateLimit(
                crate::rate_limit::RateLimitError::QuotaExhausted {
                    ref scope_id,
                    ..
                }
            ) if scope_id == "/old"
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(clock.advance(0), 0);
        let stats = limiter.try_stats().unwrap();
        assert_eq!(stats.requests_this_minute, 1);
        assert_eq!(stats.reconciled_receipts, 1);
    }

    #[tokio::test]
    async fn structured_tool_arguments_are_charged_before_provider_io() {
        let calls = Arc::new(AtomicUsize::new(0));
        let context = mock_context_manager();
        let limiter = Arc::new(
            crate::rate_limit::RateLimiter::with_store(
                crate::rate_limit::RateLimitConfig {
                    rpm: 100,
                    tpm: 100_000,
                    max_concurrent: 4,
                },
                context.clone(),
                Arc::new(crate::quota_clock::ManualQuotaClock::new(0)),
            )
            .unwrap(),
        );
        let cgroups = Arc::new(crate::cgroups::CgroupManager::new());
        let tight_group = cgroups.create(
            "tight".into(),
            cgroups.root(),
            crate::cgroups::CgroupLimits {
                tokens_per_min: 500,
                ..Default::default()
            },
        );
        let gate = Arc::new(crate::syscall_gate::SyscallGate::with_mac(
            cgroups,
            false,
            Vec::new(),
        ));
        let agent_id = uuid::Uuid::new_v4();
        gate.try_register_agent(agent_id, crate::CapabilitySet::all(), Some(tight_group))
            .unwrap();
        let mut executor = AgentExecutor::new(
            agent_id,
            Box::new(CountingContentSession {
                calls: calls.clone(),
                entered: None,
                release: None,
                fail: false,
                id: "mock".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            context,
            gate,
            "test".into(),
        );
        executor.set_rate_limiter(limiter.clone());
        let mut assistant = StandardMessage::assistant("calling");
        assistant.tool_calls = Some(vec![ToolCall {
            id: "large-call".into(),
            name: "read_file".into(),
            arguments: serde_json::json!({"payload": "x".repeat(10_000)}),
        }]);
        executor.messages.push(assistant);
        executor
            .messages
            .push(StandardMessage::tool_result("large-call", "done"));

        let error = match executor.send_with_retry(&[]).await {
            Ok(_) => panic!("oversized structured prompt must be denied"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            KernelError::RateLimit(
                crate::rate_limit::RateLimitError::RequestExceedsCgroupTpm { .. }
            )
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let stats = limiter.try_stats().unwrap();
        assert_eq!(stats.requests_this_minute, 0);
        assert_eq!(stats.reserved_receipts, 0);
    }

    #[tokio::test]
    async fn cancellation_after_provider_invocation_reconciles_started_attempt() {
        let calls = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let limiter = execution_rate_limiter();
        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(CountingContentSession {
                calls: calls.clone(),
                entered: Some(entered.clone()),
                release: Some(release),
                fail: false,
                id: "mock".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        executor.set_rate_limiter(limiter.clone());
        let cancellation = executor.cancel_token();

        let run = tokio::spawn(async move { executor.run("cancel after invoke").await });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("provider should be invoked");
        cancellation.cancel();
        let output = run.await.unwrap().unwrap();

        assert_eq!(output.content, "Cancelled.");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let stats = limiter.try_stats().unwrap();
        assert_eq!(stats.requests_this_minute, 1);
        assert!(stats.tokens_this_minute > 0);
        assert_eq!(stats.in_flight_receipts, 0);
        assert_eq!(stats.estimated_receipts, 0);
        assert_eq!(stats.reconciled_receipts, 1);
    }

    #[tokio::test]
    async fn cancellation_during_retry_backoff_creates_no_second_attempt() {
        let calls = Arc::new(AtomicUsize::new(0));
        let first_attempt = Arc::new(tokio::sync::Notify::new());
        let limiter = execution_rate_limiter();
        let mut executor = AgentExecutor::new_unconfined(
            uuid::Uuid::new_v4(),
            Box::new(CountingContentSession {
                calls: calls.clone(),
                entered: Some(first_attempt.clone()),
                release: None,
                fail: true,
                id: "mock".into(),
            }),
            mock_broker(),
            Arc::new(ToolRegistry::new()),
            mock_context_manager(),
            "test".into(),
        );
        executor.set_rate_limiter(limiter.clone());
        let cancellation = executor.cancel_token();

        let run = tokio::spawn(async move { executor.run("cancel retry").await });
        tokio::time::timeout(std::time::Duration::from_secs(1), first_attempt.notified())
            .await
            .expect("first provider attempt should run");
        cancellation.cancel();
        let output = run.await.unwrap().unwrap();

        assert_eq!(output.content, "Cancelled.");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let stats = limiter.try_stats().unwrap();
        assert_eq!(stats.requests_this_minute, 1);
        assert_eq!(stats.estimated_receipts, 0);
        assert_eq!(stats.reconciled_receipts, 1);
        assert_eq!(stats.reserved_receipts, 0);
        assert_eq!(stats.in_flight_receipts, 0);
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
                assert!(last_msg.content.contains("Tool not found."));
                assert!(!last_msg.content.contains("nonexistent_tool"));
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
        let context_budget =
            AgentExecutor::conservative_tool_tokens(&registry.definitions()).saturating_add(300);

        let mut executor = AgentExecutor::new_unconfined(
            agent_id,
            session,
            broker,
            registry,
            ctx_mgr.clone(),
            "test".into(),
        );
        executor.set_context_budget(context_budget);

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
                assert_eq!(output.usage.output_tokens, 35);
                assert_eq!(
                    output.tokens_used,
                    output
                        .usage
                        .input_tokens
                        .saturating_add(output.usage.output_tokens)
                );
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
