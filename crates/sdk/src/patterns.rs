//! Reusable agent **patterns** built on top of [`KernelClient`](crate::KernelClient)
//! and [`Agent`](crate::Agent) — Rust building blocks for orchestrating agents
//! against the kernel, so you compose agent behaviour in Rust rather than reaching
//! for an external framework.
//!
//! Two patterns ship here:
//!
//! * [`ReActLoop`] — a *reason → act → observe* outer loop. It repeatedly drives
//!   an agent turn ([`Agent::send`]); a pluggable [`Reasoner`] inspects each
//!   turn's output and decides whether the agent wants to **call a tool** (the
//!   loop executes it via [`Agent::call_tool`] and feeds the observation back as
//!   the next message) or has produced a **final answer**. The loop is bounded by
//!   a configurable max-iteration count so it can never spin forever.
//!
//! * [`PlannerExecutor`] — a *plan → execute* pattern. A pluggable [`Planner`]
//!   turns a goal into an ordered list of [`Step`]s; each step is then executed in
//!   sequence (a turn or a direct tool call), and the per-step outcomes are
//!   aggregated into a [`PlanRun`].
//!
//! Both patterns orchestrate *real* syscalls through the kernel — the
//! "intelligence" comes from whatever LLM the agent was created against. The
//! [`Reasoner`] / [`Planner`] traits keep the control flow deterministic and
//! unit-testable while leaving the agent itself fully wired.
//!
//! ## Example
//!
//! ```no_run
//! use agent_sdk::{Agent, patterns::{ReActLoop, DirectiveReasoner}};
//!
//! # async fn run() -> Result<(), agent_sdk::SdkError> {
//! let mut agent = Agent::builder()
//!     .name("researcher")
//!     .task("answer the question using tools")
//!     .provider("azure-openai")
//!     .profile("full-access")
//!     .connect("127.0.0.1:7777")
//!     .await?;
//!
//! // The default reasoner reads a `TOOL: <name> <json-args>` / `FINAL: <answer>`
//! // convention out of each turn's content.
//! let outcome = ReActLoop::new(DirectiveReasoner::default())
//!     .max_iterations(6)
//!     .run(&mut agent, "What is in /etc/hostname?")
//!     .await?;
//!
//! println!(
//!     "took {} iterations, {} tool calls",
//!     outcome.iterations,
//!     outcome.tool_calls().count()
//! );
//! println!("answer: {}", outcome.final_answer.unwrap_or_default());
//! # Ok(())
//! # }
//! ```

use serde_json::Value;

use crate::{Agent, MessageResult, SdkError};

/// What a [`Reasoner`] decided the agent wants to do after a turn.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// The agent wants to call `tool` with `args`; the [`ReActLoop`] will execute
    /// it via the kernel and feed the result back as the next observation.
    CallTool {
        /// Tool name (must be one the kernel/gate knows — see `classify_tool`).
        tool: String,
        /// JSON arguments passed straight through to [`Agent::call_tool`].
        args: Value,
    },
    /// The agent produced a final answer; the loop stops and returns it.
    Final {
        /// The final textual answer.
        answer: String,
    },
}

/// Decides, from an agent turn's output, whether to call a tool or finish.
///
/// Implement this to plug in your own parsing/policy (e.g. read structured
/// tool-call metadata, apply a heuristic, or consult another model). The default
/// [`DirectiveReasoner`] reads a simple text convention out of the turn content,
/// which keeps the loop driveable against any LLM without bespoke tool wiring.
pub trait Reasoner {
    /// Inspect the most recent turn (`turn`) — and the iteration index — and
    /// decide the next move. `iteration` starts at 0.
    fn decide(&mut self, iteration: usize, turn: &MessageResult) -> Decision;
}

/// A [`Reasoner`] that reads a line-oriented directive convention out of a turn's
/// content:
///
/// * `TOOL: <name> <json-args>` (args optional; defaults to `{}`) — call a tool.
/// * `FINAL: <text>` — finish with `<text>` as the answer.
///
/// Anything else is treated as a final answer (the whole content), so a plain
/// chat reply terminates the loop gracefully. Prefixes are matched
/// case-insensitively and may appear on any line of the content.
#[derive(Debug, Clone, Default)]
pub struct DirectiveReasoner {
    _priv: (),
}

impl DirectiveReasoner {
    /// Construct the default directive reasoner.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Reasoner for DirectiveReasoner {
    fn decide(&mut self, _iteration: usize, turn: &MessageResult) -> Decision {
        for raw in turn.content.lines() {
            let line = raw.trim();
            if let Some(rest) = strip_prefix_ci(line, "TOOL:") {
                let rest = rest.trim();
                let (tool, args_str) = match rest.split_once(char::is_whitespace) {
                    Some((name, args)) => (name.trim(), args.trim()),
                    None => (rest, ""),
                };
                let args = if args_str.is_empty() {
                    Value::Object(Default::default())
                } else {
                    serde_json::from_str(args_str).unwrap_or(Value::Object(Default::default()))
                };
                return Decision::CallTool {
                    tool: tool.to_string(),
                    args,
                };
            }
            if let Some(rest) = strip_prefix_ci(line, "FINAL:") {
                return Decision::Final {
                    answer: rest.trim().to_string(),
                };
            }
        }
        // No directive ⇒ treat the whole turn as the final answer.
        Decision::Final {
            answer: turn.content.clone(),
        }
    }
}

/// Case-insensitive prefix strip: returns the remainder if `s` starts with
/// `prefix` ignoring ASCII case, else `None`.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// One recorded step of a [`ReActLoop`] run: the turn the agent took and, if the
/// reasoner asked for a tool, the tool call + its observation.
#[derive(Debug, Clone)]
pub struct ReActStep {
    /// The agent's turn output for this iteration.
    pub turn: MessageResult,
    /// If a tool was invoked this iteration: its name, args, and the kernel's
    /// JSON result (or [`None`] if the turn went straight to a final answer).
    pub tool: Option<ToolInvocation>,
}

/// A tool call the loop executed on the agent's behalf and its observation.
#[derive(Debug, Clone)]
pub struct ToolInvocation {
    /// Tool name passed to the kernel.
    pub tool: String,
    /// Arguments passed to the kernel.
    pub args: Value,
    /// The kernel's JSON result for the tool call.
    pub observation: Value,
}

/// The result of running a [`ReActLoop`]: the final answer (if reached), the full
/// transcript of steps, and how many iterations were consumed.
#[derive(Debug, Clone)]
pub struct ReActOutcome {
    /// The final answer, if the loop reached one within the iteration bound;
    /// [`None`] if it hit `max_iterations` first.
    pub final_answer: Option<String>,
    /// Every step taken, in order.
    pub transcript: Vec<ReActStep>,
    /// Number of agent turns executed.
    pub iterations: usize,
}

impl ReActOutcome {
    /// `true` if the loop terminated with a final answer (vs. exhausting the
    /// iteration budget).
    pub fn reached_final(&self) -> bool {
        self.final_answer.is_some()
    }

    /// Iterate over the tool invocations made across the run, in order.
    pub fn tool_calls(&self) -> impl Iterator<Item = &ToolInvocation> {
        self.transcript.iter().filter_map(|s| s.tool.as_ref())
    }
}

/// A *reason → act → observe* loop over an [`Agent`].
///
/// Each iteration drives one agent turn, asks the [`Reasoner`] what to do, and —
/// if a tool is requested — executes it through the kernel and feeds the
/// observation back into the next turn. Bounded by [`max_iterations`](Self::max_iterations).
///
/// Construct with [`ReActLoop::new`], then [`run`](Self::run) it against a live
/// agent and an initial prompt.
pub struct ReActLoop<R: Reasoner> {
    reasoner: R,
    max_iterations: usize,
}

impl<R: Reasoner> ReActLoop<R> {
    /// Create a loop driven by `reasoner`, with a default bound of 8 iterations.
    pub fn new(reasoner: R) -> Self {
        Self {
            reasoner,
            max_iterations: 8,
        }
    }

    /// Set the maximum number of agent turns before the loop gives up (clamped to
    /// at least 1). Prevents an agent that never finalizes from spinning forever.
    pub fn max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max.max(1);
        self
    }

    /// Run the loop against `agent`, starting from `prompt`.
    ///
    /// The first turn is `prompt`; each subsequent turn's message is the previous
    /// tool's observation (serialized JSON, prefixed `OBSERVATION:`). Stops when
    /// the [`Reasoner`] returns [`Decision::Final`] or the iteration bound is hit.
    ///
    /// # Errors
    /// Propagates any [`SdkError`] from the underlying [`Agent::send`] /
    /// [`Agent::call_tool`] syscalls (e.g. a gate denial on the tool call).
    pub async fn run(
        mut self,
        agent: &mut Agent,
        prompt: impl Into<String>,
    ) -> Result<ReActOutcome, SdkError> {
        let mut transcript = Vec::new();
        let mut next_message = prompt.into();

        for iteration in 0..self.max_iterations {
            let turn = agent.send(next_message.clone()).await?;
            match self.reasoner.decide(iteration, &turn) {
                Decision::Final { answer } => {
                    transcript.push(ReActStep { turn, tool: None });
                    return Ok(ReActOutcome {
                        final_answer: Some(answer),
                        transcript,
                        iterations: iteration + 1,
                    });
                }
                Decision::CallTool { tool, args } => {
                    let observation = agent.call_tool(tool.clone(), args.clone()).await?;
                    transcript.push(ReActStep {
                        turn,
                        tool: Some(ToolInvocation {
                            tool,
                            args,
                            observation: observation.clone(),
                        }),
                    });
                    // Feed the observation back as the next turn's input.
                    next_message = format!("OBSERVATION: {observation}");
                }
            }
        }

        Ok(ReActOutcome {
            final_answer: None,
            transcript,
            iterations: self.max_iterations,
        })
    }
}

/// A single planned step for the [`PlannerExecutor`] pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Drive an agent turn with this message and record its output.
    Prompt(String),
    /// Call a tool directly (no LLM turn) with these arguments.
    Tool {
        /// Tool name passed to the kernel.
        tool: String,
        /// JSON arguments for the tool.
        args: Value,
    },
}

/// Produces an ordered plan (a list of [`Step`]s) for a goal.
///
/// Implement this to plug in your own planning policy. A planner can be a fixed
/// recipe, a heuristic, or itself an LLM call that emits steps. The trait is sync
/// and pure so the executor's control flow is deterministically unit-testable.
pub trait Planner {
    /// Produce the steps to accomplish `goal`, in execution order.
    fn plan(&mut self, goal: &str) -> Vec<Step>;
}

/// A [`Planner`] backed by a closure — handy for tests and simple fixed recipes.
pub struct FnPlanner<F: FnMut(&str) -> Vec<Step>>(pub F);

impl<F: FnMut(&str) -> Vec<Step>> Planner for FnPlanner<F> {
    fn plan(&mut self, goal: &str) -> Vec<Step> {
        (self.0)(goal)
    }
}

/// The outcome of executing one [`Step`].
#[derive(Debug, Clone)]
pub enum StepResult {
    /// A [`Step::Prompt`] turn completed with this output.
    Turn(MessageResult),
    /// A [`Step::Tool`] call returned this JSON.
    Tool {
        /// Tool name that was invoked.
        tool: String,
        /// The kernel's JSON result.
        observation: Value,
    },
}

/// The full result of a [`PlannerExecutor`] run: the plan that was produced and
/// the outcome of each executed step, in order.
#[derive(Debug, Clone)]
pub struct PlanRun {
    /// The steps the planner produced.
    pub plan: Vec<Step>,
    /// The result of each executed step (same order/length as `plan`).
    pub results: Vec<StepResult>,
}

impl PlanRun {
    /// Number of steps executed.
    pub fn step_count(&self) -> usize {
        self.results.len()
    }

    /// The textual output of the last `Prompt` step, if any — a convenient
    /// "answer" for plans that end on an LLM turn.
    pub fn final_content(&self) -> Option<&str> {
        self.results.iter().rev().find_map(|r| match r {
            StepResult::Turn(m) => Some(m.content.as_str()),
            StepResult::Tool { .. } => None,
        })
    }
}

/// A *plan → execute* pattern over an [`Agent`].
///
/// A [`Planner`] turns the goal into [`Step`]s; [`run`](Self::run) then executes
/// each step in sequence against the agent (a turn or a direct tool call) and
/// aggregates the outcomes into a [`PlanRun`].
pub struct PlannerExecutor<P: Planner> {
    planner: P,
}

impl<P: Planner> PlannerExecutor<P> {
    /// Create an executor driven by `planner`.
    pub fn new(planner: P) -> Self {
        Self { planner }
    }

    /// Plan for `goal`, then execute every step in order against `agent`.
    ///
    /// # Errors
    /// Propagates the first [`SdkError`] from any step's [`Agent::send`] /
    /// [`Agent::call_tool`] syscall (the run stops at the failing step).
    pub async fn run(
        mut self,
        agent: &mut Agent,
        goal: impl Into<String>,
    ) -> Result<PlanRun, SdkError> {
        let goal = goal.into();
        let plan = self.planner.plan(&goal);
        let mut results = Vec::with_capacity(plan.len());

        for step in &plan {
            match step {
                Step::Prompt(message) => {
                    let turn = agent.send(message.clone()).await?;
                    results.push(StepResult::Turn(turn));
                }
                Step::Tool { tool, args } => {
                    let observation = agent.call_tool(tool.clone(), args.clone()).await?;
                    results.push(StepResult::Tool {
                        tool: tool.clone(),
                        observation,
                    });
                }
            }
        }

        Ok(PlanRun { plan, results })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn(content: &str) -> MessageResult {
        MessageResult {
            content: content.to_string(),
            tool_calls: 0,
            tokens: 0,
        }
    }

    #[test]
    fn directive_reasoner_parses_tool_call() {
        let mut r = DirectiveReasoner::new();
        let d = r.decide(0, &turn("TOOL: read_file {\"path\":\"/etc/hostname\"}"));
        assert_eq!(
            d,
            Decision::CallTool {
                tool: "read_file".into(),
                args: serde_json::json!({"path": "/etc/hostname"}),
            }
        );
    }

    #[test]
    fn directive_reasoner_parses_tool_without_args() {
        let mut r = DirectiveReasoner::new();
        let d = r.decide(0, &turn("tool: list_dir"));
        assert_eq!(
            d,
            Decision::CallTool {
                tool: "list_dir".into(),
                args: serde_json::json!({}),
            }
        );
    }

    #[test]
    fn directive_reasoner_parses_final() {
        let mut r = DirectiveReasoner::new();
        assert_eq!(
            r.decide(0, &turn("FINAL: the answer is 42")),
            Decision::Final {
                answer: "the answer is 42".into()
            }
        );
    }

    #[test]
    fn directive_reasoner_treats_plain_text_as_final() {
        let mut r = DirectiveReasoner::new();
        assert_eq!(
            r.decide(0, &turn("just a chat reply")),
            Decision::Final {
                answer: "just a chat reply".into()
            }
        );
    }

    #[test]
    fn directive_reasoner_finds_directive_on_later_line() {
        let mut r = DirectiveReasoner::new();
        let d = r.decide(
            0,
            &turn("thinking out loud...\nTOOL: http_get {\"url\":\"x\"}"),
        );
        assert_eq!(
            d,
            Decision::CallTool {
                tool: "http_get".into(),
                args: serde_json::json!({"url": "x"}),
            }
        );
    }

    #[test]
    fn fn_planner_produces_steps() {
        let mut p = FnPlanner(|goal: &str| {
            vec![
                Step::Prompt(format!("plan for {goal}")),
                Step::Tool {
                    tool: "read_file".into(),
                    args: serde_json::json!({"path": "/x"}),
                },
            ]
        });
        let steps = p.plan("test");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0], Step::Prompt("plan for test".into()));
    }

    #[test]
    fn plan_run_final_content_picks_last_turn() {
        let run = PlanRun {
            plan: vec![],
            results: vec![
                StepResult::Turn(turn("first")),
                StepResult::Tool {
                    tool: "t".into(),
                    observation: serde_json::json!({}),
                },
                StepResult::Turn(turn("last")),
            ],
        };
        assert_eq!(run.final_content(), Some("last"));
        assert_eq!(run.step_count(), 3);
    }
}
