# Durable generation checkpoints

AI Agent OS can pause a live turn at a cooperative boundary, persist the turn,
restart the server, and continue it through the same public syscall/SDK surface.
This is distinct from a named context snapshot: a generation checkpoint carries
the provider conversation, pending tool-call state, cumulative usage, and the
original user turn.

## Public flow

1. Start `SendMessage` on one connection.
2. Call `PauseAgent` on another connection. The reply includes
   `checkpoint_id` when an in-flight turn was captured. A completion race can
   legitimately return no id because there is nothing left to resume.
3. Use `ListGenerationCheckpoints` to inspect non-sensitive metadata.
4. Call `ResumeAgent` for the newest checkpoint or
   `ResumeGenerationCheckpoint` with an explicit id. The lifecycle reply carries
   the continuation output.
5. A completed checkpoint is consumed and disappears from the active list.
   `DeleteGenerationCheckpoint` erases active or consumed records explicitly.

The Rust SDK exposes `pause_agent_durable`, `resume_agent_durable`,
`list_generation_checkpoints`, `resume_generation_checkpoint`, and
`delete_generation_checkpoint`. The simpler `pause_agent`/`resume_agent`
helpers retain their state-only return type.

The desktop and TUI expose the same list, explicit resume, and explicit delete
calls through their `KernelClient` backends. They render only the non-sensitive
metadata above. In the TUI, press `g` to load the selected agent's checkpoints,
`(`/`)` to select one, `e` to resume, and `K` to begin deletion. Deletion
freezes both the agent and checkpoint identifiers selected by the operator and
stays disabled until the full checkpoint ID is typed exactly; changing the
visible selection cannot retarget the pending mutation. The TUI additionally
rejects a cross-agent checkpoint entry before rendering it and clears the
loaded projection when agent selection changes.

## What “pause” means

- Hosted request/response APIs pause at a request boundary. If cancellation wins
  while a hosted request is outstanding, the request future is dropped and the
  accumulated pre-request state is checkpointed. AI Agent OS does not claim to
  freeze a provider's remote decoder.
- Tool execution is allowed to finish before pause returns. The resulting tool
  message is checkpointed before the next model request.
- Local/streaming providers may support a finer token boundary only when their
  adapter actually yields tokens and honors cancellation. The generic fallback
  remains request-boundary pause.
- Scheduler turn permits and LLM-core permits are RAII guards and are released
  before `PauseAgent` returns.

## Side-effect semantics

Completed tool-call IDs and results are stored in the checkpoint. On resume the
executor finds the latest assistant tool-call turn and executes only IDs without
a matching tool-result message. This prevents replay after an orderly pause or
server restart.

An external side effect that succeeds immediately before a process crash cannot
be made universally exactly-once by the kernel. Such calls are **at-least-once**
across that crash window. Stateful tools should treat their stable tool-call ID
as an idempotency key. Checkpoints left in `resuming` by a crash are re-armed on
boot so work remains recoverable.

## Compatibility, isolation, and retention

- The current checkpoint schema version is `1`. Unsupported versions are marked
  incompatible and return a migration error; corrupt JSON is marked corrupt and
  is never executed.
- Resume verifies the configured provider and model against checkpoint metadata.
  A mismatch leaves the checkpoint recoverable and reports the expected/current
  pair.
- Every query, claim, resume, and delete is tenant-scoped through the owning
  agent. Foreign tenants receive the same authorization denial as an absent
  resource. List replies expose metadata only, never prompt or tool payloads.
- Persistent SQLite files are forced to owner-only mode (`0600`) on Unix. On
  other platforms the deployment must apply an equivalent ACL to the data
  directory. Full database encryption remains a deployment option rather than a
  claim of this implementation.
- Checkpoints expire after 24 hours. Expired rows are pruned on boot and save;
  active retention is capped at eight checkpoints per agent. Explicit deletion
  is available through the wire and SDK.

Provider/model incompatibility, expiry, concurrent claim, corruption, and
foreign-tenant access are recoverable errors; none silently starts a new turn.

## Operations and latency

Pause and resume emit the same bounded lifecycle requested/completed/timed-out/
forced/failed events as other lifecycle operations. Prometheus exposition also
publishes `agentos_lifecycle_duration_seconds_sum` and
`agentos_lifecycle_duration_seconds_count`, keyed only by the bounded
`operation` label. These cumulative summary values include successful and
failed attempts without putting agent, tenant, provider, or prompt data in
metric labels.
