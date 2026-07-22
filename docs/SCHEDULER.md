# Cooperative scheduler contract

AI Agent OS schedules agent turns and provider requests. It does **not**
schedule CPU instructions and does not preempt arbitrary Rust futures. The
implementation is CFS-inspired token fairness at cooperative boundaries; it is
not equivalent to Linux CFS or modern Linux EEVDF.

## State model

- `queued`: admitted to the kernel and eligible to request a turn slot.
- `running`: currently holds a turn-admission slot.
- `blocked`: waiting for a provider core, rate-limit token, or bounded resource
  provider. Queue gauges report this; it is not a durable lifecycle state.
- `paused`: lifecycle admission is disabled. Turn/provider waiters are
  cancelled and removed; in-flight work checkpoints at a safe boundary.
- `stopped`: terminal. Scheduler, CFS, LLM, IPC, sandbox, and gate state is gone.

`AgentState::Running` means the process is runnable; `running_agents` means a
turn is actually executing. These are intentionally different.

## Admission layers and fairness units

1. Same-agent turns serialize on the per-agent executor before any scarce
   global permit is requested.
2. `TurnAdmission` bounds whole-turn concurrency. Contenders are only actual
   waiters. Normal-class selection chooses lowest virtual runtime. Token usage
   advances vruntime by `tokens * 1024 / weight`, using Linux's weight table.
3. `LlmScheduler` bounds provider-request concurrency. A permit covers one
   provider attempt and is released before retry backoff, tool work, pause, or
   the next model iteration. Lowest effective nice wins; one point of aging per
   second (to `-20`) prevents newer high-priority traffic from permanently
   starving an older waiter, assuming provider requests complete.
4. Resource-provider concurrency is independently bounded: filesystem 64,
   application 8, browser 16, peripheral 8, network 64, and IPC 256. Resource
   admission and execution each time out after 30 seconds.

The turn and LLM queues are bounded at `max(64, capacity * 64)`. A full queue
returns a stable `retry with backoff` error. Resource admission permits 1,024
waiters. Waiter registrations are RAII objects: cancellation or future drop
removes the waiter and wakes contenders, preventing ghost waiters and lost
wakeups.

## Priority changes and inversion

`set_nice(-20..19)` updates weight in place while preserving accumulated
vruntime and token usage. Changing priority cannot erase scheduling debt.

The runtime avoids nested scarce permits: same-agent serialization precedes
turn admission, LLM cores are released before tools/backoff, and resources have
bounded execution. This bounds shared-resource priority inversion without
claiming Linux mutex priority inheritance. Providers that ignore cancellation
must enforce their own timeout.

## Cancellation, starvation, and metrics

Cancellation is cooperative at turn admission, LLM-core admission, provider
request boundaries, and between tool calls. Hosted APIs are not mid-token
preempted. See [CHECKPOINTS.md](CHECKPOINTS.md).

There is no wall-clock completion bound without a provider-latency bound. The
scheduler guarantees progress after permit release and records a turn wait over
30 seconds as starvation. Prometheus exposes active/waiting/capacity gauges,
admitted/cancelled counters, cumulative wait/run nanoseconds, a starvation
counter, and lifecycle state gauges.

Real-time/background classes remain low-level experiments; public creation uses
`Normal`. No production guarantee is made for those experimental classes.

## Difference from Linux EEVDF

Linux EEVDF uses eligible virtual deadlines, lag, CPU runtime, and kernel
preemption. AI Agent OS chooses lowest vruntime over token-accounted cooperative
turn waiters. The weight table is reused; the execution contract is not. We call
this `CFS-inspired turn admission`, never a CPU scheduler.
