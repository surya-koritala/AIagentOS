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
   Kernel execution does not sleep in this slot for an exhausted RPM/TPM/cgroup
   epoch: quota admission returns retryable backpressure immediately, including
   the next epoch boundary, so independently funded cgroups can still progress.
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

Shared-resource access has one atomic exclusive holder/waiter state. A
higher-priority waiter temporarily raises a lower-priority holder's effective
priority, removing resource-pressure throttling until release; the configured
priority is restored afterward. Access waits fail after 10 seconds instead of
allowing an unbounded inversion.

Turn admission adds a starvation escape to normal vruntime ordering: after 30
seconds, the oldest overdue waiter receives the next released slot. LLM
admission uses the one-nice-point-per-second aging described above. These are
cooperative queue/holder mitigations, not Linux CPU or mutex preemption.

The runtime also bounds nested-permit waits: same-agent serialization precedes
turn admission, exhausted quota returns without an epoch wait, LLM cores are
released before executor retry backoff/tools, and resource-provider execution
is bounded. Providers that ignore cancellation must enforce their own timeout.

## Cancellation, starvation, and metrics

Cancellation is cooperative at turn admission, LLM-core admission, provider
request boundaries, and between tool calls. Hosted APIs are not mid-token
preempted. See [CHECKPOINTS.md](CHECKPOINTS.md).

There is no wall-clock completion bound without a provider-latency bound. The
scheduler guarantees progress after permit release and records every activation
of the 30-second starvation escape. Prometheus exposes
active/waiting/capacity gauges, admitted/cancelled counters, cumulative wait/run
nanoseconds, starvation escapes, per-class admission share, and completed turns
that exhausted their token slice and cooperatively yielded at the public turn
boundary. A cooperative yield is not a claim of mid-future preemption.

Real-time, deadline, and background classes remain low-level experiments;
public creation uses `Normal`. No production guarantee is made for those
experimental classes.

## Difference from Linux EEVDF

Linux EEVDF uses eligible virtual deadlines, lag, CPU runtime, and kernel
preemption. AI Agent OS chooses lowest vruntime over token-accounted cooperative
turn waiters. The weight table is reused; the execution contract is not. We call
this `CFS-inspired turn admission`, never a CPU scheduler.

## Qualification

`tests/src/scheduler_props.rs` sustains mixed-class contention and verifies that
configured concurrency is never exceeded or leaked. Kernel unit tests cover
long weighted workloads, cancellation, lost wakeups, queue overload, priority
inheritance/restoration, starvation escape, and per-class counters.
`cargo run --package os-benchmark --bin os-benchmark --locked` reports direct
turn-admission nanoseconds per slot separately from syscall-gate throughput.
