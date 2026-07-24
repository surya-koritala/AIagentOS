# Context pressure contract

AI Agent OS applies deterministic backpressure to active provider prompts and
durable agent context. This is cooperative admission, not virtual memory and
not a process-memory OOM killer.

## Bounded resources and defaults

`BudgetConfig` controls two independent resources:

| Resource | Agent | Tenant | Kernel |
|---|---:|---:|---:|
| Concurrent active prompt tokens | `max_context_tokens` (65,536) | `tenant_max_context_tokens` (262,144) | `global_max_context_tokens` (1,048,576) |
| Durable context bytes | `max_context_storage_bytes` (64 MiB) | `tenant_max_context_storage_bytes` (512 MiB) | `global_max_context_storage_bytes` (2 GiB) |

Active-token estimates include the complete serialized messages and tool
definitions submitted to the provider. Durable bytes include working contexts,
conversations, full spill payloads, fact text and embeddings, named snapshots,
and active/resuming generation checkpoints. Replacing an existing record is
charged by its net byte increase. SQLite serializes the check and write, so two
concurrent writers cannot both consume the same remaining capacity.

Host RSS, provider-side caches, and external vector databases are not included
in these counters. Host/container memory limits remain the process-isolation
contract; the runtime does not select or kill an agent under memory pressure.

## Token accounting

An adapter may provide a provider/model-specific prompt estimate through the
`LlmSession` seam. Otherwise the kernel uses a documented conservative fallback:
one token per serialized UTF-8 byte, plus four framing tokens per message. An
adapter estimate may raise this structural floor but cannot lower it. This
deliberately over-reserves normal prose so high-entropy text, code, identifiers,
and structured tool data remain inside a safe tokenizer-independent local
bound; it is not a billing total.

## What can be paged out

Required system instructions and the most recent assistant tool-call state (the
assistant declaration and its following tool results) are pinned. Older
non-pinned messages are serialized in full to the protected per-agent SQLite KV
namespace under `context_spill:<conversation>:<uuid>`. The active prompt receives
a reference containing the key, message count, and SHA-256 prefix.

No message-count placeholder or synthetic summary silently replaces history. If
the pinned state plus the smallest durable reference cannot fit, the provider
call is rejected with a stable context-pressure policy error and the original
active context is left unchanged. A failed compaction does not create an orphan
spill.

Page-in is explicit: use `StorageGet` / `KernelClient::storage_get` with the key
from the reference. The kernel checks the full SHA-256 digest before returning
content and fails closed on missing metadata, corruption, expiry, or a
cross-agent/tenant request. Automatic retrieval and model-generated summaries
are intentionally not part of the contract; the durable full-message payload
is the lossless source of truth. Page-in is one synchronous local SQLite read
plus SHA-256 verification; no fixed latency SLO is claimed, and callers should
treat it like any other storage syscall.

Before each provider attempt, active prompt tokens are atomically admitted at
agent, tenant, and kernel scopes. A failed admission returns a stable
`context pressure ... retry with backoff` policy error without calling the
provider. Admission is released on success, error, cancellation, or panic
unwind through an RAII guard. Pressure never evicts another tenant's state.

## Inspection and lifecycle

`ContextPressure` / `KernelClient::context_pressure` returns content-free
per-agent counters: the current active and configured token counts, cumulative
spill/eviction/error counts, current spill rows/bytes, and the last error. A
successful page-out also emits `StreamEvent::ContextPressure` to an in-process
caller. Tenant authorization is applied before either inspection or page-in.

Spills use the same durable SQLite store as conversations and survive a process
restart. `context_spill_retention_seconds` defaults to 30 days; expired payload
and metadata rows are removed together before storage admission, page-in, or
inspection. An authorized owner can delete a spill earlier with
`StorageDelete`. Generation checkpoints retain their separate count (eight
active checkpoints per agent) and 24-hour expiry, while their serialized bytes
also count toward durable context quotas. Restoring a checkpoint therefore
restores references or full messages without double-counting referenced spill
payloads.

`ContextPressure` / `KernelClient::context_pressure` exposes current agent,
tenant, and kernel active usage/limits, durable usage/limits, spill/eviction
counts, active rejection and persistence error counts, retention, and the last
error. It never returns prompt or spill content.

## Quality and failure policy

Compaction is lossless at the storage boundary: every source message is either
still active or round-trips exactly from the verified spill. Required
instructions and the latest tool transaction remain active. Impossible pinned
budgets, corrupt spills, expired references, full durable pools, and concurrent
active-prompt pressure all fail explicitly. The regression suite checks these
properties and measures the expected active-recall loss for an evicted fact plus
its recovery after verified page-in. It does not claim that omitting older detail
from the immediate model prompt has zero task-quality impact.
