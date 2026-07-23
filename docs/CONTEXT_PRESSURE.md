# Context pressure contract

AI Agent OS bounds an agent's **active provider prompt** when
`max_context_tokens` is non-zero. The live execution loop checks the bound
before every provider request. This is cooperative prompt admission, not virtual
memory and not a process-memory OOM killer.

## Token accounting

An adapter may provide a provider/model-specific prompt estimate through the
`LlmSession` seam. Otherwise the kernel uses a documented conservative fallback:
one token per serialized UTF-8 byte, plus four framing tokens per message. An
adapter estimate may raise this structural floor but cannot lower it. This
deliberately over-reserves normal prose so high-entropy text, code, identifiers,
and structured tool data remain inside a safe tokenizer-independent local
bound; it is not a billing total.

## What can be paged out

The root system instruction and the most recent assistant tool-call state (the
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
from the reference. Automatic retrieval and model-generated summaries are not
part of the current contract.

## Inspection and lifecycle

`ContextPressure` / `KernelClient::context_pressure` returns content-free
per-agent counters: the current active and configured token counts, cumulative
spill/eviction/error counts, current spill rows/bytes, and the last error. A
successful page-out also emits `StreamEvent::ContextPressure` to an in-process
caller. Tenant authorization is applied before either inspection or page-in.

Spills use the same durable SQLite store as conversations and survive a process
restart. They are deliberately retained when an agent is stopped, just like its
conversation and facts; an authorized operator can delete them with
`StorageDelete`. Generation checkpoints have their own bound (eight active
checkpoints per agent) and 24-hour expiry. Restoring a checkpoint restores
exactly the references or full messages captured at that boundary.

## Bounds that are not yet claimed

The current release does **not** enforce tenant/global prompt pools, a maximum
stored-spill byte quota, an embedding byte quota, or host process RSS. It also
does not kill another agent to resolve prompt pressure. These conditions use
explicit bounded queues or fail-closed backpressure where implemented; host
memory/cgroup qualification remains roadmap work. Therefore this capability is
`integrated`, not production-qualified.
