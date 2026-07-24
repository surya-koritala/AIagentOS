# Resource accounting and metrics contract

This document defines the units, scope, reset behavior, and known precision
limits for runtime accounting. Code and dashboards must not infer different
semantics from a metric name.

Accounting is an availability and spend boundary, not an authorization grant.
A successful RPM/TPM, budget, or cgroup reservation never substitutes for
tenant ownership, a validated tool declaration, capability/MAC/approval checks,
or sandbox admission. Prompts, providers, packages, MCP metadata, and tool
arguments cannot modify those controls or select a permissive/unconfined mode.

## Provider usage and price

Each completed turn records the actual provider ID and model ID, input, output,
and cached-input tokens, provider requests, retries, provider-wait latency,
tool-call count, and calculated USD price. Trusted provider-reported usage is
retained for invoice-aligned billing and user-facing telemetry. Separately, TPM
and cgroup enforcement apply a conservative input floor computed from the
complete serialized message/tool-schema payload at one token per serialized
UTF-8 byte, plus message framing. Roles, tool-call IDs, tool names/arguments,
and tool-result IDs are included. This deliberately separates the safety
ledger from the invoice ledger: a provider cannot refund quota below the local
prompt floor, while the local floor does not inflate an exact provider bill.
A provider/model tokenizer hook may raise the safety floor but cannot lower it.

If an adapter omits usable usage, the same structural input estimate and the
adapter's output token count are used for both ledgers. The durable record's
`estimated_requests` and `provider_reported_requests` fields distinguish
estimated from provider-reported billable usage.

`tokens_used` and TPM count input plus output tokens. Cached tokens are a
labelled subset of input tokens and are not added a second time. Detailed
pricing calculates:

`(uncached input × input rate + cached input × cache rate + output × output rate) / 1000`

Rates resolve in this order: provider + model detailed pricing, provider
detailed pricing, the legacy provider blended rate, detailed default pricing,
then the legacy global blended rate. The first match wins. Existing
`usd_per_1k_tokens` and `provider_pricing` TOML remains compatible and prices
input plus output at the blended rate. Detailed tables use
`input_usd_per_1k_tokens`, `cached_input_usd_per_1k_tokens`, and
`output_usd_per_1k_tokens`, for example:

```toml
[budgets.default_token_pricing]
input_usd_per_1k_tokens = 1.0
cached_input_usd_per_1k_tokens = 0.1
output_usd_per_1k_tokens = 4.0

[budgets.provider_token_pricing.openai]
input_usd_per_1k_tokens = 1.25
cached_input_usd_per_1k_tokens = 0.125
output_usd_per_1k_tokens = 5.0

[budgets.provider_model_token_pricing.openai."gpt-4o"]
input_usd_per_1k_tokens = 2.5
cached_input_usd_per_1k_tokens = 1.25
output_usd_per_1k_tokens = 10.0
```

A zero rate is valid and means that token class is free. Every legacy and
detailed price or USD ceiling must be finite and non-negative. Invalid values,
incomplete detailed tables, and unknown budget keys reject configuration
loading and kernel startup instead of being clamped, ignored, or silently
weakening a configured ceiling.

USD ceilings are cumulative and durable across process restarts: global, tenant,
and agent.
The check-through-record interval is serialized for each configured scope, so
concurrent requests cannot race through the same remaining budget. Because a
provider reveals the final charge only after completing a response, the response
that reaches a ceiling can exceed it by that one response; no subsequent request
is admitted. Every response persists the exact integer micro-dollar charge that
was applied in memory. Startup reconstructs global, tenant, and agent counters
from those fixed-point rows before admitting work, so a later pricing change
does not reprice historical usage. Stopping or unregistering an agent releases
live admission locks but does not erase its cumulative spend.

## Rate and hierarchy limits

- RPM: provider attempts per fixed, half-open Unix-minute epoch. Epoch `N`
  covers `[N × 60,000 ms, (N + 1) × 60,000 ms)` in UTC; the exact boundary
  belongs to the new epoch.
- TPM: input plus output tokens per the same durable epoch. The complete
  structural input floor plus `max_output_tokens_per_request` is committed
  before admission. Cancellation before provider invocation refunds the request
  and estimate; an invoked failure or unknown crash outcome retains it. A
  successful response reconciles to the larger of provider total usage and the
  structural prompt floor plus reported/fallback output, in the original
  admission epoch even when completion crosses the wall-clock boundary.
- Output bound: `max_output_tokens_per_request` defaults to 4,096 and must be
  positive in validated configuration. Built-in adapters translate it to the
  provider's completion/new-token field. A custom session is rejected before
  quota admission unless it explicitly declares that it enforces the option.
  This contract assumes a declaring provider/session honors the bound; such a
  declaration is part of the trusted adapter boundary.
- Provider concurrency: simultaneous provider attempts. Retry backoff and tool
  execution hold no provider permit. This live gauge is process-local and
  correctly starts at zero after restart because no prior work remains active.
- Turn concurrency: actively executing agent turns, separately CFS-ordered.
- Context limits: complete active provider-input tokens, including tool schemas,
  are admitted at agent, tenant, and kernel scopes; older non-pinned messages
  spill before a provider request, and irreducible pinned/schema or durable-byte
  pressure fails closed. Conversations, fact embeddings, snapshots, active
  checkpoints, and spills share the configured durable context ceilings.
- Per-turn tool limit: cumulative tool calls across every provider response in
  one logical user turn, including calls completed before pause/resume. Reaching
  the limit skips all remaining side effects in the response and records
  explicit denied tool results. A new user turn starts at zero.
- Tool concurrency: independently configured active tool calls across every
  cgroup ancestor. RAII guards release slots after success, error, panic unwind,
  or cancellation.
- Cgroup token charge: the provider input estimate is atomically reserved across
  root → tenant → profile → agent together with provider/global RPM/TPM. Cgroup
  scopes consume tokens but do not multiply the provider request count.
  Successful calls reconcile provider-reported input + output usage across
  every scope in the original admission epoch. Gate-time tool payload estimates
  do not consume quota. Once assistant tool-call JSON, IDs, or tool results are
  included in a later provider prompt, they are real provider input and are
  estimated and charged there.
- Cgroup membership races: admission snapshots a monotonic membership revision.
  The gate excludes low-level reassignment while it verifies that revision and
  marks the receipt in flight. A stale reservation is fully refunded and retried
  against the new hierarchy before any provider I/O. Kernel-created agents
  cannot use the raw move API; their root → tenant → profile → private-agent
  hierarchy is immutable for the agent lifetime.
- Execution-path quota exhaustion returns retryable backpressure immediately,
  with the next fixed-epoch boundary in the error. It does not sleep while
  holding a global whole-turn slot. The lower-level `RateLimiter` compatibility
  API retains cancellable wait-until-capacity behavior for direct embedders.

For RPM, TPM, provider concurrency, cumulative/concurrent tool limits, cgroup,
context, and USD configuration, zero means unlimited. The output bound is the
exception and must be positive. Counter arithmetic saturates instead of
overflowing. Provider RPM/TPM receipts and a monotonic epoch floor are persisted
before I/O. Restart within the same epoch restores terminal/reconciled usage,
refunds work proven not invoked, and conservatively retains estimates for work
that might have reached a provider. A backwards wall clock cannot reopen an
older epoch. When upgrading a non-empty database from a release that had only
process-local counters, the unknowable remainder of the current epoch is fenced
closed; the next fixed boundary opens normally.

The current SQLite runtime assumes one active kernel owner per database file.
Opening the same file from multiple live kernel processes is not supported:
startup recovery cannot yet distinguish another process's live reservations
from receipts left by a crashed owner. Distributed or active-active operation
requires the ownership/lease protocol tracked by the control-plane and durable
state roadmap before it can safely share this quota ledger.

`tenant_tokens_per_min` independently limits each tenant;
`agent_tokens_per_min` limits each non-`full-access` agent (`elevated` receives
the documented wider allowance). Profile aggregate nodes are currently
unlimited but still accounted, and `0` means unlimited at every level. Admission
reserves the full structural prompt floor and provider-enforced output allowance
at every bounded scope, so a conforming built-in provider response cannot cross
a scope limit. Runtime numeric cgroup IDs are never persisted—canonical
semantic scopes are.

## Runtime and node-load metrics

`running_agents` means turns holding active admission, not agents whose lifecycle
state happens to be `Running`. Live, queued, paused, and stopped lifecycle counts
are separate. Node placement uses active/capacity and waiting counts for both turn
admission and LLM scheduling, plus queued/live agents.

Prometheus counters are monotonically increasing until process restart. Gauges
are current values. Latencies are milliseconds; costs are USD; token quantities
are integer model tokens or documented estimates. Labels must be bounded to
provider, result class, and configured tenant identifier. Agent ID, prompt
content, resource paths, URLs, and user identity are not permitted as unbounded
metric labels. Tenant-scoped APIs may expose only that tenant's records; global
node metrics require operator/admin authorization.

## Qualification tests

The regression suite covers detailed provider/model pricing precedence,
input/output/cache formulas including a zero cache rate, legacy blended-config
compatibility, invalid-price startup rejection, exact provider parsing and
pricing fixtures, provider/fallback distinction, retries and latency
persistence, concurrent RPM, TPM, tool-slot, cgroup, and USD admission, overflow
saturation, zero/unlimited configuration, cumulative tool-call behavior across
pause/resume, exact micro-dollar restart rehydration without historical
repricing, lifecycle metrics, and load-aware cluster placement. Live-provider
invoice comparison remains a separate secret-backed qualification job rather
than a deterministic pull-request test.
