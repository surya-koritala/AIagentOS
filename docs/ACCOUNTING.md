# Resource accounting and metrics contract

This document defines the units, scope, reset behavior, and known precision
limits for runtime accounting. Code and dashboards must not infer different
semantics from a metric name.

## Provider usage and price

Each completed turn records the actual provider ID and model ID, input, output,
and cached-input tokens, provider requests, retries, provider-wait latency,
tool-call count, and calculated USD price. Provider-reported usage is preferred.
If an adapter omits usable details, the executor conservatively estimates input
tokens from the complete active message/tool-schema payload at four characters
per token and treats the adapter's token count as output. The durable record's
`estimated_requests` and `provider_reported_requests` fields distinguish them.

`tokens_used`, TPM, and blended pricing count input plus output tokens. Cached
tokens are a labelled subset of input tokens and are not added a second time.
Configured `provider_pricing` values are USD per 1,000 total tokens. Separate
input/output/cache prices are not yet supported; invoice-sensitive deployments
must configure a conservative blended rate.

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

- RPM: provider attempts per rolling 60-second process-local window.
- TPM: input plus output tokens per the same window. Input is reserved before a
  provider attempt and reconciled to actual/fallback total usage afterward.
- Provider concurrency: simultaneous provider attempts. Retry backoff and tool
  execution hold no provider permit.
- Turn concurrency: actively executing agent turns, separately CFS-ordered.
- Context limit: active input context tokens per executor; old non-system pages
  are evicted before a provider request.
- Per-turn tool limit: cumulative tool calls across every provider response in
  one logical user turn, including calls completed before pause/resume. Reaching
  the limit skips all remaining side effects in the response and records
  explicit denied tool results. A new user turn starts at zero.
- Tool concurrency: independently configured active tool calls across every
  cgroup ancestor. RAII guards release slots after success, error, panic unwind,
  or cancellation.
- Cgroup token charge: conservative tool-call estimate, atomically reserved
  across the complete agent-to-tenant/root hierarchy at gate admission.

For RPM, TPM, provider concurrency, cumulative/concurrent tool limits, cgroup,
context, and USD configuration, zero means unlimited. Counter arithmetic
saturates instead of overflowing. The rolling rate-limit window resets
deterministically after 60 seconds. Cgroup minute-window reset is driven by the
kernel timer and is currently process-local.

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

The regression suite covers exact provider parsing and pricing fixtures,
provider/fallback distinction, retries and latency persistence, concurrent RPM,
TPM, tool-slot, cgroup, and USD admission, overflow saturation, zero/unlimited
configuration, cumulative tool-call behavior across pause/resume, exact
micro-dollar restart rehydration, lifecycle metrics, and load-aware cluster
placement. Live-provider invoice comparison remains a separate secret-backed
qualification job rather than a deterministic pull-request test.
