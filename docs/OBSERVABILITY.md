# Production observability contract

AgentOS telemetry contract v2 defines the names, types, units, and complete
bounded label sets of every Prometheus family exported by the kernel. The
machine-readable source of truth is
[`observability/telemetry-contract-v2.toml`](../observability/telemetry-contract-v2.toml);
regression tests compare every rendered `# TYPE` family with that catalog and
reject forbidden high-cardinality label classes.

The contract is compatibility-sensitive. A patch may add a family only by
updating the catalog, tests, documentation, and alerting. Renaming a family,
changing its type or unit, removing a label value, or changing a label's meaning
requires a new contract version. Counters reset on process restart.

## Request accounting and traces

Every dispatched syscall is assigned a server-generated UUID correlation ID.
It is written only to structured trace spans; it never enters Prometheus labels
or durable user data. Streaming keeps its caller-visible request ID for
cancellation but uses a separate server correlation ID for logs.

The structured span path is:

```text
agentos.request
└── kernel.dispatch
    └── kernel.component (kernel | provider | tool | persistence)
```

`LOG_FORMAT=json` includes the current span and complete span list. The request
event contains the static authorization action, fixed subsystem, outcome, and
duration. It does not record credentials, tenant/user/agent IDs, prompts,
memory contents, tool arguments/results, paths, or URLs.

`agentos_requests_total` classifies each completed dispatch as `success`,
`rejected`, `failed`, `timed_out`, or `cancelled`. Rejections include expected
client, authentication, authorization, policy, quota, lifecycle, and not-found
responses; they are not availability failures. Dropping an in-flight dispatch
records `cancelled`, so transport cancellation cannot leak the in-flight gauge.
The fixed request-latency histogram supports p95/p99 calculations without
request, tenant, agent, tool, or provider labels.

Compiled runtime identity uses five `agentos_build_source_sha1{part}` gauges
with fixed `part` values `0` through `4`, each carrying one exact 32-bit segment,
and `agentos_build_source_verified`. The build script reads the actual tracked
Git source, or verifies a packaged source against bounded Git commit/tree/blob
objects and actual file bytes. Missing/invalid proof or dirty source is unverified. Numeric
segments preserve fixed label cardinality across builds. Target observations
require every segment to reconstruct the expected clean commit; package builds
without Git metadata or a valid object-bound source proof remain usable but cannot
supply eligible source evidence. Docker contexts are prepared from clean Git
objects before building, keeping `.git`, untracked files and credentials out;
the runtime image carries only shipped binaries and its entrypoint. An unchecked
SHA build argument or clean boolean never establishes verified source identity.
Prepared contexts must be new, outside the checkout, and free of Cargo output.
The container refuses pre-existing `target/`; source proof watches only present
authenticated source inputs, keeping missing-proof builds from repeating work.

`RequestSubsystem::request_class` defines the latency split in one place.
Agent, checkpoint, memory, storage and tool traffic use the `agent` class;
authentication, cluster, operator, package, protocol, service and system traffic
use `control`. The split is by subsystem, so every storage request remains in
the agent class, including a privileged storage operation. Exporters must use
this declared split rather than independently reclassifying operations.

`agentos_request_class_total` is a request counter with only the fixed `class`
label. `agentos_request_class_duration_seconds` is a seconds histogram with
`class` and the existing fixed bucket boundaries. Both project the same
completed observations as the subsystem families, including all outcomes, and
add no second observation path. Existing v1 subsystem families are retained;
class counters also reset on process restart.

`agentos_llm_requests_total{outcome}` counts admitted provider-adapter invocations
as success, failed, timed out or cancelled. A dropped invocation future is counted
as cancelled. Admission and content/policy refusals before invocation do not enter
this denominator; quota denials retain their existing counters. Executor retries
are separate invocations, while retries inside one adapter remain part of that
adapter invocation. The family carries no provider, model, tenant or agent label.

`agentos_quota_storage_healthy_seconds_total` and
`agentos_quota_storage_unhealthy_seconds_total` are fractional-second counters
derived from monotonic time and the actual durable-ledger health transition.
They start with the limiter, retain subsecond intervals and require no scrape
frequency assumption. Persistence failures latch the ledger unhealthy until
restart, so every guard/drop failure uses the same transition source. Counters
reset on restart; qualification must detect restarts and cannot infer a 30-day
continuous observation from one process's counters after a reset.

`agentos_checkpoint_recovery_attempts_total` counts completed restoration
attempts. `agentos_checkpoint_recovery_total{outcome}` distinguishes recovered
context from safe rejection before continuation execution. Their coherent
snapshot maintains `recovered + safe_rejected = attempted`; running restores
are not included until classified. Provider failure after context restoration
is represented by the provider outcome family. Explicit foreign-tenant
checkpoint IDs are measured by `agentos_checkpoint_cross_tenant_attempts_total`,
and an observed foreign restoration increments
`agentos_checkpoint_cross_tenant_recoveries_total`. Corrupt payload identity,
version and serialized content fail before continuation execution.

Expected-denial probes use trusted in-process harness entry points, with no
wire, MCP or package operation for tagging ordinary traffic.
`SyscallGate::probe_expected_tool_denial` exercises actual gate authorization
without executing a provider; `probe_expected_tenant_denial` resolves a current
leased credential and checks the same recorded-target authorization as public
dispatch. Both declare deny explicitly and count only completed decisions.
Ordinary calls cannot inflate these denominators. Auth/sandbox probes emit
`agentos_adversarial_attempts_total` and `agentos_unexpected_allows_total`;
tenant probes emit `agentos_tenant_boundary_attempts_total` and
`agentos_confirmed_violations_total`. Invalid credentials/targets and cancelled
unclassified probes do not establish a decision and cannot satisfy the minimum
attempt requirement. These counters establish measured authorization decisions;
native sandbox breakout qualification remains separate.

Protocol negotiation, malformed framing rejected before dispatch, the raw HTTP
scrape handler, and external provider-side spans are not yet separate metric
series. External OpenTelemetry export is not bundled in contract v2; JSON logs
are the supported trace export.

## Export, disable, and privacy

Metric HTTP export is opt-in: leave `AGENT_SERVER_METRICS_ADDR` unset to keep
the listener disabled. The system-authorized wire `metrics` operation remains
available to trusted operators and cannot be disabled independently in v1.
Set `LOG_FORMAT=json` to export structured traces on stdout, or set
`RUST_LOG=off` to disable log emission. These settings disable export, not the
small process-local counters used by the operator snapshot.

Metrics intentionally contain only the enumerated bounded labels in the
contract. Correlation UUIDs exist only for the lifetime of a structured log
span. JSON trace export still reveals timing, static operation names, bounded
component names, and whether the caller was tenant-scoped; operators must apply
their normal log access, transport, retention, and deletion controls. Agent,
tenant, user, credential, provider, tool, path, URL, prompt, content, argument,
and result values are neither request metric labels nor request-span fields.

## Release-candidate SLO targets

These are qualification targets, not a claim that the current release has
already met them:

| Required SLI | Measurement | Target | Window |
| --- | --- | --- | --- |
| Availability | `success / (success + failed + timed_out + cancelled)` | at least 99.5% | rolling 30 days |
| Syscall latency | `agentos_request_class_duration_seconds` and class request counts | control p95 below 1 second; agent p95 below 30 seconds with provider profile | rolling 24 hours |
| Queue wait | turn/LLM wait-time deltas divided by admissions, plus waiting/capacity and starvation totals | mean below 250 ms and zero starvation increments under the qualified profile | rolling 24 hours |
| LLM success | admitted `agentos_llm_requests_total` adapter outcomes and exact live-provider qualification | at least 99% excluding policy/quota rejection before invocation | rolling 24 hours |
| Tool success | eligible `tool` request outcomes and gate decisions | at least 99.5% after allowed admission | rolling 24 hours |
| Auth and sandbox denial | explicit expected-denial probe attempts/unexpected allows, plus native isolation qualification | zero unexpected allows; ordinary denial volume has no success target | per release and incident |
| Data durability | monotonic ledger healthy/unhealthy seconds, storage encryption state, signed-backup success/freshness, and restore drill | ledger healthy continuously without unobserved resets; verified backup within 25 hours; restore drill passes | continuous/per release |
| Checkpoint recovery | coherent completed recovery counts and exact release pause/restart/resume report | 100% recovered or documented safe rejection; zero cross-tenant recovery | per release |
| Tenant isolation | explicit leased-credential probe attempts/confirmed violations plus adversarial suite and game day | zero confirmed isolation violations | per release |

Eligible availability requests are `success + failed + timed_out + cancelled`.
`rejected` is excluded because policy enforcement and invalid input are expected
behavior. Release evidence must state request volume, subsystem mix, hardware,
provider/model, configuration, dataset, start/end timestamps, code SHA, and all
alert firings. Low-volume windows are not proof.

The fail-closed
[`release_slo_qualification.py`](../scripts/release_slo_qualification.py)
evaluator and protected
[`Release candidate SLO qualification`](../.github/workflows/release-slo-qualification.yml)
workflow implement this calculation. The minimum proof volumes, strict input
schema, exact-tag binding, evidence handoff, and retained report fields are
documented in
[`RELEASE_SLO_QUALIFICATION.md`](RELEASE_SLO_QUALIFICATION.md). Checked-in unit
fixtures prove the evaluator's rejection behavior; they are not release SLO
results. No exact release candidate has an eligible retained report yet.

The checked-in rules at
[`observability/prometheus-rules.yml`](../observability/prometheus-rules.yml)
implement fast operational signals. They do not replace the 30-day SLO report,
24-hour soak, fault injection, or release game day required by issue #125.
The checksum-pinned Prometheus 3.13.1 regression suite at
[`observability/prometheus-rule-tests.yml`](../observability/prometheus-rule-tests.yml)
parses the production rules and proves that every alert remains inactive before
its configured `for` interval, fires at the threshold, and clears when the
underlying signal recovers. This qualifies PromQL evaluation and rule state
transitions, not delivery through a deployment's Alertmanager receiver.
The importable
[`observability/grafana-dashboard.json`](../observability/grafana-dashboard.json)
uses the retained v1 subset of contract v2 and includes request success/rate/p95, queues,
gate decisions, durability, backup, and lifecycle panels.

Credential compromise, tenant leak, malicious package, node/process loss,
corrupt database, and provider outage have containment and recovery procedures
in [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md). Its scheduled automated drill
retains exact-commit technical-control evidence while explicitly remaining
ineligible as proof of a human game day.

## Alert runbooks

### Availability budget burn

Confirm the contract version and deployment SHA, split
`agentos_requests_total` by subsystem/outcome, inspect correlated JSON spans for
the first failing subsystem, and check quota, queues, backup/storage health, and
provider availability. Stop new admission or drain the node if failures are
storage-integrity or isolation related. Do not retry non-retryable rejections.

### Request timeouts

Compare control-plane and agent histograms, then inspect turn and LLM waiting
gauges. Verify the configured wire/provider deadlines and correlated component
span. Drain only after preserving evidence; a timeout does not prove a provider
side effect stopped.

### Control-plane latency

Check storage locking, quota-ledger health, service supervisor state, and host
CPU/memory/I/O. Compare p95 by bounded subsystem. If persistence is implicated,
stop writes before filesystem or database repair.

### Agent-turn latency

Check turn admission, LLM core waiting, provider health/circuit state, retry
counts, context pressure, and model/provider profile. Avoid raising global
timeouts until bounded-memory and cancellation behavior are requalified.

### Quota ledger unhealthy

Stop new provider admission. Preserve the database, WAL, logs, code SHA, and
configuration. Follow the authenticated backup/corruption procedures in
[`DURABILITY.md`](DURABILITY.md); never bypass the fail-closed ledger check.

### Backup failures

Inspect the bounded backup status and storage logs, verify free space and
permissions, then run signed verification against independently retained trust
and the exact recovery anchor. Never delete the last verified recovery point.

### Backup stale

Confirm scheduling is enabled and the process clock is correct. Run a manual
signed backup, independently retain its exact anchor, and verify it before
clearing the alert. A local success is not immutable remote custody.

### Turn queue saturation

Inspect active/waiting/capacity, lifecycle state, starvation totals, and host
resources. Drain or add qualified capacity; do not increase concurrency past
the tested memory and provider bounds.

### Provider queue saturation

Inspect LLM in-flight/waiting/capacity, provider health, circuit breakers,
retry/failover, and quota receipts. Reduce admission or add a provider only when
its routing, residency, cancellation, and credential policies are qualified.

## Evidence still required

Production qualification remains open until an exact release candidate passes
the 24-hour sustained-load and resource/leak profile, real slow-client/provider
tests through the target TLS/proxy path, privacy disable/export verification,
target Alertmanager routing/receiver delivery tests, a human incident game day,
and independent review. The controlled four-wave backpressure fixture already
proves bounded admission plus its reviewed RSS ceiling; it does not replace the
long-duration target result. The Prometheus unit suite proves rule evaluation
but cannot prove an external page or ticket arrived. The deterministic
six-scenario incident drill is regression evidence, not operator/game-day
proof. Results must be attached to issue #125 with the exact commit and
workflow run. Missing infrastructure or credentials are `not_run`, never pass.
