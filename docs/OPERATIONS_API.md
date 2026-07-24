# Operations and introspection API

`OperatorSnapshot` is the supported remote proc/sysctl analogue. The Rust SDK
exposes it as `KernelClient::operator_snapshot()`, `agentctl inspect` prints the
same typed snapshot as JSON, and the TUI refreshes from it. The legacy in-memory
`ProcFs` and `Sysctl` helpers are not public sources of truth and are not host
filesystem mounts.

Each reply contains:

- an RFC 3339 capture timestamp, scope, consistency statement, kernel version,
  and wire-protocol version;
- bounded per-agent lifecycle, scheduler, sandbox, namespace/capability,
  cgroup-limit/usage, checkpoint, context-pressure, latest-usage, and
  process-local gate-decision state;
- time-bounded provider health with sample time, elapsed milliseconds, and an
  explicit timeout flag;
- tenant-filtered package-manifest instances without prompts, memory, assets,
  tool arguments, or paths;
- the scoped gate aggregate, including bounded denial-reason categories; and
- for trusted system callers only, services, global spend, persistent tunables,
  and the exact `MetricsSnapshot` used by the Prometheus and `NodeInfo` views.

`total_visible_agents` and `agents_truncated` make response bounding explicit.
The default maximum is 10,000 agent records per snapshot.

## Scope and authorization

Tenant credentials receive only identities and package instances owned by that
tenant. Their gate aggregate is the sum of those agent identities, including
normally stopped agents during the current process lifetime. Global population,
service names, spend, system metrics, and tunables are omitted. Unknown and
foreign resources use the same authorization denial. Names, tasks/prompts,
spill content, workspace paths, credentials, and tool arguments are never
returned.

Global tunable reads/writes and audit history require the trusted system
connection. A tenant `Admin` is still tenant-bound and cannot mutate node-wide
settings. Unauthorized write attempts are added to the durable tunable audit
without recording a credential secret.

## Consistency and sampling

Agent creation, pause, resume, stop, kill, checkpoint resume, and tunable
mutation take the write side of the operator-state barrier. Structural snapshot
collection takes the read side, so a reply cannot pair `Running` lifecycle state
with a paused scheduler entry, or a terminal agent with a live sandbox/cgroup.
The barrier is released before external provider health checks so a slow
provider cannot block lifecycle progress.

Counters are atomic samples and may advance independently. Provider health is
sampled after structural collection and is bounded by
`operator.provider_probe_timeout_ms`; a timeout returns the registered provider
as unavailable with `probe_timed_out = true`. `captured_at` is written after
all samples. Prometheus/gate counters are process-local and reset on restart;
durable tunables and package-instance metadata do not.

## Durable tunables

The public settings are intentionally small. Every value drives a live path:

| Name | Default | Range | Live effect |
|---|---:|---:|---|
| `kernel.max_agents` | `0` | `0..=1,000,000` | Serializes count-and-create; zero is unlimited |
| `operator.provider_probe_timeout_ms` | `5000` | `50..=60,000` | Bounds provider health sampling |
| `operator.snapshot_max_agents` | `10000` | `1..=100,000` | Bounds returned agent records and reports truncation |

Use `KernelClient::list_operator_tunables`,
`set_operator_tunable(name, value, expected_revision)`, and
`rollback_operator_tunable(name, target_revision, expected_revision)`.
`agentctl` exposes the same operations as `tunables`, `tunable-set`,
`tunable-rollback`, and `tunable-history`.

Updates run under `BEGIN IMMEDIATE` and compare the caller's expected revision.
Exactly one concurrent writer can win; stale writers receive a conflict and
leave runtime and durable state unchanged. Rollback restores an earlier
effective value but creates a new monotonic revision. Bootstrap, applied set,
rollback, invalid, stale, and unauthorized attempts are durable audit entries.

## Package view and limitations

The package view records non-sensitive loaded instances. The signed package
registry separately persists tenant trust roots, immutable artifacts, yanks,
exact dependency locks, installed versions, rate-limit windows, mutation audit,
and a hash-chained transparency log. Authenticated wire/SDK operations cover
trust/revocation, publish/fetch/search, install/upgrade/rollback/remove, and
verified run. Marketplace ratings/download counters are not part of the v1
surface.

Provider health is currently availability plus timeout evidence; provider
error taxonomies, circuit breakers, model discovery, and external contract
tests remain tracked by issue #120. Per-agent gate counters reset on restart,
and this API is an agent-runtime control surface rather than a Linux `/proc`
mount or a claim of Linux-kernel equivalence.
