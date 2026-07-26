# Capacity qualification

AI Agent OS does not publish one hardware-independent “agents per node” number.
Capacity depends on the provider, prompt distribution, tool latency, storage,
sandbox backend, tenant mix, and the exact release commit. This document defines
the reproducible baseline and the evidence required before an operator turns a
measurement into deployment guidance.

## Checked-in workload suite

[`benchmarks/capacity-profiles.toml`](../benchmarks/capacity-profiles.toml) is a
strict schema-v1 suite. The runner rejects missing, duplicated, renamed, or
unknown profiles.

| Profile | Production path exercised |
|---|---|
| `idle` | public TCP handshake and health probes over time |
| `many-agents` | concurrent public agent admission, sandbox, cgroup, namespace, scheduler, and durable registration |
| `long-context` | large prompts through wire, context accounting, executor, and deterministic provider |
| `tool-heavy` | concurrent `list_directory` calls through wire, gate, sandbox, broker, and filesystem provider |
| `provider-latency` | bounded concurrent turns against a deterministic delayed provider |
| `tenant-contention` | authenticated tenant-isolated agents contending for the same kernel/provider capacity |
| `package-install` | generated Ed25519 trust root, signed archive verification, publish, transactional install, and removal |
| `restart` | abrupt server stop, SQLite reopen, agent rehydration, enforcement re-arm, and KV recovery |

The deterministic provider reports usage and observes prompt bytes. It makes the
AgentOS overhead repeatable but intentionally does not imitate a cloud-provider
SLA. The package profile uses a generated ephemeral signing key and synthetic
asset; no credential or generated secret is written to the report.

## Commands

Validate the checked-in schema without running load:

```bash
cargo run --package os-benchmark --bin capacity-qualification --locked -- --validate
```

Run the fast, non-publishable development matrix:

```bash
cargo run --package os-benchmark --bin capacity-qualification --locked -- \
  --all --smoke --output target/qualification/capacity-smoke.json
```

Run the complete deterministic baseline from a clean release commit:

```bash
AGENTOS_QUALIFICATION_ENVIRONMENT=staging-x64-8cpu-32g \
  cargo run --release --package os-benchmark \
  --bin capacity-qualification --locked -- \
  --all --output target/qualification/capacity-baseline.json
```

One or more named profiles can be selected with repeated `--profile NAME`.
Non-smoke debug runs are rejected unless the developer explicitly supplies
`--allow-debug`. A smoke or debug artifact can catch regressions but cannot
qualify production.

## Report contract

The JSON report includes:

- schema and suite version;
- exact Git commit and dirty-worktree state;
- Rust toolchain and build profile;
- OS, architecture, logical CPU count, CPU model, memory, and operator-supplied
  environment identifier;
- the complete configuration for every executed profile;
- attempted, successful, and failed operations;
- elapsed time, throughput, and p50/p95/p99 operation latency;
- maximum prompt bytes observed by the deterministic provider;
- the explicit active-turn and waiting-turn admission limits;
- an overall pass/fail result and explicit caveats.

Fixture reports always contain:

```json
{
  "qualification_class": "deterministic_fixture_baseline",
  "capacity_claim_allowed": false
}
```

Changing that field by hand does not create production evidence. A production
claim additionally requires the target deployment, live or operator-approved
provider fixtures, the 24-hour soak, SLO evaluation, fault injection, and
independent review tracked in issue #125.

## Sizing method

For each intended deployment shape:

1. Pin a clean release-candidate commit, config, provider/model, sandbox backend,
   storage class, and host or node pool.
2. Run the full deterministic baseline and retain its JSON plus process-level
   peak RSS, CPU, descriptor, and I/O measurements.
3. Run the same workload mix against the real deployment for at least 30
   minutes at each concurrency step. Do not mix results from different commits
   or shapes.
4. Reject a step if any target in
   [production observability](OBSERVABILITY.md) fails, if errors are hidden by
   retries, or if memory, descriptors, tasks, queues, WAL/DB size, or permits
   grow without returning to a stable band.
5. Select the highest passing step, then apply at least a 30% headroom reserve.
   The deployable limit is the lower of the SLO-constrained throughput and every
   hard admission limit: turns, provider cores, tool calls, context tokens,
   tenant quotas, storage, and sandbox capacity.
6. Repeat with slow providers, slow clients, tenant contention, package
   activity, and restart. A limit is publishable only when the worst required
   profile passes.

The deterministic overload, slow-client, and provider-outage checks are defined
separately in [Resilience qualification](RESILIENCE_QUALIFICATION.md). Capacity
evidence is incomplete if either suite fails.

Use this conservative calculation for an initial node limit:

```text
qualified_limit = floor(min(passing_workload_limit, hard_admission_limit) * 0.70)
```

This is methodology, not a pre-measured recommendation. Until an exact release
candidate has the retained evidence above, the safe public capacity status is
“not yet qualified.”

## Regression and release policy

The binary unit tests validate the exact profile inventory, schema failure
behavior, percentile calculation, and a smoke execution of every workload.
The manually dispatched `Capacity qualification` workflow runs the release
suite on a repository-owned `agentos-capacity` runner and uploads the JSON and
resource report. A missing self-hosted runner is `not_run`, never a pass.

Release reviewers compare an exact-commit artifact with the previous qualified
artifact. Regressions in pass state, error count, p95/p99 latency, throughput,
or resource use require investigation; a new number is not accepted merely
because the command exited successfully.
