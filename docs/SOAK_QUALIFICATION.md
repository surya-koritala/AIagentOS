# Resource and leak soak qualification

The target-host soak is a separate production-proof workflow, not a long unit
test. Its checked-in schema-v1 profile runs a fixed public TCP/SDK workload for
24 hours while retaining process, storage, admission, and connection samples.
A short smoke run verifies the sampler and report contract but is never
evidence for the 24-hour gate.

## What is measured

[`benchmarks/soak-profiles.toml`](../benchmarks/soak-profiles.toml) defines the
duration, warmup, sampling cadence, workload, and explicit growth thresholds.
Each retained sample contains:

- process resident memory, task count, and open descriptor count;
- SQLite database, WAL, SHM, and lease-directory bytes;
- completed public operations;
- active/waiting turn and LLM gauges;
- in-flight quota receipts; and
- active syscall-server connections.

Growth is evaluated after the configured warmup. RSS, task, and descriptor
growth must remain below their independent hard limits. Durable-state growth
is normalized per completed operation so expected retained conversation data
is distinguished from unexplained storage amplification. The final report also
requires every operation to succeed, all turn/LLM/quota/wire permits to drain,
healthy quota storage, and a successful post-soak control-plane probe.

These thresholds are release gates, not promises that every value stays
constant. A threshold change requires review and a new exact-commit artifact;
it must not be raised merely to make a failing run pass.

## Commands

Validate the checked-in full-day profile:

```bash
cargo run --release --locked --package os-benchmark \
  --bin soak-qualification -- --validate
```

Run the five-second development smoke:

```bash
export AGENTOS_QUALIFICATION_ENVIRONMENT="local-smoke"
cargo run --locked --package os-benchmark --bin soak-qualification -- \
  --smoke \
  --state-dir target/qualification/resource-soak-smoke-state \
  --output target/qualification/resource-soak-smoke.json
```

Run the full profile on an intended stable Linux qualification host:

```bash
export AGENTOS_QUALIFICATION_ENVIRONMENT="linux-x64-shape-a"
cargo run --release --locked --package os-benchmark \
  --bin soak-qualification -- \
  --state-dir target/qualification/resource-soak-state \
  --output target/qualification/resource-soak.json
```

The state directory must be absent or empty. This prevents samples from mixing
multiple runs. Use a new directory for every release candidate and retain the
JSON artifact before cleaning the runner.

The manually dispatched `Resource soak qualification` workflow performs the
same full run on the repository-owned `agentos-capacity` Linux runner. Its
25-hour job timeout leaves bounded startup and artifact-publication headroom.
It rejects dirty source, a commit mismatch, a duration below 86,400 seconds, a
missing environment identifier, a failed check, or a smoke artifact.

## Evidence classification

Only a clean release build on Linux with a named environment, a completed
duration of at least 24 hours, and every check passing can set:

```json
{
  "qualification_class": "target_resource_soak",
  "proof_scope": "resource_and_leak_soak_only",
  "resource_soak_proof_eligible": true,
  "production_claim_allowed": false
}
```

`production_claim_allowed` remains false because this artifact satisfies only
the resource/leak-soak proof within issue #125. The deterministic resilience
suite covers disk-full, database-lock, and network-partition behavior, while
the extended-security workflow retains live sandbox-crash evidence. Successful
exact-commit execution and review of those artifacts, exact-release SLO
evaluation, an exercised incident game day, and independent review remain
separate gates.

The checked-in workflow is executable proof infrastructure. Until its
exact-release 24-hour artifact is actually retained and reviewed,
`resource_soak_proof_eligible` has not been demonstrated and the corresponding
issue checkbox remains open.
