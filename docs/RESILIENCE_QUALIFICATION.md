# Resilience qualification

AI Agent OS treats overload and dependency failure as measured operating
conditions, not exceptional paths that can be declared safe from unit tests
alone. The checked-in resilience suite drives the public TCP protocol through
the Rust SDK and retains machine-readable pass/fail evidence.

## Checked-in scenarios

[`benchmarks/resilience-profiles.toml`](../benchmarks/resilience-profiles.toml)
is the strict schema-v1 configuration for four scenarios.

| Scenario | What must remain true |
|---|---|
| `turn-overload` | Active turns never exceed `max_concurrent`; waiting turns never exceed `max_waiting_turns`; excess work receives a stable retryable overload result; turn and quota gauges drain; the server remains responsive. |
| `slow-clients` | Accepted connections never exceed the configured limit; excess peers are closed before protocol admission; idle peers are reaped; every permit returns; a fresh health client succeeds. |
| `provider-outage` | Provider failures are classified as unavailable; the control plane remains responsive; turn, LLM, and quota-receipt gauges return to zero. |
| `cancellation-storm` | Every exact public stream request is cancelled from a second connection; queued and active provider work settles before deadline; request registrations and all turn, LLM, quota, and wire permits drain. |

`budgets.max_waiting_turns` is an operator-controlled hard limit. A value of
zero preserves the compatibility default (64 waiters per active turn, minimum
64); production configurations should set an explicit finite value established
by target-host qualification.

The syscall server also exposes a cloneable, server-local
`WireConnectionMetrics` read handle. Its snapshot contains only bounded,
non-identifying counters: capacity, active and peak connections, admitted and
rejected totals, handshake and idle timeouts, and I/O failures.

## Commands

Validate configuration without opening a socket:

```bash
cargo run --package os-benchmark --bin resilience-qualification --locked -- \
  --validate
```

Run the fast development regression:

```bash
cargo run --package os-benchmark --bin resilience-qualification --locked -- \
  --all --smoke --output target/qualification/resilience-smoke.json
```

Run the release fixture on the intended qualification host:

```bash
cargo run --release --package os-benchmark \
  --bin resilience-qualification --locked -- \
  --all --output target/qualification/resilience-baseline.json
```

Named scenarios can be selected with repeated `--scenario NAME`. Non-smoke
debug runs are rejected unless `--allow-debug` is supplied.

## Evidence and claim boundary

Every report binds the complete scenario configuration to the exact Git commit,
dirty state, Rust toolchain, build profile, observed bounds, checks, and
failures. Fixture reports always contain:

```json
{
  "qualification_class": "deterministic_resilience_fixture",
  "production_claim_allowed": false
}
```

This suite proves deterministic product behavior and prevents regressions. It
does not simulate every kernel, filesystem, network, provider, or sandbox
failure. Production qualification still requires:

- an actually completed 24-hour target run from the checked-in
  [resource/leak soak harness](SOAK_QUALIFICATION.md), with its retained RSS,
  task, descriptor, database/WAL, queue, and permit samples;
- disk-full, database-lock, sandbox-crash, and network-partition injection in
  addition to the provider-outage and cancellation-storm fixtures implemented
  here;
- slow real providers and clients under the intended TLS/proxy/load-balancer
  path;
- exact-release-candidate SLO evaluation and exercised incident runbooks;
- independent review of the retained artifacts.

Until those artifacts exist for an exact release candidate, issue #125 remains
open and this capability is not production-qualified.
