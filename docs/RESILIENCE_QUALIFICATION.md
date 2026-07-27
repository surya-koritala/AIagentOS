# Resilience qualification

AI Agent OS treats overload and dependency failure as measured operating
conditions, not exceptional paths that can be declared safe from unit tests
alone. The checked-in resilience suite drives the public TCP protocol through
the Rust SDK and retains machine-readable pass/fail evidence.

## Checked-in scenarios

[`benchmarks/resilience-profiles.toml`](../benchmarks/resilience-profiles.toml)
is the strict schema-v1 configuration for seven scenarios.

| Scenario | What must remain true |
|---|---|
| `turn-overload` | Active turns never exceed `max_concurrent`; waiting turns never exceed `max_waiting_turns`; excess work receives a stable retryable overload result; turn and quota gauges drain; the server remains responsive. Four delayed-provider waves retain baseline, peak, and settled RSS and enforce both peak-footprint and steady-growth limits. |
| `slow-clients` | Accepted connections never exceed the configured limit; excess peers are closed before protocol admission; idle peers are reaped; every permit returns; a fresh health client succeeds. Four saturation/reap waves retain the same bounded-RSS evidence. |
| `provider-outage` | Provider failures are classified as unavailable; the control plane remains responsive; turn, LLM, and quota-receipt gauges return to zero. |
| `cancellation-storm` | Every exact public stream request is cancelled from a second connection; queued and active provider work settles before deadline; request registrations and all turn, LLM, quota, and wire permits drain. |
| `disk-full` | A feature-gated qualification seam applies SQLite's page limit to the same live connection used by public storage syscalls. The SDK receives a retryable `Unavailable` error, the transaction rolls back, prior commits survive, retry succeeds after capacity restoration, `quick_check` passes, and both commits survive restart. |
| `database-lock` | An independent connection holds a real `BEGIN IMMEDIATE` writer lock beyond the kernel's five-second busy timeout. The public write returns a retryable `Conflict`; a separate health request remains responsive; the timed-out write is absent; retry, integrity, and restart checks pass after lock release. |
| `network-partition` | A loopback provider endpoint accepts and drops real TCP connections. The SDK receives a retryable provider error; after the production circuit-breaker cooldown, the same SDK connection and agent recover through a fresh provider socket; all admission gauges and wire permits drain. |

`budgets.max_waiting_turns` is an operator-controlled hard limit. A value of
zero preserves the compatibility default (64 waiters per active turn, minimum
64); production configurations should set an explicit finite value established
by target-host qualification.

The syscall server also exposes a cloneable, server-local
`WireConnectionMetrics` read handle. Its snapshot contains only bounded,
non-identifying counters: capacity, active and peak connections, admitted and
rejected totals, handshake and idle timeouts, and I/O failures.

The two backpressure scenarios use the reviewed 64 MiB
`max_rss_growth_bytes` ceiling. On Linux and macOS they sample RSS before the
first wave, during peak load, and after every wave. Both peak growth from the
baseline and settled growth from the first completed wave to the last must
remain within the ceiling. The retained Linux workflow requires four waves,
five RSS samples, and all four memory checks; an unsupported or missing
measurement cannot qualify the artifact. The ceiling is also fail-closed at
256 MiB in the profile validator so an accidental extreme value cannot turn
the fixture into a no-op.

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

The scheduled or manually dispatched `Extended security tests` workflow also
runs all seven scenarios in release mode on GitHub-hosted Linux. It rejects
dirty or mismatched source, debug/smoke output, missing scenarios, failed
scenario checks, missing backpressure RSS measurements, fewer than four memory
waves, and any artifact that permits a production claim. A passing report is
retained for 90 days as
`deterministic-fault-matrix-<exact-commit>`.

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

This suite and its retained workflow artifact prove deterministic product
behavior and prevent regressions. The disk capacity limit, independent SQLite
lock, and loopback TCP partition are controlled fault fixtures; they are not
evidence about the target host's filesystem, routing, proxy, TLS, or external
provider. The four-wave fixture demonstrates that the configured admission
bounds also constrain process-memory growth under controlled delayed-provider
and slow-client pressure. It is not a long-duration leak claim. Production
qualification still requires:

- an actually completed 24-hour target run from the checked-in
  [resource/leak soak harness](SOAK_QUALIFICATION.md), with its retained RSS,
  task, descriptor, database/WAL, queue, and permit samples;
- a successful exact-commit run of the separately retained live rootless Linux
  sandbox crash/cancellation artifact;
- slow real providers and clients under the intended TLS/proxy/load-balancer
  path;
- exact-release-candidate SLO evaluation and exercised incident runbooks;
- independent review of the retained artifacts.

Until those artifacts exist for an exact release candidate, issue #125 remains
open and this capability is not production-qualified.
