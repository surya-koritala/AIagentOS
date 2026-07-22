# Operations and introspection API

`OperatorSnapshot` is the remote, typed operations surface. The Rust SDK exposes
it as `KernelClient::operator_snapshot()` and `agentctl inspect` prints the same
snapshot as JSON. The TUI refreshes from this single snapshot instead of making
separate agent, gate, and node calls.

Each reply includes an RFC 3339 capture timestamp, kernel/protocol versions, the
scope, provider health probed at collection time, and per-agent lifecycle,
scheduler, sandbox, capability/namespace, checkpoint, context-pressure, and
latest-usage state. Trusted system connections also receive service state,
global budget spend, and the exact `MetricsSnapshot` used by Prometheus and
`NodeInfo`.

Tenant credentials receive only agents owned by their tenant. Global activity,
gate counters, service names, and global spend are omitted rather than filtered
approximately. Names, prompts, spill content, sandbox paths, credentials, and
tool arguments are never present. Central RBAC/tenant authorization runs before
snapshot collection.

## Consistency

Collection is a read-only pass over live subsystem owners; it does not copy from
the legacy in-memory `ProcFs`. A timestamp is taken after collection. Individual
atomic counters and maps can advance while a snapshot is being assembled, so
the contract is a bounded eventually consistent observation, not a database
transaction across all subsystems. Per-agent lifecycle coordination ensures a
completed pause/stop/kill is reflected together with its scheduler and sandbox
cleanup state.

## Tunables and unsupported views

The legacy `Sysctl` map is not exposed because its values do not yet drive every
runtime subsystem and are not durable. There is currently no public writable
tunable API, which avoids pretending that unaudited in-memory writes are
operator control. Package/registry state and per-tenant gate aggregates also
remain outside this snapshot until their owning subsystems are durable. These
gaps keep the capability below production-qualified status.
