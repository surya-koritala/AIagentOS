# Agent service supervisor

AI Agent OS can boot long-lived agents from declarative TOML definitions and
keep them healthy through a kernel-owned supervisor. Set `service_dir` in the
main configuration:

```toml
service_dir = "/etc/agent-os/services"
```

At startup the kernel parses the complete directory before publishing any
definition. Unknown fields, duplicate names, missing required dependencies,
cycles, invalid policy, unavailable secret references, and unsupported service
features reject the whole configuration. `agent-server` registers providers
and then starts services in deterministic dependency order. A failed initial
boot stops everything started by that attempt in reverse order and exits
non-zero.

## Service definition

```toml
name = "researcher"
description = "Continuously process research work"

[exec]
provider = "openai"
system_prompt = "You are the research service."

[service]
restart = "OnFailure"
restart_delay_ms = 1000
restart_max_delay_ms = 60000
restart_jitter_ms = 250
restart_window_ms = 60000
max_restarts = 5
service_type = "Simple"

[dependencies]
requires = ["database"]
wants = ["cache"]
after = ["database"]

[resources]
token_budget = "10000/hour"
max_context = 32000
max_concurrent_tool_calls = 4
nice = 5

[policy]
tenant_id = "default"
profile = "standard"
namespace = "research"
secret_refs = ["openai"]

[policy.sandbox]
workspace_dir = "/var/lib/agent-os/researcher"
allowed_network_hosts = ["api.openai.com"]
max_disk_usage_bytes = 1073741824
max_memory_bytes = 536870912
isolation_level = "Filesystem"

[health]
startup_timeout_ms = 30000
readiness_delay_ms = 250
liveness_interval_ms = 1000
shutdown_timeout_ms = 30000
```

Secret references are names only. Each name must match a key in the main
configuration's `[api_keys]` table; secret values are never copied into service
definitions, runtime state, history, events, or metrics.

`requires` is a hard dependency: the dependent starts only when every required
service is running, ready, and healthy. A required service failure stops its
dependents and defers their restart until dependencies recover. `wants`,
`after`, and `before` affect deterministic ordering without becoming readiness
requirements. Shutdown runs in reverse dependency order and enforces each
service's deadline, escalating to forced cleanup if necessary.

The supported service type is `Simple`. `Oneshot`, `Notify`, per-service model
overrides, and per-service tool allow-lists are rejected during validation
because silently accepting fields that are not enforced would be unsafe. Select
the provider's model in provider configuration, and govern tool access with the
service permission profile, MAC policy, sandbox, and concurrent-tool budget.

## Health and restart behavior

Readiness means the created service owner remains in the kernel's running state
after its configured readiness delay. Liveness is the same kernel-owned
lifecycle state checked by the background runtime; it is not an arbitrary HTTP
or shell probe.

An unexpected failure applies `Always`, `OnFailure`, or `Never`, then uses
bounded exponential delay plus deterministic jitter. Attempts are counted in a
restart window. Reaching `max_restarts` leaves the service `Failed` with
`restart_exhausted = true`; the failed owner is still fully reclaimed.
Dependencies that are not ready defer—not consume—the next restart attempt.

SQLite stores desired state, owner ID, definition revision, readiness/health,
restart window and count, failure reason, and transition history. After a
process crash, a live rehydrated owner is rebound rather than duplicated. A
missing, terminal, or stale-revision owner is cleaned before recovery creates a
replacement.

## Live reload

`service-reload` parses and validates a complete replacement before changing
live state. Changed/removed services and their required dependents stop in
reverse order, then desired services start in the new order. If quiescing or
rollout fails, the previous graph is restored and its desired services are
restarted. Removed durable rows are deleted only after a successful rollout.

## Operator surfaces

All surfaces call the same system-only supervisor syscalls:

```bash
cargo run --package agent-cli --bin agentctl -- services
cargo run --package agent-cli --bin agentctl -- service-start researcher
cargo run --package agent-cli --bin agentctl -- service-stop researcher
cargo run --package agent-cli --bin agentctl -- service-restart researcher
cargo run --package agent-cli --bin agentctl -- service-reload
cargo run --package agent-cli --bin agentctl -- service-history researcher 100
```

The Rust SDK exposes the corresponding `list_services`, `start_service`,
`stop_service`, `restart_service`, `reload_services`, and `service_history`
methods. In the TUI, `[`/`]` select a service, `u` starts, `d` stops, `R`
restarts, and `L` reloads. The desktop Operations view starts inactive services,
shows bounded transition history, and freezes the displayed service name before
a stop or restart. Those disruptive actions require the exact name and disclose
that stopping may block dependents and restarting may interrupt in-flight work.
All desktop actions still traverse `KernelClient`; there is no in-process
supervisor shortcut. Tenant credentials cannot access global service state or
lifecycle operations.

Prometheus output includes configured, desired, running, ready, healthy, failed,
restart, and dependency-block counters. Operator snapshots and history contain
state and failure metadata only—never prompts or secret values.

## Qualification boundary

The production-qualified contract covers a single kernel owner on Linux, macOS,
and Windows: atomic configuration, deterministic dependency lifecycle,
kernel-state readiness/liveness, restart/backoff/exhaustion, durable crash
recovery without duplicate owners, rolling rollback, bounded shutdown, public
operator controls, metrics, and regression tests.

It is not a distributed service manager, cluster lease protocol, HTTP probe
runner, or replacement for host init systems such as systemd.
