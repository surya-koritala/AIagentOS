# Writing agent service files

Service files declare long-lived agents managed by the kernel supervisor.

## 1. Configure a directory

Add the directory to the main AI Agent OS configuration:

```toml
service_dir = "/etc/agent-os/services"

[api_keys]
openai = "configured-outside-the-service-file"
```

The directory is read as one configuration. One invalid file rejects the
complete startup or reload.

## 2. Create a service

Save this as `/etc/agent-os/services/researcher.toml`:

```toml
name = "researcher"
description = "Research agent that finds information"

[exec]
provider = "openai"
system_prompt = "You are a research specialist. Research and summarize assigned work."

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
nice = -5

[policy]
tenant_id = "default"
profile = "standard"
namespace = "research"
secret_refs = ["openai"]

[health]
startup_timeout_ms = 30000
readiness_delay_ms = 250
liveness_interval_ms = 1000
shutdown_timeout_ms = 30000
```

`requires` blocks readiness and propagates failure. `wants`, `after`, and
`before` only order services. Lower `nice` values receive higher cooperative
scheduling priority. Token budgets accept a per-minute integer or
`amount/minute`, `amount/hour`, `amount/min`, or `amount/hr`.

Only `Simple` services are supported. Per-service model overrides, per-service
tool allow-lists, `Oneshot`, and `Notify` fail validation instead of being
silently ignored. Provider configuration selects the model; permission
profiles, MAC policy, sandbox configuration, and resource budgets govern tools.

## 3. Start and inspect

Start `agent-server`, which validates and boots configured services, then use
the public operator CLI:

```bash
cargo run --package agent-cli --bin agentctl -- services
cargo run --package agent-cli --bin agentctl -- service-history researcher 50
```

Live management uses:

```bash
cargo run --package agent-cli --bin agentctl -- service-start researcher
cargo run --package agent-cli --bin agentctl -- service-stop researcher
cargo run --package agent-cli --bin agentctl -- service-restart researcher
cargo run --package agent-cli --bin agentctl -- service-reload
```

Reload validates the full replacement first and rolls back to the old graph if
the new dependency closure cannot become ready.

See [Agent service supervisor](../SERVICES.md) for the complete durability,
restart, security, metrics, and crash-recovery contract.
