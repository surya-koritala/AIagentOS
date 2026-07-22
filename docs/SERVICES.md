# Agent service supervisor

Set `service_dir` in the main configuration to a directory of `*.toml` service
definitions. Kernel construction parses the complete directory, rejects invalid
files/duplicate names/missing required dependencies/cycles, and installs the
definitions atomically. `agent-server` starts the validated boot order after LLM
providers are registered. A startup failure stops services already started by
that attempt in reverse order and exits non-zero.

```toml
service_dir = "/etc/agent-os/services"
```

```toml
name = "researcher"
description = "Continuously process research work"

[exec]
provider = "openai"
system_prompt = "You are the research service."
tools = ["http_get"]

[service]
restart = "OnFailure"
restart_delay_ms = 1000
max_restarts = 3
service_type = "Simple"

[dependencies]
requires = ["database"]
after = ["database"]

[resources]
nice = 5
```

`StartService`, `StopService`, `RestartService`, and `ListServices` are exposed
over the public wire/SDK and by `agentctl service-*` / `agentctl services`.
They are system-operator operations: tenant credentials are denied because the
current service definition does not yet carry tenant ownership. Start uses
`create_agent_full`; stop and restart use the coordinated lifecycle cleanup.
Shutdown stops service agents in reverse dependency order.

Definitions can be reloaded atomically through the in-process kernel method
only while every service is inactive or failed. This prevents removing a live
definition while leaving an orphan agent.

## Current qualification boundary

The public coordinated lifecycle, deterministic dependency ordering, startup
rollback, manual restart history, and system-only authorization are implemented
and tested. Automatic health/readiness probes, crash-loop monitoring with
jitter/windows, durable service ownership/history, tenant/profile/secret/tool
policy fields, oneshot/notify semantics, and rolling live reload are not yet
implemented. `RestartPolicy` is therefore configuration metadata for future
automatic supervision; it does not currently spawn a background restart loop.
