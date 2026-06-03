# Server Quickstart

`agent-server` is the primary entry surface: a long-lived kernel that exposes
the JSON syscall protocol (see `kernel::syscall_server`) over TCP. The container
image ships it as `/usr/local/bin/agent-server`, and `docker-compose.yml`
defines an `agentos-server` service that brings it up reachable and persistent.

## One command

```bash
./scripts/quickstart.sh
```

This builds the image, starts the `agentos-server` service, waits until the
container's healthcheck confirms the server **answers a real syscall** (not just
that the port is open), then sends one `NodeInfo` round-trip and prints the
reply. It finishes with:

```
server is up on tcp://localhost:7777 — connect with the SDK/CLI
```

Equivalent raw commands:

```bash
docker compose up -d --build agentos-server   # build + start, mapped 7777:7777
docker compose ps                              # wait for STATUS = healthy
```

## Keyless by default

The service boots with `AGENTOS_LLM_PROVIDER=local`, so it comes up with **no
API keys** and **without depending on Ollama**. The enforcement / non-LLM
syscalls — `NodeInfo`, `CreateAgent`, `GateStats`, `AgentInfo`, the storage and
snapshot calls, tool calls subject to the syscall gate — all work immediately.

Only the LLM-backed `SendMessage` needs a reachable provider. Point
`OLLAMA_BASE_URL` at the `ollama` service and pull a model if you want that path
(see `docker-compose.yml`). The server itself never blocks on the provider, so
it is **not** hard-wired to `ollama` becoming healthy.

## The wire protocol

Requests and replies are newline-delimited JSON. The request enum is internally
tagged with `"op"` (snake_case); the reply enum is tagged with `"status"`.
`NodeInfo` is a unit variant, so the request is:

```json
{"op":"node_info"}
```

and a healthy server replies:

```json
{"status":"node_info","agent_count":0,"running_agents":0}
```

Round-trip from the host with bash:

```bash
exec 3<>/dev/tcp/127.0.0.1/7777
printf '{"op":"node_info"}\n' >&3
head -1 <&3
```

## Healthcheck

The compose healthcheck does the same round-trip inside the container using
`nc` (netcat-openbsd, installed in the runtime stage) and requires the reply to
contain `"status":"node_info"`. A port-open probe alone is not sufficient — the
check proves the kernel is actually serving.

## Persistence

The service mounts the named `agentos-data` volume at `/data`, where the
rendered `config.toml` and the SQLite `agent_os.db` live. State survives:

```bash
docker compose restart agentos-server   # comes back healthy on the same volume
```

Tear down without deleting state:

```bash
docker compose down        # keeps named volumes
```

## Optional hardening

`agent-server` honors these environment variables (see
`crates/cli/src/bin/agent-server.rs`):

- `AGENT_SERVER_TOKEN` — require token auth as the first syscall on each
  connection.
- `AGENT_SERVER_TLS_CERT` / `AGENT_SERVER_TLS_KEY` — terminate TLS (rustls) on
  the TCP bind.
- `AGENT_SERVER_UNIX` — bind a Unix-domain socket instead of TCP.

## Observability

`agent-server` (and the `agent` CLI) install a `tracing` subscriber at startup,
so the kernel's structured logs actually emit:

- `RUST_LOG` — env-filter directive; defaults to `info` when unset (e.g.
  `RUST_LOG=kernel=debug,info`).
- `LOG_FORMAT=json` (or `AGENT_LOG_FORMAT=json`) — emit machine-readable JSON
  log lines for ingestion. Any other value keeps the human-readable format.

### Metrics

The kernel renders a Prometheus text exposition (format version `0.0.4`) from
the syscall-gate enforcement counters, agent counts, system token/api totals,
and process uptime. There are two ways to read it:

- **Over the wire** — the `metrics` syscall (`{"op":"metrics"}`) returns the
  exposition in a `metrics` reply; the SDK exposes it as
  `KernelClient::metrics()`.
- **HTTP scrape endpoint** — set `AGENT_SERVER_METRICS_ADDR` (e.g.
  `0.0.0.0:9090`) to start a tiny built-in HTTP listener. `GET /metrics`
  returns `200` with the exposition; any other path returns `404`. The endpoint
  is only opened when the variable is set, so it costs nothing by default. In
  `docker-compose.yml` the `agentos-server` service sets it and publishes
  `9090`, so a scraper can hit `http://localhost:9090/metrics`.

Sample exposition:

```
# HELP agentos_syscall_gate_total Tool-call decisions made by the syscall gate, by result.
# TYPE agentos_syscall_gate_total counter
agentos_syscall_gate_total{result="allowed"} 5
agentos_syscall_gate_total{result="denied_capability"} 2
agentos_syscall_gate_total{result="denied_mac"} 0
agentos_syscall_gate_total{result="denied_cgroup"} 0
agentos_syscall_gate_total{result="denied_namespace"} 1
agentos_syscall_gate_total{result="denied_unknown"} 0
# HELP agentos_syscall_gate_audited_total Allowed tool calls that also matched a MAC audit rule.
# TYPE agentos_syscall_gate_audited_total counter
agentos_syscall_gate_audited_total 0
# HELP agentos_agents Total agents the kernel hosts.
# TYPE agentos_agents gauge
agentos_agents 3
# HELP agentos_running_agents Agents currently executing a turn.
# TYPE agentos_running_agents gauge
agentos_running_agents 1
# HELP agentos_tokens_consumed_total Tokens consumed across all agents.
# TYPE agentos_tokens_consumed_total counter
agentos_tokens_consumed_total 1280
# HELP agentos_api_calls_total LLM API calls made across all agents.
# TYPE agentos_api_calls_total counter
agentos_api_calls_total 7
# HELP agentos_process_uptime_seconds Seconds since this server process rendered its first metrics.
# TYPE agentos_process_uptime_seconds gauge
agentos_process_uptime_seconds 42
```
