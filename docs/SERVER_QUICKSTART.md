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
SDK clients send `{"op":"hello","protocol_version":2}` automatically. A raw
client that skips `hello` stays on the compatible v1 reply shape; v2 errors are
`typed_error` replies with `code`, `message`, and `retryable` fields. `hello`
also returns stable feature identifiers. Send `{"op":"describe_protocol"}` to
retrieve the live JSON Schemas and transport bounds before authentication. See
[`PROTOCOL.md`](PROTOCOL.md) and
[`ADR-0001-PUBLIC-ABI.md`](ADR-0001-PUBLIC-ABI.md).
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

The server profile also mounts `agentos-backups` at `/backups` and enables a
verified startup backup plus hourly maintenance. It always keeps 24 backups and
expires additional backups after seven days. Inspect the scheduler through the
system-only client:

```bash
cargo run -p agent-cli --bin agentctl --locked -- \
  --addr 127.0.0.1:7777 --token "$AGENT_SERVER_TOKEN" backup-status
```

The backup volume is separate from live state but remains on the same Docker
host. Replicate verified backups to another failure domain before treating them
as node-loss disaster recovery.

The running server creates backups only in its configured `/backups` managed
root. A confirmed agent, user, or tenant erasure locks that root, verifies and
removes every current-installation backup, and only then commits live deletion.
An unknown, corrupt, foreign, augmented, symlinked, or unavailable-key entry
causes erasure to fail closed before the database changes. The next startup or
scheduled cycle publishes a clean post-erasure recovery point. Any replica
copied outside this root must implement the same deletion request through its
independent object-store lifecycle; AI Agent OS cannot erase an unconfigured
external copy.

The profile also mounts `agentos-keys` at `/keys`. On first boot the entrypoint
creates `/keys/storage.json` without overwrite; subsequent boots require that
exact key and SQLCipher-authenticate the database before schema access. Export
the key volume to an independently protected recovery location. It is
deliberately absent from `agentos-backups`; losing it makes every backup from
that key generation unrecoverable.

After an offline key rotation, point `AGENTOS_STORAGE_KEY_PATH` at the new key
and set `AGENTOS_STORAGE_RETIRED_KEY_PATHS` to colon-separated old key files
still referenced by retained backups. Retired keys are not accepted by the
live database; they only let verified retention process older generations.

The development Compose profile does not ship a signing secret. For production,
generate one with `agentctl backup-key-generate`, retain the public trust JSON
outside the backup host, mount the private PKCS#8 file read-only, and set
`AGENTOS_BACKUP_SIGNING_KEY_PATH` plus `AGENTOS_BACKUP_SIGNING_KEY_ID`
together. The entrypoint rejects unpaired, relative, missing, or symlinked key
paths. Use `backup-verify --storage-key STORAGE.json --require-signature
TRUST.json` and `backup-restore ... --storage-key STORAGE.json
--require-signature TRUST.json --confirm-offline` for recovery qualification.

## Optional hardening

`agent-server` honors these environment variables (see
`crates/cli/src/bin/agent-server.rs`):

- `AGENT_SERVER_TOKEN` — require token auth as the first syscall on each
  connection.
- `AGENT_SERVER_TLS_CERT` / `AGENT_SERVER_TLS_KEY` — terminate TLS (rustls) on
  the TCP bind.
- `AGENT_SERVER_TLS_CLIENT_CA` — require a client certificate chaining to this
  PEM CA bundle. This requires the TLS cert/key variables and rejects peers
  before the syscall protocol handshake.
- `AGENT_SERVER_TLS_CLIENT_CRL` — optional PEM CRL bundle for individual mTLS
  client-certificate revocation. It requires `AGENT_SERVER_TLS_CLIENT_CA`;
  unknown revocation status fails closed and CRL expiry is enforced.
- `AGENT_SERVER_TLS_RELOAD_TRIGGER` — enable restart-free replacement of the
  configured certificate, key, optional client CA, and optional CRL. The trigger
  file must exist at startup. Install every new PEM with an atomic rename, then
  atomically replace this small trigger file with different content. The server
  validates the complete candidate before one atomic generation change; a bad
  or partial update leaves the old generation active. Existing sessions finish
  their current request and close before another request is accepted.
- `AGENT_SERVER_TLS_RELOAD_INTERVAL_SECONDS` — trigger polling interval,
  `1..=3600` seconds (default `5`). It is accepted only when
  `AGENT_SERVER_TLS_RELOAD_TRIGGER` is set.
- `AGENT_SERVER_UNIX` — bind a Unix-domain socket instead of TCP.

## Observability

`agent-server` (and the `agent` CLI) install a `tracing` subscriber at startup,
so the kernel's structured logs actually emit:

- `RUST_LOG` — env-filter directive; defaults to `info` when unset (e.g.
  `RUST_LOG=kernel=debug,info`).
- `LOG_FORMAT=json` (or `AGENT_LOG_FORMAT=json`) — emit machine-readable JSON
  log lines for ingestion, including the current correlation span and its
  wire→kernel→component parent path. Any other value keeps the human-readable
  format. Request IDs, credentials, prompts, contents, arguments, paths, and
  URLs are not metric labels.

### Metrics

The kernel renders a Prometheus text exposition (format version `0.0.4`) from
the syscall-gate enforcement counters, agent counts, backup maintenance
health, system token/api totals, and process uptime. There are two ways to read
it:

The complete compatibility and privacy contract, SLO targets, alert rules, and
runbooks are in [`OBSERVABILITY.md`](OBSERVABILITY.md).

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
agentos_syscall_gate_total{result="denied_approval"} 0
# HELP agentos_syscall_gate_audited_total Allowed tool calls that also matched a MAC audit rule.
# TYPE agentos_syscall_gate_audited_total counter
agentos_syscall_gate_audited_total 0
# HELP agentos_agents Total agents the kernel hosts.
# TYPE agentos_agents gauge
agentos_agents 3
# HELP agentos_running_agents Agents currently executing a turn.
# TYPE agentos_running_agents gauge
agentos_running_agents 1
# TYPE agentos_backup_successes_total counter
agentos_backup_successes_total 4
# TYPE agentos_backup_signing_enabled gauge
agentos_backup_signing_enabled 1
# TYPE agentos_backup_consecutive_failures gauge
agentos_backup_consecutive_failures 0
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
