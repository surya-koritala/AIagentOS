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
