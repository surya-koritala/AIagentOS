# AI Agent OS — Docker Runbook

Two ways to run AI Agent OS in a container, ordered by how much they need:

| Tier | What runs | LLM needed? | Keys needed? | Proves |
|------|-----------|-------------|--------------|--------|
| **1 — Keyless OS demo** | `os-demo` binary | No | No | The load-bearing OS layer: syscall-gate capability / cgroup / namespace / scheduler enforcement |
| **2 — Full interactive CLI** | `agent` binary against Ollama | Yes (local Ollama) | No (keyless via Ollama) | The end-to-end think→act→observe agent loop through the kernel |

The image builds only `agent-cli` (binary `agent`) and `os-benchmark` (binaries
`os-demo`, `os-benchmark`, `stress-test`). `crates/tauri-app` is **never** built
(it needs GTK/WebKit), so the image stays slim.

---

## Prerequisites

- Docker Engine + the Compose v2 plugin (`docker compose`, not the legacy `docker-compose`).
- No API keys for Tier 1 or for the Ollama path of Tier 2.
- A few GB of disk for the Ollama model in Tier 2.
- GPU optional (CPU inference works; it is just slower — see Troubleshooting).

---

## Tier 1 — Keyless OS enforcement demo (no LLM, no keys)

This is the fastest proof that the OS layer is real. It runs `os-demo`, which
boots the in-memory kernel and exercises the syscall gate directly.

### 1. Build the image

```bash
docker build -t agentos:latest .
```

The first build is slow (it compiles the kernel, adapters, CLI and benchmark
crates from scratch — see Troubleshooting → "slow first build"). Subsequent
builds reuse Docker layer cache.

### 2. Run the demo

```bash
docker run --rm agentos:latest
# (os-demo is the default CMD; this is equivalent to:)
docker run --rm agentos:latest os-demo
```

Expected output (exit code 0, `10 passed, 0 failed`):

```
════════════════════════════════════════════════════════════
  AI Agent OS — load-bearing enforcement demo (keyless, no LLM)
════════════════════════════════════════════════════════════

[1] BOOT: kernel::boot_in_memory() (spawns scheduler observer + cgroup reset)
    booted; full-access agent uuid=... pid=1
    booted; read-only  agent uuid=... pid=2
  [PASS] boot — two agents registered with distinct PIDs on the syscall gate

[2] CAPABILITY: caps are derived from permission_profile at agent creation
  [PASS] capability/full-access write_file allowed ...
  [PASS] capability/read-only write_file denied — Err(MissingCapability(16))
  [PASS] capability/read-only run_command denied — Err(MissingCapability(64))
  [PASS] capability/read-only read_file allowed ...

[3] CGROUP QUOTA: tight cgroup (tokens_per_min=100); burn 90, request 30
  [PASS] cgroup/over-budget denied — Err(CgroupQuota)
  [PASS] cgroup/after-reset allowed — Ok(1)

[4] NAMESPACE: tool registered in a namespace the agent is NOT a member of
  [PASS] namespace/foreign tool denied — Err(NotInNamespace{...})
  [PASS] namespace/after-join tool resolves — Ok(1)

[5] SCHEDULER/PROCFS: sleep 150ms, read /system/current_agent
    /system/current_agent = Some("1")  (live pids: ["1", "2"])
  [PASS] scheduler/current_agent published by observer

════════════════════════════════════════════════════════════
  RESULT: 10 passed, 0 failed
════════════════════════════════════════════════════════════
```

**What it proves:** capability checks (read-only agents can't write or run
commands), cgroup token-budget enforcement, namespace isolation of tools, and
the scheduler observer publishing live PIDs into procfs — all without any LLM.

### Optional: the kernel benchmarks (also keyless)

```bash
docker run --rm agentos:latest os-benchmark
docker run --rm agentos:latest stress-test
```

---

## Tier 2 — Full interactive CLI against Ollama (keyless LLM)

The `agent` CLI's default provider is `azure-openai`, which needs a cloud key.
The **keyless** route is the `local` (Ollama) provider. The container's
entrypoint wires this up for you from environment variables (set in
`docker-compose.yml`): it writes a `config.toml` with `llm_provider = "local"`
and points the Ollama URL at `http://ollama:11434`.

> The CLI **panics at startup** if its provider is unreachable. So for Tier 2,
> Ollama must be running *and* have a model pulled before you launch `agent`.

### 1. Start the stack

```bash
docker compose up -d --build
```

This builds the `agentos` image (if needed) and starts the `ollama` service.
`agentos` waits for `ollama` to become healthy (its healthcheck calls
`ollama list`, which is what the CLI's adapter probes via `/api/tags`).

### 2. Pull a model into Ollama (one time)

```bash
docker compose exec ollama ollama pull llama3.2
```

The model name must match `AGENTOS_MODEL` in `docker-compose.yml` (default
`llama3.2`). If you pull a different model, update that env var to match.

### 3a. Run the interactive REPL

```bash
docker compose run --rm agentos agent
```

You get the interactive `agent` prompt. Type a request; the CLI runs the
think→act→observe loop through the kernel against your local Ollama model.
Slash commands like `/history`, `/id`, `/quit` are available.

### 3b. Or run a one-shot command

```bash
docker compose run --rm agentos agent -c "list three facts about Linux cgroups"
```

### 3c. Or pipe input

```bash
echo "summarize this" | docker compose run --rm -T agentos agent "be terse"
```

**What it proves:** the full agent runtime — config load, provider
registration, kernel orchestration, and the execution loop — works end to end
against a real (local) model, with conversation state persisted to
`agent_os.db` under the `/data` volume.

### Stop the stack

```bash
docker compose down            # keep volumes (models + db persist)
docker compose down -v         # also delete volumes (fresh start)
```

---

## Where state lives

Inside the `agentos` container everything is under `/data` (a named volume
`agentos-data`):

- `/data/config/ai-agent-os/config.toml` — rendered by the entrypoint from env vars.
- `/data/share/ai-agent-os/agent_os.db` — the SQLite kernel/conversation store.

`HOME`, `XDG_CONFIG_HOME` and `XDG_DATA_HOME` are pinned in the Dockerfile /
compose so the `dirs` crate resolves these paths deterministically. There is no
dedicated data-dir env var in the app — it follows XDG.

Ollama models live in the `ollama-models` volume at `/root/.ollama`.

---

## Environment variables

Consumed by `docker/entrypoint.sh` to render `config.toml`:

| Var | Default | Maps to |
|-----|---------|---------|
| `AGENTOS_LLM_PROVIDER` | `local` | `config.llm_provider` |
| `AGENTOS_MODEL` | `llama3.2` | `config.default_model` |
| `OLLAMA_BASE_URL` | `http://ollama:11434` (compose) / `http://localhost:11434` (image default) | `api_keys.local` (the Ollama URL field) |

Cloud-provider keys are read directly from the process environment by the CLI
(no TOML needed) — set these and switch `AGENTOS_LLM_PROVIDER` accordingly:

| Provider (`AGENTOS_LLM_PROVIDER`) | Required env vars |
|-----------------------------------|-------------------|
| `azure-openai` (app default) | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_API_VERSION` |
| `openai` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `local` (keyless, default here) | none — uses `OLLAMA_BASE_URL` + `AGENTOS_MODEL` |

---

## Troubleshooting

**CLI panics at startup: "Failed to connect to LLM..."**
The selected provider is unreachable. For the `local` path this means Ollama is
down or has no model. Fix: ensure `docker compose up -d` shows `ollama` healthy,
then `docker compose exec ollama ollama pull <model>` with the model matching
`AGENTOS_MODEL`. For cloud providers it means no/invalid key — set the right
key env var (table above). Tier 1 (`os-demo`) never connects to an LLM and so
never hits this.

**Model not pulled / "model not found".**
Run `docker compose exec ollama ollama pull llama3.2` (or your chosen model).
Verify it landed with `docker compose exec ollama ollama list`. The name must
exactly match `AGENTOS_MODEL` in `docker-compose.yml`.

**No GPU.**
CPU inference works out of the box — the GPU `deploy:` block in
`docker-compose.yml` is commented out. Expect slower responses and pick a small
model (e.g. `llama3.2`, `qwen2.5:3b`). To enable GPU, install the
nvidia-container-toolkit on the host and uncomment the `deploy:` block under the
`ollama` service.

**Slow first build.**
The first `docker build` compiles the entire Rust dependency graph (tokio,
reqwest, wasmtime, rusqlite-bundled, etc.) and can take many minutes. This is
expected. Docker layer cache makes rebuilds fast as long as `Cargo.lock` and the
sources copied before the `cargo build` step don't change. Do **not** switch to
`cargo build --workspace` to "fix" anything — that pulls in `tauri-app` and its
GTK/WebKit system deps, which are not installed in this image and will fail.

**`config.toml` not taking effect.**
The entrypoint regenerates `/data/config/ai-agent-os/config.toml` on every
start from the env vars. If you hand-edit it, your edits are overwritten next
run — change the env vars in `docker-compose.yml` instead (or override the
entrypoint).

**Interactive prompt exits immediately / no TTY.**
Use `docker compose run --rm agentos agent` (compose `run` allocates a TTY since
`tty: true` / `stdin_open: true` are set). For raw `docker run`, add `-it`:
`docker run -it --rm agentos:latest agent`.

**Permission denied writing to /data.**
The container runs as the non-root `agentos` user (uid 10001) and `/data` is
chowned to it in the image. If you bind-mount a host directory over `/data`,
ensure it is writable by uid 10001 (or use the named volume, the default).

---

## Quick reference

```bash
# Tier 1 — keyless OS enforcement demo
docker build -t agentos:latest .
docker run --rm agentos:latest                       # os-demo (default)

# Tier 2 — full CLI against local Ollama
docker compose up -d --build
docker compose exec ollama ollama pull llama3.2
docker compose run --rm agentos agent                # interactive
docker compose run --rm agentos agent -c "..."       # one-shot
docker compose down -v                               # tear down + wipe volumes
```
