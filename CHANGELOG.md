# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project uses [Semantic Versioning](https://semver.org/). While pre-1.0, a
**minor** bump (0.x.0) marks a shipped feature batch and a **patch** (0.x.y)
marks fixes. Every PR adds an entry under `## [Unreleased]`; cutting a release
moves it to a versioned, dated section. See [RELEASING.md](RELEASING.md).

## [Unreleased]

### Memory & retrieval

- **Approximate-nearest-neighbor index** — a real, dependency-free ANN behind the
  existing `VectorIndex` seam: multi-table random-hyperplane LSH (`LshIndex`),
  deterministic via a fixed-seed PRNG, with a radius-1 probe and a full-scan
  safety net so recall degrades gracefully. The live memory-query path now ranks
  through the seam (`rank_topk`) — exact `BruteForceIndex` at small fact counts,
  `LshIndex` above a threshold so a large fact store bounds the work instead of
  scoring every vector — and caps results to a top-K so the caller stops dumping
  the whole store into the prompt. Stays pure-Rust and fully offline (#100).

### Wire protocol (toward 1.0)

- **Versioned wire protocol** — the `Syscall`/`SyscallReply` schema now carries an
  explicit `PROTOCOL_VERSION` (1), versioned independently of the crate release.
  A new optional `Hello { protocol_version }` handshake lets a client negotiate:
  the server replies with its `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]` support
  window, and an out-of-range (or pre-versioning) server surfaces as a clear
  `SdkError::IncompatibleProtocol` rather than a confusing later failure. The SDK
  pins the version it was built against and adds `KernelClient::hello()`. `Hello`
  is allowed before authentication so a client can check compatibility before
  presenting credentials. Foundation for the 1.0 stability promise (#99).

### Reliability

- **Graceful startup degradation** — `agent-server` and the `agent` CLI no longer
  panic on operator errors (unwritable/locked data dir, corrupt DB, unreachable
  LLM provider). Kernel init, agent creation, provider connect, and one-shot/pipe
  runs now exit non-zero with a clear, actionable message instead of a panic
  backtrace. A malformed `config.toml` warns and falls back to defaults rather
  than being silently swallowed (#98).

### Observability

- **Production logging** — `agent-server` and the CLI install a `tracing`
  subscriber driven by `RUST_LOG` (default `info`), with `LOG_FORMAT=json` for
  ingestion; the kernel's existing `tracing` lines now actually emit (#96).
- **Prometheus metrics** — hand-rendered `text/plain; version=0.0.4` exposition
  (gate counters, agent counts, token/api totals, uptime) readable two ways: a
  `Metrics` syscall + `KernelClient::metrics()`, and an optional dependency-free
  HTTP `/metrics` endpoint started via `AGENT_SERVER_METRICS_ADDR` (#96).

## [0.2.0] - 2026-06-03

**Platform + Governed Execution.** Since 0.1.0 made the syscall gate
load-bearing, 0.2.0 turns the kernel into a real, reachable, multi-tenant
service: a JSON wire API over TCP/Unix/TLS, an embeddable Rust SDK and clients,
nine LLM providers with a hardened send-path, durable state across restarts,
first-class tenancy, and a one-command container. The governance wedge — agents
governed like Linux processes — is now proven un-bypassable and demonstrated
end-to-end. (64 commits since 0.1.0.)

### Kernel as a service (wire API)

- **Syscall server** — expose the kernel over a newline-delimited JSON protocol,
  generic over the transport (#41, #43, #47).
- **Transports** — TCP, **Unix-domain socket**, and **TLS** (rustls/ring), with
  an optional shared-secret `Authenticate` (#47, #84).
- **Syscall surface** — `AgentInfo` introspection (#44), `CallTool` (#43),
  per-agent **storage** (`StoragePut/Get/List/Delete`) (#71), **context
  snapshot/restore** (#78), and **`NodeInfo`** node-load (#80).

### SDK & clients

- **Embeddable Rust SDK** (`KernelClient`) over the syscall server (#46).
- **Agent patterns** — `ReActLoop` and `PlannerExecutor` templates (#69).
- **Distributed `ClusterClient`** — N nodes, `LeastLoaded` / `RoundRobin`
  placement (#80).
- **Terminal UI** — a ratatui TUI for observing and driving agents (#82).

### LLM providers & path

- **Six new adapters** — Groq, Deepseek (#45), Gemini, vLLM, HuggingFace (#51),
  bringing the total to **nine** providers.
- **Function-calling shim** for models without native tool support (#53).
- **Hardened send-path** — provider **failover**, bounded **retry/backoff**, and
  **rate-limiting under concurrent load** (atomic RPM/TPM reserve) (#90).

### Scheduling

- **CFS-ordered turn admission** — nice decides who runs under contention (#33).
- **LLM-request scheduling** — priority-ordered LLM-core admission (#52).
- **Mid-generation context switch** — pause/resume a turn at a boundary (#85).
- **Non-blocking create-time admission** (#29) and a **lost-wakeup fix** in the
  resource-access scheduler (#75).

### Memory & context

- **Memory manager** — embeddings + vector search (#67).
- **Pluggable embedding seam** — object-safe `Embedder` + `VectorIndex` traits
  with a stronger pure-Rust default (#89).
- **ContextPager** wired to bound the active context by tokens (#32).

### Security, governance & tenancy

- **Namespace differentiation** — isolate agent groups; group-scoped tools make
  tool-namespace isolation load-bearing (#22, #30).
- **MAC** — enforceable gate stage (#17), allow-and-log `Audit` decisions (#25),
  glob object matching on raw paths/URLs (#24).
- **Budget** — hard cumulative USD spend ceiling on the LLM path (#26).
- **Adversarial gate fuzz** — ~2500 proptest cases per run with an independent
  oracle, proving the 4-layer gate has no bypass (#87).
- **First-class multi-tenancy** — a tenant model atop namespaces/cgroups/auth;
  cross-tenant tool/IPC/state access is denied at the gate (#93).

### Persistence

- **Durable agent registry** — agents (and conversations/memory/KV/snapshots)
  survive a process restart; enforcement is re-armed on rehydrate (#92).

### IPC & multi-agent

- Agent-to-agent **messaging** (#18), **delegation** tools with orphan-on-reject
  (#19), **discovery** + address-by-name (#21), namespace-scoped discovery (#23),
  and delegation authorized by caller identity (#31).

### Packages, hub & MCP

- **Agent package format** + loader/runner (#49).
- **Shareable tool registry** (#72) and an **agent hub** — publish/fetch/share
  packages (#77).
- **MCP server** exposing kernel tools over JSON-RPC, gate-enforced (#68).

### Tools

- Extensible tool **registry** + git/browse/edit tools (#16).

### Benchmarks, demos & distribution

- **Agent-task benchmark** + eval harness with a CI smoke test (#73).
- **Governed-execution scenario** + runnable keyless demo (#88); keyless
  `os-demo` + Docker/Ollama test harness (#13).
- **Container image + one-command bootstrap** — ships `agent-server`, keyless by
  default, with a real-syscall healthcheck and `scripts/quickstart.sh` (#94).

### CLI

- Enforce the syscall gate on CLI tool calls (#12).

## [0.1.0] - 2026-05-09

First tagged release. Marks the point at which the Linux-mapped subsystems
became *load-bearing* — capability checks, MAC policy, cgroup quotas, and
namespace isolation now enforce on every tool call and IPC send instead of
existing as scaffolding next to the runtime path.

### Added — OS contract

- **`SyscallGate`** chokepoint (`crates/kernel/src/syscall_gate.rs`). Every
  tool call from `AgentExecutor::execute_tool` runs:
  `namespace visibility → capability → MAC → cgroup quota` before reaching
  the resource broker. Denials surface to the LLM as structured tool errors
  so the model can recover without the kernel trusting it.
- **Capabilities** — 9 capability types; `http_get` requires
  `CAP_NET_ACCESS`, `write_file` requires `CAP_FILE_WRITE`, etc. Profiles
  (`read-only`/`standard`/`elevated`/`full-access`) translate to capability
  sets.
- **MAC policy enforcement** — `MacEngine` consulted on every tool call;
  `MacDeny` returned to the LLM.
- **Cgroup quotas reject** — `tokens_per_min` over-budget calls return
  `CgroupQuota` (≈ EAGAIN); the minute-counter resets via background timer.
- **Namespace-scoped tools** — `register_tool_namespace(name, ns)` plus
  per-agent `set_agent_namespaces` produces `NotInNamespace` (≈ ENOENT)
  for foreign tools. Check runs first so MAC information cannot leak.
- **Namespace-scoped IPC** — `IpcManager.send/publish` consults a
  `NamespaceVisibility` checker; cross-namespace sends look like
  `AgentNotFound`.
- **Scheduler observability** — every `send_message` accounts tokens against
  CFS vruntime; `set_nice` and `next_runnable_agent` make fairness queryable.

### Added — orchestration

- **Unified `AgentKernelImpl`** with `OsSubsystems` (CFS, namespaces, init,
  procfs, sysctl, service registry). The standalone `OsKernel` is removed.
- **`kernel::boot(config)`** as the documented top-level entry point;
  spawns `KernelRuntime` automatically. CLI and Tauri use this.
- **`KernelRuntime::start()`** — scheduler observer + cgroup minute reset
  timer running as background tasks driven by the unified kernel.
- **Bounded observability retention** (default 1000 entries/agent) plus
  `purge_agent` on shutdown so multi-hour runs don't leak.

### Added — distribution

- **Lean default build** — `chromiumoxide` (~50 MB) and `scraper` moved
  behind `browser` and `web` cargo features on the `resources` crate. CI
  exercises both lean (`cargo test`) and full (`--all-features`) modes.

### Added — quality

- `tests/src/os_enforcement.rs` — 8 e2e tests pinning every contract above.
- `cargo clippy --workspace --exclude tauri-app -- -D warnings` runs clean.
- CI (`cargo fmt --check` + `cargo test --workspace --exclude tauri-app`)
  green on `main`. Test count: 416 passing.
- `.gitattributes` enforces LF line endings to prevent CRLF drift on
  cross-platform contributions.

### Removed

- **`OsKernel`** — superseded by `AgentKernelImpl`. Functionality fully
  migrated; stress benchmark (`benchmarks/stress_test.rs`) now drives the
  unified kernel + `SyscallGate`.

### Documentation

- **`ROADMAP.md`** — 5-phase plan with exit criteria; tracks load-bearing
  status of each subsystem.
- **`CLAUDE.md`** — orientation for AI assistants working in the repo;
  documents the syscall-gate convention.
- **`README.md`** — honest "Live / Defined / Planned" status table
  replacing the prior all-✅ marketing.

## [Pre-audit baseline] - 2025-05-05

### Added

- **Core Kernel**
  - Agent lifecycle management (create, pause, resume, stop) with state machine validation
  - Priority-based scheduler (1-5, max 10 concurrent agents, deadlock detection)
  - SQLite-backed context persistence with auto-summarization
  - Long-term memory store with text-based retrieval
  - Permission system with 4 profiles (read-only, standard, elevated, full-access)
  - Sandbox isolation with path traversal prevention and network allowlists
  - Inter-agent communication (direct messaging, pub/sub, task delegation)
  - Observability engine (action logging, metrics, plan deviation detection)
  - WASM module system (Wasmtime-based, manifest validation, crash isolation)
  - System prerequisite validation (RAM, disk, internet)

- **Agent Execution**
  - Think→Act→Observe execution loop with tool calling
  - LLM retry with exponential backoff (3 attempts)
  - Tool failure recovery (errors sent back to LLM for self-correction)
  - Context window management (auto-summarize at 20+ messages)
  - Long-term memory integration (facts stored and queried across sessions)

- **LLM Adapters**
  - Azure OpenAI (with api-key auth, deployment URLs)
  - OpenAI (GPT-4, function calling)
  - Anthropic (Claude, tool_use content blocks)
  - Local (Ollama/llama.cpp via HTTP)

- **Built-in Tools**
  - `read_file` — Read file contents
  - `write_file` — Write/create files
  - `list_directory` — List directory contents
  - `http_get` — HTTP GET requests
  - `run_command` — Execute shell commands

- **Desktop Application**
  - Tauri 2 + Svelte frontend
  - Setup wizard (provider selection, API key entry)
  - Dashboard with agent cards and system metrics
  - Chat panel with tool call indicators
  - Configuration persistence (TOML)

- **Testing**
  - 160 tests (unit + property-based + integration)
  - 28 correctness properties validated via proptest
  - E2E pipeline tests with wiremock
  - Adapter-specific wiremock tests (OpenAI, Anthropic)
