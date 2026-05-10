# Changelog

All notable changes to this project will be documented in this file.

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
