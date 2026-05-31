# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AI Agent OS is a Rust workspace that implements a Linux-kernel-inspired runtime for managing AI agents. The mental model is the load-bearing thing here: **agents are processes, context is virtual memory, tools are files, and the kernel orchestrates them**. Every module name in `crates/kernel/src/` maps to a Linux kernel subsystem — see `docs/ARCHITECTURE.md` for the mapping table. When in doubt about where something belongs, find its Linux analogue first.

## Common Commands

```bash
# Workspace tests (CI runs exactly this — tauri-app is excluded because it needs system libs)
cargo test --workspace --exclude tauri-app

# Test a single crate / module / test name
cargo test --package kernel
cargo test --package kernel execution            # filter by name substring
cargo test --package adapters
cargo test --package integration-tests           # property + e2e tests in tests/src/

# Lint / format (CI gates on fmt; clippy is continue-on-error but treats warnings as errors locally)
cargo fmt --all -- --check
cargo clippy --workspace --exclude tauri-app -- -D warnings

# Run the headless agent CLI (binary is `agent`, not `agent-cli`)
cargo run --package agent-cli                          # interactive REPL
cargo run --package agent-cli -- -c "do something"     # one-shot
cargo run --package agent-cli -- --conversation <ID>   # resume
echo "input" | cargo run --package agent-cli -- "prompt"  # pipe mode

# Tauri desktop app (requires libgtk-3-dev, libwebkit2gtk-4.1-dev, libayatana-appindicator3-dev, librsvg2-dev on Linux)
cd crates/tauri-app/ui && npm install && npx vite build
cargo build --package tauri-app

# Benchmarks (package is `os-benchmark`; bin names use hyphens, not underscores)
cargo run --package os-benchmark --bin os-benchmark
cargo run --package os-benchmark --bin stress-test
```

LLM provider config is via env vars (see `.env.example`); Azure OpenAI is the default. Other supported providers: `openai`, `anthropic`, `local` (Ollama). The CLI reads `config.llm_provider` to decide which adapter to register — see `crates/cli/src/main.rs` `register_providers`.

## Architecture

### Workspace layout

```
crates/
  kernel/      # The OS kernel — 50+ modules, each maps to a Linux subsystem
  adapters/    # LLM provider adapters (Azure OpenAI, OpenAI, Anthropic, local Ollama)
  resources/   # Resource providers (filesystem, network, application)
  cli/         # `agent` binary — headless terminal client
  tauri-app/   # Desktop app (Rust backend + Svelte/Vite frontend)
tests/         # Property-based + e2e tests (proptest, wiremock); package name `integration-tests`
benchmarks/    # OS-level benchmarks + SWE-bench harness
examples/      # CLI usage examples
```

### Kernel orchestrator

`AgentKernelImpl` in `crates/kernel/src/lib.rs:667` is the wired root object that owns every subsystem (`agent_manager`, `scheduler`, `context_manager`, `permission_manager`, `sandbox_manager`, `ipc`, `observability`, `connector`, `resource_broker`, `tool_registry`, `rate_limiter`, `cgroups`, `syscall_gate`). Constructors:

- `AgentKernelImpl::new()` — in-memory SQLite, used by tests
- `AgentKernelImpl::with_db_path(path)` — persistent SQLite at a chosen path
- `AgentKernelImpl::from_config(&config)` — reads `config.data_dir` and persists to `agent_os.db`

The documented top-level entry points are the free functions `kernel::boot(&config)` and `kernel::boot_in_memory()` (lib.rs): they build the kernel **and** call `AgentKernelImpl::start_runtime()`, which spawns the background tasks — a scheduler observer that publishes the CFS pick into procfs as `current_agent`, and a per-minute cgroup-counter reset so `tokens_per_min` quotas regenerate. `from_config`/`new` do *not* start the runtime. Prefer `boot()` for new entry points — note the CLI and Tauri `main.rs` currently call `from_config` directly, so the background tasks don't run in those binaries yet.

Agent creation flows through `create_agent_full`, which enqueues into both the priority `scheduler` and the CFS run queue. The priority scheduler hard-caps at `MAX_CONCURRENT_AGENTS = 10` (`scheduler.rs`): beyond that, `schedule()` *blocks* waiting for a free slot and returns `QueueFull` after a 10s deadlock timeout — so bulk-creating agents that never run to completion will stall.

When adding a new subsystem, wire it through `AgentKernelImpl::with_context_manager`. The CLI and Tauri app both go through this orchestrator — never instantiate subsystems directly in entry points.

### The syscall gate (load-bearing OS layer)

`crates/kernel/src/syscall_gate.rs` is the **chokepoint that makes namespaces, capabilities, MAC, and cgroups load-bearing**. Every tool call from `AgentExecutor::execute_tool` (`crates/kernel/src/execution.rs:321`) consults `SyscallGate::check_tool_call`, which runs these in order (first failure wins):

0. **Namespace visibility** — if the tool is tagged with a namespace, the calling agent must be a member; `NotInNamespace` otherwise. Untagged tools are global. (Phase 3 — runs *before* capability/MAC.)
1. **Capability check** — `classify_tool(name)` → required cap (e.g. `http_get` requires `CAP_NET_ACCESS`); `MissingCapability` denial otherwise.
2. **MAC check** — `MacEngine::check(pid, action, resource)`; `MacDeny` if the policy returns Deny.
3. **Cgroup quota check** — `cgroups.check_token_limit(cg, est_tokens)`; `CgroupQuota` if over budget.

The gate maintains a translation table from kernel `Uuid` agent IDs to `agent_struct::AgentId` (u64 "PIDs") so the older OS-style subsystems (which use u64) can talk to the newer kernel orchestrator (which uses Uuid) without either side changing. Capabilities are derived from the `permission_profile` string at agent creation via `caps_for_profile` in `lib.rs`. The contract is locked by the `tests/src/os_enforcement.rs` suite (capability/MAC/cgroup ordering, namespace isolation for both tools and IPC, scheduler `pick_next` honoring nice values) — if those tests fail, the OS framing is broken.

When adding a new tool, **classify it in `syscall_gate::classify_tool`** so it inherits the right action label and capability requirement. Don't bypass the gate from new code paths.

### Linux → Agent OS mapping (load-bearing convention)

| Module | Role |
|---|---|
| `agent_struct`, `agent`, `agent_syscalls` | task_struct + fork/exec/signals |
| `cfs`, `scheduler` | CFS-style fair scheduling with vruntime/nice |
| `context`, `context_paging` | Virtual memory: token budgets, LRU eviction, OOM kills lowest-priority agent |
| `tools`, `tool_descriptors`, `mount_table`, `custom_tools` | VFS: tools are files, descriptors mount at paths |
| `agent_sockets`, `pipes`, `ipc`, `service_discovery` | Networking + Unix sockets + DNS |
| `mac`, `permissions`, `namespaces`, `sandbox`, `cgroups` | Security: SELinux-style MAC, capabilities, isolation |
| `init_system`, `agentctl`, `agentps` | systemd-style service files + dependency ordering |
| `syscall_interface` | Numbered syscalls with errno + capability checks |
| `procfs`, `observability`, `event_loop` | /proc filesystem + audit logging |
| `agentpkg`, `package`, `marketplace` | apt-like package manager |
| `execution`, `planning`, `editing`, `delegation` | The think→act→observe loop and multi-agent delegation |
| `connector`, `mcp`, `github`, `database` | External-system integrations |

The mapping isn't cosmetic — module boundaries, naming, and even error semantics deliberately echo the Linux kernel. Don't introduce abstractions that break the mapping; if a feature has no Linux analogue, that's a signal to reconsider where it should live.

### Persistence

State persists through `SqliteContextManager` (`crates/kernel/src/context.rs`) using bundled `rusqlite`. Both the `agent_os.db` schema and conversation/message structures are owned there — don't open separate SQLite handles elsewhere in the kernel.

### LLM adapters

Each adapter in `crates/adapters/src/` implements `LlmProviderAdapter` (defined in `kernel::connector`). Adapters are registered into the kernel via `kernel.register_provider(Arc::new(adapter))`. Streaming is centralized in `crates/adapters/src/streaming.rs`. Adapter tests use `wiremock` (see `*_tests.rs` siblings) — never hit real APIs from tests.

### Testing strategy

- **Unit tests** live next to source under `#[cfg(test)]`.
- **Property tests** live in `tests/src/*_props.rs` using `proptest` — these encode correctness invariants (lifecycle, scheduler fairness, permission monotonicity, etc.). When changing a subsystem, run/extend the matching `*_props.rs` file.
- **E2E tests** live in `tests/src/e2e_pipeline.rs` and exercise the full kernel through `wiremock`-backed adapters.
- The `tests/` crate is named `integration-tests` (see `tests/Cargo.toml`).

## Conventions

- **Conventional Commits** are required (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
- **License**: AGPL-3.0. Modifications must remain AGPL-licensed.
- **Rust toolchain**: stable, MSRV 1.75+.
- **Workspace deps**: shared versions live in the root `Cargo.toml` `[workspace.dependencies]` table; member crates should reference them via `workspace = true` rather than pinning their own versions.
- **CI excludes `tauri-app`** from `cargo test` because it needs GTK/WebKit system libraries; the `build-app` job builds it separately. Don't add tests that require Tauri to the default test run.
