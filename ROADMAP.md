# AI Agent OS — Roadmap to a True OS

> **Next frontier:** the Phase 1–3 OS-unification work below is complete (the syscall gate,
> namespaces, MAC, cgroups, CFS turn admission, context paging, and budget enforcement are
> load-bearing; `OsKernel` is gone). The forward-looking platform backlog — reaching
> feature-comparability with [AIOS](https://github.com/agiresearch/AIOS) (kernel-as-server,
> agent SDK, LLM-core breadth, context switching, memory/storage retrieval) — lives in
> [docs/AIOS_PARITY_BACKLOG.md](docs/AIOS_PARITY_BACKLOG.md).

## Where we are (May 2026 audit)

Today, ~33% of the Linux-mapped subsystems are load-bearing on the live runtime path; ~67% exist in code but are bypassed. Two parallel orchestrators (`AgentKernelImpl` used by CLI/Tauri, `OsKernel` used only in benchmarks) own different halves of the design — that split is the single biggest reason "OS" is currently naming rather than architecture.

| Layer | Status today | Becomes load-bearing in |
|---|---|---|
| IPC (agent messaging + delegation + discovery) | Real and used | — |
| Init system (boot order + supervisor) | Real and used | — |
| Signals + agent state machine | Real, partial | Phase 1 |
| Context storage (SQLite) | Real and used | — |
| **Syscall interface (MAC + caps + cgroup gate)** | **Defined, never called** | **Phase 1** |
| **Cgroups (token / call quotas)** | **Counts, never rejects** | **Phase 1** |
| **Context paging (LRU eviction)** | **Tested, never invoked** | **Phase 2** |
| CFS scheduler (vruntime, nice) | Logic real, runtime ignores it | Phase 3 |
| Namespaces (resource hiding) | Membership tags only | Phase 3 |
| VFS / tool descriptors | Allocated, never used | Phase 3 |
| Package manager / marketplace | Mock in-memory | Phase 4 |
| ProcFS | Snapshot-only | Phase 4 |

## Goal

Be the first thing on the internet that earns the name "AI Agent OS": a runtime where **isolation, capability checks, and resource quotas are enforced on every tool call**, not optional scaffolding. The benchmark for "true OS" is one e2e test:

> An agent without `CAP_NET` is denied a network tool with `EPERM`; an agent over its cgroup quota is denied with `EAGAIN`; an agent in namespace X cannot resolve a tool registered in namespace Y.

When that test passes, we ship v0.1.0.

## Phases

### Phase 1 — Make the OS load-bearing (this PR series)

Goal: every tool call goes through the syscall layer; quotas reject; CI is green; README is honest.

- [x] Audit + roadmap (this document)
- [ ] **Fix CI** — 3 failing tests block any honest "tests passing" claim
  - `indexer::tests::build_repo_map` uses absolute `/home/surya/...` path
  - `os_kernel::boot_from_service_files` and `boot_respects_dependency_order` assume `/tmp/agent_services` exists with seeded files
  - Switch to `tempfile::tempdir()` + `CARGO_MANIFEST_DIR`
- [ ] **Wire syscall gate into tool execution** (the critical change)
  - Add `SyscallGate` in `kernel::syscall_gate` wrapping: `check_capability` → `MacEngine::check` → `cgroups::enforce_limits` → execute → `cgroups::record_tokens` → emit observability event
  - Modify `AgentExecutor::execute_tool` (`crates/kernel/src/execution.rs:255`) to call the gate first; on deny return a structured `EPERM`/`EACCES`/`EAGAIN` to the LLM
  - Wire from `AgentKernelImpl::send_message` (`lib.rs:622`) so every CLI/Tauri call exercises it
  - Each agent gets a default cgroup at create time; default policy is `allow` so existing behaviour is preserved unless a profile asserts otherwise
- [ ] **Wire context paging into context.rs**
  - On `save_message` / `append`, call `ContextPager::add_page`; OOM eviction returns paged-out content via summarization
- [ ] **Observability retention** — bounded ring buffer (default 10k events) + per-agent purge on shutdown
- [ ] **Honest README** — replace "368 tests passing" badge with live CI badge; replace the Linux-mapping table with a "load-bearing today / planned" table; link to this roadmap
- [ ] **OS-ness e2e test** — `tests/src/os_enforcement.rs` exercising the three denials above

**Exit criteria for Phase 1:** CI green on `main`, the e2e test passes, README mentions only enforced subsystems as "real."

### Phase 2 — Fold the two orchestrators into one

Goal: `AgentKernelImpl` owns the OS surface; `OsKernel` is no longer the source of truth.

- [x] Move `cfs`, `namespaces`, `init_system`, `procfs`, `sysctl` into `AgentKernelImpl` via the new `OsSubsystems` field. (`mac` lives inside `SyscallGate`; `cgroups` already moved in Phase 1. The socket-style `service_discovery::ServiceRegistry` was later removed — agent discovery ships through the agent directory via the `discover_agents` tool, so the registry was dead weight.)
- [x] `create_agent_full` now wires every new agent into the default Agent + Tool namespaces, the CFS scheduler, and procfs through the gate's PID translation.
- [x] `tests/src/os_enforcement.rs::unified_kernel_places_agent_in_os_subsystems` proves the wiring is real.
- [x] `OsKernel` documented as superseded; retained only for the raw-PID stress benchmark.
- [x] Migrated `runtime.rs` background loops to `AgentKernelImpl::start_runtime`. Now: scheduler observer (publishes CFS pick to procfs) + cgroup minute-reset timer.
- [x] Added `kernel::boot(config)` and `kernel::boot_in_memory()` as documented top-level entry points; both spawn `KernelRuntime` automatically.
- [x] `OsKernel` deleted entirely. `benchmarks/stress_test.rs` migrated to `AgentKernelImpl::create_agent_full` + `SyscallGate::check_tool_call`.

**Exit criteria for Phase 2:** ✅ one orchestrator owns the OS surface; new agents land in the OS subsystems on the live path.

### Phase 3 — Real isolation and scheduling

Goal: namespaces actually hide resources; scheduler actually decides who runs.

- [x] **Namespace enforcement in tool resolution** — `SyscallGate` now consults a `tool_namespaces` table and per-agent `namespaces: Vec<NamespaceId>` membership; tools tagged with a namespace return `GateDenial::NotInNamespace` (≈ ENOENT) for non-members. The check runs first so foreign tools look indistinguishable from non-existent ones (no MAC-probe leak). Proven by `tests/src/os_enforcement.rs::namespace_isolation_denies_foreign_tool` and `namespace_denial_precedes_capability_and_mac`.
- [x] **Per-namespace IPC** — `IpcManager` consults a `NamespaceVisibility` trait (impl by `SyscallGate::shares_namespace`) on every `send` and `publish`. Cross-namespace sends fail as `AgentNotFound` so a sender cannot probe for foreign mailboxes. Proven by `tests/src/os_enforcement.rs::namespace_isolation_blocks_cross_namespace_ipc`.
- [x] **Scheduler observability + accounting** — `AgentKernelImpl::send_message` accounts each turn's tokens against the agent's CFS vruntime; new `kernel.set_nice(agent_id, nice)` and `kernel.next_runnable_agent()` make fairness inspectable. Proven by `tests/src/os_enforcement.rs::nice_values_change_scheduler_pick_next` — equal token spend with different nice values produces ordered `pick_next()` outcomes. Strict admission gating (block `send_message` until the agent's CFS turn) is a follow-up.
- [ ] **Real OOM kill** — `context_paging` overflow triggers signal to lowest-priority agent in the cgroup
- [ ] **VFS for tools** — agents `tool_open()` a path → fd; `tool_call()` takes fd; descriptor table enforces per-agent open limits

**Exit criteria for Phase 3:** Stress test runs 100 agents across 3 namespaces and 5 cgroups; isolation and quota are observable from the outside.

### Phase 4 — Package manager, procfs, distribution

Goal: someone can `agentpkg install foo` from a real registry and it runs.

- [ ] **Real package format** — `.agent` archive: manifest + tools + policies + signed checksum
- [ ] **Local registry** that actually serves packages over HTTP; `cargo run --bin agentpkg-registry`
- [ ] **Install / verify / uninstall** end-to-end with deps
- [ ] **Live procfs** — agent can read `/proc/agents/<id>/status`, `/proc/cgroups`, `/proc/syscalls/stats`
- [ ] **Cross-platform sandbox** — Windows Job Objects, macOS sandbox-exec, Linux via existing docker_sandbox
- [x] **Feature-gate heavy deps in `resources` crate** — `chromiumoxide` (~50 MB) behind `browser`, `scraper` behind `web`. Default build is lean. CI exercises both lean (`cargo test`) and full (`cargo build --all-features`) modes. Note: `wasmtime` (~10 MB) is still load-bearing in the kernel for `models.rs` types — gating it out is a follow-up that requires moving `ResourceRequirements` out of `modules.rs`.

**Exit criteria for Phase 4:** `cargo install agent-cli && agent` works for a fresh user with no env vars beyond an LLM key.

### Phase 5 — Open-source positioning

Goal: external contributors can land PRs.

- [ ] Tag **v0.1.0** when Phase 1 + Phase 2 land + green CI
- [ ] Open ~15 seed issues for Phase 3/4 work, labelled `good-first-issue` / `help-wanted`
- [ ] Repo topics: `rust`, `ai-agents`, `operating-system`, `multi-agent`, `llm`, `kernel`
- [ ] Repo description tightened to claim only what's enforced
- [ ] `docs/ARCHITECTURE.md` updated to mark each subsystem as real / planned
- [ ] Discord or GH Discussions for design conversations
- [ ] Release notes per tag; CHANGELOG.md actually maintained
- [ ] Submit to `awesome-rust`, `awesome-ai-agents` once v0.1.0 is out

**Exit criteria for Phase 5:** non-author opens and lands a PR.

## Non-goals

- Replacing Linux. This runs *on* an OS; it does not boot bare metal.
- Sandboxing untrusted code at the kernel-bypass level — we rely on Docker/WASM for that.
- Distributed agents across machines. That's a separate layer.
- Re-implementing every Linux feature. We take what serves multi-agent management; we don't import what doesn't.

## How to read the code as we land this

- `crates/kernel/src/syscall_gate.rs` (Phase 1) is the new chokepoint — read it first to understand where enforcement happens.
- `crates/kernel/src/lib.rs::AgentKernelImpl` is the orchestrator; after Phase 2 it absorbs `os_kernel.rs`.
- `crates/kernel/src/execution.rs::AgentExecutor::execute_tool` is the call site that invokes the gate.
- `tests/src/os_enforcement.rs` (Phase 1) is the proof. If it ever flakes, the OS claim is broken.
