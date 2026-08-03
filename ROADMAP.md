# AI Agent OS — Roadmap to a True OS

> **Archived historical roadmap (2026-07-21).** This document explains how the
> architecture evolved; its checkboxes are not the active backlog. Remaining
> work was migrated to the evidence-gated
> [v1 roadmap and child issues](https://github.com/surya-koritala/AIagentOS/issues/105).
> Current capability maturity lives in
> [`docs/capabilities.toml`](docs/capabilities.toml).

> **Next frontier:** the Phase 1–3 OS-unification work below is complete (the syscall gate,
> namespaces, MAC, cgroups, CFS turn admission, context paging, and budget enforcement are
> load-bearing; `OsKernel` is gone). The forward-looking platform roadmap — kernel-as-server,
> an embeddable Rust SDK, LLM-core breadth, context management, memory/storage retrieval, and
> tooling (all Rust) — lives in [docs/PLATFORM_ROADMAP.md](docs/PLATFORM_ROADMAP.md).

## Historical audit snapshot (May 2026)

At the time of this audit, ~33% of the Linux-mapped subsystems were load-bearing on the live runtime path; ~67% existed in code but were bypassed. Two parallel orchestrators (`AgentKernelImpl` used by CLI/Tauri, `OsKernel` used only in benchmarks) owned different halves of the design. The archived plan below records how that split was removed; it is not a description of the current tree.

| Layer | Status today | Becomes load-bearing in |
|---|---|---|
| IPC (agent messaging + delegation + discovery) | Real and used | — |
| Init system (boot order + supervisor) | Real and used | — |
| Signals + agent state machine | Real, partial | Phase 1 |
| Context storage (SQLite) | Real and used | — |
| **Syscall interface (MAC + caps + cgroup gate)** | **Defined, never called** | **Phase 1** |
| **Cgroups (token / call quotas)** | **Counts, never rejects** | **Phase 1** |
| **Context paging (LRU eviction)** | **Tested, never invoked** | **Phase 2** |
| CFS-inspired scheduler (vruntime, nice) | Production-qualified cooperative turn/provider admission; not CPU preemption or EEVDF | Phase 3 |
| Namespaces (resource hiding) | Membership tags only | Phase 3 |
| VFS / tool descriptors | Allocated, never used | Phase 3 |
| Package manager / marketplace | Mock in-memory | Phase 4 |
| ProcFS | Snapshot-only | Phase 4 |

## Goal

Be the first thing on the internet that earns the name "AI Agent OS": a runtime where **tool isolation and authorization are enforced on every tool call, and provider resource quotas are enforced at provider admission**, not optional scaffolding. The benchmark for "true OS" is one e2e test:

> An agent without `CAP_NET` is denied a network tool with `EPERM`; an agent in namespace X cannot resolve a tool registered in namespace Y; and an LLM request over its durable cgroup token budget is denied before provider invocation.

When that test passes, we ship v0.1.0.

## Phases

### Phase 1 — Make the OS load-bearing (this PR series)

Goal: every tool call goes through the syscall layer; provider quotas reject at provider admission; CI is green; README is honest.

- [x] Audit + roadmap (this document)
- [x] **Fix CI** — the three historical environment-dependent failures were removed
  - `indexer::tests::build_repo_map` uses absolute `/home/surya/...` path
  - `os_kernel::boot_from_service_files` and `boot_respects_dependency_order` assume `/tmp/agent_services` exists with seeded files
  - Switch to `tempfile::tempdir()` + `CARGO_MANIFEST_DIR`
- [x] **Wire syscall gate into tool execution** (the critical change)
  - `SyscallGate` now fails closed in declaration → namespace → capability → MAC → approval → cgroup-membership order; execution separately holds the cgroup concurrent-tool slot.
  - Provider token budgets are reserved and reconciled on the LLM path. The gate's legacy payload/`est_tokens` input never consumes quota; structured tool-call JSON and results included in a later LLM prompt do.
  - Modify `AgentExecutor::execute_tool` (`crates/kernel/src/execution.rs:255`) to call the gate first; on deny return a structured `EPERM`/`EACCES`/`EAGAIN` to the LLM
  - Wire from `AgentKernelImpl::send_message` (`lib.rs:622`) so every CLI/Tauri call exercises it
  - Each agent gets a default cgroup at create time; default policy is `allow` so existing behaviour is preserved unless a profile asserts otherwise
- [x] **Wire context pressure into live execution**
  - Before each provider attempt, enforce atomic per-agent/tenant/kernel active-token admission; serialize evicted messages to a quota-bound, retained, SHA-256-verified spill and fail closed when pinned state or durable storage cannot fit.
  - Conversations, embeddings, snapshots, active checkpoints, and spills share per-agent/tenant/kernel durable-byte ceilings. See `docs/CONTEXT_PRESSURE.md`.
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
- [x] Migrated the scheduler observer to `AgentKernelImpl::start_runtime` (publishes the CFS pick to procfs). Durable fixed-epoch token windows require no process-local cgroup reset timer.
- [x] Added `kernel::boot(config)` and `kernel::boot_in_memory()` as documented top-level entry points; both spawn `KernelRuntime` automatically.
- [x] `OsKernel` deleted entirely. `benchmarks/stress_test.rs` migrated to `AgentKernelImpl::create_agent_full` + `SyscallGate::check_tool_call`.

**Exit criteria for Phase 2:** ✅ one orchestrator owns the OS surface; new agents land in the OS subsystems on the live path.

### Phase 3 — Real isolation and scheduling

Goal: namespaces actually hide resources; scheduler actually decides who runs.

- [x] **Namespace enforcement in tool resolution** — `SyscallGate` now consults a `tool_namespaces` table and per-agent `namespaces: Vec<NamespaceId>` membership; tools tagged with a namespace return `GateDenial::NotInNamespace` (≈ ENOENT) for non-members. The check runs first so foreign tools look indistinguishable from non-existent ones (no MAC-probe leak). Proven by `tests/src/os_enforcement.rs::namespace_isolation_denies_foreign_tool` and `namespace_denial_precedes_capability_and_mac`.
- [x] **Per-namespace IPC** — `IpcManager` consults a `NamespaceVisibility` trait (impl by `SyscallGate::shares_namespace`) on every `send` and `publish`. Cross-namespace sends fail as `AgentNotFound` so a sender cannot probe for foreign mailboxes. Proven by `tests/src/os_enforcement.rs::namespace_isolation_blocks_cross_namespace_ipc`.
- [x] **Scheduler admission, observability + accounting** — `AgentKernelImpl::send_message` serializes each agent before bounded CFS-inspired turn admission, acquires LLM cores per provider request, accounts tokens against vruntime, and exposes queue, wait/run, cancellation, starvation, class-share, and cooperative-yield metrics. `set_nice` preserves accumulated debt; shared-resource holders inherit waiting priority until release. This is cooperative scheduling, not CPU preemption or EEVDF.
- [x] **Honest context-pressure policy** — prompt/storage pressure uses explicit backpressure and never advertises an OOM victim killer; host RSS remains the sandbox/container isolation boundary
- [ ] **VFS for tools** — agents `tool_open()` a path → fd; `tool_call()` takes fd; descriptor table enforces per-agent open limits

**Exit criteria for Phase 3:** Stress test runs 100 agents across 3 namespaces and 5 cgroups; isolation and provider-admission quota are observable from the outside.

### Phase 4 — Package manager, procfs, distribution

Goal: someone can `agentpkg install foo` from a real registry and it runs.

- [ ] **Real package format** — `.agent` archive: manifest + tools + policies + signed checksum
- [ ] **Local registry** that actually serves packages over HTTP; `cargo run --bin agentpkg-registry`
- [ ] **Install / verify / uninstall** end-to-end with deps
- [x] **Live operator control** — remote typed agent/cgroup/namespace/gate/package/service/provider views plus durable audited CAS/rollback tunables; legacy `ProcFs`/`Sysctl` are not public mounts
- [ ] **Cross-platform sandbox** — Linux has a fail-closed hardened rootless-container contract pending live breakout/crash qualification; Windows Job Objects/AppContainer and a supported macOS process sandbox remain to be implemented
- [x] **Feature-gate heavy deps in `resources` crate** — `chromiumoxide` (~50 MB) behind `browser`, `scraper` behind `web`. Default build is lean. CI exercises both lean (`cargo test`) and full (`cargo build --all-features`) modes. `wasmtime` now sits behind an off-by-default `wasm` feature on `kernel`; `ResourceRequirements` moved to `models.rs`, so the default build drops 79 crates including all of Cranelift (274 -> 195).

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
