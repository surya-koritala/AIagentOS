# Platform Roadmap

Forward-looking feature roadmap for **AI Agent OS**: turning the load-bearing
Rust kernel into a complete, usable agent platform.

> **Rust-only.** The kernel, the SDK, agents, and all tooling are Rust. We do not
> introduce other languages or runtimes. The one external boundary (the syscall
> server) speaks plain JSON so it is language-neutral on the wire, but everything
> we build and ship is Rust.

## Where we stand

- **Strong — OS-grade enforcement & isolation.** SELinux-style MAC (label + path/URL
  glob), Linux capabilities, cgroup token quotas, a cumulative-USD budget ceiling,
  namespace isolation across agents/IPC/delegation/discovery/tools, an audit trail,
  and CFS fairness driving turn admission. This is the differentiator; keep it.
- **Thin — the platform surface.** No way yet for *external* agents to drive the
  kernel (no SDK / server until now); narrow LLM-backend coverage; no context
  snapshot/restore; basic memory (no retrieval); small tool ecosystem.

## Direction

Expose the kernel over a **syscall API** (a long-lived server) and ship an
**embeddable Rust SDK**, so agents — in-process or in separate Rust processes —
drive the kernel through a single boundary that always flows through the
enforcement gate. Build outward from there: LLM-core breadth, context
management, memory/storage with retrieval, and tooling.

Sizes: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ 3–6 weeks, **XL** ≈ a quarter (solo).

---

## Phase 0 — Kernel-as-server + SDK (unblocks everything)

| ID | Title | Size | Deps | Status |
|----|-------|------|------|--------|
| **B0.1** | Syscall server: expose `AgentKernelImpl` over a JSON syscall API (TCP + Unix socket); promote `syscall_interface` toward the real agent↔kernel boundary | XL | — | **Done** (`syscall_server`: agent lifecycle + LLM turn/providers + memory store/query + tool call + gate stats/agent info; TCP **and** Unix socket; optional shared-secret auth; enforcement over the wire) |
| **B0.2** | Embeddable **Rust SDK** crate: `Agent` builder + typed client over the syscall API (and an in-process mode), `llm` / `memory` / `storage` / `tool` calls | L | B0.1 | **Done** (`agent-sdk`: `KernelClient` + `Agent` builder; create/list/send/tool/gate + providers/memory/load_package) |
| **B0.3** | Agent package format + loader/runner (a Rust agent crate + a manifest the kernel can load and run) | M | B0.2 | **Done** (`agent_package`: TOML `AgentManifest` + `load_package`/`run_package`; `LoadPackage` syscall + SDK; `docs/AGENT_PACKAGE.md` + sample) |

## Phase 1 — LLM Core

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B1.1** | LLM backend breadth: add more `LlmProviderAdapter`s — 4 → 9+ | M | — | **Done** (9 providers: azure-openai, openai, anthropic, local, groq, deepseek, gemini, vllm, huggingface; routing/failover via the connector) |
| **B1.2** | LLM-request scheduling: scheduler dispatches queued LLM *requests* to LLM cores (today CFS/TurnAdmission gates agent *turns*) | L | B0.1 | **Done** (`llm_sched::LlmScheduler`: bounded LLM cores + priority-ordered RAII admission, wired into `send_message`) |
| **B1.3** | Function-calling shim for open-source models (structured tool-calling for models without native support) | M | — | **Done** (`function_calling`: render_tools_prompt + parse_tool_calls; executor plaintext-fallback path) |

## Phase 2 — Context management

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B2.1** | Context snapshot / restore (persist + restore an agent's in-flight context so a turn can pause/resume) | L | — | **Done** (`context_snapshots` table + `snapshot/restore/list/delete` methods; `Snapshot*`/`RestoreSnapshot` syscalls + SDK) |
| **B2.2** | Mid-generation context switch (pause/resume LLM decoding; feasible with local/vLLM, checkpoint-at-token-boundary for hosted APIs) | XL | B2.1, B1.1 | We only trim the buffer today (ContextPager) |

## Phase 3 — Memory & storage

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B3.1** | Memory Manager with retrieval: promote `query_memory` into a per-agent subsystem with embeddings + vector search | L | — | **Done** (`memory_manager`: deterministic offline feature-hash embedder + cosine ranking; `query_memory` now semantic, transparent to the memory syscalls) |
| **B3.2** | Storage Manager: formalize persistent-storage syscalls beyond raw SQLite | M | B0.1 | **Done** (per-agent `agent_kv` store on SqliteContextManager; `Storage{Put,Get,List,Delete}` syscalls + SDK methods) |
| **B3.3** | Semantic file system over agent storage | XL | B3.2 | **Optional / defer** |

## Phase 4 — Tools

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B4.1** | MCP *server* (we have an MCP client; add a server so agents expose/consume MCP tools) | M | — | **Done** (`mcp_server`: JSON-RPC `initialize`/`tools.list`/`tools.call` over TCP; gate-enforced call path, denials as JSON-RPC errors) |
| **B4.2** | Shareable tool registry (downloadable Rust tools / templates) | M | B0.3 | **Done** (`tool_registry_share`: `SharedToolRegistry`/`SharedToolDef`; publish/fetch, install into `ToolRegistry`, resolve from package `tools`) |
| **B4.3** | Computer-use / sandboxed automation controller | XL | — | **Optional / defer** |

## Phase 5 — Ecosystem

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B5.1** | Rust agent templates + reference patterns (ReAct-style loop, planner/executor) shipped on the SDK | L | B0.2 | **Done** (`agent_sdk::patterns`: `ReActLoop<Reasoner>` + `PlannerExecutor<Planner>` over `KernelClient`; wiremock-backed e2e) |
| **B5.2** | Agent hub (publish/fetch/share Rust agent packages) | L | B0.3 | **Done** (`agent_hub::AgentHub`: versioned publish/fetch/list/search of `AgentManifest`s; fetched package loads via `load_package`) |
| **B5.3** | Rust TUI / extend the desktop app for observing + driving agents | M | B0.2 | |

## Phase 6 — Distributed & validation

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B6.1** | Remote kernel / distributed deployment | L | B0.1 | |
| **B6.2** | Benchmarks + eval harness: run `stress_test` in CI; add an agent-task benchmark | M | — | **Done** (`agent-bench` bin + Rust eval harness in `benchmarks/`; fast CI smoke test runs under `cargo test --workspace`) |
| **B6.3** | Docs site + examples | M | — | **Done** (mdBook site under `docs/`: `book.toml` + `SUMMARY.md`; intro/getting-started/concepts pages wrapping the canonical docs) |

## Keep our lead (do not regress)

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B7.1** | Surface enforcement (MAC / capabilities / cgroups / namespaces / audit / USD-budget) as first-class SDK calls | M | B0.1 | Our genuine differentiator — make it visible. Do alongside Phase 0 |

---

## Recommended sequencing

**B0.1 syscall server → B0.2 Rust SDK → B1.1 backend breadth**, with **B7.1** in
parallel so the security model is a headline SDK feature from day one. That turns
the kernel library into a usable platform and unblocks the later phases.

## Notes

- Everything stays **Rust**. Where the broader agent ecosystem leans on other
  languages, we provide the Rust-native equivalent (SDK, templates, patterns)
  rather than embedding another runtime.
- **Defer** the optional XLs (semantic FS B3.3, computer-use B4.3) until the core
  platform exists.
