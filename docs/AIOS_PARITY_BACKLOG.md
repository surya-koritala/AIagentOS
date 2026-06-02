# AIOS Parity Backlog

A feature backlog for reaching feature-comparability with [AIOS (agiresearch)](https://github.com/agiresearch/AIOS)
on the kernel / SDK / serving axes, while keeping AIagentOS's lead on OS-grade enforcement.

> Grounded against AIOS **v0.3.0** (Jan 2026): kernel modules `config, context, hooks,
> llm_core, memory, scheduler, storage, syscall, terminal, tool, utils`; SDK =
> [Cerebrum](https://github.com/agiresearch/Cerebrum) (LLM / Memory / Storage / Tool APIs +
> an agent-package format + ToolHub / agent hub). Paper: [COLM 2025](https://arxiv.org/abs/2403.16971).
> Authored 2026-06-01.

## Where we stand (honest)

- **We lead** on OS-grade *enforcement & isolation*: SELinux-style MAC (label + path/URL glob),
  Linux capabilities, cgroup token quotas, cumulative-USD budget ceiling, namespace isolation
  across agents/IPC/delegation/discovery/tools, an audit trail, and CFS fairness driving turn
  admission. AIOS's "Access Manager" is comparatively light.
- **We are behind** on the things that make AIOS *usable for running agents*: a real **agent SDK**,
  **kernel-as-server** deployment, **mid-generation context switching**, **memory/storage with
  retrieval**, **LLM backend breadth** (4 vs 9), **agent-framework support** (ReAct/AutoGen/MetaGPT/…),
  and **adoption/validation** (paper, community, releases).

## The strategic decision that shapes everything

AIOS's real architecture is **kernel-as-server + a separate SDK + an agent hub**. That split is *why*
it can host Python agent frameworks — they call the kernel over a client. AIagentOS is today a Rust
**in-process** library + CLI. So the highest-leverage move is **not** "add features" — it is to
**expose the Rust kernel over a syscall API (server) and ship a Python SDK**. The Rust kernel stays
Rust (its strength); the SDK and framework adapters are Python (where the ecosystem is). This mirrors
AIOS's design exactly, and nothing in Phases 1–6 is reachable by external builders until it exists.

Sizes: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ 3–6 weeks, **XL** ≈ a quarter (solo).

---

## Phase 0 — Kernel-as-server (unblocks everything)

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B0.1** | Syscall server: expose `AgentKernelImpl` over gRPC/JSON-RPC (Unix socket + TCP); promote the dormant `syscall_interface` into the real agent↔kernel boundary (LLM/memory/storage/tool/agent syscalls) | XL | — | AIOS's core pattern |
| **B0.2** | Python SDK ("Cerebrum-equivalent"): pip-installable client with `Agent` base class + `llm.chat()` / `memory.*` / `storage.*` / `tool.*` / syscall client | XL | B0.1 | Without this there are no external users |
| **B0.3** | Agent package format: `author/agent/{entry.py, config.json, requirements}` loader + runner | M | B0.2 | Matches Cerebrum's convention |

## Phase 1 — LLM Core ("LLMs as CPU cores")

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B1.1** | LLM backend breadth: add vLLM, Gemini, Groq, Deepseek, HuggingFace (4 → 9+) | M | — | Likely a `litellm`-style layer in the SDK |
| **B1.2** | LLM-request scheduling: scheduler dispatches queued LLM *syscalls* to LLM cores (today CFS/TurnAdmission gates agent *turns*, not LLM requests) | L | B0.1 | |
| **B1.3** | Function-calling shim for open-source models (structured tool-calling for models without native support) | M | — | |

## Phase 2 — Context Manager (AIOS's signature hard feature)

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B2.1** | Context snapshot / restore (persist + restore an agent's in-flight context so a turn can pause/resume) | L | — | |
| **B2.2** | Mid-generation context switch (pause/resume LLM *decoding*; feasible with vLLM/local, checkpoint-at-token-boundary for hosted APIs) | XL | B2.1, B1.1 | We have *none* of this today; ContextPager only trims the buffer |

## Phase 3 — Memory & Storage

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B3.1** | Memory Manager with retrieval: promote `query_memory` into a per-agent memory subsystem with embeddings + vector search | L | — | `indexer`/embeddings seam already exists |
| **B3.2** | Storage Manager: formalize persistent-storage syscalls beyond raw SQLite | M | B0.1 | |
| **B3.3** | LLM semantic file system (their research thread) | XL | B3.2 | **Optional / defer** — high effort, lower ROI |

## Phase 4 — Tool Manager

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B4.1** | MCP *server* (we have an MCP client; add server so agents expose/consume MCP tools) | M | — | |
| **B4.2** | ToolHub / shareable tool registry (downloadable tools) | M | B0.3 | |
| **B4.3** | Computer-use / VM controller (browser/desktop automation in a sandbox) | XL | — | **Optional / defer** |

## Phase 5 — Ecosystem & frameworks

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B5.1** | Framework adapters: ReAct + one of AutoGen/MetaGPT on the SDK | L | B0.2 | |
| **B5.2** | Agent hub (upload/download/share agents) | L | B0.3 | |
| **B5.3** | Web/terminal UI (extend the Tauri app; AIOS ships a semantic-FS terminal) | M | B0.2 | |

## Phase 6 — Distributed & validation

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B6.1** | Remote kernel / distributed deployment | L | B0.1 | |
| **B6.2** | Benchmarks + eval harness: run `stress_test` in CI; add an agent-task benchmark | M | — | SWE-bench harness seam exists |
| **B6.3** | Docs site + examples (AIOS has `docs.aios.foundation`) | M | — | |

## Keep our lead (do not regress)

| ID | Title | Size | Deps | Notes |
|----|-------|------|------|-------|
| **B7.1** | Expose enforcement via the syscall API: surface MAC / capabilities / cgroups / namespaces / audit / USD-budget as first-class SDK calls | M | B0.1 | **Our genuine differentiator** — make it visible, not buried. Do alongside Phase 0 |

---

## Recommended sequencing

1. **B0.1 syscall server** → 2. **B0.2 Python SDK** → 3. **B1.1 backend breadth**, with **B7.1** in
parallel so the security model is a headline SDK feature from day one. That turns a Rust library into
a usable agent platform and is the precondition for frameworks, hub, and distributed deploy.

## Honest reality check

- This is **multi-month, XL-heavy** work. AIOS is a funded research group with a multi-paper line and
  ~5.8k GitHub stars; **adoption/paper/community are not closeable by coding**. The achievable goal is
  *feature-comparable on the kernel/SDK/serving axes*, starting from a real lead on enforcement.
- Embrace the **Rust kernel / Python SDK split** — it is exactly AIOS's design and the bridge to the
  existing (Python) agent ecosystem.
- **Defer** the optional XLs (semantic FS B3.3, computer-use B4.3) until the core platform exists.
