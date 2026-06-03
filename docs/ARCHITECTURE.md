# AI Agent OS — Architecture

> **Mental model (load-bearing):** *agents are processes, context is virtual
> memory, tools are files, and the kernel orchestrates them.* Every module in
> `crates/kernel/src/` maps to a Linux kernel subsystem. When deciding where
> something belongs, find its Linux analogue first.

This document describes the system **as it is built today**. It is the canonical
reference for the README and for new design work.

---

## 1. The one-paragraph version

AI Agent OS is a Rust workspace that runs AI agents the way Linux runs
processes. A single orchestrator — `AgentKernelImpl` — owns every subsystem and
wires them together. Agents are created, scheduled (CFS-style fair scheduling
with priorities/nice), and given a token budget that behaves like virtual
memory (paged, evicted, OOM-killed). Every tool an agent calls passes through
one **syscall gate** that enforces namespace visibility, capabilities, MAC
policy, and per-minute token quotas — first failure wins, before any real work
happens. The kernel speaks a versioned JSON wire protocol over TCP / Unix
socket / TLS, so the same kernel is reachable from a CLI, a Rust SDK, a cluster
client, a TUI, a desktop app, or an MCP server. LLM access goes through a
provider-agnostic connector with nine adapters, failover, retry/backoff, and
rate limiting. State persists through a single SQLite handle.

**The product wedge is _governed multi-agent execution_:** the enforced
isolation at the syscall gate is the differentiator; everything else is
supporting cast.

---

## 2. Workspace layout

```
crates/
  kernel/      # The OS kernel — ~60 modules, each maps to a Linux subsystem
  adapters/    # 9 LLM provider adapters + centralized streaming
  resources/   # Resource providers (filesystem, network, application, browser, …)
  cli/         # `agent` binary (REPL/one-shot) + `agent-server` binary
  sdk/         # Rust client SDK: KernelClient, ClusterClient, agent patterns
  tui/         # Ratatui terminal UI over the SDK
  tauri-app/   # Desktop app (Rust backend + Svelte/Vite frontend)
tests/         # Property-based + e2e tests (proptest, wiremock); pkg `integration-tests`
benchmarks/    # OS-level benchmarks, stress test, governance demo, SWE-bench harness
examples/      # CLI usage examples
docs/          # This doc + spec, roadmap, runbook, package format
```

**Rust-only.** No Python/TS/Go runtimes, SDKs, or bindings anywhere in the
product. TLS is `rustls` (ring provider, no C toolchain). Embeddings are
pure-Rust and deterministic. Persistence is bundled `rusqlite`.

---

## 3. Boot path and the kernel root object

Three documented entry points (in `crates/kernel/src/lib.rs`):

| Function | DB | Starts background runtime? | Use |
|---|---|---|---|
| `kernel::boot(&config)` | persistent (`config.data_dir/agent_os.db`) | **yes** | preferred for real binaries |
| `kernel::boot_in_memory()` | in-memory SQLite | **yes** | tests, demos |
| `AgentKernelImpl::new()` / `with_db_path()` / `from_config()` | varies | **no** | low-level construction |

`boot*` calls `start_runtime()`, which spawns the background tasks: a scheduler
observer that publishes the CFS pick into procfs as `current_agent`, and a
per-minute cgroup-counter reset so `tokens_per_min` quotas regenerate.

**`AgentKernelImpl` is the wired root object that owns every subsystem:**

```
agent_manager        scheduler (PriorityScheduler)   context_manager (SQLite)
permission_manager   sandbox_manager                 ipc (IpcManager)
observability        connector (LLM)                 resource_broker
tool_registry        rate_limiter                    cgroups
syscall_gate ◀── the chokepoint                       budget_enforcer (USD ceiling)
turn_admission (CFS-ordered turn gate)                llm_scheduler (bounded "LLM cores")
profile_cgroups (one cgroup per permission profile)   group_namespaces (per agent group)
executors (per-agent AgentExecutor)                   event_tx (broadcast KernelEvent)
os: OsSubsystems { cfs, namespaces, init, procfs, sysctl }
```

Everything funnels through this orchestrator. **Never instantiate subsystems
directly in an entry point** — wire through `AgentKernelImpl::with_context_manager`.

---

## 4. Linux → Agent OS subsystem map (current status)

| Module(s) | Linux analogue | Status |
|---|---|---|
| `agent_struct`, `agent`, `agent_syscalls` | `task_struct` + fork/exec/signals | Built |
| `cfs`, `scheduler`, `llm_sched` | CFS fair scheduling, vruntime/nice, bounded run pool | Built |
| `context`, `context_paging` | Virtual memory: token budgets, LRU eviction, OOM kill | Built |
| `memory_manager` | Long-term memory: embeddings + vector ranking | Built (pluggable seam) |
| `tools`, `tool_descriptors`, `mount_table`, `custom_tools`, `tool_registry_share` | VFS: tools are files, mounted at paths | Built |
| `ipc` | Inter-agent messaging + delegation, broker-routed, directory discovery | Built |
| `mac`, `permissions`, `namespaces`, `sandbox`, `docker_sandbox`, `cgroups`, `auth` | SELinux-style MAC, capabilities, isolation, tenancy | Built |
| `syscall_gate` | The enforcement chokepoint (see §6) | Built + fuzz-proven |
| `init_system`, `agentctl`, `agentps` | systemd-style service files + dependency ordering | Built |
| `syscall_interface`, `syscall_server` | Numbered syscalls + JSON wire protocol over TCP/Unix/TLS | Built |
| `procfs`, `observability`, `event_loop`, `sysctl` | `/proc` + audit logging + tunables | Built |
| `agentpkg`, `package`, `agent_package`, `marketplace`, `agent_hub` | apt-like packages + versioned hub | Built |
| `execution`, `planning`, `editing`, `delegation`, `function_calling` | think→act→observe loop + multi-agent delegation | Built |
| `connector`, `mcp`, `mcp_server`, `github`, `database` | External-system integration + MCP (client & server) | Built |
| `runtime`, `production`, `config`, `models`, `modules`, `linux_compat` | runtime tasks, prod hardening, config, model registry | Built |
| `budget` | Cumulative USD spend ceiling on the LLM path | Built |
| `indexer`, `learning`, `shell`, `vision`, `voice`, `prerequisites` | code index, feedback, shell, multimodal, dep checks | Built (varying depth) |

The mapping is not cosmetic: module boundaries, naming, and error semantics
deliberately echo Linux. A feature with no Linux analogue is a signal to
reconsider where it belongs.

---

## 5. The execution loop (`execution.rs`)

`AgentExecutor` runs the classic **think → act → observe** loop:

1. **Think** — assemble context (history + long-term memory + tools), call the
   LLM through the connector.
2. **Act** — parse tool calls (`function_calling.rs`; plaintext fallback when a
   provider lacks native tool-calling). **Every tool call routes through
   `SyscallGate::check_tool_call` before the resource broker is ever touched.**
3. **Observe** — feed results back, loop until the turn completes.

**Mid-generation context switch.** A turn is resumable: `run_resumable`/`resume`
with a `GenerationCheckpoint` let the scheduler pause a turn at a boundary and
resume it later (`TurnResult::{Completed, Paused}`, `StreamEvent::Paused`). This
is what makes CFS preemption meaningful for long generations.

An agent is marked `Running` only for the duration of each turn (`set_running`/
`set_queued`), so `running_agents` reflects real concurrency. Concurrent
*execution* is bounded by the rate limiter (`max_concurrent`, default 3) and by
`turn_admission`; the LLM-request step inside a turn is additionally bounded by
`llm_scheduler` (a pool of "LLM cores", CFS-ordered under contention).

---

## 6. The syscall gate — the load-bearing OS layer

`crates/kernel/src/syscall_gate.rs` is **the chokepoint that makes namespaces,
capabilities, MAC, and cgroups load-bearing.** Every tool call from
`AgentExecutor::execute_tool` calls `check_tool_call`, which runs four checks in
order — **first failure wins:**

```
0. Namespace visibility — tool tagged with a namespace ⇒ caller must be a member,
   else NotInNamespace (≈ ENOENT, the tool is invisible). Untagged tools are global.
1. Capability check — classify_tool(name) → required cap (e.g. http_get needs
   CAP_NET_ACCESS); MissingCapability otherwise.
2. MAC check — MacEngine::check(pid, action, resource); MacDeny on policy Deny.
3. Cgroup quota — cgroups.check_token_limit(cg, est_tokens); CgroupQuota if over.
```

The gate maintains a translation table from kernel `Uuid` agent IDs to
`agent_struct::AgentId` (u64 "PIDs") so the older OS-style subsystems (u64) and
the newer orchestrator (Uuid) interoperate without either side changing.
Capabilities derive from the `permission_profile` string at creation via
`caps_for_profile`. Denials and audited allows flow to a pluggable `AuditSink`.

**This contract is locked by tests** (`tests/src/os_enforcement.rs` for ordering
and isolation; `tests/src/gate_adversarial_props.rs` runs ~2500 proptest cases
per run with an independent oracle that re-derives the 4-layer verdict — proving
no bypass). **When adding a tool, classify it in `classify_tool`.** Don't bypass
the gate from new code paths.

---

## 7. Scheduling

- **CFS** (`cfs.rs`) — vruntime + nice, fair share, `pick_next` honors priority.
- **PriorityScheduler** (`scheduler.rs`) — admission + run queue. Agent creation
  *admits* to the system (non-blocking) and enqueues into the CFS run queue;
  creation never blocks on the concurrency gate. `wait_for_turn` races a notify
  against a 5ms poll to avoid lost-wakeups.
- **TurnAdmission** — bounds concurrent *turns* to `max_concurrent`; under
  contention grants the next slot to the CFS-preferred (lowest-vruntime) waiter.
- **LlmScheduler** (`llm_sched.rs`) — a bounded pool of "LLM cores" gating the
  LLM-request step inside a turn; freed cores go to the lowest-nice waiter.

---

## 8. Context & memory

- **Context paging** (`context_paging.rs`) — token budget per agent = virtual
  memory. Old context is summarized (page-out); over-budget triggers eviction;
  OOM kills the lowest-priority agent. Driven by `max_context_tokens`.
- **Long-term memory** (`memory_manager.rs`) — a pluggable embedding seam:
  - `Embedder` trait (object-safe, `Arc<dyn Embedder>`); default `BlendedEmbedder`
    (word unigrams + bigrams + char-trigrams in salted hash subspaces, sublinear
    TF, L2-normalized). `FeatureHashEmbedder` preserves the original FNV-1a
    behavior for bit-compatibility.
  - `VectorIndex` trait with an exact-cosine `BruteForceIndex` default — the seam
    where an ANN index can later drop in without touching callers.
  - Wired through `SqliteContextManager` (`with_embedder(...)` builder); store
    and query both route through the same embedder.
  - All pure-Rust, deterministic, offline — no models downloaded, no network.

---

## 9. Security & tenancy stack

- **Capabilities** (`permissions.rs`) — per-profile cap sets (`CAP_NET_ACCESS`,
  `CAP_FILE_WRITE`, …) derived at agent creation.
- **MAC** (`mac.rs`) — SELinux-style subject/action/object policy, enforcing mode,
  audit sink.
- **Namespaces** (`namespaces.rs`) — agent + tool namespaces per group; tools
  tagged to a namespace are invisible to non-members. IPC respects namespaces.
- **Cgroups** (`cgroups.rs`) — per-minute token quotas; one cgroup per permission
  profile created at boot, reset every minute by the runtime task.
- **Budget** (`budget.rs`) — the single `BudgetEnforcer` caps cumulative USD on
  the LLM path (cgroups only bound per-minute tokens, not lifetime cost).
- **Sandbox** (`sandbox.rs`, `docker_sandbox.rs`) — execution isolation.
- **Auth** (`auth.rs`) — account/tenant layer atop per-agent caps/budgets/namespaces.

---

## 10. LLM connector layer

`connector.rs` defines `LlmProviderAdapter`; adapters live in `crates/adapters/src/`:

```
anthropic   azure_openai (default)   openai   gemini   groq
deepseek    huggingface              vllm     local (Ollama)
```

Centralized streaming in `streaming.rs`. The send path supports:
- **Failover** — ordered, acyclic backup chain; falls over to the next provider
  on transient/unavailable errors.
- **Retry/backoff** — bounded exponential backoff (injectable clock) for transient
  errors; permanent errors (auth/protocol) are not retried.
- **Rate limiting** (`rate_limit.rs`) — single-mutex atomic check-and-reserve for
  RPM/TPM windows (closes the TOCTOU race) + a counting semaphore for concurrency
  (no lost wakeups). Streaming and non-streaming share semantics.

Adapter tests use `wiremock` — tests never hit real APIs.

---

## 11. The wire API — kernel as a server

`syscall_server.rs` exposes the kernel as a service over a **newline-delimited
JSON** protocol (`Syscall` request / `SyscallReply` response), generic over the
transport (`handle<R, W>`):

- **Transports:** TCP, Unix socket (`bind_unix`/`connect_unix`), and **TLS**
  (`bind_tls`/`connect_tls`, rustls/ring). Optional shared-secret `Authenticate`.
- **Syscalls (current surface):**
  `CreateAgent · ListAgents · AgentInfo · SendMessage · CallTool · GateStats ·
   ListProviders · MemoryStore · MemoryQuery · StoragePut/Get/List/Delete ·
   SnapshotContext · RestoreSnapshot · ListSnapshots · DeleteSnapshot ·
   LoadPackage · NodeInfo · Authenticate`

This single protocol is the seam every client speaks to.

---

## 12. Entry surfaces (clients)

| Surface | Crate | Notes |
|---|---|---|
| **Service** (primary) | `cli` `agent-server` bin | the kernel over the wire protocol |
| **CLI** | `cli` `agent` bin | REPL, one-shot (`-c`), resume (`--conversation`), pipe |
| **Rust SDK** | `sdk` | `KernelClient` (storage/snapshot/memory/node/package, `connect_tls`) |
| **Cluster** | `sdk::cluster` | `ClusterClient`, N nodes, `Placement::{LeastLoaded, RoundRobin}` |
| **Agent patterns** | `sdk::patterns` | `ReActLoop`, `PlannerExecutor` |
| **TUI** | `tui` | Ratatui UI; render-free testable `App` state machine |
| **Desktop** | `tauri-app` | Svelte/Vite frontend + Rust backend |
| **MCP server** | `kernel::mcp_server` | JSON-RPC `initialize`/`tools.list`/`tools.call`, gate-enforced |

The chosen **primary entry surface is the service** (`agent-server` + SDK/TUI as
the lens). *Note: the CLI and Tauri `main.rs` currently call `from_config`
directly, so they don't yet start the background runtime tasks — prefer `boot()`
for new entry points.*

---

## 13. Tools/VFS, packages, hub, MCP

- **Tools as files** — `tools.rs` + `tool_descriptors.rs` mount tool providers at
  paths (`mount_table.rs`); `custom_tools.rs` + `tool_registry_share.rs` add
  user-defined and shareable tools.
- **Packages** — `agent_package.rs` (TOML `AgentManifest`, `load_package`/
  `run_package`), `agentpkg.rs`/`package.rs`/`marketplace.rs` (apt-like).
- **Hub** — `agent_hub.rs` versioned publish/fetch.
- **MCP** — client (`mcp.rs`) and gate-enforced server (`mcp_server.rs`).

---

## 14. Persistence

All state goes through **one** `SqliteContextManager` (`context.rs`, bundled
`rusqlite`) — conversations, messages, long-term facts (with embeddings),
agent KV storage (`agent_kv`), and context snapshots (`context_snapshots`).
**Don't open a second SQLite handle anywhere in the kernel.**

---

## 15. Testing strategy

- **Unit tests** next to source under `#[cfg(test)]`.
- **Property tests** in `tests/src/*_props.rs` (`proptest`) encode invariants:
  lifecycle, scheduler fairness, permission monotonicity, gate non-bypass, etc.
- **E2E** in `tests/src/e2e_pipeline.rs` + `governance_e2e.rs` drive the full
  kernel through `wiremock`-backed adapters.
- CI runs `cargo test --workspace --exclude tauri-app` (tauri needs GTK/WebKit;
  built separately in `build-app`). Gates on `fmt`; clippy is `-D warnings`.

---

## 16. End-to-end data flow (a single tool-using turn)

```
client (CLI/SDK/TUI/MCP)
  │  Syscall::SendMessage  (TCP / Unix / TLS, optional auth)
  ▼
syscall_server → AgentKernelImpl::send_message
  │  set_running · turn_admission (CFS-ordered) · BudgetEnforcer installed
  ▼
AgentExecutor (think → act → observe)
  │  think:  context_paging assembles window + memory_manager ranks facts
  │  LLM:    llm_scheduler core → connector (failover/retry) → rate_limit → adapter
  │  act:    function_calling parses tool calls
  ▼
  ┌──────────────────────────────────────────────────────────┐
  │ SyscallGate::check_tool_call   (FIRST FAILURE WINS)        │
  │  0 namespace → 1 capability → 2 MAC → 3 cgroup quota       │
  │  audit sink records allow/deny                             │
  └──────────────────────────────────────────────────────────┘
  │  (only on Ok)
  ▼
resource_broker → resource provider (filesystem / network / application / …)
  │  observe: result fed back; loop or TurnResult::{Completed|Paused}
  ▼
SqliteContextManager persists; KernelEvent broadcast; SyscallReply to client
```

---

## 17. Load-bearing vs supporting (the wedge)

**Load-bearing — deepen these:** the syscall gate (the differentiator), the LLM
path under load, context/memory, persistence/lifecycle, and auth/tenancy.
**Supporting cast — scope as such, don't over-deepen:** hub, marketplace, TUI,
MCP, packages, vision/voice. The product story is *governed multi-agent
execution* — agents governed like Linux processes, with enforcement proven
un-bypassable at the gate.
