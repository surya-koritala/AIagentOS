# AI Agent OS — Architecture

> **Mental model (load-bearing):** *agents are processes, context is virtual
> memory, tools are files, and the kernel orchestrates them.* Every module in
> `crates/kernel/src/` maps to a Linux kernel subsystem. When deciding where
> something belongs, find its Linux analogue first.

This document describes the system **as it is built today**. It is the canonical
reference for the README and for new design work.

The multi-node authority, ownership, partition, and retry rules are specified
separately in the
[distributed control-plane consistency contract](DISTRIBUTED_CONTROL_PLANE.md).
The durable OpenRaft storage-v2 implementation in
`crates/kernel/src/cluster_consensus.rs` and the bounded mTLS peer/election
runtime in `crates/kernel/src/cluster_runtime.rs` form the optional quorum
authority. Under strict, default-off `[cluster_raft]` configuration,
`agent-server` routes public membership and ownership mutations through the
replicated deterministic state machine and serves linearizable reads, including
transparent follower forwarding. The disabled default retains the designated
single SQLite authority. Application-listener leaves have a bounded replicated
prepare/activate/finalize rollout. The voter subset can change by one durable
generation through persisted target intent, learner catch-up, and OpenRaft
joint consensus; non-voters remain replicated learners. Separate durable
transport-trust generations atomically replace the complete digest-pinned peer
map, add/remove learners, and rotate exact server/client leaves plus CA roots
through an expiring overlap. The immutable application genesis, complete
challenged application catalog, and current transport subset remain separate
exact inputs; retained peers preserve identity, leaf, and CA continuity.
Self-contained authority authentication at
workload destinations, migration, global quotas/trust, rolling upgrades, and
disaster recovery are not complete. Ownership revisions and destination fences
do retain the committed authority term and exact bounded lease expiry.

---

## 1. The one-paragraph version

AI Agent OS is a Rust workspace that runs AI agents the way Linux runs
processes. A single orchestrator — `AgentKernelImpl` — owns every subsystem and
wires them together. Agents are created, scheduled (CFS-style fair scheduling
with priorities/nice), and given a token budget that behaves like virtual
context (bounded active prompts with durable spill/backpressure). Every tool an agent calls passes through
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

`boot*` calls `start_runtime()`, which spawns the scheduler observer that
publishes the CFS pick into procfs as `current_agent`. Provider and cgroup token
limits use durable fixed Unix-minute epochs in SQLite and require no reset task.

**`AgentKernelImpl` is the wired root object that owns every subsystem:**

```
agent_manager        scheduler (PriorityScheduler)   context_manager (SQLite)
permission_manager   sandbox_manager                 ipc (IpcManager)
observability        connector (LLM)                 resource_broker
tool_registry        rate_limiter                    cgroups
syscall_gate ◀── the chokepoint                       budget_enforcer (USD ceiling)
turn_admission (CFS-ordered turn gate)                llm_scheduler (bounded "LLM cores")
tenant/profile/agent cgroup maps (stable hierarchy)  group_namespaces (per agent group)
executors (per-agent AgentExecutor)                   event_tx (broadcast KernelEvent)
operator_control (durable tunables + snapshot barrier)
os: OsSubsystems { cfs, namespaces, init, procfs, sysctl }
```

Everything funnels through this orchestrator. **Never instantiate subsystems
directly in an entry point** — wire through `AgentKernelImpl::with_context_manager`.

---

## 4. Linux → Agent OS subsystem map

The Linux analogy describes module boundaries, not implementation maturity.
Maturity is authoritative only in [the capability registry](capabilities.toml),
which CI verifies against every public kernel module.

| Module(s) | Linux analogue | Registry capability |
|---|---|---|
| `agent_struct`, `agent`, `agent_syscalls` | `task_struct` + fork/exec/signals | `agent-lifecycle` |
| `cfs`, `scheduler`, `llm_sched` | CFS-inspired cooperative turn admission (token vruntime/nice; not Linux EEVDF/CPU preemption) | `scheduling-admission` |
| `context`, `context_paging` | Virtual memory: token budgets, paging, pressure handling | `context-pressure` |
| `memory_manager` | Long-term memory: embeddings + vector ranking | `llm-memory-backends` |
| `tools`; experimental `tool_descriptors`, `mount_table` | Governed named tools; VFS prototypes are outside v1 | `syscall-vfs` |
| `ipc`, `delegation` | Inter-agent messaging + delegation | `agent-lifecycle` |
| `mac`, `permissions`, `namespaces`, `auth`, `policy` | SELinux-style MAC, capabilities, isolation, tenancy | `tenant-authorization`, `tool-governance` |
| `sandbox`, `docker_sandbox`, `resources` | Process/container/resource isolation | `sandbox-isolation` |
| `cgroups`, `budget`, `rate_limit`, `metrics` | Resource control and accounting | `resource-accounting` |
| `syscall_gate`, `custom_tools` | Tool enforcement chokepoint | `tool-governance` |
| `init_system`, `runtime` | systemd-style service boot and supervision | `init-supervisor` |
| SDK-backed `crates/cli/src/bin/agentctl.rs`, `agentps`, `procfs`, `observability`, `event_loop`, `sysctl` | typed control, audit, events, tunables | `operator-control` |
| `syscall_server`, `mcp`, `mcp_server`; experimental `syscall_interface` | Versioned JSON/TLS ABI and MCP; numbered prototype outside v1 | `syscall-vfs`, `wire-protocol` |
| `agentpkg`, `package`, `agent_package`, `marketplace`, `agent_hub`, `tool_registry_share` | apt-like packages and registry | `package-trust` |
| `execution` | resumable think→act→observe loop | `turn-checkpoints` |
| `connector`, `memory_manager`, `models` | LLM/model/retrieval backends | `llm-memory-backends` |
| `database` | Durable external data access helper | `durable-state` |
| `github`, `vision`, `voice` | External and multimodal providers | `resource-providers` |
| `production` | Runtime hardening primitives | `production-operations` |
| `editing`, `function_calling`, `indexer`, `learning`, `linux_compat`, `modules`, `planning`, `shell` | Supporting utilities with an explicit per-module v1 disposition | `secondary-modules` ([inventory](SECONDARY_CAPABILITIES.md)) |
| `config`, `prerequisites` | Configuration and host checks | `quality-gates` |

The mapping is not cosmetic: module boundaries, naming, and error semantics
deliberately echo Linux. A feature with no Linux analogue is a signal to
reconsider where it belongs.

---

## 5. The execution loop (`execution.rs`)

`AgentExecutor` runs the classic **think → act → observe** loop:

1. **Think** — assemble context (history + long-term memory + tools), call the
   LLM through the connector.
2. **Act** — parse tool calls (`function_calling.rs`; plaintext fallback when a
   provider lacks native tool-calling). **Every execution path routes through
   `ToolRegistry::authorize_and_acquire_call`, which validates the declared
   security contract and atomically acquires a cgroup tool slot before the
   resource broker is ever touched.** The older gate `check_*` methods are
   authorization-only compatibility/introspection helpers and must not be used
   as execution entry points.
3. **Observe** — feed results back, loop until the turn completes.

**Mid-generation context switch.** A turn is resumable: `run_resumable`/`resume`
with a `GenerationCheckpoint` let the scheduler pause a turn at a boundary and
resume it later (`TurnResult::{Completed, Paused}`, `StreamEvent::Paused`). This
is cooperative checkpointing at safe boundaries, not CPU or arbitrary mid-token
preemption.

An agent is marked `Running` only for the duration of each turn (`set_running`/
`set_queued`), so `running_agents` reflects real concurrency. Concurrent
*execution* is bounded by the rate limiter (`max_concurrent`, default 3) and by
`turn_admission`; the LLM-request step inside a turn is additionally bounded by
`llm_scheduler` (a pool of "LLM cores", ordered by aged nice priority under
contention and released between provider requests).

---

## 6. The syscall gate — the load-bearing OS layer

`crates/kernel/src/syscall_gate.rs` is **the chokepoint that makes namespaces,
capabilities, MAC, and cgroups load-bearing.** Every tool call from
`AgentExecutor::execute_tool` calls the declaration-aware gate, which runs these
checks in order — **first failure wins:**

```
0. Namespace visibility — tool tagged with a namespace ⇒ caller must be a member,
   else NotInNamespace (≈ ENOENT, the tool is invisible). Untagged tools are global.
1. Capability check — resolve the registered tool's typed security declaration
   and require every declared capability (for example `http_get` requires
   `CAP_NET_ACCESS`); `MissingCapability` otherwise.
2. MAC check — MacEngine::check(pid, action, resource); MacDeny on policy Deny.
3. Exact local approval for declarations that require it.
4. Cgroup hierarchy/membership validation. Concurrent tool slots are acquired
   separately and released by RAII.
```

Provider-token admission is a distinct path. It atomically reserves provider
RPM/TPM and root → tenant → profile → agent token scopes in one SQLite receipt,
verifies the membership revision while marking the receipt in flight, and
reconciles provider-reported input + output usage into the original epoch.
Serialized tool payload size is not provider usage.

The gate maintains a translation table from kernel `Uuid` agent IDs to
`agent_struct::AgentId` (u64 "PIDs") so the older OS-style subsystems (u64) and
the newer orchestrator (Uuid) interoperate without either side changing.
Capabilities derive from the `permission_profile` string at creation via
`caps_for_profile`. Denials and audited allows flow to a pluggable `AuditSink`.

**This contract is locked by tests** (`tests/src/os_enforcement.rs` for ordering
and isolation; `tests/src/gate_adversarial_props.rs` runs ~2500 proptest cases
per run with an independent oracle that re-derives the ordered verdict). When
adding a tool, register one complete `ToolBinding`; built-in compatibility
classification and the LLM-visible constraint summary are derived from that same
validated declaration. The summary omits constant resource values and other
secret-bearing policy data. Policy files accept only the declaration's canonical
action labels (`exec`, not `execute`). Do not add a parallel name matcher or
bypass the combined declaration/slot gate from a new execution path.

---

## 7. Scheduling

- **CFS-inspired admission** (`cfs.rs`) — token vruntime + nice weights over
  cooperative turn waiters; see [`SCHEDULER.md`](SCHEDULER.md) for EEVDF differences.
- **PriorityScheduler** (`scheduler.rs`) — admission + run queue. Agent creation
  *admits* to the system (non-blocking) and enqueues into the CFS run queue;
  creation never blocks on the concurrency gate. `wait_for_turn` races a notify
  against a 5ms poll to avoid lost-wakeups.
- **TurnAdmission** — bounds concurrent *turns* to `max_concurrent`; under
  contention grants the next slot to the CFS-preferred (lowest-vruntime) waiter.
- **LlmScheduler** (`llm_sched.rs`) — a bounded pool of "LLM cores" gating one
  provider request at a time; freed cores use aged nice priority.

---

## 8. Context & memory

- **Context pressure** (`execution.rs`, with legacy paging primitives in
  `context_paging.rs`) — agent, tenant, and kernel limits atomically bound
  active provider prompts, while durable-byte limits cover conversations,
  spills, embeddings, snapshots, and checkpoints. Old non-pinned messages are
  serialized to retained per-agent storage and replaced by a digest-verified
  reference; impossible pinned or storage state fails closed. There is no
  host-memory OOM-killer claim. See
  [`CONTEXT_PRESSURE.md`](CONTEXT_PRESSURE.md).
- **Long-term memory** (`memory_manager.rs`) — a pluggable embedding seam:
  - `Embedder` trait (object-safe, `Arc<dyn Embedder>`); default `BlendedEmbedder`
    (word unigrams + bigrams + char-trigrams in salted hash subspaces, sublinear
    TF, L2-normalized). `FeatureHashEmbedder` preserves the original FNV-1a
    behavior for bit-compatibility.
  - `VectorIndex` trait with exact-cosine `BruteForceIndex` and deterministic
    multi-table `LshIndex`; CI compares ANN results with exact search and fails
    below documented recall/top-1 thresholds.
  - Wired through `SqliteContextManager` (`with_embedder(...)` builder); store
    and query route through the same embedder. Facts persist model, version,
    dimension, and content-hash metadata; invalid/stale vectors rebuild before
    ranking. Store/query/update/delete/reindex are available over wire + SDK.
  - All pure-Rust, deterministic, offline — no models downloaded, no network.

---

## 9. Security & tenancy stack

- **Capabilities** (`permissions.rs`) — per-profile cap sets (`CAP_NET_ACCESS`,
  `CAP_FILE_WRITE`, …) derived at agent creation.
- **MAC** (`mac.rs`) — SELinux-style subject/action/object policy, enforcing mode,
  audit sink.
- **Namespaces** (`namespaces.rs`) — agent + tool namespaces per group; tools
  tagged to a namespace are invisible to non-members. IPC respects namespaces.
- **Cgroups** (`cgroups.rs`) — stable root → tenant → profile → agent hierarchy;
  durable fixed-epoch provider-token quotas plus structural concurrent-tool
  slots. Numeric cgroup IDs remain process-local.
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
on_device (feature-gated CPU GGUF)
```

Centralized streaming in `streaming.rs`. The send path supports:
- **Failover** — ordered, acyclic backup chain with tool, region, and
  local-to-cloud compatibility checks before a backup receives the prompt.
- **Retry/backoff** — the executor owns bounded transient retry rounds; each
  round uses one fresh attempt per compatible failover provider, with
  cancellation/timeouts, per-provider circuits, and actual
  serving-provider/model attribution.
- **Typed failure handling** — auth, authorization, rate-limit, service,
  invalid-request, content-filter, timeout, and cancellation errors with
  bounded/redacted diagnostics and request IDs.
- **Rate limiting** (`rate_limit.rs`) — atomic durable SQLite RPM/TPM
  worst-case-attempt reservation and exact reconciliation, plus a counting
  semaphore for concurrency. Streaming and non-streaming share semantics.

Pull-request adapter tests use `wiremock` and never hit live APIs. Protected
nightly/manual workflows record live `passed`, `failed`, or `not_run` artifacts.
Exact evidence and unsupported behavior are listed in
[PROVIDERS.md](PROVIDERS.md).

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
the lens). `boot()` starts the scheduler observer automatically. The CLI, Tauri
app, and `agent-server` construct from config and then explicitly call
`start_runtime`; new entry points must follow one of those two complete paths.

---

## 13. Tools, packages, hub, MCP

- **Governed tools** — `tools.rs` supplies validated security declarations and
  `custom_tools.rs` + `tool_registry_share.rs` add user-defined/shareable tools.
  `tool_descriptors.rs` and `mount_table.rs` are disconnected experimental
  prototypes, not an alternate runtime. See
  [`ADR-0001-PUBLIC-ABI.md`](ADR-0001-PUBLIC-ABI.md).
- **Packages** — `package.rs` provides deterministic signed `.agent` archives,
  durable tenant trust/revocation, immutable publish/yank records, semver
  dependency locks, policy admission, and transactional
  install/upgrade/rollback/remove. `agent_package.rs` maps verified manifests
  through normal tenant admission; its unsigned TOML loader remains a
  trusted-local compatibility path. `marketplace.rs` and `agent_hub.rs` are
  non-public experiments and are not used by the v1 supply chain.
- **MCP** — client (`mcp.rs`) and gate-enforced server (`mcp_server.rs`).
  Discovered client tools are prevalidated and published all-or-nothing; an
  invalid/conflicting entry or late publication failure leaves the prior
  registry intact.

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
- CI runs deterministic Rust tests on Linux, macOS, and Windows. The Tauri
  backend is checked separately on all three platforms (Linux installs
  GTK/WebKit first), and the Svelte frontend has locked install, audit,
  warning, and production-build gates. Formatting, Clippy, docs, dependency
  policy, coverage, and container persistence feed one required status.

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
  │ ToolRegistry::authorize_and_acquire_call (FIRST FAILURE WINS)│
  │  0 declaration → 1 namespace → 2 capability → 3 MAC        │
  │  4 approval → 5 membership + concurrent cgroup tool slot    │
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
