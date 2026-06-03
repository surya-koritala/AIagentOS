# AI Agent OS

[![Build Status](https://github.com/surya-koritala/AIagentOS/actions/workflows/ci.yml/badge.svg)](https://github.com/surya-koritala/AIagentOS/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

**An OS kernel for AI agents.** Tool calls go through a real syscall gate — capability checks, MAC policy, and cgroup token quotas enforce on every call, not as scaffolding.

> **Status:** v0.1 in progress. The core enforcement path is live (Phase 1). Full Linux-parity isolation, scheduling, and a real package manager are tracked in [ROADMAP.md](ROADMAP.md).

## What Is This?

AI Agent OS is not a chatbot. It's not a coding assistant. It's the **platform layer** that sits beneath AI agents and manages them — the same way Linux sits beneath applications.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CLIENTS   agent CLI · Rust SDK · ClusterClient · TUI · desktop · MCP       │
└───────────────────────────────────┬────────────────────────────────────────┘
              Syscall / SyscallReply (newline-JSON over TCP · Unix · TLS, auth)
┌───────────────────────────────────▼────────────────────────────────────────┐
│  WIRE LAYER  syscall_server — kernel as a service (CreateAgent, SendMessage, │
│  CallTool, Memory*, Storage*, Snapshot*, LoadPackage, NodeInfo, …)           │
└───────────────────────────────────┬────────────────────────────────────────┘
┌───────────────────────────────────▼────────────────────────────────────────┐
│  AgentKernelImpl — the wired root orchestrator (boot → start_runtime)        │
│                                                                              │
│  PROCESS/EXEC         SCHEDULING            CONTEXT (virtual memory)          │
│  agent_manager        cfs (vruntime/nice)   context_paging (summarize·OOM)    │
│  agent_struct (PID)   PriorityScheduler     memory_manager (Embedder+Index)   │
│  execution loop       TurnAdmission                                           │
│  think→act→observe    LlmScheduler                                            │
│  mid-gen pause/resume                                                         │
│         │ every tool call                                                    │
│         ▼                                                                    │
│  ╔════════════════════════════════════════════════════════════════════════╗ │
│  ║  SYSCALL GATE  —  THE CHOKEPOINT, first-failure-wins                      ║ │
│  ║   0 namespace → 1 capability → 2 MAC → 3 cgroup quota → AuditSink         ║ │
│  ╚════════════════════════════════════════════════════════════════════════╝ │
│         │ (only on Ok)                                                       │
│  SECURITY/TENANCY     INTEGRATION           RESOURCES (VFS)                   │
│  permissions·mac      connector (9 LLMs,    resource_broker                   │
│  namespaces·cgroups    failover·retry·rate)  filesystem·network·application   │
│  budget($)·sandbox    mcp · github · db     tools · mount_table · registry    │
│  auth                 IpcManager (broker)                                     │
│                                                                              │
│  OS SERVICES  init_system·agentctl·procfs·sysctl·observability/audit          │
│  PLATFORM     agent_package·agentpkg·marketplace·agent_hub                    │
└───────────────────────────────────┬────────────────────────────────────────┘
┌───────────────────────────────────▼────────────────────────────────────────┐
│  PERSISTENCE  single SqliteContextManager                                    │
│   conversations · messages · facts(+embeddings) · agent_kv · snapshots       │
└───────────────────────────────────┬────────────────────────────────────────┘
                  EXTERNAL  LLM APIs · Ollama/vLLM · filesystem · HTTP · GitHub
```

> **The one thing this diagram says:** every tool call from every agent crosses
> *one* gate, and the gate runs *before* the resource broker. That's the product
> thesis in a single box — agents governed like Linux processes.

## Why?

Running one AI agent is easy. Running **ten agents simultaneously** — with different permissions, resource budgets, isolated workspaces, and the ability to communicate — requires an operating system.

AI Agent OS provides:
- **Process management** — create, clone, signal, kill agents (like fork/exec/kill)
- **Fair scheduling** — CFS ensures every agent gets proportional resources
- **Memory management** — context paging, token budgets, OOM killer
- **Isolation** — namespaces, cgroups, sandboxes (agents can't see each other)
- **Security** — MAC policies, capabilities, audit logging
- **IPC** — inter-agent messaging, delegation, and discovery (broker-routed via `IpcManager`)
- **Init system** — service files, dependency ordering, auto-restart
- **Package manager** — install, version, and distribute agent packages

## Quick Start

### One command: bring up the server

The primary entry surface is `agent-server` — a long-lived kernel exposing the
JSON syscall protocol over TCP. One command builds the image, starts it, waits
until it actually answers a syscall, and prints the reply:

```bash
./scripts/quickstart.sh
```

That brings up a running, reachable, persistent server on
`tcp://localhost:7777` with **no API keys and no Ollama required** (the
enforcement / non-LLM syscalls boot keyless). State (the SQLite DB + rendered
config) persists in the `agentos-data` volume across restarts.

Equivalent raw one-liner, plus a manual round-trip:

```bash
docker compose up -d --build agentos-server
# Send a real NodeInfo syscall and read the reply:
exec 3<>/dev/tcp/127.0.0.1/7777; printf '{"op":"node_info"}\n' >&3; head -1 <&3
# -> {"status":"node_info","agent_count":0,"running_agents":0}
```

Connect with the SDK or any client speaking newline-delimited JSON syscalls.
See [docs/SERVER_QUICKSTART.md](docs/SERVER_QUICKSTART.md) for details.

### From source

```bash
# Clone
git clone https://github.com/surya-koritala/AIagentOS.git
cd AIagentOS

# Run tests (kernel 441 + integration-tests 102, across the workspace)
cargo test --workspace --exclude tauri-app

# Run the CLI agent (requires Azure OpenAI or OpenAI API key)
export AZURE_OPENAI_API_KEY="your-key"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o"
export AZURE_OPENAI_API_VERSION="2024-08-01-preview"
cargo run --package agent-cli
```

## Kernel Modules (53)

| Category | Modules |
|----------|---------|
| **Process Mgmt** | `agent_struct`, `agent_syscalls`, `agent` |
| **Scheduling** | `cfs`, `scheduler` |
| **Memory** | `context`, `context_paging` |
| **Tool System (VFS)** | `tools`, `tool_descriptors`, `mount_table`, `custom_tools` |
| **Networking** | `ipc` |
| **Security** | `mac`, `permissions`, `namespaces`, `sandbox` |
| **Resource Control** | `cgroups`, `rate_limit`, `production` |
| **Init & Services** | `init_system`, `agentctl`, `agentps` |
| **Observability** | `observability`, `procfs`, `event_loop` |
| **Syscall Layer** | `syscall_interface` |
| **Execution** | `execution`, `planning`, `editing`, `delegation` |
| **Integrations** | `connector`, `mcp`, `github`, `database` |
| **Platform** | `config`, `sysctl`, `package`, `marketplace`, `auth` |
| **Intelligence** | `learning`, `indexer`, `vision` |
| **Infrastructure** | `docker_sandbox`, `modules`, `prerequisites`, `shell`, `agentpkg` |

## How It Maps to Linux

We mark each subsystem honestly: **Live** = enforced on the runtime path, **Defined** = exists with logic + tests but not yet on the live path, **Planned** = scheduled in [ROADMAP.md](ROADMAP.md).

| Linux | AI Agent OS | Status |
|-------|-------------|--------|
| Capabilities | 9 capability types — checked on every tool call via `SyscallGate` | **Live** |
| SELinux / AppArmor | `MacEngine` policy — checked on every tool call | **Live** |
| cgroups | Token / agent-count quotas — `EAGAIN` returned over-budget | **Live** |
| `task_struct` | `AgentStruct` (Uuid + u64 PID via gate translation) | **Live** |
| Signals (SIGKILL, SIGSTOP) | Agent signals stored in agent struct | **Live** |
| Unix sockets / IPC | Inter-agent messaging + delegation + discovery via `IpcManager` (broker-routed tools) | **Live** |
| systemd | Init system (service files, deps, supervisor restart) | **Live** |
| syscall interface | 25 numbered syscalls + `SecureSyscallDispatch` | Defined — gate covers tool-call path |
| `fork()/clone()` | `agent_clone(flags)` | Defined |
| CFS scheduler | Each turn's tokens accounted to vruntime; `set_nice` / `next_runnable_agent` make fairness queryable | **Live (observability)** |
| Virtual memory + paging | `ContextPager` LRU eviction — auto-summarization covers the live path | Defined |
| Namespaces | Tool-namespace isolation: cross-namespace calls return `NotInNamespace` (≈ ENOENT) | **Live** |
| VFS + mount | Tool descriptors + mount table | Planned (Phase 3) |
| /proc filesystem | `ProcFs` snapshot reads (no live agent queries) | Planned (Phase 4) |
| apt/rpm | `agentpkg` (in-memory mock, no remote registry) | Planned (Phase 4) |

## How enforcement works in practice

Every tool call from an agent goes through `SyscallGate::check_tool_call`:

```
agent → AgentExecutor::execute_tool
      → SyscallGate::check_tool_call   (first failure wins)
          0. namespace visibility (tool tagged to a namespace ⇒ caller must be a member)
          1. capability check     (e.g. http_get requires CAP_NET_ACCESS)
          2. MAC policy check     (subject/action/object rule match)
          3. cgroup quota check   (token budget per minute)
      → ResourceBroker (only if all four pass)
      → record_tool_usage  (propagates up cgroup hierarchy)
```

A denial returns a structured error message back to the LLM as a tool failure, so the model can recover gracefully without the kernel trusting it to obey policy. The contract is proven by `tests/src/os_enforcement.rs` — four end-to-end tests that fail loudly if any layer stops enforcing.

## Benchmarks

### OS Kernel Benchmarks
- Agent creation: 10 agents in 2ms
- IPC throughput: ~200,000 msg/s (in-process)
- Permission checks: ~1M checks/sec
- Fault tolerance: supervisor restarts crashed agents per service policy
- Graceful shutdown: all agents stopped, observability + gate state purged

### Real-World Agent Benchmarks
Tool-using benchmarks (file ops, git, HTTP, multi-step plans) live in `benchmarks/`. Run `cargo run --package benchmarks --bin os_benchmark` to reproduce.

## Architecture Docs

- [`ROADMAP.md`](ROADMAP.md) — current phase plan with exit criteria (start here)
- [`CLAUDE.md`](CLAUDE.md) — orientation for AI assistants working in the repo
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Linux kernel → AI Agent OS mapping
- [`docs/COMPLETE_SPEC.md`](docs/COMPLETE_SPEC.md) — long-form implementation spec
- [`docs/FULL_ROADMAP.md`](docs/FULL_ROADMAP.md) — long-form vision roadmap

## LLM Providers

All adapters share centralized streaming and run behind a connector with failover, retry/backoff, and rate-limiting under load. Tests use `wiremock` — never real APIs.

| Provider | Status |
|----------|--------|
| Azure OpenAI | ✅ Full support (streaming, tool calling) — default |
| OpenAI | ✅ Full support |
| Anthropic (Claude) | ✅ Full support |
| Gemini | ✅ Full support |
| Groq | ✅ Full support |
| DeepSeek | ✅ Full support |
| Hugging Face | ✅ Full support |
| vLLM | ✅ Full support |
| Local (Ollama) | ✅ Full support |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The project uses AGPL-3.0 — all modifications must be shared.

## License

[AGPL-3.0](LICENSE) — like Linux uses GPL-2.0, we use AGPL-3.0 to ensure all improvements to the OS are shared with the community.
