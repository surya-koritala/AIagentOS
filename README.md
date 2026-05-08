# AI Agent OS

[![Build Status](https://github.com/surya-koritala/AIagentOS/actions/workflows/ci.yml/badge.svg)](https://github.com/surya-koritala/AIagentOS/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

**An OS kernel for AI agents.** Tool calls go through a real syscall gate — capability checks, MAC policy, and cgroup token quotas enforce on every call, not as scaffolding.

> **Status:** v0.1 in progress. The core enforcement path is live (Phase 1). Full Linux-parity isolation, scheduling, and a real package manager are tracked in [ROADMAP.md](ROADMAP.md).

## What Is This?

AI Agent OS is not a chatbot. It's not a coding assistant. It's the **platform layer** that sits beneath AI agents and manages them — the same way Linux sits beneath applications.

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Applications                         │
│         (researcher, coder, reviewer, etc.)                  │
├─────────────────────────────────────────────────────────────┤
│                    System Call Interface                      │
│              (25 numbered syscalls, formal ABI)               │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│  Agent   │ Context  │  Tool    │  Agent   │    Security     │
│  Mgmt    │  Mgmt    │  System  │  Comms   │    Module       │
│(fork,kill│(paging,  │(VFS,mount│(sockets, │(MAC,caps,       │
│ signals) │ OOM,snap)│ drivers) │ pipes)   │ namespaces)     │
├──────────┼──────────┼──────────┼──────────┼─────────────────┤
│    CFS Scheduler    │  Cgroups │  Init System  │  ProcFS    │
├─────────────────────┼──────────┼───────────────┼────────────┤
│         Tool Drivers (LLM, FS, Net, DB, Browser)             │
├─────────────────────────────────────────────────────────────┤
│         Hardware Abstraction (LLM APIs, OS APIs)             │
└─────────────────────────────────────────────────────────────┘
```

## Why?

Running one AI agent is easy. Running **ten agents simultaneously** — with different permissions, resource budgets, isolated workspaces, and the ability to communicate — requires an operating system.

AI Agent OS provides:
- **Process management** — create, clone, signal, kill agents (like fork/exec/kill)
- **Fair scheduling** — CFS ensures every agent gets proportional resources
- **Memory management** — context paging, token budgets, OOM killer
- **Isolation** — namespaces, cgroups, sandboxes (agents can't see each other)
- **Security** — MAC policies, capabilities, audit logging
- **IPC** — sockets, pipes, pub/sub, service discovery
- **Init system** — service files, dependency ordering, auto-restart
- **Package manager** — install, version, and distribute agent packages

## Quick Start

```bash
# Clone
git clone https://github.com/surya-koritala/AIagentOS.git
cd AIagentOS

# Run tests (412 across the workspace)
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
| **Networking** | `agent_sockets`, `pipes`, `ipc`, `service_discovery` |
| **Security** | `mac`, `permissions`, `namespaces`, `sandbox` |
| **Resource Control** | `cgroups`, `rate_limit`, `production` |
| **Init & Services** | `init_system`, `agentctl`, `agentps` |
| **Observability** | `observability`, `procfs`, `event_loop` |
| **Syscall Layer** | `syscall_interface` |
| **Execution** | `execution`, `planning`, `editing`, `delegation` |
| **Integrations** | `connector`, `mcp`, `github`, `database` |
| **Platform** | `config`, `sysctl`, `package`, `marketplace`, `auth`, `workspaces` |
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
| Unix sockets + pipes | Agent sockets + pipes (IPC) | **Live** |
| systemd | Init system (service files, deps, supervisor restart) | **Live** |
| syscall interface | 25 numbered syscalls + `SecureSyscallDispatch` | Defined — gate covers tool-call path |
| `fork()/clone()` | `agent_clone(flags)` | Defined |
| CFS scheduler | `CfsScheduler` (vruntime, nice) — Tokio still drives turn execution | Defined |
| Virtual memory + paging | `ContextPager` LRU eviction — auto-summarization covers the live path | Defined |
| Namespaces | Membership tags (no cross-namespace hiding yet) | Planned (Phase 3) |
| VFS + mount | Tool descriptors + mount table | Planned (Phase 3) |
| /proc filesystem | `ProcFs` snapshot reads (no live agent queries) | Planned (Phase 4) |
| apt/rpm | `agentpkg` (in-memory mock, no remote registry) | Planned (Phase 4) |

## How enforcement works in practice

Every tool call from an agent goes through `SyscallGate::check_tool_call`:

```
agent → AgentExecutor::execute_tool
      → SyscallGate
          1. capability check  (e.g. http_get requires CAP_NET_ACCESS)
          2. MAC policy check  (subject/action/object rule match)
          3. cgroup quota check (token budget per minute)
      → ResourceBroker (if all three pass)
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

| Provider | Status |
|----------|--------|
| Azure OpenAI | ✅ Full support (streaming, tool calling) |
| OpenAI | ✅ Full support |
| Anthropic (Claude) | ✅ Full support |
| Local (Ollama) | ✅ Full support |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The project uses AGPL-3.0 — all modifications must be shared.

## License

[AGPL-3.0](LICENSE) — like Linux uses GPL-2.0, we use AGPL-3.0 to ensure all improvements to the OS are shared with the community.
