# AI Agent OS

[![Build Status](https://github.com/surya-koritala/AIagentOS/actions/workflows/ci.yml/badge.svg)](https://github.com/surya-koritala/AIagentOS/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-368%20passing-brightgreen)]()
[![Modules](https://img.shields.io/badge/kernel%20modules-53-orange)]()

**A real operating system kernel for AI agents** — managing autonomous agents the way Linux manages processes: with scheduling, isolation, permissions, IPC, and a formal syscall interface.

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

# Run tests (368 tests)
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

| Linux | AI Agent OS | Status |
|-------|-------------|--------|
| `task_struct` | `AgentStruct` | ✅ |
| `fork()/clone()` | `agent_clone(flags)` | ✅ |
| Signals (SIGKILL, SIGSTOP) | Agent signals (same semantics) | ✅ |
| CFS scheduler | `CfsScheduler` (vruntime, nice values) | ✅ |
| Virtual memory + paging | Context paging (LRU eviction) | ✅ |
| VFS + mount | Tool descriptors + mount table | ✅ |
| Namespaces (pid, net, mnt) | Agent namespaces (tool, context, agent, net) | ✅ |
| cgroups | Token/tool-call/context controllers | ✅ |
| SELinux/AppArmor | MAC engine (policy-based) | ✅ |
| Capabilities | 9 capability types (CAP_NET, CAP_EXEC, etc.) | ✅ |
| systemd | Init system (service files, deps, restart) | ✅ |
| syscall interface | 25 numbered syscalls with errno | ✅ |
| /proc filesystem | ProcFS (agent introspection) | ✅ |
| Unix sockets + pipes | Agent sockets + pipes | ✅ |
| apt/rpm | agentpkg (install, deps, registry) | ✅ |

## Benchmarks

### OS Kernel Benchmarks (10/10)
- Agent creation: 10 agents in 2ms
- IPC throughput: 200,000 msg/s
- Permission checks: 1M checks/sec
- Fault tolerance: crash 1 of 5, others survive
- Graceful shutdown: all agents stopped cleanly

### Real-World Agent Benchmarks (10/10 with GPT-5.4)
- Multi-file project creation ✅
- Bug finding and fixing ✅
- System administration ✅
- Web API interaction ✅
- Multi-step file operations ✅
- Memory across conversation turns ✅
- Error recovery ✅
- Code generation + execution ✅
- Logic/reasoning ✅

## Architecture Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Linux kernel → AI Agent OS mapping
- [`docs/COMPLETE_SPEC.md`](docs/COMPLETE_SPEC.md) — 213-item implementation spec
- [`docs/FULL_ROADMAP.md`](docs/FULL_ROADMAP.md) — 3-year, 930-item roadmap

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
