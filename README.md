# AI Agent OS

[![Build Status](https://github.com/surya-koritala/AIagentOS/actions/workflows/ci.yml/badge.svg)](https://github.com/surya-koritala/AIagentOS/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

**An OS kernel for AI agents.** Tool calls go through a real syscall gate — capability checks, MAC policy, and cgroup token quotas enforce on every call, not as scaffolding.

> **Status:** **v0.3.0 is the latest stable release.** The current tree contains
> unreleased security, lifecycle, scheduling, checkpoint, operator, service,
> package, protocol-v2, and release-pipeline hardening. Local regression evidence
> is strong, but the changes are not a production-qualified release until the
> remote review, cross-platform, tagged-release, live-provider, isolation,
> recovery, and independent-security gates complete. See
> [CHANGELOG.md](CHANGELOG.md) for the exact shipped/unreleased split and
> [RELEASING.md](RELEASING.md) for the release process.

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
│  agent_manager        CFS-inspired turns    durable spill · backpressure      │
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
│   conversations · facts(+embeddings) · agent_kv · snapshots · checkpoints    │
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
- **Fair scheduling** — cooperative, CFS-inspired weighted turn admission
- **Context management** — bounded active prompts, durable spill references, explicit backpressure
- **Isolation** — namespaces, cgroups, sandboxes (agents can't see each other)
- **Security** — MAC policies, capabilities, audit logging
- **IPC** — inter-agent messaging, delegation, and discovery (broker-routed via `IpcManager`)
- **Init system** — service files, dependency ordering, auto-restart
- **Package manager** — install, version, and distribute agent packages

Durable pause/resume semantics and their hosted-provider limitations are
documented in [docs/CHECKPOINTS.md](docs/CHECKPOINTS.md).
The scheduling states, fairness unit, queue bounds, and Linux EEVDF differences
are documented in [docs/SCHEDULER.md](docs/SCHEDULER.md).
The token estimate, pinned-state, durable spill, page-in, and backpressure
contract is documented in [docs/CONTEXT_PRESSURE.md](docs/CONTEXT_PRESSURE.md).
The tenant-safe live snapshot used by the SDK, `agentctl`, and TUI is documented
in [docs/OPERATIONS_API.md](docs/OPERATIONS_API.md).
Declarative service boot ordering and the current supervision boundary are in
[docs/SERVICES.md](docs/SERVICES.md).

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
| **Tool System** | `tools`, `custom_tools` (descriptor/mount prototypes are experimental) |
| **Networking** | `ipc` |
| **Security** | `mac`, `permissions`, `namespaces`, `sandbox` |
| **Resource Control** | `cgroups`, `rate_limit`, `production` |
| **Init & Services** | `init_system`, `agentctl`, `agentps` |
| **Observability** | `observability`, `procfs`, `event_loop` |
| **Syscall Layer** | `syscall_server` JSON ABI (`syscall_interface` is experimental) |
| **Execution** | `execution`, `planning`, `editing`, `delegation` |
| **Integrations** | `connector`, `mcp`, `github`, `database` |
| **Platform** | `config`, `sysctl`, `package`, `marketplace`, `auth` |
| **Intelligence** | `learning`, `indexer`, `vision` |
| **Infrastructure** | `docker_sandbox`, `modules`, `prerequisites`, `shell`, `agentpkg` |

## How It Maps to Linux

Capability maturity is controlled by the machine-readable
[capability registry](docs/capabilities.toml), using the five levels Scaffolded,
Unit-tested, Integrated, Public-API E2E, and Production-qualified. CI verifies
that every public kernel module is classified and rejects unsupported maturity
promotions. The table below is a concise registry view, not a separate status
source. Standalone supporting modules are classified individually in the
[secondary-capability disposition](docs/SECONDARY_CAPABILITIES.md); their mere
presence in the Rust crate is not a v1 support claim.

| Linux | AI Agent OS | Status |
|-------|-------------|--------|
| Capabilities | Gate checks plus custom-tool declarations | Integrated — [#108](https://github.com/surya-koritala/AIagentOS/issues/108) |
| SELinux / AppArmor | `MacEngine` and declarative policy | Integrated — [#108](https://github.com/surya-koritala/AIagentOS/issues/108) |
| cgroups | Token and agent-count accounting/limits | Integrated — [#109](https://github.com/surya-koritala/AIagentOS/issues/109) |
| `task_struct` | `AgentStruct` (Uuid + u64 PID translation) | Unit-tested — [#112](https://github.com/surya-koritala/AIagentOS/issues/112) |
| Signals (SIGKILL, SIGSTOP) | Agent signal/state primitives | Unit-tested — [#112](https://github.com/surya-koritala/AIagentOS/issues/112) |
| Unix sockets / IPC | Messaging, delegation, and discovery | Unit-tested — [#112](https://github.com/surya-koritala/AIagentOS/issues/112) |
| systemd | Service files, dependency ordering, restart policy | Unit-tested — [#118](https://github.com/surya-koritala/AIagentOS/issues/118) |
| syscall interface | Versioned JSON wire protocol; numbered table explicitly experimental | Public-API E2E — [#116](https://github.com/surya-koritala/AIagentOS/issues/116) |
| `fork()/clone()` | `agent_clone(flags)` primitive | Unit-tested — [#112](https://github.com/surya-koritala/AIagentOS/issues/112) |
| CFS scheduler | Vruntime/nice accounting and admission primitives | Integrated — [#114](https://github.com/surya-koritala/AIagentOS/issues/114) |
| Virtual memory analogy | Active prompt bound, durable spill, explicit backpressure | Integrated — [#115](https://github.com/surya-koritala/AIagentOS/issues/115) |
| Namespaces | Tool and IPC visibility primitives | Unit-tested — [#107](https://github.com/surya-koritala/AIagentOS/issues/107) |
| VFS + mount | Experimental descriptor/mount prototypes, excluded from v1 | Scaffolded — [ADR 0001](docs/ADR-0001-PUBLIC-ABI.md) |
| /proc filesystem | Snapshot-oriented `ProcFs` helpers | Unit-tested — [#117](https://github.com/surya-koritala/AIagentOS/issues/117) |
| apt/rpm | Validated unsigned manifest loading; registry/signing remain prototypes | Public-API E2E (not supply-chain qualified) — [#119](https://github.com/surya-koritala/AIagentOS/issues/119) |

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
      → provider execution (quota was atomically reserved at admission)
```

A denial returns a structured error message back to the LLM as a tool failure, so the model can recover gracefully without the kernel trusting it to obey policy. The contract is proven by `tests/src/os_enforcement.rs` — four end-to-end tests that fail loudly if any layer stops enforcing.

The MAC policy at step 2 is **authorable as a declarative document** — operators write rules in TOML, validate and dry-run them with `agent policy validate` / `agent policy explain`, and point the kernel at a `policy_file`. See [docs/POLICY.md](docs/POLICY.md).

## Benchmarks

### OS Kernel Benchmarks
- Agent creation: 10 agents in 2ms
- IPC throughput: ~200,000 msg/s (in-process)
- Permission checks: ~1M checks/sec
- Fault tolerance: supervisor restarts crashed agents per service policy
- Graceful shutdown: all agents stopped, observability + gate state purged

### Real-World Agent Benchmarks
Tool-using benchmarks (file ops, git, HTTP, multi-step plans) live in `benchmarks/`. Run `cargo run --package os-benchmark --bin os-benchmark` to reproduce. This command is verified against the canonical capability registry in CI.

## Architecture Docs

- [`ROADMAP.md`](ROADMAP.md) — current phase plan with exit criteria (start here)
- [`CLAUDE.md`](CLAUDE.md) — orientation for AI assistants working in the repo
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Linux kernel → AI Agent OS mapping
- [`docs/POLICY.md`](docs/POLICY.md) — authoring, validating, and explaining MAC policy
- [`docs/ACCOUNTING.md`](docs/ACCOUNTING.md) — usage, pricing, quotas, and metrics contract
- [`docs/COMPLETE_SPEC.md`](docs/COMPLETE_SPEC.md) — long-form implementation spec
- [`docs/FULL_ROADMAP.md`](docs/FULL_ROADMAP.md) — long-form vision roadmap

## LLM Providers

Adapters run behind a connector with failover, retry/backoff, and rate-limiting
under load. Tests use `wiremock` rather than live vendor APIs, so these statuses
describe current fixture evidence—not production support. See the complete
[provider contract matrix](docs/PROVIDERS.md).

| Provider | Status |
|----------|--------|
| Azure OpenAI | Public-path E2E with native SSE/tools; live qualification pending — default |
| OpenAI | Fixture-verified text/tools; live qualification pending |
| Anthropic (Claude) | Fixture-verified text/tools; live qualification pending |
| Gemini | Fixture-verified text only; tools not implemented |
| Groq | Fixture-verified text/tools; live qualification pending |
| DeepSeek | Fixture-verified text/tools; live qualification pending |
| Hugging Face | Fixture-verified text only; tools/usage unavailable |
| vLLM | Fixture-verified OpenAI-compatible text/tools; live qualification pending |
| Local (Ollama) | Experimental configured local endpoint; no live nightly contract |
| On-device Candle/GGUF | Feature-gated spike; not production-supported |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The project uses AGPL-3.0 — all modifications must be shared.

## License

[AGPL-3.0](LICENSE) — like Linux uses GPL-2.0, we use AGPL-3.0 to ensure all improvements to the OS are shared with the community.
