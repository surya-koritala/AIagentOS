# Concepts

AI Agent OS is organized around one idea: an AI agent runtime should be built
like an operating system. This section collects the conceptual references.

## The Linux mapping

Every kernel module maps to a Linux subsystem. The boundaries, naming, and error
semantics are deliberately the same so the OS framing stays load-bearing.

| Subsystem | Role |
|---|---|
| `agent_struct`, `agent`, `agent_syscalls` | `task_struct` + fork/exec/signals |
| `cfs`, `scheduler` | CFS-style fair scheduling with vruntime / nice |
| `context`, `execution` | Context pressure: active token bounds, durable spills, backpressure |
| `tools`, `custom_tools` | Governed named tools on the live path |
| `tool_descriptors`, `mount_table` | Experimental VFS analogy, excluded from v1 |
| `ipc` | Inter-agent messaging + delegation, broker-routed; discovery via the agent directory |
| `mac`, `permissions`, `namespaces`, `sandbox`, `cgroups` | Security: SELinux-style MAC, capabilities, isolation |
| `init_system`, `agentps`, SDK-backed `agentctl` binary | service supervision + operator control |
| `syscall_server` | Canonical versioned JSON public ABI |
| `syscall_interface` | Experimental numbered-syscall prototype; unsupported calls return ENOSYS |
| `procfs`, `observability`, `event_loop` | `/proc` filesystem + audit logging |
| `agentpkg`, `package`, `marketplace` | apt-like package manager |
| `execution`, `planning`, `editing`, `delegation` | the think → act → observe loop + multi-agent delegation |
| `connector`, `mcp`, `github`, `database` | external-system integrations |

The full subsystem-by-subsystem blueprint is in [Architecture](./architecture.md).

## The kernel orchestrator

`AgentKernelImpl` is the wired root object that owns every subsystem
(`agent_manager`, `scheduler`, `context_manager`, `permission_manager`,
`sandbox_manager`, `ipc`, `observability`, `connector`, `resource_broker`,
`tool_registry`, `rate_limiter`, `cgroups`, `syscall_gate`). The documented
entry points are `kernel::boot(&config)` and `kernel::boot_in_memory()`, which
build the kernel and start its scheduler observer, which publishes the CFS pick
into procfs. Token quotas use durable fixed Unix-minute epochs in SQLite; no
reset timer can erase or extend quota.

Agent creation flows through `create_agent_full`, which *admits* the agent to the
priority scheduler and enqueues it into the CFS run queue without blocking on the
concurrency gate — creation admits to the *system*, not the CPU. An agent is
marked `Running` only for the duration of each turn, so concurrency counters
reflect real execution; concurrent execution is bounded by the rate limiter.

## The pages in this section

- **[Architecture](./architecture.md)** — the Linux → Agent OS mapping and a
  subsystem-by-subsystem blueprint.
- **[The Syscall Gate](./syscall-gate.md)** — the chokepoint that makes
  capabilities, MAC, cgroups, and namespaces load-bearing.
- **[Agent Package Format](./agent-package.md)** — the declarative `agent.toml`
  manifest the kernel can load and run.
- **[Platform Roadmap](./platform-roadmap.md)** — the forward plan: kernel-as-
  server, the Rust SDK, and the phases beyond.

For long-form material, the [Reference](./complete-spec.md) section carries the
complete implementation spec, the full vision roadmap, and an operations runbook.
