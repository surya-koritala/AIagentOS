# AI Agent OS

**An OS kernel for AI agents.** Tool calls go through a real syscall gate —
capability checks, MAC policy, and cgroup token quotas enforce on *every* call,
not as scaffolding.

AI Agent OS is not a chatbot and not a coding assistant. It is the **platform
layer** that sits beneath AI agents and manages them, the same way Linux sits
beneath applications.

## The mental model

The load-bearing idea is a direct mapping from the Linux kernel:

- **Agents are processes.** Each agent is a `task_struct`-style record you can
  create, clone, signal, and kill.
- **Context is virtual memory.** Token budgets, context windows, and LRU
  eviction stand in for pages, paging, and the OOM killer.
- **Tools are files.** Tool descriptors and a mount table mirror the VFS; a tool
  call is an `open`/`read`/`write` against a mounted provider.
- **The kernel orchestrates.** A CFS-style scheduler, cgroups, namespaces, a MAC
  engine, capabilities, an init system, and a syscall gate tie it together.

Every module under `crates/kernel/src/` is named after its Linux analogue. The
mapping is not cosmetic — module boundaries, naming, and error semantics
deliberately echo the kernel. See [Architecture](./architecture.md) for the full
table.

## Why an OS?

Running one agent is easy. Running **ten agents at once** — with different
permissions, resource budgets, isolated workspaces, and the ability to talk to
each other — is an operating-systems problem. AI Agent OS provides:

- **Process management** — create, clone, signal, kill agents.
- **Fair scheduling** — CFS keeps every agent's share proportional.
- **Memory management** — context paging, token budgets, an OOM killer.
- **Isolation** — namespaces, cgroups, sandboxes.
- **Security** — MAC policies, capabilities, audit logging.
- **IPC** — inter-agent messaging, delegation, and discovery (broker-routed via
  `IpcManager`).
- **Init system** — service files, dependency ordering, supervised restart.
- **Package manager** — declarative agent packages the kernel can load and run.

## What's enforced today

The differentiator is that enforcement is **live on the runtime path**, not
mocked. Every tool call from an agent flows through `SyscallGate::check_tool_call`,
which runs a capability check, a MAC policy check, and a cgroup token-quota check
in order — first failure wins. A denial is returned to the model as a structured
tool failure, so the kernel never trusts the model to obey policy. See
[The Syscall Gate](./syscall-gate.md) for how that chokepoint works.

## Where to go next

- [Getting Started](./getting-started.md) — build the workspace, run the CLI, run
  the kernel as a syscall server, and drive it from the Rust SDK.
- [Concepts](./concepts.md) — the architecture, the syscall gate, the agent
  package format, and the platform roadmap.
- [Tutorials](./tutorials/service-files.md) — write a service file, add a custom
  tool.

## License

AGPL-3.0. Like Linux uses GPL-2.0, AI Agent OS uses AGPL-3.0 so improvements to
the platform are shared back.
