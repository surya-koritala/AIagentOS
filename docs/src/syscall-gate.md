# The Syscall Gate

`crates/kernel/src/syscall_gate.rs` is the **chokepoint that makes namespaces,
capabilities, MAC, and cgroups load-bearing**. Every tool call from an agent —
`AgentExecutor::execute_tool` in `crates/kernel/src/execution.rs` — consults
`SyscallGate::check_tool_call` before the call reaches the resource broker.

## What it checks (first failure wins)

The gate runs these in order:

0. **Namespace visibility** — if the tool is tagged with a namespace, the calling
   agent must be a member, or the call returns `NotInNamespace` (≈ `ENOENT`).
   Untagged tools are global. This runs *before* the capability and MAC checks.
1. **Capability check** — `classify_tool(name)` maps the tool to a required
   capability (for example `http_get` requires `CAP_NET_ACCESS`); a
   `MissingCapability` denial otherwise.
2. **MAC check** — `MacEngine::check(pid, action, resource)`; a `MacDeny` if the
   policy returns Deny.
3. **Cgroup quota check** — `cgroups.check_token_limit(cg, est_tokens)`; a
   `CgroupQuota` (≈ `EAGAIN`) if the call would go over budget.

```text
agent → AgentExecutor::execute_tool
      → SyscallGate
          0. namespace visibility
          1. capability check
          2. MAC policy check
          3. cgroup quota check
      → ResourceBroker (only if all pass)
      → record_tool_usage  (propagates up the cgroup hierarchy)
```

A denial is returned to the LLM as a structured tool failure, so the model can
recover gracefully — the kernel never trusts the model to obey policy.

## The Uuid ↔ PID translation table

The newer kernel orchestrator identifies agents by `Uuid`; the older OS-style
subsystems use `agent_struct::AgentId` (u64 "PIDs"). The gate maintains a
translation table between them so both sides can talk without either changing.
Capabilities are derived from the agent's `permission_profile` string at creation
via `caps_for_profile`.

## Extending the gate

When you add a new tool, **classify it in `syscall_gate::classify_tool`** so it
inherits the right action label and capability requirement. Do not bypass the
gate from new code paths — the gate is the single point where enforcement is
guaranteed.

## The contract is tested

The behavior is locked by the `tests/src/os_enforcement.rs` suite: capability /
MAC / cgroup ordering, namespace isolation for both tools and IPC, and the
scheduler honoring nice values. If those tests fail, the OS framing is broken.
