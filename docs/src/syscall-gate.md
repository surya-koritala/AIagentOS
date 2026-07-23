# The Syscall Gate

`crates/kernel/src/syscall_gate.rs` is the **chokepoint that makes namespaces,
capabilities, MAC, and cgroups load-bearing**. Every tool call from an agent —
`AgentExecutor::execute_tool` in `crates/kernel/src/execution.rs` — consults
the registry's validated declaration and `SyscallGate::check_tool_call_declared`
before the call reaches the resource broker. The executor, JSON syscall server,
MCP server, and SDK-backed wire client all use `ToolRegistry::authorize_call`
for the same action, resource extraction, gate decision, and token estimate.

## What it checks (first failure wins)

The gate runs these in order:

0. **Namespace visibility** — if the tool is tagged with a namespace, the calling
   agent must be a member, or the call returns `NotInNamespace` (≈ `ENOENT`).
   Untagged tools are global. This runs *before* the capability and MAC checks.
1. **Capability check** — every capability in the binding's declaration is
   required (for example `http_get` requires `CAP_NET_ACCESS`); a
   `MissingCapability` denial otherwise. Unknown, combined, and duplicate
   capability values are rejected at registration.
2. **MAC check** — `MacEngine::check(pid, action, resource)`; a `MacDeny` if the
   policy returns Deny.
3. **Approval check** — declarations marked `user` or `administrator` need an
   exact, one-shot local approval bound to agent, tool, extracted resource, and
   the complete validated declaration. Trusted in-process operator/UI code uses
   `AgentKernelImpl::approve_tool_call`; wire, package, SDK payload, and MCP
   metadata cannot create approvals.
4. **Cgroup quota check** — the estimate is atomically charged through the
   cgroup hierarchy; a
   `CgroupQuota` (≈ `EAGAIN`) if the call would go over budget.

```text
agent → AgentExecutor::execute_tool
      → SyscallGate
          0. namespace visibility
          1. capability check
          2. MAC policy check
          3. exact one-shot approval
          4. cgroup quota check
      → ResourceBroker (only if all pass)
          → permission profile
          → mandatory sandbox identity and resource interception
          → provider
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

When you add a tool, register one complete `ToolBinding`: resource type,
operation, action, required capabilities, typed resource extractor, namespace
visibility, approval policy, and sandbox requirement. Registration rejects
missing or contradictory declarations. The compatibility classifier is
generated from the same validated built-in catalog; do not add a separate name
matching table.

`SyscallGate::new` and `AgentKernelImpl::new` use enforcing/default-deny MAC
defaults. Permissive MAC requires an explicit local `with_mac(..., false, ...)`
constructor and emits a security warning. The fully unconfined gate exists only
in test/documentation builds.

## The contract is tested

The behavior is locked by kernel registration tests plus
`tests/src/os_enforcement.rs` and `tests/src/gate_adversarial_props.rs`:
declaration completeness, confused-deputy provider mismatches, exact resource
approval, capability/MAC/cgroup ordering, adversarial resources, and namespace
isolation. If those tests fail, the OS framing is broken.
