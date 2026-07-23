# The Syscall Gate

`crates/kernel/src/syscall_gate.rs` is the **chokepoint that makes namespaces,
capabilities, MAC, and cgroups load-bearing**. Every tool call from an agent —
`AgentExecutor::execute_tool` in `crates/kernel/src/execution.rs` — consults
the registry's validated declaration and the combined declaration/slot gate
before the call reaches the resource broker. The executor, JSON syscall server,
MCP server, and SDK-backed wire client all use
`ToolRegistry::authorize_and_acquire_call`; its RAII slot guard is held through
binding execution. The older `authorize_call`/`check_tool_call_declared` APIs
are authorization-only compatibility helpers, not execution entry points.

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
4. **Cgroup membership validation** — the agent must still be a valid member of
   a complete root-to-leaf hierarchy. Concurrent tool-call slots are reserved
   separately with an RAII guard.

```text
agent → AgentExecutor::execute_tool
      → SyscallGate
          0. namespace visibility
          1. capability check
          2. MAC policy check
          3. exact one-shot approval
          4. cgroup membership validation
      → ResourceBroker (only if all pass)
          → permission profile
          → mandatory sandbox identity and resource interception
          → provider
```

A denial is returned to the LLM as a structured tool failure, so the model can
recover gracefully — the kernel never trusts the model to obey policy.

Provider-token quota is deliberately not charged here. Before each LLM attempt,
the executor snapshots root → tenant → profile → agent constraints and the
membership revision. The durable limiter atomically reserves provider RPM/TPM
and all cgroup token scopes, then the gate verifies the revision while the
receipt is marked in flight. A raced low-level gate reassignment refunds and
retries. Kernel-created agents are pinned to their managed root → tenant →
profile → private-agent hierarchy; the raw gate move API rejects them so it
cannot discard configured quota scopes. Actual provider input + output usage
reconciles every scope. Gate-time serialized
argument estimates consume no quota; assistant tool-call JSON and tool results
included in the next provider prompt are counted as real provider input.

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
matching table. Policy files use the declaration's canonical action labels
(`exec`, not provider-operation aliases such as `execute` or `launch`) and
reject unknown labels.

MCP discovery is installed as one validated batch. Conversion errors, duplicate
discovery names, conflicts with existing bindings, or late publication failures
leave none of that batch installed; a late failure rolls back only names
inserted by the batch and preserves pre-existing tools.

LLM definitions are generated from that same binding. Their constraint suffix
includes the non-secret resource/action/capability/approval/sandbox/visibility
classes, while deliberately omitting constant resource values, approval grants,
host sandbox paths, credentials, and policy contents. This suffix helps planning
but grants no authority; the kernel re-resolves and enforces the declaration for
every call.

`SyscallGate::new` and `AgentKernelImpl::new` use enforcing/default-deny MAC
defaults. Permissive MAC requires an explicit local `with_mac(..., false, ...)`
constructor and emits a security warning. The fully unconfined gate exists only
in test/documentation builds.

## The contract is tested

The behavior is locked by kernel registration tests plus
`tests/src/os_enforcement.rs` and `tests/src/gate_adversarial_props.rs`:
declaration completeness, confused-deputy provider mismatches, exact resource
approval, capability/MAC/approval ordering, cgroup membership and concurrent
slots, adversarial resources, and namespace isolation. Provider hierarchy
accounting has separate restart and race regressions. If those tests fail, the
OS framing is broken.
