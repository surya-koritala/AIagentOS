# Tool VFS

The process-local namespace table can mount governed aliases and revoke an
exact binding. See [Namespace mounts](NAMESPACE_MOUNTS.md) for authority,
generation, restart, and in-flight-operation semantics.

The initial VFS slice exposes the live tool registry at `/tools/<name>` through
the JSON syscall ABI, Rust SDK, and `agentctl`. It is an agent object namespace
on the host OS, with one built-in tool mount.

`vfs_mounts` returns sorted, namespace-visible paths, a truncation flag, and the
agent's handle usage and limit. Listing and opening expose declarations only;
they grant no permission to execute them. Names use ASCII letters, digits,
underscore, hyphen, and dot, up to 128 bytes. Empty names, `.` and `..`, path
aliases, escaping, encoded separators, and nested paths are rejected.

`vfs_open` allocates a random handle owned by the specified agent and bound to
one exact registration. Replacing a tool, even with an identical declaration,
or attaching a command template revokes that registration's existing handles.
Unrelated registrations do not revoke them. Each invocation resolves one
immutable request and passes once through the current declaration, namespace,
capability, MAC, approval, cgroup, sandbox, and resource-broker checks. Handles
cannot cache permission or substitute a different binding.

Handles are bounded to 64 per agent and 4,096 per kernel. Explicit close and
agent teardown reclaim slots. Closed, absent, and other-agent handles return
the same `not_found` category. Opening and invocation are new workload
admissions, so draining rejects them. Every handle mutation is subject to the
existing destination ownership-fence rules and tenant/role authorization.

Close revokes new invocations. A call that already passed admission before a
concurrent close can finish; close does not undo effects. A close observed
before or during gate admission prevents provider dispatch. Request deadlines,
broker cancellation, and lifecycle cleanup retain the normal broker and
gate behavior. Opening is serialized against lifecycle teardown.

Handles are ephemeral. Restart loses all handles; clone inherits none. A caller
must explicitly reopen a path on a runnable agent. No approvals, credentials,
in-flight calls, or external effects transfer with a handle.

## Use

```bash
agentctl vfs-mounts AGENT_ID
agentctl vfs-open AGENT_ID /tools/read_file
agentctl vfs-invoke AGENT_ID HANDLE '{"path":"README.md"}'
agentctl vfs-close AGENT_ID HANDLE
```

The path argument to `read_file` remains relative to the agent's governed
workspace. The tool mount does not permit ambient host file access.

The Rust SDK provides `KernelClient::vfs_mounts`, `vfs_open`, `vfs_invoke`, and
`vfs_close`. Servers advertise `tool_vfs` through `hello` and
`describe_protocol`; callers should check that feature before using the slice.
Ownership-fenced deployments wrap handle mutations in the existing
`FencedAgentMutation` request through `KernelClient::call`.

## Other mounts and delivery status

[Workspace entry handles](WORKSPACE_VFS.md) provide attenuated rights and
governed read/write/list/stat with native directory capabilities.
[Namespace mount controls](NAMESPACE_MOUNTS.md) provide governed aliases and
generation-fenced unmount. [Data handles](DATA_VFS.md) provide persistent
memory/KV and local IPC under the same gate and shared handle bounds.

Workspace and data descriptors support independent, attenuating duplicates.
Tool descriptors identify registrations; callers can explicitly reopen a
visible registration to obtain an independent descriptor. Every descriptor is
agent-owned, ephemeral, and closed on restart or clone. There is no implicit
inheritance of descriptors, approvals, credentials or live operations.

Issue [#392](https://github.com/surya-koritala/AIagentOS/issues/392) retains its
broader acceptance and qualification requirements. Durable copy-on-write
cloning in #393 and the coding agent in #394 build on these contracts.
