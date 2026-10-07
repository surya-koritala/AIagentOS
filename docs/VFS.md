# Tool VFS

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

## Remaining VFS work

Issue [#392](https://github.com/surya-koritala/AIagentOS/issues/392) stays open.
Workspace file/directory handles with attenuated rights, administrable
per-namespace mounts and unmount generations, memory/KV/IPC mounts, and
dup/inheritance semantics remain separate delivery slices. This tool mount
does not establish a complete VFS or production qualification. Durable
copy-on-write cloning in #393 and the coding agent in #394 follow those
contracts.
