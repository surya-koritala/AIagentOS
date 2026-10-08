# Workspace VFS handles

The built-in `/workspace` mount exposes the agent's existing sandbox through
file and directory entry handles. It shares the VFS handle budget and close
operation with `/tools`. Servers advertise `workspace_vfs` through protocol
discovery. The slice is integrated; it does not complete issue #392 or establish
production qualification.

## Object and rights contract

Each handle belongs to one agent and one sandbox identity. A directory handle
pins a native directory capability. A file handle pins its parent directory and
one entry name; atomic replacement updates that entry, so the handle reads its
current contents rather than preserving an old inode snapshot. A changed or
renamed directory binding and a replaced sandbox revoke existing references.
Operations never fall back to resolving an ambient host path.
On Windows, retained native directory capabilities prevent directory rename or
deletion until all references close; fresh opens then resolve the new binding.

Rights are explicit: `read`, `write`, `list`, and `stat`. `open_at` and `dup`
can only preserve or remove the parent's rights. Duplicate descriptors close
independently. No handle transfers to another agent or survives restart or
clone. Requested rights do not grant capabilities or bypass current namespace,
MAC, approval, cgroup, permission-profile, node-admission, or ownership-fence
checks. Every backing operation passes once through the normal tool gate and
resource broker. A read-only operator role cannot perform file I/O through a
handle when it could not call the corresponding tool.

Paths use `/workspace` or canonical relative components beneath it. Empty,
duplicate, dot, parent, drive, backslash, control-character, trailing-space/dot,
and portable device-name aliases are rejected. Percent characters are literal;
the VFS does not URL-decode them. UTF-8 names are supported within the portable
name constraints. Symlink components and special files cannot be opened.
Additional absolute roots can be selected by the namespace mount table;
`open_at` paths remain relative to their directory descriptor.

## I/O and lifecycle

Reads return base64-encoded binary chunks with the requested offset and an
explicit `eof` flag. The transfer limit is 1 MiB; larger reads must use repeated
bounded requests. Writes atomically replace the complete entry with up to
1 MiB of bytes. Staging is private, synced, quota-checked against the entire
workspace, and removed on failure or cancellation before commit. Opening with
`allow_missing` and write rights binds a prospective file entry; it creates no
file until a write commits.

Directory listing retains the sandbox's deterministic, typed 4,096-entry bound.
`stat` returns file/directory kind, size, and the host readonly bit. The readonly
bit is metadata, not a promise that policy permits writing.

Pending opens reserve handle capacity and reclaim it on failure or cancellation.
Opening releases tool admission before final lifecycle publication, preventing
stop/open deadlocks. Close prevents new work; already admitted work may finish.
The existing controlled worker owns its admission permit through real I/O and
drain, and observes cancellation before mutation. Stop/kill revoke descriptor
admission and the sandbox; no retired capability can commit later work.

## SDK and CLI

The SDK supplies typed `vfs_open_workspace`, `vfs_open_at`, `vfs_dup_workspace`,
`vfs_read_bytes`, `vfs_write_bytes`, `vfs_list_workspace`, `vfs_stat_workspace`,
and `vfs_close`. Raw base64 read/write methods are available for other clients.
Mutation retries remain explicit after an indeterminate transport failure.
Fenced deployments use the existing `FencedAgentMutation` envelope.

```bash
agentctl vfs-workspace-mounts AGENT_ID
agentctl vfs-workspace-open AGENT_ID /workspace/src directory read,write,list,stat
agentctl vfs-open-at AGENT_ID DIRECTORY_HANDLE main.rs file read,write,stat
agentctl vfs-read AGENT_ID FILE_HANDLE
agentctl vfs-stat AGENT_ID FILE_HANDLE
agentctl vfs-write AGENT_ID FILE_HANDLE ./replacement.rs
agentctl vfs-dup AGENT_ID FILE_HANDLE read
agentctl vfs-close AGENT_ID FILE_HANDLE
```

`vfs-write` reads an explicit local operator source file, or `-` for stdin, and
sends bounded bytes to the remote governed entry. It does not let an agent name
a host path on the kernel. Readers must inspect `eof`; JSON output never labels
a partial chunk as a complete file.

Namespace mount administration and revocation are described in
[Namespace mounts](NAMESPACE_MOUNTS.md). Memory/KV/IPC mounts and full qualification remain in
[#392](https://github.com/surya-koritala/AIagentOS/issues/392). Native process
isolation and platform durability gaps retain their existing support status.
