# Namespace mount tables

Agents share a Mount namespace with their namespace group. Tenant-created
agents use that tenant's group; ungrouped agents use the shared default. Each
table starts with `/tools` and `/workspace`. A mount selects a governed built-in
backend for the calling agent's resources. Aliases use the same tool registry
or agent-owned sandbox and the same authorization and quota paths.

`vfs_namespace_mounts` returns the table identity, namespace, current generation,
and sorted mount bindings. `vfs_mount_entries` discovers an exact mounted root.
Tenant Admin or trusted operator authority is required for `vfs_mount` and
`vfs_unmount`; the target agent selects the namespace and must belong to the
authenticated tenant. Mount writes retain node admission and destination fences.

Administrative writes must supply the table identity and generation from the
last read. Unmount additionally requires the exact mount identity. Stale
revisions return `Conflict`, and an old mount identity cannot remove a new
binding at the same path. Paths must be canonical, portable absolute names.
Duplicate roots, ancestor roots, and descendant roots collide; `/a` and `/ab`
are separate roots. A table has at most 32 mounts, and the process holds at most
1,024 tables. An emptied table remains empty until explicitly mounted again.

Descriptors capture their exact mount binding and namespace membership epoch.
Unmount immediately closes descriptor admission and reclaims all handles and
pending reservations bound to that mount, including peers in the same namespace.
An operation that passed its final VFS admission check may finish with its held
gate/broker permits. A pending native open cannot publish a descriptor after
unmount. Close, unmount, and stop remain safe when concurrent. Mounting the same
path again or leaving/rejoining a namespace never resurrects old descriptors.

Mount tables are process-local. Restart creates new table and binding identities
and restores the two built-in defaults; custom mounts and unmounts must be
configured again. Old administrative revisions and descriptors fail. Mounts
control VFS availability; shared gate and broker policy governs resource access
through every supported entry point. Durable mount configuration and distributed
mount replication are outside this delivered slice.

```bash
agentctl vfs-namespace-mounts AGENT_ID
agentctl vfs-mount AGENT_ID TABLE_ID TABLE_GENERATION /commands tools
agentctl vfs-mount-entries AGENT_ID /commands
agentctl vfs-open AGENT_ID /commands/read_file
agentctl vfs-invoke AGENT_ID HANDLE '{"path":"README.md"}'
agentctl vfs-namespace-mounts AGENT_ID
agentctl vfs-unmount AGENT_ID TABLE_ID TABLE_GENERATION /commands MOUNT_ID
```

The SDK exposes the same typed methods and `MountKind::{Tools, Workspace}`.
Read the table again after each administrative change and pass its new generation.
Clients must explicitly reconcile an indeterminate mutation outcome.

Servers advertise `namespace_mounts`. Memory/KV/IPC mounts and full qualification
remain in [#392](https://github.com/surya-koritala/AIagentOS/issues/392).
