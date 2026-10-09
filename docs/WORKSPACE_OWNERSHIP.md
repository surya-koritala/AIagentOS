# Managed workspace ownership

Each persistent datastore uses its immutable installation identity and canonical
database path to select a private workspace namespace. In-memory kernels use
separate instance namespaces. Ownership records live in a private control
directory outside the writable workspace mounted for an agent.

Cleanup requires a valid record binding the current store, agent and workspace.
It scans only the current namespace. Empty legacy `.aiagentos-managed` markers
and unverified UUID directories do not authorize deletion. A copied or restored
database cannot automatically adopt another store's recorded workspace paths.
Legacy UUID paths below `aiagentos-workspaces` require resolution even when the
installation's temporary directory has changed.

An unresolved active record remains in the database with its original identity,
status and workspace bytes. It is withheld from admission while verified peers
can start. Malformed lifecycle or sandbox records are also preserved and require
record repair. Intentionally stopped or killed records are excluded from the
maintenance list.

## Local maintenance

Stop the runtime using this datastore before running maintenance. The command
loads the existing configuration and acquires the same exclusive database lease;
it fails if another runtime still holds the store.
Maintenance verifies recorded agents without loading service definitions or
retiring stored services omitted from the current config. It does not start
service supervision or provider work.

```sh
agentctl workspace-ownership CONFIG_FILE list
agentctl workspace-ownership CONFIG_FILE retain AGENT_UUID --confirm-offline
agentctl workspace-ownership CONFIG_FILE list
```

`list` reports admitted agent IDs, unresolved recorded paths with bounded reasons,
and whether the output was truncated. `retain` selects the path already recorded
for that agent ID. It accepts no path override and creates no remote or tool
authority. Retention treats the path as an explicit operator workspace and does
not grant automatic deletion ownership. Its bytes and identity remain unchanged
on subsequent admission. Use this only after checking that the recorded path is
the workspace that should remain associated with that agent.

The source-bound CI workflow checks two actual processes with different stores
under one OS user and shared temporary directory, second-store crash/restart,
fresh authorized file I/O, local legacy retention, malformed-record preservation,
allocation crash cutpoints and ownership-manifest rejection. These checks are
separate from deployment filesystem and hardware qualification.
