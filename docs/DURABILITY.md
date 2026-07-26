# Durable state and schema compatibility

AI Agent OS currently stores kernel-owned state in one SQLite database. The
database includes context, memory, usage and quota accounting, agent lifecycle,
packages, operator settings, services, identity, and cluster control state.

This document describes the guarantees implemented today. The kernel backup
and offline restore primitives plus authenticated SDK/CLI entry points are
integrated. Transactional storage erasure and non-identifying deletion receipts
are integrated as an internal foundation, but live-resource coordination,
operator erasure commands, scheduled recovery, and encryption are not yet
production-qualified.

## Database identity and version

Every database created or successfully adopted by the kernel carries:

- SQLite `application_id = 0x41494f53` (`AIOS`);
- a monotonic SQLite `user_version`;
- one `storage_meta` row with the application ID, schema version, minimum
  reader version, installation ID, and timestamps; and
- an append-only `schema_migrations` record for every applied version.

Version `0` is reserved for an empty database or a recognized database from an
older AI Agent OS release. An unowned SQLite database containing unrelated
tables is rejected instead of being adopted.

At startup, the kernel runs a non-mutating `quick_check`, reads the application
ID and schema version, and rejects corrupt, unrelated, or newer databases before
changing durability PRAGMAs or schema objects. A newer binary may migrate an
older supported database. An older binary must never write a newer schema.

## Migration contract

Schema versions only move forward. A version marker is committed after the
required kernel and cluster tables, indexes, column upgrades, and data
reconciliation have succeeded. Missing-column upgrades inspect the existing
schema first; SQLite errors such as read-only media, locking, corruption, or
disk exhaustion are not treated as harmless duplicate-column errors.

After migration, startup verifies the ownership metadata, exact schema version,
physical integrity, and foreign-key consistency. Reopening the current version
is idempotent and does not append a duplicate migration record.

There is no supported in-place downgrade. Rollback to a binary that requires an
older schema requires an offline restore of a compatible, verified pre-upgrade
backup.

## Online backup

`SqliteContextManager::create_backup` uses SQLite's online backup API. It never
copies the main database file directly, so committed rows that are still in WAL
are included in a transactionally consistent snapshot. The backup runs in
bounded page steps and tolerates concurrent SQLite writers.

The caller supplies an operator-controlled backup root and a simple backup
name. The root and published backup must be real directories rather than
symlinks. Names cannot contain path separators. Creation uses a private staging
directory, syncs the database and manifest, and renames the complete directory
into place. Existing destinations are never overwritten.

Each backup directory contains:

- `agent_os.db`, a standalone SQLite snapshot without a required WAL sidecar;
- `manifest.json`, containing the format version, application ID, schema
  version, installation ID, timestamp, byte count, and SHA-256 digest.

`storage::verify_backup` rejects unknown manifest fields, unsupported backup or
schema versions, symlinked inputs, size or hash changes, corrupt SQLite pages,
foreign-key violations, and mismatched installation metadata. SHA-256 detects
accidental or uncoordinated modification; it is not an authenticity signature
against an attacker who can replace both the database and manifest.

A trusted system operator can create a live backup through the running server:

```bash
agentctl --addr 127.0.0.1:7777 --token "$AGENT_SERVER_TOKEN" \
  backup-create /var/lib/agentos/backups nightly_2026_07_25
```

`BACKUP_ROOT` is a path on the server host, not the client host. Tenant-bound
credentials, including tenant administrators, cannot invoke this operation.
The SDK exposes the same operation as `KernelClient::create_storage_backup`.

## Offline restore

`storage::restore_backup` is intentionally offline. Every file-backed kernel
(and every standalone file-backed context manager) holds an exclusive lock on
`agent_os.db.lock` for its lifetime, and restore must acquire the same lock. A
running kernel therefore causes restore to fail before the destination is
changed.

Restore verifies the backup first, copies it to a same-directory staging file,
syncs and verifies that copy, checkpoints an existing destination, and retains
the old database under a unique rollback name. The staged snapshot is then
renamed atomically into place and verified again. Any failure after publication
removes the failed replacement and automatically renames the original database
back. The rollback copy is removed only after the replacement passes all
checks.
If cleanup of the obsolete rollback file cannot be made durable, restore still
returns a successful report with `rollback_retained = true` so the operator is
not told that the already-verified replacement failed.

Verify a backup without changing any state, then stop the server and restore it
to the configured database path:

```bash
agentctl backup-verify /var/lib/agentos/backups/nightly_2026_07_25
agentctl backup-restore /var/lib/agentos/backups/nightly_2026_07_25 \
  /var/lib/agentos/agent_os.db --confirm-offline
```

The confirmation flag makes the destructive intent explicit; it does not
bypass the storage lease. If any kernel still owns the destination, restore
fails before changing it. Both commands emit versioned manifest/report JSON so
automation can retain recovery evidence.

Fresh-host and replacement restore are supported by this CLI workflow.
Scheduled retention, remote object storage, and measured recovery objectives
remain future work.

## Data ownership and erasure contract

`context::DURABLE_DATA_CATALOG` is the authoritative table-by-table ownership
and deletion registry. A schema-introspection regression compares that catalog
with every logical SQLite table, excluding only the private FTS5 shadow tables.
Adding a durable table without assigning an owner and deletion behavior fails
the kernel test suite.

The current policy classes are:

- agent-private state: contexts, facts/embeddings, conversations and their FTS
  index, KV, spills, pressure, snapshots, checkpoints, usage rows, loaded
  package instances, and the agent registry row;
- tenant-private state: tenant identity and credentials plus package trust,
  archives, installations, history, rate limits, transparency, and audit;
- user identity state: the user row, sessions, API-key hashes, and that user's
  package rate-limit state;
- system state: schema/install metadata, cluster identity/control, global
  operator settings, and shared quota/accounting records.

`erase_agent_data`, `erase_user_data`, and `erase_tenant_data` use
`BEGIN IMMEDIATE` and either commit the complete classified mutation plus one
receipt or roll everything back. They also reconcile orphaned child rows when a
registry identity is already absent. Agent and tenant erasure removes FTS
entries, clears optional service references, and removes the subject's stable
cgroup quota scopes. Provider/global quota aggregates, quota receipt UUIDs,
refund tombstones, and system state remain so deletion cannot manufacture new
global capacity or break idempotency.

Deletion receipts contain only an opaque receipt UUID, subject kind, timestamp,
per-table row counts, and a fixed list of retained record classes. They never
contain a tenant, user, agent, actor, reason, prompt, path, or deleted value.
Receipts are retained indefinitely because automated pruning is not yet
implemented. User erasure retains the now-pseudonymous actor UUID in per-tenant
package transparency/audit chains; deleting the tenant removes those chains.

All kernel SQLite tables are included in verified backups. Published backups
are immutable snapshots and are not retroactively changed by a live-database
erasure; operators must expire and destroy backup directories according to
their retention policy. The database is protected with owner-only permissions
on Unix, but application-level encryption and key rotation remain open in
#123. Provider configuration files, agent workspaces, remote provider data, and
external object stores are outside this SQLite deletion boundary.

Ephemeral process state includes scheduler queues, executors and cancellation
handles, syscall-gate registrations, namespaces/cgroups, sandboxes, credential
leases/auth caches, provider circuit state, and in-memory observability data.
Normal kernel lifecycle cleanup or process exit removes it. A supported
system-authorized erase operation that first drains those live resources and
then invokes the transactional storage primitive is the next deletion slice;
the storage primitives must not be treated as a safe remote hot-delete API on
their own.

## Current durability boundary

File-backed stores require WAL mode, `synchronous=FULL`, foreign-key
enforcement, a bounded busy timeout, and owner-only database permissions on
Unix. The existing restart suite verifies recovery of application state,
admission accounting, checkpoints, and agent rehydration.

The following remain open under issue #123:

- scheduling, retention, remote object storage, and a measured recovery runbook;
- signed manifests or external authenticity/immutability controls;
- corruption recovery beyond fail-closed startup detection;
- encryption at rest and key rotation;
- live-resource-coordinated system API/SDK/CLI erasure, backup expiration, and
  measured retention enforcement;
- disk-full, interrupted migration, object-store, and extended crash
  qualification;
- measured RPO/RTO on supported deployment profiles.
