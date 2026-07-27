# Durable state and schema compatibility

AI Agent OS currently stores kernel-owned state in one SQLite database. The
database includes context, memory, usage and quota accounting, agent lifecycle,
packages, operator settings, services, identity, and cluster control state.

This document describes the guarantees implemented today. The kernel backup
and offline restore primitives plus authenticated SDK/CLI entry points are
integrated. Transactional storage erasure, non-identifying deletion receipts,
and live-resource-coordinated system operator erasure through the wire, SDK,
and CLI are integrated. Verified local-backup retention, disabled-by-default
automatic local backup maintenance, optional Ed25519 manifest authenticity,
exact independently retained recovery-point anchors, and SQLCipher
whole-database encryption with operator-custodied keys are integrated.
Server-created backups are constrained to one configured managed root; hot
subject erasure purges that root under the publication lock before committing.
Authenticated configured-host disaster recovery, plaintext migration, and
storage-key rotation remain explicit offline operator actions. Remote
retention, measured recovery objectives, and independent release qualification
are not yet complete.

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

Schema versions only move forward. Startup holds an immediate SQLite
transaction across required kernel and cluster tables, indexes, column
upgrades, data reconciliation, quota migration fences, the migration ledger,
storage metadata, and the final version markers. A failure in any late step
rolls back every earlier DDL and backfill from that attempt; the database is
never published at the new version with only part of the migration applied.
Missing-column upgrades inspect the existing schema first; SQLite errors such
as read-only media, locking, corruption, or disk exhaustion are not treated as
harmless duplicate-column errors.

After migration, startup verifies the ownership metadata, exact schema version,
physical integrity, foreign-key consistency, authenticated accounting root, and
complete accounting event chain. Reopening the current version is idempotent
and does not append a duplicate migration record.

## Authenticated accounting integrity

Schema version `3` authenticates the enforcement state in `usage_log`,
`quota_epoch_floor`, `quota_epochs`, `quota_receipts`,
`quota_receipt_scopes`, `quota_refunded_receipts`, and
`quota_migration_fence`.

Each protected row contributes a domain-separated HMAC-SHA256 digest to a
commutative state root. Persistent SQLite triggers replace that contribution
and append a chained, authenticated insert/update/delete event in the same
transaction as the accounting mutation. The steady-state cost is constant per
changed row; quota admission does not rescan historical receipts. Startup and
every canonical schema/backup qualification path independently scan all
protected rows, recompute the root, verify contiguous event sequences and
links, and fail closed before accounting can be trusted.

The integrity secret is random and stored inside the database so it survives
backup, restore, and storage-key rotation. A production SQLCipher store protects
the secret from a database-file-only attacker. A deliberately plaintext
development store detects accidental corruption, but a reader that can obtain
the secret can forge new state. This mechanism also cannot distinguish a
complete rollback to an older internally valid live database snapshot.
Production backup recovery requires an independently retained exact recovery
anchor, but immutable retention and a monotonic policy proving which anchor is
newest remain operator/release concerns under #123.

Accounting events retain only keyed pseudonymous record digests and before/after
MACs, not raw tenant, user, agent, scope, usage, cost, or model values. Subject
erasure removes the classified live rows while retaining this non-identifying
integrity chain.

There is no supported in-place downgrade. Rollback to a binary that requires an
older schema requires an offline restore of a compatible, verified pre-upgrade
backup.

Reviewable SQL fixtures under `tests/fixtures/storage/` reproduce representative
stores from every immutable published tag (`v0.1.0`, `v0.2.0`, and `v0.3.0`).
The fixture manifest pins each source tag commit and SQL SHA-256 digest. The
regression suite builds a real SQLite database from every fixture, upgrades it,
verifies current ownership/integrity/migration metadata, exercises context
restore, and checks memory, FTS, usage-cost backfill, tenant, and KV retention
before an idempotent reopen. A workspace version bump is rejected until the
matching release fixture is added, so a future release cannot silently leave
the upgrade matrix behind.

Before upgrading a supported installation:

1. Create and independently verify a signed backup while the current server is
   healthy; retain every storage key and public trust document required by that
   backup.
2. Stop the server cleanly. Never copy a live SQLite main file without the
   online backup API. For legacy `v0.1.0`–`v0.3.0` installations that predate
   `backup-create`, preserve an offline snapshot of the complete data directory,
   including any `-wal` and `-shm` companions.
3. Start the new binary against the original database. Startup either commits
   the whole forward migration and passes schema verification or returns an
   error with no migration step published.
4. Verify normal agent/context access and create a new signed backup under the
   upgraded binary before resuming production traffic.

If rollback is required, stop the new binary and restore the verified
pre-upgrade backup or offline legacy snapshot before starting the older binary.
Do not point an older binary at a database that a newer schema has committed.

## Encryption at rest and storage-key custody

When `[storage_encryption].key_path` is configured, SQLCipher encrypts the
complete SQLite database, including WAL pages. The kernel supplies 256-bit key
bytes through SQLCipher's C API rather than interpolating secrets into SQL.
Startup authenticates the database before schema inspection and fails closed
for a missing, malformed, wrong, or symlinked key file. On Unix it also rejects
group/other-accessible files and files not owned by the current user.

Generate a key outside both the data and backup directories:

```bash
install -d -m 700 /etc/agentos/storage-keys
agentctl storage-key-generate storage-generation-1 \
  /etc/agentos/storage-keys/storage-generation-1.json
```

The command creates a bounded versioned JSON document without overwrite and
uses owner-only permissions on Unix. Configure production startup:

```toml
[storage_encryption]
required = true
key_path = "/etc/agentos/storage-keys/storage-generation-1.json"
```

`required = true` without `key_path` is invalid. A relative key path is always
invalid. Legacy/developer configurations remain plaintext only when no key path
is configured and encryption is not required.

Encrypt a legacy plaintext database while every kernel is stopped:

```bash
agentctl storage-encrypt /var/lib/agentos/agent_os.db \
  /etc/agentos/storage-keys/storage-generation-1.json \
  --confirm-offline
```

Migration acquires the kernel storage lease, checkpoints WAL, verifies source
identity and integrity, uses `sqlcipher_export` into a same-directory encrypted
staging database, syncs and verifies it, preserves the plaintext source as a
rollback during publication, and removes that rollback only after the
encrypted replacement authenticates. Before staging begins it durably writes an
owner-only, secret-free migration journal containing the randomized companion
filenames, public key identifier, and database identity. If the process exits
at any point, keep the kernel stopped and reconcile the journal:

```bash
agentctl storage-encrypt-recover /var/lib/agentos/agent_os.db \
  /etc/agentos/storage-keys/storage-generation-1.json \
  --confirm-offline
```

Recovery takes the same exclusive lease and verifies every surviving database
against the journaled application, schema, and installation identity. It
finishes publication only when the encrypted stage authenticates with the
named key; otherwise it preserves or restores the verified plaintext source.
It refuses symlinks, corrupt files, a wrong key identifier, foreign database
identity, and ambiguous layouts without deleting evidence. A process-exit
regression terminates a separate test process after the plaintext rename and
proves recovery retains all data and removes the plaintext rollback. Until
recovery completes, treat the database directory as sensitive. File deletion
is not guaranteed to erase blocks on copy-on-write filesystems or SSDs, so
production hosts should also use volume/disk encryption.

Rotate the live database key offline:

```bash
agentctl storage-key-generate storage-generation-2 \
  /etc/agentos/storage-keys/storage-generation-2.json
agentctl storage-key-rotate /var/lib/agentos/agent_os.db \
  /etc/agentos/storage-keys/storage-generation-1.json \
  /etc/agentos/storage-keys/storage-generation-2.json \
  --confirm-offline
```

Rotation refuses a running database, verifies the current key before writing,
rekeys every page, verifies the new key, and proves the retired key no longer
opens the database. Update configuration only after the command succeeds, and
list generations still needed by retained backups:

```toml
[storage_encryption]
required = true
key_path = "/etc/agentos/storage-keys/storage-generation-2.json"
retired_key_paths = [
  "/etc/agentos/storage-keys/storage-generation-1.json",
]
```

Retired keys are selected only by the key ID in historical backup manifests;
they are never tried against the live database or used for new backups. This
lets automatic retention authenticate and expire old generations safely.
Remove generation 1 from configuration and custody only after every dependent
backup has expired.

## Versioned full-installation portability

Portable storage bundles move the complete durable SQLite installation across
hosts or storage-key generations. They are not a tenant- or user-selective data
export. Every agent, conversation, memory record, package, service, quota,
credential digest, integrity secret, audit record, and installation identifier
in the source database is preserved.

Stop every source and destination kernel before running the workflow:

```bash
agentctl storage-portable-export /var/lib/agentos/agent_os.db \
  /srv/transfer/agentos-portable \
  --storage-key /etc/agentos/storage-keys/storage-generation-1.json \
  --confirm-offline
agentctl storage-portable-verify /srv/transfer/agentos-portable
agentctl storage-portable-import /srv/transfer/agentos-portable \
  /var/lib/agentos-new/agent_os.db \
  --storage-key /etc/agentos/storage-keys/storage-generation-2.json \
  --confirm-offline
```

Export takes the same exclusive storage lease used by restore, verifies the
source schema and authenticated accounting state, checkpoints committed WAL
pages, uses SQLCipher's logical export, verifies the plaintext result, and
atomically publishes an owner-only directory. Its version 1 manifest fixes the
payload format and filename and records application/schema compatibility,
installation identity, source key identifier, byte count, timestamp, and a
SHA-256 digest. Verification rejects unknown manifest fields, unexpected files,
symlinks, unsupported versions, changed bytes, corrupt SQLite pages, schema or
accounting-integrity failures, and identity mismatches.

Import re-verifies the bundle before and after staging, only accepts a fresh
destination, optionally encrypts it under an independently supplied destination
key, verifies the staged database with that key, and publishes it by
same-directory atomic rename. A running owner, existing destination, bad key,
or failed verification leaves no destination database.

The transfer payload is intentionally plaintext so an encrypted installation
can be re-keyed. It contains all durable sensitivity classes, including the
database-resident accounting integrity secret and credential digests. Keep it
on owner-only encrypted media, transport it through a trusted channel, and
delete it according to operator policy after the destination is qualified.
SHA-256 detects corruption or payload changes relative to the manifest but does
not authenticate who created the bundle or prevent an attacker from replacing
both files; wrap it in an independently authenticated transport or signed
archive when provenance matters. Backups remain the supported recovery artifact
and can carry an independently verified Ed25519 signature.

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

- `agent_os.db`, a standalone SQLite snapshot without a required WAL sidecar,
  encrypted under the source storage key when source encryption is enabled;
- `manifest.json`, containing the format version, application ID, schema
  version, installation ID, timestamp, byte count, SHA-256 digest, optional
  SQLCipher algorithm/key ID, and—when configured—an Ed25519 key identifier,
  public-key fingerprint, and signature.

`storage::verify_backup` rejects unknown manifest fields, unsupported backup or
schema versions, symlinked inputs, size or hash changes, corrupt SQLite pages,
foreign-key violations, and mismatched installation metadata. This
integrity-only operation deliberately remains compatible with existing unsigned
plaintext backups. An encrypted manifest requires
`verify_backup_with_storage_key` (CLI `--storage-key`) and authenticates the
database with the independently retained matching key. Signing and encryption
are separate: the storage key provides confidentiality; the external Ed25519
trust root establishes provenance.

A trusted system operator can create a live backup through the running server:

```bash
agentctl --addr 127.0.0.1:7777 --token "$AGENT_SERVER_TOKEN" \
  backup-create /var/lib/agentos/backups nightly_2026_07_25
```

`BACKUP_ROOT` is a path on the server host, not the client host. Tenant-bound
credentials, including tenant administrators, cannot invoke this operation.
The SDK exposes the same operation as `KernelClient::create_storage_backup`.

## Signed authenticity and key rotation

Production operators can generate an Ed25519 PKCS#8 signing key and a versioned
public trust file:

```bash
install -d -m 700 /etc/agentos/backup-keys /srv/recovery/agentos-trust
agentctl backup-key-generate release-2026.1 \
  /etc/agentos/backup-keys/release-2026.1.pk8 \
  /srv/recovery/agentos-trust/release-2026.1.json
```

The private file is created without overwrite and must remain owner-only on
Unix. Keep the public trust JSON outside the backup failure domain; it is not
embedded in the backup. Configure the private identity using an absolute path:

```toml
[backup]
enabled = true
root = "/var/lib/agentos-backups"
interval_seconds = 3600
run_on_start = true
keep_latest = 24
max_age_seconds = 604800
# Recommended for production; omit both fields only for integrity-only backups.
signing_key_path = "/etc/agentos/backup-keys/release-2026.1.pk8"
signing_key_id = "release-2026.1"
```

Startup loads and validates the configured key before publishing the new
policy. Scheduled backups and live system-operator `backup-create` calls then
use the same signer. Status exposes only the key ID, never the private path or
key bytes. Container deployments can supply the paired
`AGENTOS_BACKUP_SIGNING_KEY_PATH` and `AGENTOS_BACKUP_SIGNING_KEY_ID`
environment variables; the key path must be a mounted regular non-symlink file.

After selecting a signed recovery point, publish a non-overwriting anchor
outside the backup directory and failure domain. The trust root proves signing
provenance; the anchor pins the exact raw manifest and database identity:

```bash
install -d -m 700 /srv/recovery/agentos-anchors
agentctl backup-anchor-create \
  /var/lib/agentos-backups/nightly_2026_07_25 \
  /srv/recovery/agentos-trust/release-2026.1.json \
  /srv/recovery/agentos-anchors/nightly_2026_07_25.json \
  --storage-key /etc/agentos/storage-keys/storage-generation-1.json
agentctl backup-verify /var/lib/agentos-backups/nightly_2026_07_25 \
  --storage-key /etc/agentos/storage-keys/storage-generation-1.json \
  --require-signature /srv/recovery/agentos-trust/release-2026.1.json \
  --require-anchor /srv/recovery/agentos-anchors/nightly_2026_07_25.json
agentctl backup-restore /var/lib/agentos-backups/nightly_2026_07_25 \
  /var/lib/agentos/agent_os.db \
  --storage-key /etc/agentos/storage-keys/storage-generation-1.json \
  --require-signature /srv/recovery/agentos-trust/release-2026.1.json \
  --require-anchor /srv/recovery/agentos-anchors/nightly_2026_07_25.json \
  --confirm-offline
```

Anchor creation verifies the complete signed backup and, for SQLCipher, its
independently supplied storage key. It creates an owner-only file without
overwrite and rejects direct co-location inside the backup. That path check
cannot prove separate media, immutable storage, or that an operator selected
the newest recovery point; those are custody-policy requirements.

Anchored verification and restore reject unsigned backups, the wrong key ID or
public key, any signed-manifest modification, and substitution of another valid
signed backup before restore mutates the destination. For rotation, generate a
new key ID, retain the old public trust files and anchors for every recovery
point still inside retention, update both configuration fields together, and
restart or reload the owning kernel configuration. Removing old trust material
before its dependent backups expire makes those backups intentionally
unverifiable.

## Verified local-backup retention

`SqliteContextManager::apply_backup_retention` scans a bounded backup root under
the same exclusive publication lock used by online backup. It considers only
strictly verified backups whose installation ID matches the running database.
The policy always preserves `keep_latest` backups and preserves any additional
backup younger than `max_age_seconds`.

Unknown files, hidden staging entries, symlinks, corrupt or foreign-installation
backups, future timestamps, and backup directories containing unexpected
content are skipped and reported; they are never recursively deleted.
Expiration first renames a selected directory to a unique same-root tombstone,
syncs the root, and removes only the known database, SQLite verification
sidecars, and manifest. Retention cannot race backup publication.

Preview a 30-day policy while always keeping seven backups, then enforce the
same policy:

```bash
agentctl --addr 127.0.0.1:7777 --token "$AGENT_SERVER_TOKEN" \
  backup-retention /var/lib/agentos/backups 7 2592000 --dry-run
agentctl --addr 127.0.0.1:7777 --token "$AGENT_SERVER_TOKEN" \
  backup-retention /var/lib/agentos/backups 7 2592000 --confirm
```

The typed SDK separates preview from enforcement and requires
`CONFIRM_BACKUP_RETENTION` for deletion. Reports list eligible, deleted,
retained, and skipped entries. This feature applies only to verified backups in
the named local root; scheduling, remote/object-store lifecycle, and external
workspace/provider deletion remain separate operator responsibilities.

The server-side `create_storage_backup` operation accepts only the exact
configured `backup.root`. This prevents a live system operator from creating an
untracked snapshot outside the root that hot erasure governs. Direct offline
library-created snapshots and replicas copied by infrastructure are external
copies and require an independent lifecycle policy.

## Automatic local backups

`agent-server` starts one backup-maintenance loop when `[backup].enabled` is
true. The root must be absolute; interval, retention age, and `keep_latest`
must be positive, and the retention age cannot be shorter than the interval.
Invalid policy fails startup before creating the data directory. Defaults keep
the scheduler disabled, so an upgrade never starts writing to an unchosen path.

```toml
[backup]
enabled = true
root = "/var/lib/agentos-backups"
interval_seconds = 3600
run_on_start = true
keep_latest = 24
max_age_seconds = 604800
```

Each tick moves the blocking SQLite backup work off the asynchronous runtime,
publishes a uniquely named verified snapshot, then runs confirmed retention
under the same publication lock. If backup or retention fails, the server keeps
running, preserves previously published backups, emits a structured error, and
increments bounded health counters. A retention failure never rolls back or
deletes the new verified backup; the next cycle can retry cleanup.

The system-only `storage_backup_status` operation, typed
`KernelClient::storage_backup_status`, and `agentctl backup-status` report the
policy, attempts, successes, failures, consecutive failures, deleted count,
last timestamps, last backup name, and a bounded diagnostic. Prometheus exports
the same health without path labels:

- `agentos_storage_encryption_enabled`
- `agentos_backup_scheduler_enabled`
- `agentos_backup_signing_enabled`
- `agentos_backup_attempts_total`
- `agentos_backup_successes_total`
- `agentos_backup_failures_total`
- `agentos_backup_retention_deleted_total`
- `agentos_backup_erasure_purge_attempts_total`
- `agentos_backup_erasure_purge_successes_total`
- `agentos_backup_erasure_purge_failures_total`
- `agentos_backup_erasure_purge_deleted_total`
- `agentos_backup_consecutive_failures`
- `agentos_backup_last_success_unixtime_seconds`

The Compose profile enables hourly backups on a separate `agentos-backups`
volume. A separate mount protects against deletion of the live data volume, but
it is still local to one Docker host. Operators must replicate verified
snapshots to an independently governed failure domain to claim node-loss
recovery.

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

Verify a signed backup without changing any state, then stop the server and run
configured-host recovery:

```bash
agentctl backup-verify /var/lib/agentos/backups/nightly_2026_07_25 \
  --storage-key /etc/agentos/storage-keys/storage-generation-1.json \
  --require-signature /srv/recovery/agentos-trust/release-2026.1.json \
  --require-anchor /srv/recovery/agentos-anchors/nightly_2026_07_25.json
agentctl backup-disaster-recover \
  /var/lib/agentos/backups/nightly_2026_07_25 \
  /etc/agentos/config.toml \
  /srv/recovery/agentos-trust/release-2026.1.json \
  /srv/recovery/agentos-anchors/nightly_2026_07_25.json \
  --confirm-offline
```

The recovery command requires an existing configuration with an absolute
`data_dir`, derives `agent_os.db` and its independently retained storage key
from that configuration, and always requires the external public trust file
and exact recovery anchor.
After authenticated restore, it boots the complete configured kernel, including
budget reconstruction and service recovery, and verifies every persisted agent
is present in the live enforcing registry. The previous database remains the
rollback target until that qualification succeeds. A failed qualification
removes a fresh-host destination or atomically restores the previous database.

The confirmation flag makes the destructive intent explicit; it does not
bypass the storage lease. If any kernel still owns the destination, recovery
fails before changing it. The command emits a versioned manifest/report so
automation can retain evidence. The lower-level `backup-restore` command remains
available for manual repair, but it does not perform configured-kernel
qualification.

Fresh-host and replacement recovery are supported by this workflow. The fresh
host must receive the exact storage-key generation and configuration required by
the manifest; key material is intentionally absent from the backup. Recovery
remains deliberately offline and operator-initiated. Remote object storage and
measured recovery objectives remain future work.

## Corrupt database recovery

Normal restore intentionally refuses an existing database that cannot pass
schema verification and a WAL checkpoint. Do not delete that database to force
restore. Stop every process using the configured data directory, retain an
independent copy of the complete directory, and use the explicit corruption
workflow:

```bash
agentctl backup-corruption-recover \
  /var/lib/agentos/backups/nightly_2026_07_25 \
  /etc/agentos/config.toml \
  /srv/recovery/agentos-trust/release-2026.1.json \
  /srv/recovery/agentos-anchors/nightly_2026_07_25.json \
  5df0185b-03c3-4f1d-8026-2d99d4d82f22 \
  --confirm-offline
```

The expected installation UUID is a mandatory independent recovery input. It
must come from operator inventory or previously retained trusted evidence, not
from the backup being considered. Recovery refuses a signed backup for any
other installation, a wrong signature trust root, a wrong SQLCipher key, a
healthy destination, a symlink/non-file database or sidecar, or a destination
still owned by a running kernel.

Preflight checks inspect an isolated copy because SQLite may update `-shm` even
when a connection is read-only. Once the signed backup, key, UUID, paths, and
lease pass, recovery writes an owner-only, secret-free journal beside
`agent_os.db`, then moves the original database and its exact WAL/SHM files
into a unique owner-only quarantine. It copies and re-verifies the backup,
publishes it atomically, boots the complete configured kernel, and verifies
that every persisted agent returns to the live enforcement registry.

An interrupted command can be rerun with the exact same backup, configuration,
trust root, recovery anchor, and UUID. The journal binds the verified backup
identity and resumes from the observed files without deleting ambiguous state.
An ordinary qualification or publication error automatically restores the
corrupt original and its sidecars; the failed replacement remains in quarantine
for diagnosis. If automatic rollback itself fails, the journal is retained and
the error reports its location. Do not move, edit, or delete journal-owned
files before investigation.

On success, the JSON report includes `quarantine_dir`. Quarantine can contain
all tenant and system data. SQLCipher source files remain encrypted, while a
plaintext installation remains plaintext. Restrict custody, copy it to
approved forensic storage if required, and securely remove it only after an
independent operator accepts the recovered installation. Filesystem
secure-deletion guarantees depend on the underlying storage medium.

## Data ownership and erasure contract

`data_inventory::SQLITE_DATA_INVENTORY` is the authoritative full policy
registry. It classifies every logical SQLite table or view by owner, tenant key,
sensitivity, retention, encryption, backup, and deletion behavior.
`context::DURABLE_DATA_CATALOG` is the compact erasure implementation registry
used by deletion code. A schema-introspection regression compares both catalogs
with every logical SQLite object, excluding only private FTS5 shadow tables.
Adding durable state without complete policy and erasure classifications fails
the kernel test suite.

`data_inventory::NON_SQLITE_DATA_INVENTORY` also classifies supported
configuration/key files, backups, workspaces, in-process state, sandbox
processes, providers, remote backups, telemetry sinks, registries, and external
tool services. A trusted system operator can inspect the combined, versioned
policy document through `KernelClient::storage_data_inventory` or:

```bash
agentctl --addr 127.0.0.1:7777 --token "$AGENT_SERVER_TOKEN" \
  data-inventory
```

The command returns policy metadata only. It never reads or returns live
content, credentials, tenant identifiers, configured paths, or secret material.
The inventory deliberately reports boundaries that are not encrypted or not
locally deletable; publication is evidence of classification, not evidence that
those gaps are resolved.

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
remain immutable: hot erasure does not edit snapshots in place. Instead, every
server-created backup belongs to the configured managed root. Before an agent,
user, or tenant SQLite erasure commits, the kernel exclusively locks that root,
preflights every entry, deletes every verified backup for the current
installation, and holds publication fenced through the database commit. A
corrupt, foreign, unknown, augmented, symlinked, or unavailable-key entry
aborts erasure before the live database changes; the operation never skips a
possibly recoverable copy. Only a successfully committed erasure returns a
success receipt. The receipt counts removed managed backup copies without
identifying their path or the subject. The next startup or scheduled cycle
creates a clean post-erasure recovery point.

Direct offline library snapshots, infrastructure replicas, remote object-store
copies, and other systems outside the configured root remain under their
independent deletion policy. The database is protected with owner-only
permissions on Unix. Configured production
deployments additionally use SQLCipher whole-database encryption; offline
encryption migration and key rotation are supported. Provider configuration
files, agent workspaces, remote provider data, and external object stores are
outside this SQLite deletion boundary.

Ephemeral process state includes scheduler queues, executors and cancellation
handles, syscall-gate registrations, namespaces/cgroups, sandboxes, credential
leases/auth caches, provider circuit state, and in-memory observability data.
Normal kernel lifecycle cleanup or process exit removes it.

The supported hot-delete boundary is system-authorized `erase_data`. It requires
explicit confirmation, closes and drains affected credentials, disables
supervised owners, quiesces turns and external tool calls, removes every
kernel-owned live boundary, and then commits the classified storage erasure
behind a global request barrier. Tenant users and tenant administrators cannot
invoke it. An agent-only operation reopens unaffected tenant credentials after
completion; successful user and tenant erasure permanently revokes their
credentials. Pre-commit failures reopen credentials whose identities remain
valid. Operators can use the typed SDK or:

```bash
agentctl --addr 127.0.0.1:7777 --token "$AGENT_SERVER_TOKEN" \
  erase-agent 00000000-0000-0000-0000-000000000001 --confirm
agentctl --addr 127.0.0.1:7777 --token "$AGENT_SERVER_TOKEN" \
  erase-user USER_ID --confirm
agentctl --addr 127.0.0.1:7777 --token "$AGENT_SERVER_TOKEN" \
  erase-tenant TENANT_ID --confirm
```

These commands return a privacy-safe receipt or `null` when no classified data
existed. The configured managed backup root is included as described above.
Provider configuration files, external workspaces, remote provider data,
offline-created backup copies, replicas, and external object stores remain
outside this operation and require their own retention/deletion controls.

## Current durability boundary

File-backed stores require WAL mode, `synchronous=FULL`, foreign-key
enforcement, a bounded busy timeout, and owner-only database permissions on
Unix. The existing restart suite verifies recovery of application state,
admission accounting, checkpoints, and agent rehydration.

A deterministic `SQLITE_FULL` regression constrains SQLite's page budget,
attempts a transaction that must grow the database, and verifies the failed
transaction leaves no partial row while previously committed data survives
integrity verification and reopen. This qualifies SQLite's transactional
failure behavior. A separate guarded Linux qualification fills an explicitly
marked 32–128 MiB disposable filesystem until the host returns `ENOSPC`, then
proves rollback, capacity restoration, retry, `quick_check`, and reopen. See
[Host storage fault qualification](HOST_STORAGE_FAULT_QUALIFICATION.md). This
single ext4 fixture does not substitute for destructive capacity tests on every
supported deployment profile or filesystem.

All three schema-wide erasure transactions have real process-exit regressions
at every statement boundary: 17 agent, 5 user, and 28 tenant boundaries. The
agent matrix covers FTS, each owned data table, service references, cgroup quota
records, the agent identity, and the deletion receipt. The user matrix covers
sessions, API keys, package rate limits, the user identity, and the receipt
while proving pseudonymous transparency/audit evidence remains. The tenant
matrix covers agent data and indexes, services, package supply-chain state,
identities and credentials, tenant quota scopes, agent and tenant identities,
and the receipt.

After each of the 50 forced child-process exits, a fresh connection validates
the schema and `quick_check` and compares a canonical value fingerprint of
every durable table. The expected `storage_meta.upgraded_at` refresh performed
before the transaction is excluded; every durable identity/version field
remains included. A final retry for each scope must remove the complete seeded
subject and commit exactly one private receipt. This proves all-or-nothing
recovery for the agent, user, and tenant SQLite erasure transactions. It does
not by itself cover the surrounding live-resource coordinator.

A second file-backed child-process matrix exits at 18 supported hot-erasure
boundaries: six agent, five user, and seven tenant points. The points cover
credential fencing/drain completion, the service-stop loop, acquisition of the
global request and operator-mutation barriers, completion of the managed-backup
purge while its publication lock remains held, live-agent quiescence and
resource removal, the handoff after the SQLite erasure commit, and final
user/tenant auth revocation. Every fixture begins with a verified managed
backup; the tenant fixture also includes a supervised service and multiple live
agents.

After every forced coordinator exit, a new kernel opens the same database,
performs normal lifecycle/tenancy rehydration, retries the same erasure, and
must leave the subject absent with exactly one private deletion receipt.
Agent retries also prove the process-local agent registry and syscall-gate
registration are absent, and every scope proves the pre-erasure managed backup
is gone. This qualifies process termination between the documented coordinator
stages. It does not emulate interruption inside one opaque cleanup or
managed-backup deletion call, host power loss, torn writes, device loss, or
provider/workspace systems outside the kernel process.

A third file-backed matrix qualifies 26 statement boundaries across eleven
high-value multi-table context mutations: conversation plus FTS publication;
context-spill store, expiry purge, and deletion; operator-tunable ensure,
update, and rollback plus audit history; service runtime save/remove plus
history; and user/tenant identity revocation. Each child process terminates
after one successful SQLite statement but before commit. A fresh connection
must match the canonical pre-transaction fingerprint of every durable table,
then a clean retry must publish the complete related state and pass schema
verification plus `quick_check`. Conversation persistence also treats an FTS
write failure as a transaction failure instead of committing an unindexed
conversation.

This matrix proves process-termination atomicity for those context workflows.
It does not yet qualify the separate quota/accounting, package-registry, or
cluster-control multi-table transactions, interruption inside external side
effects, host power loss, torn writes, or device loss.

The following remain open under issue #123:

- remote object storage retention and a measured recovery runbook;
- independent immutable/remote retention controls and released trust fixtures;
- measured deletion/retention enforcement across external workspaces,
  providers, remote backup copies, and object stores;
- power-loss, torn-write, device-loss, object-store, other deployment
  filesystem, and extended crash qualification beyond the disposable ext4
  `ENOSPC` run, deterministic interrupted-encryption recovery, and the
  erasure transaction/coordinator and context-mutation matrices covered above;
- process-exit statement-boundary matrices for the remaining quota/accounting,
  package-registry, and cluster-control multi-table transactions;
- measured RPO/RTO on supported deployment profiles.
