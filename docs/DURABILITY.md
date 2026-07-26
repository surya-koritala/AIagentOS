# Durable state and schema compatibility

AI Agent OS currently stores kernel-owned state in one SQLite database. The
database includes context, memory, usage and quota accounting, agent lifecycle,
packages, operator settings, services, identity, and cluster control state.

This document describes the guarantees implemented today. It does not claim
that backup, restore, encryption, or deletion are production-qualified.

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
older schema will require restoring a verified pre-upgrade backup. Until the
backup/restore work in issue #123 is complete, operators should treat a schema
upgrade as irreversible and test it on a copy of their data.

## Current durability boundary

File-backed stores require WAL mode, `synchronous=FULL`, foreign-key
enforcement, a bounded busy timeout, and owner-only database permissions on
Unix. The existing restart suite verifies recovery of application state,
admission accounting, checkpoints, and agent rehydration.

The following remain open under issue #123:

- online, WAL-consistent backup with a signed or hashed manifest;
- offline verified restore with atomic rollback and fresh-host recovery tests;
- corruption recovery beyond fail-closed startup detection;
- encryption at rest and key rotation;
- schema-wide agent and tenant deletion with retention policy and receipts;
- disk-full, interrupted migration/restore, and extended crash qualification;
- operator commands and recovery runbooks with measured RPO/RTO.
