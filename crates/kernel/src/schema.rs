//! Versioned ownership and compatibility checks for the kernel SQLite store.
//!
//! Version zero is the only unowned/legacy shape accepted by the migration
//! layer. Once adopted, both `application_id` and `user_version` are written so
//! an older or unrelated binary cannot silently mutate the database.

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::ContextError;

/// ASCII `AIOS`, registered on every database owned by this kernel.
pub(crate) const APPLICATION_ID: i64 = 0x4149_4f53;
/// Latest schema this binary can read and write.
pub(crate) const CURRENT_SCHEMA_VERSION: i64 = 2;
const MIN_READABLE_SCHEMA_VERSION: i64 = 1;

const MIGRATIONS: &[(i64, &str)] = &[
    (1, "adopt-versioned-kernel-schema"),
    (2, "add-privacy-safe-deletion-receipts"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StorageMetadata {
    pub application_id: i64,
    pub schema_version: i64,
    pub min_reader_schema_version: i64,
    pub installation_id: String,
}

const REQUIRED_TABLES: &[&str] = &[
    "contexts",
    "facts",
    "conversations",
    "conversations_fts",
    "usage_log",
    "agent_kv",
    "context_spills",
    "context_pressure",
    "context_snapshots",
    "generation_checkpoints",
    "agents",
    "loaded_package_instances",
    "package_trust_keys",
    "package_artifacts",
    "package_installations",
    "package_install_history",
    "package_rate_limits",
    "package_transparency",
    "package_audit",
    "operator_tunables",
    "operator_tunable_audit",
    "service_runtime",
    "service_history",
    "tenants",
    "users",
    "api_keys",
    "sessions",
    "quota_epoch_floor",
    "quota_epochs",
    "quota_receipts",
    "quota_receipt_scopes",
    "quota_refunded_receipts",
    "quota_migration_fence",
    "cluster_node_identity",
    "cluster_node_control",
    "cluster_node_control_audit",
    "cluster_membership_authority",
    "cluster_join_challenges",
    "cluster_members",
    "cluster_membership_audit",
    "deletion_receipts",
];

const LEGACY_MARKER_TABLES: &[&str] = &[
    "contexts",
    "facts",
    "conversations",
    "usage_log",
    "agent_kv",
    "agents",
    "tenants",
    "users",
    "quota_epochs",
    "package_artifacts",
    "service_runtime",
    "cluster_node_identity",
];

fn storage_error(message: impl Into<String>) -> ContextError {
    ContextError::StorageError(message.into())
}

/// Validate database identity, compatibility, and physical integrity before any
/// startup PRAGMA or migration is allowed to mutate the file.
pub(crate) fn preflight(connection: &Connection) -> Result<i64, ContextError> {
    let integrity: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|error| {
            storage_error(format!("SQLite preflight integrity check failed: {error}"))
        })?;
    if integrity != "ok" {
        return Err(storage_error(format!(
            "SQLite preflight integrity check failed: {integrity}"
        )));
    }

    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|error| storage_error(format!("failed to read SQLite application id: {error}")))?;
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| storage_error(format!("failed to read SQLite schema version: {error}")))?;

    if application_id == 0 && schema_version == 0 {
        let user_table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                storage_error(format!("failed to inspect legacy SQLite tables: {error}"))
            })?;
        if user_table_count == 0 {
            return Ok(0);
        }
        for marker in LEGACY_MARKER_TABLES {
            let recognized = connection
                .query_row(
                    "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                    [marker],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|error| {
                    storage_error(format!(
                        "failed to inspect legacy SQLite marker {marker}: {error}"
                    ))
                })?
                .is_some();
            if recognized {
                return Ok(0);
            }
        }
        return Err(storage_error(
            "unowned SQLite database has no recognized AI Agent OS legacy tables",
        ));
    }
    if application_id != APPLICATION_ID {
        return Err(storage_error(format!(
            "SQLite database is not an AI Agent OS store (application_id={application_id})"
        )));
    }
    if schema_version > CURRENT_SCHEMA_VERSION {
        return Err(ContextError::DatabaseTooNew {
            found: schema_version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if schema_version < MIN_READABLE_SCHEMA_VERSION {
        return Err(storage_error(format!(
            "SQLite schema version {schema_version} is below the minimum readable version \
             {MIN_READABLE_SCHEMA_VERSION}"
        )));
    }
    Ok(schema_version)
}

pub(crate) fn add_column_if_missing(
    connection: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), ContextError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|error| storage_error(format!("failed to inspect {table}: {error}")))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| storage_error(format!("failed to enumerate {table} columns: {error}")))?;
    for existing in columns {
        if existing
            .map_err(|error| storage_error(format!("failed to read {table} column: {error}")))?
            == column
        {
            return Ok(());
        }
    }
    connection
        .execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )
        .map_err(|error| {
            storage_error(format!(
                "failed to add {table}.{column} during migration: {error}"
            ))
        })?;
    Ok(())
}

/// Atomically publish the ownership metadata and final version marker only
/// after all version-zero adoption work has succeeded.
pub(crate) fn complete_migration(
    connection: &mut Connection,
    starting_version: i64,
) -> Result<(), ContextError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| storage_error(format!("failed to start schema transaction: {error}")))?;

    for table in REQUIRED_TABLES {
        let exists = transaction
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type IN ('table', 'view') AND name = ?1",
                [table],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| {
                storage_error(format!(
                    "failed to validate required table {table}: {error}"
                ))
            })?
            .is_some();
        if !exists {
            return Err(storage_error(format!(
                "schema migration did not create required table {table}"
            )));
        }
    }

    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS storage_meta (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 application_id INTEGER NOT NULL,
                 schema_version INTEGER NOT NULL,
                 min_reader_schema_version INTEGER NOT NULL,
                 installation_id TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 upgraded_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY CHECK (version > 0),
                 name TEXT NOT NULL,
                 applied_at TEXT NOT NULL
             );",
        )
        .map_err(|error| storage_error(format!("failed to create schema metadata: {error}")))?;

    let now = Utc::now().to_rfc3339();
    for (version, name) in MIGRATIONS
        .iter()
        .filter(|(version, _)| *version > starting_version)
    {
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, name, applied_at)
                 VALUES (?1, ?2, ?3)",
                params![version, name, &now],
            )
            .map_err(|error| {
                storage_error(format!("failed to record schema migration: {error}"))
            })?;
    }
    transaction
        .execute(
            "INSERT INTO storage_meta
                 (singleton, application_id, schema_version,
                  min_reader_schema_version, installation_id, created_at, upgraded_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(singleton) DO UPDATE SET
                 application_id = excluded.application_id,
                 schema_version = excluded.schema_version,
                 min_reader_schema_version = excluded.min_reader_schema_version,
                 upgraded_at = excluded.upgraded_at",
            params![
                APPLICATION_ID,
                CURRENT_SCHEMA_VERSION,
                MIN_READABLE_SCHEMA_VERSION,
                uuid::Uuid::new_v4().to_string(),
                &now
            ],
        )
        .map_err(|error| storage_error(format!("failed to update schema metadata: {error}")))?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|error| storage_error(format!("failed to set SQLite application id: {error}")))?;
    transaction
        .pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)
        .map_err(|error| storage_error(format!("failed to set SQLite schema version: {error}")))?;
    transaction
        .commit()
        .map_err(|error| storage_error(format!("failed to commit schema migration: {error}")))?;

    verify(connection)
}

pub(crate) fn verify(connection: &Connection) -> Result<(), ContextError> {
    let version = preflight(connection)?;
    if version != CURRENT_SCHEMA_VERSION {
        return Err(storage_error(format!(
            "SQLite schema version is {version}, expected {CURRENT_SCHEMA_VERSION}"
        )));
    }

    let foreign_key_violation = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(|error| storage_error(format!("SQLite foreign-key check failed: {error}")))?;
    if let Some(table) = foreign_key_violation {
        return Err(storage_error(format!(
            "SQLite foreign-key check found a violation in table {table}"
        )));
    }

    let metadata = read_storage_metadata(connection)?;
    if (
        metadata.application_id,
        metadata.schema_version,
        metadata.min_reader_schema_version,
    ) != (
        APPLICATION_ID,
        CURRENT_SCHEMA_VERSION,
        MIN_READABLE_SCHEMA_VERSION,
    ) {
        return Err(storage_error(format!(
            "schema metadata is inconsistent: application_id={}, schema_version={}, \
             min_reader_schema_version={}",
            metadata.application_id, metadata.schema_version, metadata.min_reader_schema_version
        )));
    }
    if uuid::Uuid::parse_str(&metadata.installation_id).is_err() {
        return Err(storage_error(
            "schema metadata installation_id is not a UUID",
        ));
    }
    Ok(())
}

pub(crate) fn read_storage_metadata(
    connection: &Connection,
) -> Result<StorageMetadata, ContextError> {
    connection
        .query_row(
            "SELECT application_id, schema_version, min_reader_schema_version, installation_id
             FROM storage_meta WHERE singleton = 1",
            [],
            |row| {
                Ok(StorageMetadata {
                    application_id: row.get(0)?,
                    schema_version: row.get(1)?,
                    min_reader_schema_version: row.get(2)?,
                    installation_id: row.get(3)?,
                })
            },
        )
        .map_err(|error| storage_error(format!("failed to read schema metadata: {error}")))
}
