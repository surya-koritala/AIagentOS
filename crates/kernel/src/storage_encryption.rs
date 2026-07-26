//! Operator-custodied whole-database encryption keys.
//!
//! Keys are random binary material stored outside the database and every
//! backup. Only their non-secret identifier may enter manifests, status, or
//! logs. SQLCipher receives key bytes through its C API so the secret is never
//! interpolated into SQL text.

use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{ffi, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::ContextError;

const STORAGE_KEY_FORMAT_VERSION: u32 = 1;
const STORAGE_KEY_BYTES: usize = 32;
const MAX_STORAGE_KEY_FILE_BYTES: u64 = 4 * 1024;
const ENCRYPTION_MIGRATION_FORMAT_VERSION: u32 = 1;
const MAX_ENCRYPTION_MIGRATION_FILE_BYTES: u64 = 16 * 1024;

/// Auditable result of an offline encryption migration or key rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageEncryptionChangeReport {
    pub database_path: PathBuf,
    pub operation: String,
    pub previous_key_id: Option<String>,
    pub current_key_id: String,
    pub application_id: i64,
    pub schema_version: i64,
    pub installation_id: String,
}

/// Auditable result of reconciling an interrupted offline encryption migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageEncryptionRecoveryReport {
    pub database_path: PathBuf,
    pub outcome: String,
    pub current_key_id: String,
    pub application_id: i64,
    pub schema_version: i64,
    pub installation_id: String,
    pub plaintext_rollback_removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptionMigrationJournal {
    format_version: u32,
    database_file: String,
    stage_file: String,
    rollback_file: String,
    current_key_id: String,
    application_id: i64,
    schema_version: i64,
    min_reader_schema_version: i64,
    installation_id: String,
}

/// Secret whole-database key retained only in protected process memory.
pub struct StorageEncryptionKey {
    key_id: String,
    bytes: Zeroizing<[u8; STORAGE_KEY_BYTES]>,
}

impl fmt::Debug for StorageEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageEncryptionKey")
            .field("key_id", &self.key_id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageKeyDocument {
    format_version: u32,
    key_id: String,
    key_hex: String,
}

impl Drop for StorageKeyDocument {
    fn drop(&mut self) {
        self.key_hex.zeroize();
    }
}

impl StorageEncryptionKey {
    /// Build a key from exactly 256 bits of externally protected random
    /// material.
    pub fn from_bytes(
        key_id: impl Into<String>,
        bytes: [u8; STORAGE_KEY_BYTES],
    ) -> Result<Self, ContextError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        Ok(Self {
            key_id,
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Generate a fresh random key in memory.
    pub fn generate(key_id: impl Into<String>) -> Result<Self, ContextError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        let mut bytes = [0_u8; STORAGE_KEY_BYTES];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| storage_error("failed to generate storage encryption key"))?;
        Self::from_bytes(key_id, bytes)
    }

    /// Public operator identifier for this key generation.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Apply the key before the first operation on a SQLCipher connection.
    pub(crate) fn apply(&self, connection: &Connection) -> Result<(), ContextError> {
        let result = unsafe {
            ffi::sqlite3_key(
                connection.handle(),
                self.bytes.as_ptr().cast(),
                STORAGE_KEY_BYTES as std::os::raw::c_int,
            )
        };
        if result != ffi::SQLITE_OK {
            return Err(storage_error(format!(
                "SQLCipher rejected storage key {:?} with code {result}",
                self.key_id
            )));
        }
        connection
            .query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))
            .map_err(|_| {
                storage_error(format!(
                    "storage key {:?} cannot authenticate this database",
                    self.key_id
                ))
            })
    }

    pub(crate) fn apply_to_attached(
        &self,
        connection: &Connection,
        database_name: &str,
    ) -> Result<(), ContextError> {
        if database_name != "encrypted" {
            return Err(storage_error(
                "storage encryption only supports the fixed attached database name",
            ));
        }
        let database_name = CString::new(database_name)
            .map_err(|_| storage_error("attached database name contains a NUL byte"))?;
        let result = unsafe {
            ffi::sqlite3_key_v2(
                connection.handle(),
                database_name.as_ptr(),
                self.bytes.as_ptr().cast(),
                STORAGE_KEY_BYTES as std::os::raw::c_int,
            )
        };
        if result != ffi::SQLITE_OK {
            return Err(storage_error(format!(
                "SQLCipher rejected storage key {:?} for migration with code {result}",
                self.key_id
            )));
        }
        connection
            .query_row("SELECT count(*) FROM encrypted.sqlite_schema", [], |_| {
                Ok(())
            })
            .map_err(|_| {
                storage_error(format!(
                    "storage key {:?} cannot initialize migration database",
                    self.key_id
                ))
            })
    }

    /// Atomically re-encrypt an open database under a new key.
    ///
    /// Callers must hold the database storage lease and quiesce all use of the
    /// connection before invoking this primitive.
    pub(crate) fn rekey(
        connection: &Connection,
        next: &StorageEncryptionKey,
    ) -> Result<(), ContextError> {
        let result = unsafe {
            ffi::sqlite3_rekey(
                connection.handle(),
                next.bytes.as_ptr().cast(),
                STORAGE_KEY_BYTES as std::os::raw::c_int,
            )
        };
        if result != ffi::SQLITE_OK {
            return Err(storage_error(format!(
                "SQLCipher storage-key rotation to {:?} failed with code {result}",
                next.key_id
            )));
        }
        connection
            .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .map_err(|_| storage_error("rotated database failed integrity verification"))
            .and_then(|result| {
                if result.eq_ignore_ascii_case("ok") {
                    Ok(())
                } else {
                    Err(storage_error(format!(
                        "rotated database integrity check returned {result:?}"
                    )))
                }
            })
    }
}

/// Write a new owner-only key document without overwriting any existing path.
pub fn generate_storage_encryption_key_file(key_id: &str, path: &Path) -> Result<(), ContextError> {
    let key = StorageEncryptionKey::generate(key_id.to_string())?;
    let document = StorageKeyDocument {
        format_version: STORAGE_KEY_FORMAT_VERSION,
        key_id: key.key_id.clone(),
        key_hex: hex_encode(key.bytes.as_ref()),
    };
    let encoded = Zeroizing::new(
        serde_json::to_vec_pretty(&document)
            .map_err(|_| storage_error("failed to encode storage key document"))?,
    );
    let mut file = create_owner_only_new_file(path)?;
    if let Err(error) = (|| {
        file.write_all(encoded.as_ref())?;
        file.write_all(b"\n")?;
        file.sync_all()
    })() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(storage_error(format!(
            "failed to publish storage key {}: {error}",
            path.display()
        )));
    }
    sync_parent(path)?;
    Ok(())
}

/// Load and validate one bounded owner-only key document.
pub fn load_storage_encryption_key(path: &Path) -> Result<StorageEncryptionKey, ContextError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| {
        storage_error(format!(
            "failed to open storage key {} as a regular non-symlink file: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        storage_error(format!(
            "failed to inspect opened storage key {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(storage_error(
            "storage key path must be a regular file, not a symlink",
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_STORAGE_KEY_FILE_BYTES {
        return Err(storage_error("storage key file has an invalid size"));
    }
    verify_owner_only(path, &metadata)?;

    let mut encoded = Zeroizing::new(Vec::with_capacity(metadata.len() as usize + 1));
    file.take(MAX_STORAGE_KEY_FILE_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| {
            storage_error(format!(
                "failed to read storage key {}: {error}",
                path.display()
            ))
        })?;
    if encoded.len() as u64 > MAX_STORAGE_KEY_FILE_BYTES {
        return Err(storage_error("storage key file exceeds the size limit"));
    }
    let document: StorageKeyDocument = serde_json::from_slice(encoded.as_ref())
        .map_err(|_| storage_error("storage key document is not valid bounded JSON"))?;
    if document.format_version != STORAGE_KEY_FORMAT_VERSION {
        return Err(storage_error(format!(
            "unsupported storage key format version {}",
            document.format_version
        )));
    }
    validate_key_id(&document.key_id)?;
    let decoded = Zeroizing::new(
        hex_decode(&document.key_hex)
            .ok_or_else(|| storage_error("storage key material is not valid hexadecimal"))?,
    );
    let bytes: [u8; STORAGE_KEY_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| storage_error("storage key must contain exactly 32 bytes"))?;
    StorageEncryptionKey::from_bytes(document.key_id.clone(), bytes)
}

/// Encrypt an existing plaintext AIagentOS database in place while offline.
///
/// The caller must retain the supplied key independently. The process acquires
/// the same exclusive storage lease as the kernel, checkpoints WAL, verifies
/// schema and integrity before and after rekeying, and fails if the database is
/// already encrypted or in use.
pub fn encrypt_existing_database(
    database_path: &Path,
    key: &StorageEncryptionKey,
) -> Result<StorageEncryptionChangeReport, ContextError> {
    let _lease = crate::storage::acquire_storage_lease(database_path)?;
    let journal_path = encryption_migration_journal_path(database_path)?;
    if regular_migration_file_exists(&journal_path, "encryption migration journal")? {
        return Err(storage_error(format!(
            "interrupted encryption migration journal exists at {}; run \
             storage-encrypt-recover while offline before retrying",
            journal_path.display()
        )));
    }
    require_database_file(database_path)?;
    let connection = Connection::open(database_path).map_err(|error| {
        storage_error(format!(
            "failed to open plaintext database {}: {error}",
            database_path.display()
        ))
    })?;
    let metadata = prepare_database_for_rekey(&connection).map_err(|error| {
        storage_error(format!(
            "database is not a verified plaintext AIagentOS store: {error}"
        ))
    })?;
    let stage = migration_companion_path(database_path, "encrypted", "staging")?;
    let rollback = migration_companion_path(database_path, "plaintext", "rollback")?;
    reject_existing_migration_path(&stage)?;
    reject_existing_migration_path(&rollback)?;
    reject_existing_migration_path(&journal_path).map_err(|error| {
        storage_error(format!(
            "{error}; run storage-encrypt-recover while offline before retrying"
        ))
    })?;
    let journal =
        EncryptionMigrationJournal::new(database_path, &stage, &rollback, key.key_id(), &metadata)?;
    write_encryption_migration_journal(&journal_path, &journal)?;
    let mut journal_guard = MigrationFile::new(journal_path.clone());
    let mut stage_guard = MigrationFile::new(stage.clone());
    let stage_text = stage
        .to_str()
        .ok_or_else(|| storage_error("database path must be valid UTF-8 for SQLCipher export"))?;
    connection
        .execute("ATTACH DATABASE ?1 AS encrypted", [stage_text])
        .map_err(|error| {
            storage_error(format!(
                "failed to attach encrypted migration database: {error}"
            ))
        })?;
    key.apply_to_attached(&connection, "encrypted")?;
    connection
        .query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()))
        .map_err(|error| storage_error(format!("SQLCipher export failed: {error}")))?;
    connection
        .pragma_update(
            Some(rusqlite::DatabaseName::Attached("encrypted")),
            "application_id",
            metadata.application_id,
        )
        .map_err(|error| {
            storage_error(format!(
                "failed to preserve application id during encryption: {error}"
            ))
        })?;
    connection
        .pragma_update(
            Some(rusqlite::DatabaseName::Attached("encrypted")),
            "user_version",
            metadata.schema_version,
        )
        .map_err(|error| {
            storage_error(format!(
                "failed to preserve schema version during encryption: {error}"
            ))
        })?;
    connection
        .execute("DETACH DATABASE encrypted", [])
        .map_err(|error| {
            storage_error(format!(
                "failed to finalize encrypted migration database: {error}"
            ))
        })?;
    drop(connection);
    remove_migration_sidecar(database_path, "-wal")?;
    remove_migration_sidecar(database_path, "-shm")?;
    set_owner_only_database(&stage)?;
    sync_database_file(&stage)?;
    let verified = verify_database_with_key(&stage, key)?;
    if verified != metadata {
        return Err(storage_error(
            "encrypted database identity changed during migration",
        ));
    }

    fs::rename(database_path, &rollback).map_err(|error| {
        storage_error(format!(
            "failed to preserve plaintext database during migration: {error}"
        ))
    })?;
    #[cfg(test)]
    abort_encryption_migration_after_rollback_for_test();
    let publish = (|| {
        fs::rename(&stage, database_path).map_err(|error| {
            storage_error(format!(
                "failed to publish encrypted database {}: {error}",
                database_path.display()
            ))
        })?;
        stage_guard.disarm();
        sync_parent(database_path)?;
        let published = verify_database_with_key(database_path, key)?;
        if published != metadata {
            return Err(storage_error(
                "published encrypted database identity does not match source",
            ));
        }
        Ok(())
    })();
    if let Err(error) = publish {
        let _ = fs::remove_file(database_path);
        if let Err(rollback_error) = fs::rename(&rollback, database_path) {
            stage_guard.disarm();
            journal_guard.disarm();
            return Err(storage_error(format!(
                "encryption migration failed ({error}); plaintext rollback also failed: \
                 {rollback_error}; recovery journal retained at {}",
                journal_path.display()
            )));
        }
        sync_parent(database_path)?;
        return Err(error);
    }
    if let Err(error) = fs::remove_file(&rollback) {
        journal_guard.disarm();
        return Err(storage_error(format!(
            "database is encrypted but obsolete plaintext rollback {} could not be removed: \
             {error}; recovery journal retained at {}",
            rollback.display(),
            journal_path.display()
        )));
    }
    sync_parent(database_path)?;
    fs::remove_file(&journal_path).map_err(|error| {
        storage_error(format!(
            "database is encrypted but completed migration journal {} could not be removed: {error}",
            journal_path.display()
        ))
    })?;
    journal_guard.disarm();
    sync_parent(database_path)?;

    let unkeyed = Connection::open(database_path).and_then(|connection| {
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))
    });
    if unkeyed.is_ok() {
        return Err(storage_error(
            "database remained readable without a key after encryption migration",
        ));
    }
    Ok(change_report(
        database_path,
        "encrypt",
        None,
        key.key_id(),
        metadata,
    ))
}

/// Recover an interrupted offline plaintext-to-encrypted migration.
///
/// Recovery is deliberately conservative: every surviving database is opened
/// read-only and must match the journaled AIagentOS installation identity
/// before any file is published or removed. Unknown, symlinked, corrupt, or
/// identity-mismatched files fail closed for operator inspection.
pub fn recover_interrupted_encryption_migration(
    database_path: &Path,
    key: &StorageEncryptionKey,
) -> Result<StorageEncryptionRecoveryReport, ContextError> {
    let _lease = crate::storage::acquire_storage_lease(database_path)?;
    let journal_path = encryption_migration_journal_path(database_path)?;
    let journal = load_encryption_migration_journal(database_path, &journal_path)?;
    if journal.current_key_id != key.key_id() {
        return Err(storage_error(format!(
            "encryption migration requires key id {:?}, not {:?}",
            journal.current_key_id,
            key.key_id()
        )));
    }
    let expected = journal.storage_metadata();
    let parent = database_path
        .parent()
        .ok_or_else(|| storage_error("database path has no parent directory"))?;
    let stage = parent.join(&journal.stage_file);
    let rollback = parent.join(&journal.rollback_file);
    let database_exists = regular_migration_file_exists(database_path, "database")?;
    let stage_exists = regular_migration_file_exists(&stage, "encrypted staging database")?;
    let rollback_exists = regular_migration_file_exists(&rollback, "plaintext rollback database")?;

    if database_exists {
        if let Ok(metadata) = verify_database_with_key(database_path, key) {
            require_matching_migration_identity(
                "published encrypted database",
                &metadata,
                &expected,
            )?;
            if stage_exists {
                let staged = verify_database_with_key(&stage, key)?;
                require_matching_migration_identity(
                    "encrypted staging database",
                    &staged,
                    &expected,
                )?;
                fs::remove_file(&stage).map_err(|error| {
                    storage_error(format!(
                        "failed to remove verified obsolete encryption stage {}: {error}",
                        stage.display()
                    ))
                })?;
            }
            let plaintext_rollback_removed = if rollback_exists {
                let plaintext = verify_plaintext_database(&rollback)?;
                require_matching_migration_identity(
                    "plaintext rollback database",
                    &plaintext,
                    &expected,
                )?;
                fs::remove_file(&rollback).map_err(|error| {
                    storage_error(format!(
                        "failed to remove verified plaintext rollback {}: {error}",
                        rollback.display()
                    ))
                })?;
                true
            } else {
                false
            };
            remove_completed_migration_journal(&journal_path)?;
            sync_parent(database_path)?;
            return Ok(recovery_report(
                database_path,
                "completed-encryption",
                key.key_id(),
                expected,
                plaintext_rollback_removed,
            ));
        }

        let plaintext = verify_plaintext_database(database_path).map_err(|error| {
            storage_error(format!(
                "canonical database is neither the journaled encrypted database nor a valid \
                 plaintext rollback: {error}"
            ))
        })?;
        require_matching_migration_identity("plaintext database", &plaintext, &expected)?;
        if rollback_exists {
            return Err(storage_error(
                "recovery found both canonical plaintext and a rollback database; refusing \
                 ambiguous mutation",
            ));
        }
        if stage_exists {
            fs::remove_file(&stage).map_err(|error| {
                storage_error(format!(
                    "failed to remove journal-owned interrupted encryption stage {}: {error}",
                    stage.display()
                ))
            })?;
        }
        remove_completed_migration_journal(&journal_path)?;
        sync_parent(database_path)?;
        return Ok(recovery_report(
            database_path,
            "restored-plaintext",
            key.key_id(),
            expected,
            false,
        ));
    }

    if !rollback_exists {
        return Err(storage_error(
            "recovery journal exists but neither the canonical database nor plaintext rollback \
             exists; refusing data-loss recovery",
        ));
    }
    let plaintext = verify_plaintext_database(&rollback)?;
    require_matching_migration_identity("plaintext rollback database", &plaintext, &expected)?;

    if stage_exists {
        let staged = verify_database_with_key(&stage, key).map_err(|error| {
            storage_error(format!(
                "canonical database is missing and encrypted stage cannot be authenticated; \
                 leaving the verified plaintext rollback untouched: {error}"
            ))
        })?;
        require_matching_migration_identity("encrypted staging database", &staged, &expected)?;
        fs::rename(&stage, database_path).map_err(|error| {
            storage_error(format!(
                "failed to publish verified interrupted encryption stage {}: {error}",
                stage.display()
            ))
        })?;
        sync_parent(database_path)?;
        let published = verify_database_with_key(database_path, key)?;
        require_matching_migration_identity("published encrypted database", &published, &expected)?;
        fs::remove_file(&rollback).map_err(|error| {
            storage_error(format!(
                "encrypted database recovered but verified plaintext rollback {} could not be \
                 removed: {error}",
                rollback.display()
            ))
        })?;
        remove_completed_migration_journal(&journal_path)?;
        sync_parent(database_path)?;
        return Ok(recovery_report(
            database_path,
            "completed-encryption",
            key.key_id(),
            expected,
            true,
        ));
    }

    fs::rename(&rollback, database_path).map_err(|error| {
        storage_error(format!(
            "failed to restore verified plaintext rollback {}: {error}",
            rollback.display()
        ))
    })?;
    sync_parent(database_path)?;
    let restored = verify_plaintext_database(database_path)?;
    require_matching_migration_identity("restored plaintext database", &restored, &expected)?;
    remove_completed_migration_journal(&journal_path)?;
    sync_parent(database_path)?;
    Ok(recovery_report(
        database_path,
        "restored-plaintext",
        key.key_id(),
        expected,
        false,
    ))
}

/// Rotate an encrypted AIagentOS database to a new independently retained key.
///
/// Rotation is deliberately offline and refuses to run while a kernel owns the
/// database lease. A wrong current key fails before any write.
pub fn rotate_database_encryption_key(
    database_path: &Path,
    current_key: &StorageEncryptionKey,
    next_key: &StorageEncryptionKey,
) -> Result<StorageEncryptionChangeReport, ContextError> {
    if current_key.key_id() == next_key.key_id() {
        return Err(storage_error(
            "storage-key rotation requires a distinct new key id",
        ));
    }
    if current_key.bytes.as_ref() == next_key.bytes.as_ref() {
        return Err(storage_error(
            "storage-key rotation requires distinct new key material",
        ));
    }
    let _lease = crate::storage::acquire_storage_lease(database_path)?;
    require_database_file(database_path)?;
    let connection = Connection::open(database_path).map_err(|error| {
        storage_error(format!(
            "failed to open encrypted database {}: {error}",
            database_path.display()
        ))
    })?;
    current_key.apply(&connection)?;
    let metadata = prepare_database_for_rekey(&connection)?;
    StorageEncryptionKey::rekey(&connection, next_key)?;
    drop(connection);
    sync_database_file(database_path)?;
    let verified = verify_database_with_key(database_path, next_key)?;
    if verified != metadata {
        return Err(storage_error(
            "encrypted database identity changed during key rotation",
        ));
    }
    if verify_database_with_key(database_path, current_key).is_ok() {
        return Err(storage_error(
            "database still accepts the retired storage key after rotation",
        ));
    }
    Ok(change_report(
        database_path,
        "rotate",
        Some(current_key.key_id()),
        next_key.key_id(),
        metadata,
    ))
}

fn prepare_database_for_rekey(
    connection: &Connection,
) -> Result<crate::schema::StorageMetadata, ContextError> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| storage_error(format!("failed to set rekey busy timeout: {error}")))?;
    crate::schema::verify(connection)?;
    let metadata = crate::schema::read_storage_metadata(connection)?;
    let (busy, _log_pages, _checkpointed_pages): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| storage_error(format!("failed to checkpoint database WAL: {error}")))?;
    if busy != 0 {
        return Err(storage_error(
            "database WAL is busy; stop all database users before changing encryption",
        ));
    }
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| storage_error(format!("failed to read journal mode: {error}")))?;
    if journal_mode.eq_ignore_ascii_case("wal") {
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .map_err(|error| {
                storage_error(format!("failed to disable WAL before rekey: {error}"))
            })?;
    }
    Ok(metadata)
}

fn verify_database_with_key(
    database_path: &Path,
    key: &StorageEncryptionKey,
) -> Result<crate::schema::StorageMetadata, ContextError> {
    let connection = Connection::open(database_path).map_err(|error| {
        storage_error(format!(
            "failed to reopen database {}: {error}",
            database_path.display()
        ))
    })?;
    key.apply(&connection)?;
    crate::schema::verify(&connection)?;
    crate::schema::read_storage_metadata(&connection)
}

fn change_report(
    database_path: &Path,
    operation: &str,
    previous_key_id: Option<&str>,
    current_key_id: &str,
    metadata: crate::schema::StorageMetadata,
) -> StorageEncryptionChangeReport {
    StorageEncryptionChangeReport {
        database_path: database_path.to_path_buf(),
        operation: operation.into(),
        previous_key_id: previous_key_id.map(str::to_owned),
        current_key_id: current_key_id.into(),
        application_id: metadata.application_id,
        schema_version: metadata.schema_version,
        installation_id: metadata.installation_id,
    }
}

impl EncryptionMigrationJournal {
    fn new(
        database_path: &Path,
        stage: &Path,
        rollback: &Path,
        current_key_id: &str,
        metadata: &crate::schema::StorageMetadata,
    ) -> Result<Self, ContextError> {
        Ok(Self {
            format_version: ENCRYPTION_MIGRATION_FORMAT_VERSION,
            database_file: migration_filename(database_path, "database")?,
            stage_file: migration_filename(stage, "encrypted stage")?,
            rollback_file: migration_filename(rollback, "plaintext rollback")?,
            current_key_id: current_key_id.to_owned(),
            application_id: metadata.application_id,
            schema_version: metadata.schema_version,
            min_reader_schema_version: metadata.min_reader_schema_version,
            installation_id: metadata.installation_id.clone(),
        })
    }

    fn storage_metadata(&self) -> crate::schema::StorageMetadata {
        crate::schema::StorageMetadata {
            application_id: self.application_id,
            schema_version: self.schema_version,
            min_reader_schema_version: self.min_reader_schema_version,
            installation_id: self.installation_id.clone(),
        }
    }
}

fn migration_filename(path: &Path, label: &str) -> Result<String, ContextError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| storage_error(format!("{label} path must have a non-empty UTF-8 filename")))
}

fn encryption_migration_journal_path(database_path: &Path) -> Result<PathBuf, ContextError> {
    let file_name = database_path
        .file_name()
        .ok_or_else(|| storage_error("database path has no filename"))?;
    let mut name = file_name.to_os_string();
    name.push(".encryption-migration.json");
    Ok(database_path.with_file_name(name))
}

fn write_encryption_migration_journal(
    path: &Path,
    journal: &EncryptionMigrationJournal,
) -> Result<(), ContextError> {
    let encoded = serde_json::to_vec_pretty(journal)
        .map_err(|error| storage_error(format!("failed to encode migration journal: {error}")))?;
    if encoded.len() as u64 > MAX_ENCRYPTION_MIGRATION_FILE_BYTES {
        return Err(storage_error(
            "encryption migration journal exceeds size limit",
        ));
    }
    let mut file = create_owner_only_new_file_for(path, "encryption migration journal")?;
    if let Err(error) = (|| {
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all()
    })() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(storage_error(format!(
            "failed to publish encryption migration journal {}: {error}",
            path.display()
        )));
    }
    sync_parent(path)
}

fn load_encryption_migration_journal(
    database_path: &Path,
    journal_path: &Path,
) -> Result<EncryptionMigrationJournal, ContextError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(journal_path).map_err(|error| {
        storage_error(format!(
            "failed to open encryption migration journal {}: {error}",
            journal_path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        storage_error(format!(
            "failed to inspect encryption migration journal {}: {error}",
            journal_path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(storage_error(
            "encryption migration journal must be a regular non-symlink file",
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_ENCRYPTION_MIGRATION_FILE_BYTES {
        return Err(storage_error(
            "encryption migration journal has an invalid size",
        ));
    }
    verify_owner_only(journal_path, &metadata)?;
    let mut encoded = Vec::with_capacity(metadata.len() as usize + 1);
    file.take(MAX_ENCRYPTION_MIGRATION_FILE_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| {
            storage_error(format!(
                "failed to read encryption migration journal {}: {error}",
                journal_path.display()
            ))
        })?;
    if encoded.len() as u64 > MAX_ENCRYPTION_MIGRATION_FILE_BYTES {
        return Err(storage_error(
            "encryption migration journal exceeds the size limit",
        ));
    }
    let journal: EncryptionMigrationJournal = serde_json::from_slice(&encoded)
        .map_err(|_| storage_error("encryption migration journal is not valid bounded JSON"))?;
    validate_encryption_migration_journal(database_path, journal_path, &journal)?;
    Ok(journal)
}

fn validate_encryption_migration_journal(
    database_path: &Path,
    journal_path: &Path,
    journal: &EncryptionMigrationJournal,
) -> Result<(), ContextError> {
    if journal.format_version != ENCRYPTION_MIGRATION_FORMAT_VERSION {
        return Err(storage_error(format!(
            "unsupported encryption migration journal version {}",
            journal.format_version
        )));
    }
    validate_key_id(&journal.current_key_id)?;
    if journal.database_file != migration_filename(database_path, "database")? {
        return Err(storage_error(
            "encryption migration journal targets a different database",
        ));
    }
    for (label, name) in [
        ("database", &journal.database_file),
        ("encrypted stage", &journal.stage_file),
        ("plaintext rollback", &journal.rollback_file),
    ] {
        if name.is_empty()
            || name.len() > 512
            || Path::new(name).file_name().and_then(|value| value.to_str()) != Some(name.as_str())
        {
            return Err(storage_error(format!(
                "encryption migration journal {label} filename is invalid"
            )));
        }
    }
    if journal.database_file == journal.stage_file
        || journal.database_file == journal.rollback_file
        || journal.stage_file == journal.rollback_file
        || migration_filename(journal_path, "journal")? == journal.stage_file
        || migration_filename(journal_path, "journal")? == journal.rollback_file
    {
        return Err(storage_error(
            "encryption migration journal contains overlapping file identities",
        ));
    }
    if uuid::Uuid::parse_str(&journal.installation_id).is_err() {
        return Err(storage_error(
            "encryption migration journal installation id is not a UUID",
        ));
    }
    Ok(())
}

fn regular_migration_file_exists(path: &Path, label: &str) -> Result<bool, ContextError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            storage_error(format!("{label} must be a regular non-symlink file")),
        ),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))),
    }
}

fn verify_plaintext_database(
    database_path: &Path,
) -> Result<crate::schema::StorageMetadata, ContextError> {
    require_database_file(database_path)?;
    let connection = Connection::open_with_flags(database_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| {
        storage_error(format!(
            "failed to open plaintext database {} read-only: {error}",
            database_path.display()
        ))
    })?;
    crate::schema::verify(&connection)?;
    crate::schema::read_storage_metadata(&connection)
}

fn require_matching_migration_identity(
    label: &str,
    actual: &crate::schema::StorageMetadata,
    expected: &crate::schema::StorageMetadata,
) -> Result<(), ContextError> {
    if actual != expected {
        return Err(storage_error(format!(
            "{label} does not match the journaled AIagentOS installation identity"
        )));
    }
    Ok(())
}

fn remove_completed_migration_journal(path: &Path) -> Result<(), ContextError> {
    fs::remove_file(path).map_err(|error| {
        storage_error(format!(
            "failed to remove completed encryption migration journal {}: {error}",
            path.display()
        ))
    })
}

fn recovery_report(
    database_path: &Path,
    outcome: &str,
    current_key_id: &str,
    metadata: crate::schema::StorageMetadata,
    plaintext_rollback_removed: bool,
) -> StorageEncryptionRecoveryReport {
    StorageEncryptionRecoveryReport {
        database_path: database_path.to_path_buf(),
        outcome: outcome.to_owned(),
        current_key_id: current_key_id.to_owned(),
        application_id: metadata.application_id,
        schema_version: metadata.schema_version,
        installation_id: metadata.installation_id,
        plaintext_rollback_removed,
    }
}

fn require_database_file(path: &Path) -> Result<(), ContextError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        storage_error(format!(
            "failed to inspect database {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(storage_error(
            "database path must be a regular file, not a symlink",
        ));
    }
    Ok(())
}

fn sync_database_file(path: &Path) -> Result<(), ContextError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            storage_error(format!(
                "failed to sync encrypted database {}: {error}",
                path.display()
            ))
        })?;
    sync_parent(path)
}

struct MigrationFile {
    path: PathBuf,
    armed: bool,
}

impl MigrationFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for MigrationFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
            let _ = sync_parent(&self.path);
        }
    }
}

fn migration_companion_path(
    database_path: &Path,
    label: &str,
    suffix: &str,
) -> Result<PathBuf, ContextError> {
    let file_name = database_path
        .file_name()
        .ok_or_else(|| storage_error("database path has no filename"))?;
    let mut name = file_name.to_os_string();
    name.push(format!(".{label}-{}.{suffix}", uuid::Uuid::new_v4()));
    Ok(database_path.with_file_name(name))
}

fn reject_existing_migration_path(path: &Path) -> Result<(), ContextError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(storage_error(format!(
            "encryption migration path already exists: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage_error(format!(
            "failed to inspect encryption migration path {}: {error}",
            path.display()
        ))),
    }
}

fn remove_migration_sidecar(database_path: &Path, suffix: &str) -> Result<(), ContextError> {
    let mut path = database_path.as_os_str().to_os_string();
    path.push(suffix);
    let path = PathBuf::from(path);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage_error(format!(
            "failed to remove checkpointed SQLite sidecar {}: {error}",
            path.display()
        ))),
    }
}

#[cfg(unix)]
fn set_owner_only_database(path: &Path) -> Result<(), ContextError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        storage_error(format!(
            "failed to protect encrypted database {}: {error}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_owner_only_database(_path: &Path) -> Result<(), ContextError> {
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), ContextError> {
    if key_id.is_empty()
        || key_id.len() > 96
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(storage_error(
            "storage key id must be 1-96 ASCII letters, digits, '-', '_' or '.'",
        ));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn create_owner_only_new_file(path: &Path) -> Result<File, ContextError> {
    create_owner_only_new_file_for(path, "storage key")
}

#[cfg(not(unix))]
fn create_owner_only_new_file(path: &Path) -> Result<File, ContextError> {
    create_owner_only_new_file_for(path, "storage key")
}

#[cfg(unix)]
fn create_owner_only_new_file_for(path: &Path, label: &str) -> Result<File, ContextError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            storage_error(format!(
                "failed to create {label} {} without overwrite: {error}",
                path.display()
            ))
        })
}

#[cfg(not(unix))]
fn create_owner_only_new_file_for(path: &Path, label: &str) -> Result<File, ContextError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            storage_error(format!(
                "failed to create {label} {} without overwrite: {error}",
                path.display()
            ))
        })
}

#[cfg(unix)]
fn verify_owner_only(path: &Path, metadata: &fs::Metadata) -> Result<(), ContextError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(storage_error(format!(
            "storage key {} must not grant group or other permissions",
            path.display()
        )));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(storage_error(format!(
            "storage key {} is not owned by the current user",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_owner_only(_path: &Path, _metadata: &fs::Metadata) -> Result<(), ContextError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), ContextError> {
    let parent = path
        .parent()
        .ok_or_else(|| storage_error("storage key path has no parent directory"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            storage_error(format!(
                "failed to sync storage key parent {}: {error}",
                parent.display()
            ))
        })
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), ContextError> {
    Ok(())
}

fn storage_error(message: impl Into<String>) -> ContextError {
    ContextError::StorageError(message.into())
}

#[cfg(test)]
fn abort_encryption_migration_after_rollback_for_test() {
    if std::env::var_os("AIAGENTOS_TEST_EXIT_ENCRYPT_AFTER_ROLLBACK").is_some() {
        std::process::exit(86);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "agentos-storage-encryption-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixed_key(key_id: &str, fill: u8) -> StorageEncryptionKey {
        StorageEncryptionKey::from_bytes(key_id, [fill; STORAGE_KEY_BYTES]).unwrap()
    }

    #[test]
    fn sqlcipher_is_bundled_and_key_debug_is_redacted() {
        let connection = Connection::open_in_memory().unwrap();
        let version: String = connection
            .pragma_query_value(None, "cipher_version", |row| row.get(0))
            .expect("SQLCipher cipher_version");
        assert!(!version.is_empty());
        let key = StorageEncryptionKey::generate("release-2026.1").unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("release-2026.1"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&hex_encode(key.bytes.as_ref())));
    }

    #[test]
    fn key_file_is_owner_only_bounded_non_overwriting_and_authenticates_database() {
        let root = TestDirectory::new();
        let key_path = root.0.join("storage-key.json");
        generate_storage_encryption_key_file("release-2026.1", &key_path).unwrap();
        assert!(generate_storage_encryption_key_file("other", &key_path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            assert_eq!(
                fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link_path = root.0.join("storage-key-link.json");
            symlink(&key_path, &link_path).unwrap();
            assert!(load_storage_encryption_key(&link_path).is_err());
        }
        let oversized_path = root.0.join("oversized-key.json");
        fs::write(
            &oversized_path,
            vec![b'x'; MAX_STORAGE_KEY_FILE_BYTES as usize + 1],
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&oversized_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(load_storage_encryption_key(&oversized_path).is_err());
        let key = load_storage_encryption_key(&key_path).unwrap();
        assert_eq!(key.key_id(), "release-2026.1");

        let database_path = root.0.join("encrypted.db");
        {
            let connection = Connection::open(&database_path).unwrap();
            key.apply(&connection).unwrap();
            connection
                .execute("CREATE TABLE secret(value TEXT NOT NULL)", [])
                .unwrap();
            connection
                .execute("INSERT INTO secret VALUES ('needle-secret')", [])
                .unwrap();
        }
        let raw = fs::read(&database_path).unwrap();
        assert!(!raw
            .windows(b"needle-secret".len())
            .any(|window| window == b"needle-secret"));
        assert!(Connection::open(&database_path)
            .unwrap()
            .query_row("SELECT value FROM secret", [], |_| Ok(()))
            .is_err());
        let reopened = Connection::open(&database_path).unwrap();
        key.apply(&reopened).unwrap();
        assert_eq!(
            reopened
                .query_row("SELECT value FROM secret", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "needle-secret"
        );
    }

    #[test]
    fn wrong_key_is_rejected_without_disclosing_key_material() {
        let root = TestDirectory::new();
        let database_path = root.0.join("encrypted.db");
        let first = StorageEncryptionKey::generate("first").unwrap();
        {
            let connection = Connection::open(&database_path).unwrap();
            first.apply(&connection).unwrap();
            connection.execute("CREATE TABLE t(x)", []).unwrap();
        }
        let wrong = StorageEncryptionKey::generate("wrong").unwrap();
        let connection = Connection::open(&database_path).unwrap();
        let error = wrong.apply(&connection).unwrap_err().to_string();
        assert!(error.contains("wrong"));
        assert!(!error.contains(&hex_encode(wrong.bytes.as_ref())));
    }

    #[test]
    fn offline_plaintext_migration_and_rotation_preserve_identity_and_fail_closed() {
        let root = TestDirectory::new();
        let database_path = root.0.join("agent_os.db");
        let secret = "migration-secret-that-must-survive-rotation";
        {
            let manager = crate::context::SqliteContextManager::new(&database_path).unwrap();
            manager
                .conn
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO agent_kv(agent_id, key, value, updated_at)
                     VALUES ('00000000-0000-0000-0000-000000000001',
                             'migration-proof', ?1, '2026-01-01T00:00:00Z')",
                    [secret],
                )
                .unwrap();
        }

        let first = fixed_key("storage-generation-1", 0x11);
        let migration = encrypt_existing_database(&database_path, &first).unwrap();
        assert_eq!(migration.operation, "encrypt");
        assert_eq!(migration.previous_key_id, None);
        assert_eq!(migration.current_key_id, "storage-generation-1");
        assert_eq!(migration.application_id, crate::schema::APPLICATION_ID);
        let encrypted_bytes = fs::read(&database_path).unwrap();
        assert!(!encrypted_bytes
            .windows(secret.len())
            .any(|window| window == secret.as_bytes()));
        assert!(Connection::open(&database_path)
            .unwrap()
            .query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))
            .is_err());

        {
            let manager = crate::context::SqliteContextManager::new_encrypted(
                &database_path,
                fixed_key("storage-generation-1", 0x11),
            )
            .unwrap();
            let locked_error = rotate_database_encryption_key(
                &database_path,
                &fixed_key("storage-generation-1", 0x11),
                &fixed_key("storage-generation-2", 0x22),
            )
            .unwrap_err()
            .to_string();
            assert!(locked_error.contains("already owned"), "{locked_error}");
            let persisted: String = manager
                .conn
                .lock()
                .unwrap()
                .query_row(
                    "SELECT value FROM agent_kv WHERE key = 'migration-proof'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(persisted, secret);
        }

        let before_wrong_key = fs::read(&database_path).unwrap();
        let duplicate_material_error = rotate_database_encryption_key(
            &database_path,
            &fixed_key("storage-generation-1", 0x11),
            &fixed_key("storage-generation-alias", 0x11),
        )
        .unwrap_err()
        .to_string();
        assert!(
            duplicate_material_error.contains("distinct new key material"),
            "{duplicate_material_error}"
        );
        assert_eq!(fs::read(&database_path).unwrap(), before_wrong_key);

        let wrong_error = rotate_database_encryption_key(
            &database_path,
            &fixed_key("storage-generation-wrong", 0x33),
            &fixed_key("storage-generation-2", 0x22),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_error.contains("cannot authenticate"), "{wrong_error}");
        assert_eq!(fs::read(&database_path).unwrap(), before_wrong_key);

        let rotation = rotate_database_encryption_key(
            &database_path,
            &fixed_key("storage-generation-1", 0x11),
            &fixed_key("storage-generation-2", 0x22),
        )
        .unwrap();
        assert_eq!(
            rotation.previous_key_id.as_deref(),
            Some("storage-generation-1")
        );
        assert_eq!(rotation.current_key_id, "storage-generation-2");
        assert!(
            verify_database_with_key(&database_path, &fixed_key("storage-generation-1", 0x11))
                .is_err()
        );
        let manager = crate::context::SqliteContextManager::new_encrypted(
            &database_path,
            fixed_key("storage-generation-2", 0x22),
        )
        .unwrap();
        let persisted: String = manager
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM agent_kv WHERE key = 'migration-proof'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, secret);
    }

    #[test]
    fn interrupted_process_migration_is_recovered_without_data_loss_or_plaintext_residue() {
        let root = TestDirectory::new();
        let database_path = root.0.join("agent_os.db");
        let secret = "crash-recovery-secret";
        {
            let manager = crate::context::SqliteContextManager::new(&database_path).unwrap();
            manager
                .conn
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO agent_kv(agent_id, key, value, updated_at)
                     VALUES ('00000000-0000-0000-0000-000000000001',
                             'crash-proof', ?1, '2026-01-01T00:00:00Z')",
                    [secret],
                )
                .unwrap();
        }

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--ignored")
            .arg("encryption_migration_process_exit_helper")
            .env("AIAGENTOS_TEST_EXIT_ENCRYPT_AFTER_ROLLBACK", "1")
            .env("AIAGENTOS_TEST_ENCRYPT_DATABASE", &database_path)
            .status()
            .unwrap();
        assert_eq!(child.code(), Some(86));
        assert!(!database_path.exists());
        assert!(encryption_migration_journal_path(&database_path)
            .unwrap()
            .exists());

        let journal_path = encryption_migration_journal_path(&database_path).unwrap();
        let journal = load_encryption_migration_journal(&database_path, &journal_path).unwrap();
        let stage_path = root.0.join(&journal.stage_file);
        let rollback_path = root.0.join(&journal.rollback_file);
        let before_wrong_key = (
            fs::read(&journal_path).unwrap(),
            fs::read(&stage_path).unwrap(),
            fs::read(&rollback_path).unwrap(),
        );
        let wrong_id_error = recover_interrupted_encryption_migration(
            &database_path,
            &fixed_key("wrong-key-id", 0x44),
        )
        .unwrap_err()
        .to_string();
        assert!(
            wrong_id_error.contains("requires key id"),
            "{wrong_id_error}"
        );
        let wrong_material_error = recover_interrupted_encryption_migration(
            &database_path,
            &fixed_key("crash-recovery-key", 0x45),
        )
        .unwrap_err()
        .to_string();
        assert!(
            wrong_material_error.contains("cannot be authenticated"),
            "{wrong_material_error}"
        );
        assert_eq!(fs::read(&journal_path).unwrap(), before_wrong_key.0);
        assert_eq!(fs::read(&stage_path).unwrap(), before_wrong_key.1);
        assert_eq!(fs::read(&rollback_path).unwrap(), before_wrong_key.2);
        assert!(!database_path.exists());

        let mut foreign_identity = journal.clone();
        foreign_identity.installation_id = uuid::Uuid::new_v4().to_string();
        fs::write(
            &journal_path,
            serde_json::to_vec_pretty(&foreign_identity).unwrap(),
        )
        .unwrap();
        let identity_error = recover_interrupted_encryption_migration(
            &database_path,
            &fixed_key("crash-recovery-key", 0x44),
        )
        .unwrap_err()
        .to_string();
        assert!(
            identity_error.contains("does not match the journaled"),
            "{identity_error}"
        );
        assert_eq!(fs::read(&stage_path).unwrap(), before_wrong_key.1);
        assert_eq!(fs::read(&rollback_path).unwrap(), before_wrong_key.2);
        assert!(!database_path.exists());
        fs::write(&journal_path, &before_wrong_key.0).unwrap();

        let key = fixed_key("crash-recovery-key", 0x44);
        let report = recover_interrupted_encryption_migration(&database_path, &key).unwrap();
        assert_eq!(report.outcome, "completed-encryption");
        assert!(report.plaintext_rollback_removed);
        assert!(!encryption_migration_journal_path(&database_path)
            .unwrap()
            .exists());
        let entries = fs::read_dir(&root.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            !entries.iter().any(|name| {
                name.contains(".plaintext-")
                    || name.contains(".encrypted-")
                    || name.ends_with(".encryption-migration.json")
            }),
            "{entries:?}"
        );
        let connection = Connection::open(&database_path).unwrap();
        key.apply(&connection).unwrap();
        let persisted: String = connection
            .query_row(
                "SELECT value FROM agent_kv WHERE key = 'crash-proof'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, secret);
        let raw = fs::read(&database_path).unwrap();
        assert!(!raw
            .windows(secret.len())
            .any(|window| window == secret.as_bytes()));
    }

    #[test]
    #[ignore = "child-process helper for interrupted migration regression"]
    fn encryption_migration_process_exit_helper() {
        let Some(database_path) = std::env::var_os("AIAGENTOS_TEST_ENCRYPT_DATABASE") else {
            return;
        };
        let key = fixed_key("crash-recovery-key", 0x44);
        let _ = encrypt_existing_database(Path::new(&database_path), &key);
        panic!("migration test helper did not terminate at the injected process-exit point");
    }

    #[test]
    fn inventory_type_remains_available_with_encrypted_sqlite_linkage() {
        let inventory: crate::data_inventory::StorageDataInventory =
            crate::data_inventory::storage_data_inventory();
        assert!(!inventory.entries.is_empty());
    }
}
