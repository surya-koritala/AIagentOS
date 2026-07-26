//! Consistent backup, verification, and offline restore for kernel-owned state.
//!
//! Backups use SQLite's online backup API, never a raw copy of a live WAL
//! database. Restore is deliberately offline: a process-lifetime lock held by
//! every file-backed kernel (or standalone [`SqliteContextManager`]) prevents
//! replacement while it is running.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use ring::digest::{Context as DigestContext, SHA256};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::context::SqliteContextManager;
use crate::ContextError;

const BACKUP_FORMAT_VERSION: u32 = 1;
const BACKUP_DATABASE_FILE: &str = "agent_os.db";
const BACKUP_DATABASE_SHM_FILE: &str = "agent_os.db-shm";
const BACKUP_DATABASE_WAL_FILE: &str = "agent_os.db-wal";
const BACKUP_MANIFEST_FILE: &str = "manifest.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_BACKUP_ROOT_ENTRIES: usize = 10_000;

/// Integrity and compatibility metadata published beside a SQLite snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub format_version: u32,
    pub database_file: String,
    pub application_id: i64,
    pub schema_version: i64,
    pub installation_id: String,
    pub created_at: String,
    pub byte_count: u64,
    pub sha256: String,
}

/// Result of an offline restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    pub manifest: BackupManifest,
    pub replaced_existing: bool,
    /// `true` only when the replacement is valid but removal of the obsolete
    /// rollback file could not be made durable. Operators may safely remove any
    /// retained rollback file while offline.
    pub rollback_retained: bool,
}

/// Bounded policy for expiring verified backups from one installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRetentionPolicy {
    /// Always preserve at least this many newest verified backups.
    pub keep_latest: usize,
    /// Backups younger than this age are preserved even when they exceed
    /// `keep_latest`.
    pub max_age_seconds: u64,
}

/// One verified backup considered by a retention run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRetentionEntry {
    pub name: String,
    pub created_at: String,
    pub byte_count: u64,
}

/// A root entry that retention deliberately left untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRetentionIssue {
    pub name: String,
    pub reason: String,
}

/// Auditable result of a dry-run or confirmed retention pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRetentionReport {
    pub evaluated_at: String,
    pub dry_run: bool,
    pub policy: BackupRetentionPolicy,
    /// Old verified backups selected by the policy. In dry-run mode these are
    /// the backups that would be deleted.
    pub eligible: Vec<BackupRetentionEntry>,
    /// Successfully deleted backups. Empty in dry-run mode.
    pub deleted: Vec<BackupRetentionEntry>,
    /// Verified current-installation backups preserved by the policy.
    pub retained: Vec<BackupRetentionEntry>,
    /// Unknown, unsafe, corrupt, or foreign-installation entries.
    pub skipped: Vec<BackupRetentionIssue>,
}

fn storage_error(message: impl Into<String>) -> ContextError {
    ContextError::StorageError(message.into())
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

struct StagingFile {
    path: PathBuf,
    armed: bool,
}

impl StagingFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct StagingDirectory {
    path: PathBuf,
    armed: bool,
}

impl StagingDirectory {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn acquire_storage_lease(database_path: &Path) -> Result<File, ContextError> {
    let lock_path = companion_path(database_path, ".lock");
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| {
            storage_error(format!(
                "failed to open storage lease {}: {error}",
                lock_path.display()
            ))
        })?;
    set_owner_only_file(&lock_path)?;
    lock.try_lock().map_err(|error| {
        storage_error(format!(
            "database {} is already owned by a running kernel or restore: {error}",
            database_path.display()
        ))
    })?;
    Ok(lock)
}

fn validate_backup_name(name: &str) -> Result<(), ContextError> {
    if name.is_empty()
        || name.len() > 96
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(storage_error(
            "backup name must be 1-96 ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(())
}

fn prepare_backup_root(root: &Path) -> Result<(), ContextError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(storage_error(format!(
                    "backup root {} must be a real directory, not a symlink",
                    root.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root).map_err(|error| {
                storage_error(format!(
                    "failed to create backup root {}: {error}",
                    root.display()
                ))
            })?;
        }
        Err(error) => {
            return Err(storage_error(format!(
                "failed to inspect backup root {}: {error}",
                root.display()
            )));
        }
    }
    set_owner_only_directory(root)
}

fn acquire_backup_publication_lock(root: &Path) -> Result<File, ContextError> {
    let publication_lock_path = root.join(".agentos-backup.lock");
    match fs::symlink_metadata(&publication_lock_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(storage_error(
                "backup publication lock must be a regular file, not a symlink",
            ))
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(storage_error(format!(
                "failed to inspect backup publication lock: {error}"
            )))
        }
    }
    let publication_lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&publication_lock_path)
        .map_err(|error| {
            storage_error(format!("failed to open backup publication lock: {error}"))
        })?;
    let metadata = fs::symlink_metadata(&publication_lock_path).map_err(|error| {
        storage_error(format!(
            "failed to inspect opened backup publication lock: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(storage_error(
            "backup publication lock must be a regular file, not a symlink",
        ));
    }
    set_owner_only_file(&publication_lock_path)?;
    publication_lock.try_lock().map_err(|error| {
        storage_error(format!(
            "another backup publication or retention pass is active: {error}"
        ))
    })?;
    Ok(publication_lock)
}

fn reject_existing_path(path: &Path, label: &str) -> Result<(), ContextError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(storage_error(format!(
            "{label} {} already exists",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))),
    }
}

fn require_regular_file(path: &Path, label: &str) -> Result<u64, ContextError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        storage_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(storage_error(format!(
            "{label} {} must be a regular file, not a symlink",
            path.display()
        )));
    }
    Ok(metadata.len())
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), ContextError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        storage_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(storage_error(format!(
            "{label} {} must be a real directory, not a symlink",
            path.display()
        )));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, ContextError> {
    let mut file = File::open(path)
        .map_err(|error| storage_error(format!("failed to hash {}: {error}", path.display())))?;
    let mut digest = DigestContext::new(&SHA256);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            storage_error(format!("failed to hash {}: {error}", path.display()))
        })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn open_verified_database(
    path: &Path,
) -> Result<(Connection, crate::schema::StorageMetadata), ContextError> {
    require_regular_file(path, "backup database")?;
    let connection =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|error| {
            storage_error(format!(
                "failed to open {} read-only: {error}",
                path.display()
            ))
        })?;
    crate::schema::verify(&connection)?;
    let metadata = crate::schema::read_storage_metadata(&connection)?;
    Ok((connection, metadata))
}

fn write_manifest(path: &Path, manifest: &BackupManifest) -> Result<(), ContextError> {
    let mut bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|error| storage_error(format!("failed to serialize backup manifest: {error}")))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            storage_error(format!(
                "failed to create backup manifest {}: {error}",
                path.display()
            ))
        })?;
    set_owner_only_file(path)?;
    file.write_all(&bytes).map_err(|error| {
        storage_error(format!(
            "failed to write backup manifest {}: {error}",
            path.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        storage_error(format!(
            "failed to sync backup manifest {}: {error}",
            path.display()
        ))
    })
}

fn read_manifest(path: &Path) -> Result<BackupManifest, ContextError> {
    let size = require_regular_file(path, "backup manifest")?;
    if size > MAX_MANIFEST_BYTES {
        return Err(storage_error(format!(
            "backup manifest {} exceeds {MAX_MANIFEST_BYTES} bytes",
            path.display()
        )));
    }
    let file = File::open(path).map_err(|error| {
        storage_error(format!(
            "failed to open backup manifest {}: {error}",
            path.display()
        ))
    })?;
    serde_json::from_reader(file).map_err(|error| {
        storage_error(format!(
            "failed to parse backup manifest {}: {error}",
            path.display()
        ))
    })
}

/// Verify manifest integrity, the complete database hash, physical SQLite
/// integrity, schema compatibility, foreign keys, and installation identity.
pub fn verify_backup(backup_dir: &Path) -> Result<BackupManifest, ContextError> {
    require_real_directory(backup_dir, "backup")?;
    let manifest_path = backup_dir.join(BACKUP_MANIFEST_FILE);
    let manifest = read_manifest(&manifest_path)?;
    if manifest.format_version != BACKUP_FORMAT_VERSION {
        return Err(storage_error(format!(
            "unsupported backup format version {}, expected {BACKUP_FORMAT_VERSION}",
            manifest.format_version
        )));
    }
    if manifest.database_file != BACKUP_DATABASE_FILE {
        return Err(storage_error(format!(
            "backup database filename {:?} is not supported",
            manifest.database_file
        )));
    }
    if uuid::Uuid::parse_str(&manifest.installation_id).is_err() {
        return Err(storage_error("backup installation id is not a UUID"));
    }
    chrono::DateTime::parse_from_rfc3339(&manifest.created_at)
        .map_err(|error| storage_error(format!("backup creation timestamp is invalid: {error}")))?;

    let database_path = backup_dir.join(BACKUP_DATABASE_FILE);
    let byte_count = require_regular_file(&database_path, "backup database")?;
    if byte_count != manifest.byte_count {
        return Err(storage_error(format!(
            "backup byte count mismatch: manifest={}, actual={byte_count}",
            manifest.byte_count
        )));
    }
    let hash = sha256_file(&database_path)?;
    if hash != manifest.sha256 {
        return Err(storage_error("backup SHA-256 mismatch"));
    }

    let (_connection, metadata) = open_verified_database(&database_path)?;
    if manifest.application_id != metadata.application_id
        || manifest.schema_version != metadata.schema_version
        || manifest.installation_id != metadata.installation_id
    {
        return Err(storage_error(
            "backup manifest identity does not match the SQLite storage metadata",
        ));
    }
    Ok(manifest)
}

fn validate_retention_policy(policy: &BackupRetentionPolicy) -> Result<(), ContextError> {
    if policy.keep_latest == 0 {
        return Err(storage_error(
            "backup retention must keep at least one verified backup",
        ));
    }
    if policy.max_age_seconds == 0 {
        return Err(storage_error(
            "backup retention max_age_seconds must be greater than zero",
        ));
    }
    Ok(())
}

fn bounded_entry_name(entry: &fs::DirEntry) -> String {
    let name = entry.file_name().to_string_lossy().into_owned();
    if name.len() <= 128 {
        name
    } else {
        format!("{}…", name.chars().take(128).collect::<String>())
    }
}

fn require_removable_backup_contents(backup_dir: &Path) -> Result<(), ContextError> {
    let mut found_database = false;
    let mut found_manifest = false;
    for entry in fs::read_dir(backup_dir).map_err(|error| {
        storage_error(format!(
            "failed to enumerate backup {}: {error}",
            backup_dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            storage_error(format!(
                "failed to enumerate backup {}: {error}",
                backup_dir.display()
            ))
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            storage_error(format!(
                "failed to inspect backup entry {}: {error}",
                entry.path().display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(storage_error(
                "backup contains a non-regular file and cannot be expired automatically",
            ));
        }
        match entry.file_name().to_str() {
            Some(BACKUP_DATABASE_FILE) => found_database = true,
            // SQLite may leave an empty shared-memory index after read-only
            // verification of a WAL-mode database. It is a known sidecar, not
            // user-controlled backup content.
            Some(BACKUP_DATABASE_SHM_FILE) => {}
            Some(BACKUP_DATABASE_WAL_FILE) if metadata.len() == 0 => {}
            Some(BACKUP_DATABASE_WAL_FILE) => {
                return Err(storage_error(
                    "backup has a non-empty WAL and cannot be expired automatically",
                ))
            }
            Some(BACKUP_MANIFEST_FILE) => found_manifest = true,
            _ => {
                return Err(storage_error(format!(
                    "backup contains unexpected entry {:?} and cannot be expired automatically",
                    entry.file_name()
                )))
            }
        }
    }
    if !found_database || !found_manifest {
        return Err(storage_error(
            "backup is incomplete and cannot be expired automatically",
        ));
    }
    Ok(())
}

fn delete_verified_backup(
    backup_root: &Path,
    entry: &BackupRetentionEntry,
    expected_manifest: &BackupManifest,
) -> Result<(), ContextError> {
    validate_backup_name(&entry.name)?;
    let backup_dir = backup_root.join(&entry.name);
    require_real_directory(&backup_dir, "backup selected for expiration")?;
    require_removable_backup_contents(&backup_dir)?;
    let tombstone = backup_root.join(format!(".{}.{}.deleting", entry.name, uuid::Uuid::new_v4()));
    reject_existing_path(&tombstone, "backup deletion staging directory")?;
    fs::rename(&backup_dir, &tombstone).map_err(|error| {
        storage_error(format!(
            "failed to stage backup {} for expiration: {error}",
            backup_dir.display()
        ))
    })?;
    sync_directory(backup_root)?;
    require_real_directory(&tombstone, "staged backup selected for expiration")?;
    let staged_manifest = verify_backup(&tombstone)?;
    if &staged_manifest != expected_manifest {
        return Err(storage_error(format!(
            "backup {} changed before expiration; deletion staging requires operator inspection at {}",
            entry.name,
            tombstone.display()
        )));
    }
    require_removable_backup_contents(&tombstone)?;

    let deletion = (|| {
        fs::remove_file(tombstone.join(BACKUP_DATABASE_FILE)).map_err(|error| {
            storage_error(format!(
                "failed to remove expired backup database {}: {error}",
                entry.name
            ))
        })?;
        remove_if_exists(&tombstone.join(BACKUP_DATABASE_SHM_FILE))?;
        remove_if_exists(&tombstone.join(BACKUP_DATABASE_WAL_FILE))?;
        fs::remove_file(tombstone.join(BACKUP_MANIFEST_FILE)).map_err(|error| {
            storage_error(format!(
                "failed to remove expired backup manifest {}: {error}",
                entry.name
            ))
        })?;
        fs::remove_dir(&tombstone).map_err(|error| {
            storage_error(format!(
                "failed to remove expired backup directory {}: {error}",
                entry.name
            ))
        })?;
        sync_directory(backup_root)
    })();
    if let Err(error) = deletion {
        return Err(storage_error(format!(
            "{error}; deletion staging may require offline operator cleanup at {}",
            tombstone.display()
        )));
    }
    Ok(())
}

impl SqliteContextManager {
    /// Create and atomically publish a WAL-consistent online SQLite backup.
    pub fn create_backup(
        &self,
        backup_root: &Path,
        name: &str,
    ) -> Result<BackupManifest, ContextError> {
        validate_backup_name(name)?;
        prepare_backup_root(backup_root)?;
        let _publication_lock = acquire_backup_publication_lock(backup_root)?;

        let final_dir = backup_root.join(name);
        reject_existing_path(&final_dir, "backup destination")?;
        let staging_dir = backup_root.join(format!(".{name}.{}.staging", uuid::Uuid::new_v4()));
        fs::create_dir(&staging_dir).map_err(|error| {
            storage_error(format!(
                "failed to create backup staging directory {}: {error}",
                staging_dir.display()
            ))
        })?;
        let mut staging_guard = StagingDirectory::new(staging_dir.clone());
        set_owner_only_directory(&staging_dir)?;

        let manifest = (|| {
            let database_path = staging_dir.join(BACKUP_DATABASE_FILE);
            {
                let connection = self
                    .conn
                    .lock()
                    .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
                let mut destination = Connection::open(&database_path).map_err(|error| {
                    storage_error(format!("failed to create backup database: {error}"))
                })?;
                let backup = rusqlite::backup::Backup::new(&connection, &mut destination).map_err(
                    |error| storage_error(format!("failed to initialize SQLite backup: {error}")),
                )?;
                backup
                    .run_to_completion(64, Duration::from_millis(2), None)
                    .map_err(|error| {
                        storage_error(format!("SQLite online backup failed: {error}"))
                    })?;
            }
            set_owner_only_file(&database_path)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&database_path)
                .and_then(|file| file.sync_all())
                .map_err(|error| {
                    storage_error(format!(
                        "failed to sync backup database {}: {error}",
                        database_path.display()
                    ))
                })?;

            let (verified, metadata) = open_verified_database(&database_path)?;
            // Windows does not allow the staging directory to be renamed while
            // this read-only SQLite handle remains open.
            drop(verified);
            let byte_count = require_regular_file(&database_path, "backup database")?;
            let manifest = BackupManifest {
                format_version: BACKUP_FORMAT_VERSION,
                database_file: BACKUP_DATABASE_FILE.to_string(),
                application_id: metadata.application_id,
                schema_version: metadata.schema_version,
                installation_id: metadata.installation_id,
                created_at: Utc::now().to_rfc3339(),
                byte_count,
                sha256: sha256_file(&database_path)?,
            };
            write_manifest(&staging_dir.join(BACKUP_MANIFEST_FILE), &manifest)?;
            sync_directory(&staging_dir)?;
            #[cfg(test)]
            if name == "inject_failure_before_publish" {
                return Err(storage_error("injected backup failure before publication"));
            }

            reject_existing_path(&final_dir, "backup destination")?;
            fs::rename(&staging_dir, &final_dir).map_err(|error| {
                storage_error(format!(
                    "failed to publish backup {}: {error}",
                    final_dir.display()
                ))
            })?;
            if let Err(error) = sync_directory(backup_root) {
                fs::rename(&final_dir, &staging_dir).map_err(|rollback_error| {
                    storage_error(format!(
                        "backup publication was not durable ({error}); reverting it also failed: \
                         {rollback_error}"
                    ))
                })?;
                return Err(error);
            }
            Ok(manifest)
        })()?;
        staging_guard.disarm();
        Ok(manifest)
    }

    /// Preview or enforce a bounded retention policy over verified backups.
    ///
    /// Only backups belonging to this manager's installation are considered.
    /// Unknown entries, symlinks, corrupt backups, foreign-installation
    /// backups, and directories with extra content are never deleted.
    pub fn apply_backup_retention(
        &self,
        backup_root: &Path,
        policy: BackupRetentionPolicy,
        dry_run: bool,
    ) -> Result<BackupRetentionReport, ContextError> {
        validate_retention_policy(&policy)?;
        require_real_directory(backup_root, "backup root")?;
        let _publication_lock = acquire_backup_publication_lock(backup_root)?;
        let installation_id = {
            let connection = self
                .conn
                .lock()
                .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
            crate::schema::read_storage_metadata(&connection)?.installation_id
        };
        let evaluated_at = Utc::now();
        let mut verified = Vec::new();
        let mut skipped = Vec::new();
        let mut scanned = 0_usize;

        for entry in fs::read_dir(backup_root).map_err(|error| {
            storage_error(format!(
                "failed to enumerate backup root {}: {error}",
                backup_root.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                storage_error(format!(
                    "failed to enumerate backup root {}: {error}",
                    backup_root.display()
                ))
            })?;
            scanned += 1;
            if scanned > MAX_BACKUP_ROOT_ENTRIES {
                return Err(storage_error(format!(
                    "backup root exceeds the scan limit of {MAX_BACKUP_ROOT_ENTRIES} entries"
                )));
            }
            let name = bounded_entry_name(&entry);
            if name == ".agentos-backup.lock"
                || name.starts_with('.')
                || validate_backup_name(&name).is_err()
            {
                continue;
            }
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) => {
                    skipped.push(BackupRetentionIssue {
                        name,
                        reason: format!("could not inspect entry: {error}"),
                    });
                    continue;
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                skipped.push(BackupRetentionIssue {
                    name,
                    reason: "not a real backup directory".into(),
                });
                continue;
            }
            let manifest = match verify_backup(&entry.path()) {
                Ok(manifest) => manifest,
                Err(error) => {
                    skipped.push(BackupRetentionIssue {
                        name,
                        reason: format!("verification failed: {error}"),
                    });
                    continue;
                }
            };
            if manifest.installation_id != installation_id {
                skipped.push(BackupRetentionIssue {
                    name,
                    reason: "belongs to a different installation".into(),
                });
                continue;
            }
            if let Err(error) = require_removable_backup_contents(&entry.path()) {
                skipped.push(BackupRetentionIssue {
                    name,
                    reason: error.to_string(),
                });
                continue;
            }
            let created_at = match chrono::DateTime::parse_from_rfc3339(&manifest.created_at) {
                Ok(created_at) => created_at.with_timezone(&Utc),
                Err(error) => {
                    skipped.push(BackupRetentionIssue {
                        name,
                        reason: format!("invalid creation timestamp: {error}"),
                    });
                    continue;
                }
            };
            if created_at > evaluated_at {
                skipped.push(BackupRetentionIssue {
                    name,
                    reason: "creation timestamp is in the future".into(),
                });
                continue;
            }
            verified.push((
                created_at,
                BackupRetentionEntry {
                    name,
                    created_at: manifest.created_at.clone(),
                    byte_count: manifest.byte_count,
                },
                manifest,
            ));
        }

        verified.sort_by(|(left_time, left, _), (right_time, right, _)| {
            right_time
                .cmp(left_time)
                .then_with(|| right.name.cmp(&left.name))
        });
        let max_age_seconds = i64::try_from(policy.max_age_seconds).unwrap_or(i64::MAX);
        let mut eligible = Vec::new();
        let mut eligible_manifests = Vec::new();
        let mut retained = Vec::new();
        for (index, (created_at, entry, manifest)) in verified.into_iter().enumerate() {
            let age_seconds = evaluated_at.signed_duration_since(created_at).num_seconds();
            if index >= policy.keep_latest && age_seconds >= max_age_seconds {
                eligible.push(entry);
                eligible_manifests.push(manifest);
            } else {
                retained.push(entry);
            }
        }

        let mut deleted = Vec::new();
        if !dry_run {
            for (entry, manifest) in eligible.iter().zip(&eligible_manifests) {
                delete_verified_backup(backup_root, entry, manifest)?;
                deleted.push(entry.clone());
            }
        }
        Ok(BackupRetentionReport {
            evaluated_at: evaluated_at.to_rfc3339(),
            dry_run,
            policy,
            eligible,
            deleted,
            retained,
            skipped,
        })
    }
}

fn checkpoint_existing_database(path: &Path) -> Result<(), ContextError> {
    require_regular_file(path, "restore destination database")?;
    let connection = Connection::open(path).map_err(|error| {
        storage_error(format!(
            "failed to open restore destination {}: {error}",
            path.display()
        ))
    })?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| storage_error(format!("failed to set restore busy timeout: {error}")))?;
    crate::schema::verify(&connection)?;
    let (busy, _log_pages, _checkpointed_pages): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| {
            storage_error(format!("failed to checkpoint restore destination: {error}"))
        })?;
    if busy != 0 {
        return Err(storage_error(
            "restore destination WAL is busy; stop all database users before restore",
        ));
    }
    drop(connection);
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            storage_error(format!(
                "failed to sync restore destination {}: {error}",
                path.display()
            ))
        })
}

fn copy_to_new_file(source: &Path, destination: &Path) -> Result<(), ContextError> {
    let mut source_file = File::open(source).map_err(|error| {
        storage_error(format!(
            "failed to open backup database {}: {error}",
            source.display()
        ))
    })?;
    let mut destination_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| {
            storage_error(format!(
                "failed to create restore staging file {}: {error}",
                destination.display()
            ))
        })?;
    set_owner_only_file(destination)?;
    std::io::copy(&mut source_file, &mut destination_file).map_err(|error| {
        storage_error(format!(
            "failed to copy backup into restore staging file: {error}"
        ))
    })?;
    destination_file.sync_all().map_err(|error| {
        storage_error(format!(
            "failed to sync restore staging file {}: {error}",
            destination.display()
        ))
    })
}

fn remove_if_exists(path: &Path) -> Result<(), ContextError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage_error(format!(
            "failed to remove stale SQLite sidecar {}: {error}",
            path.display()
        ))),
    }
}

/// Restore a verified backup while no kernel owns `destination_database`.
///
/// The verified snapshot is copied to a same-directory staging file, synced,
/// verified again, and atomically renamed. An existing database is checkpointed
/// and retained as a rollback file until the replacement passes verification.
pub fn restore_backup(
    backup_dir: &Path,
    destination_database: &Path,
) -> Result<RestoreReport, ContextError> {
    let manifest = verify_backup(backup_dir)?;
    let parent = destination_database
        .parent()
        .ok_or_else(|| storage_error("restore destination must have a parent directory"))?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(storage_error(format!(
                    "restore destination parent {} must be a real directory",
                    parent.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(parent).map_err(|error| {
                storage_error(format!(
                    "failed to create restore destination directory {}: {error}",
                    parent.display()
                ))
            })?;
            set_owner_only_directory(parent)?;
        }
        Err(error) => {
            return Err(storage_error(format!(
                "failed to inspect restore destination directory {}: {error}",
                parent.display()
            )));
        }
    }
    let _lease = acquire_storage_lease(destination_database)?;

    let stage = companion_path(
        destination_database,
        &format!(".restore-{}.staging", uuid::Uuid::new_v4()),
    );
    reject_existing_path(&stage, "restore staging file")?;
    let mut stage_guard = StagingFile::new(stage.clone());
    copy_to_new_file(&backup_dir.join(BACKUP_DATABASE_FILE), &stage)?;
    let stage_result = (|| {
        let (_connection, metadata) = open_verified_database(&stage)?;
        if metadata.installation_id != manifest.installation_id {
            return Err(storage_error(
                "restore staging database installation identity changed during copy",
            ));
        }
        if sha256_file(&stage)? != manifest.sha256 {
            return Err(storage_error(
                "restore staging database SHA-256 changed during copy",
            ));
        }
        Ok(())
    })();
    stage_result?;

    let replaced_existing = destination_database.exists();
    let rollback = companion_path(
        destination_database,
        &format!(".rollback-{}", uuid::Uuid::new_v4()),
    );
    if replaced_existing {
        checkpoint_existing_database(destination_database)?;
        reject_existing_path(&rollback, "restore rollback file")?;
        fs::rename(destination_database, &rollback).map_err(|error| {
            storage_error(format!(
                "failed to preserve restore rollback database {}: {error}",
                rollback.display()
            ))
        })?;
    }

    let publish_result = (|| {
        if replaced_existing {
            remove_if_exists(&companion_path(destination_database, "-wal"))?;
            remove_if_exists(&companion_path(destination_database, "-shm"))?;
        }
        fs::rename(&stage, destination_database).map_err(|error| {
            storage_error(format!(
                "failed to publish restored database {}: {error}",
                destination_database.display()
            ))
        })?;
        stage_guard.disarm();
        #[cfg(test)]
        if destination_database
            .file_name()
            .and_then(|name| name.to_str())
            == Some("inject-failure.db")
        {
            return Err(storage_error("injected failure after restore publication"));
        }
        sync_directory(parent)?;
        let (_connection, metadata) = open_verified_database(destination_database)?;
        if metadata.installation_id != manifest.installation_id
            || sha256_file(destination_database)? != manifest.sha256
        {
            return Err(storage_error(
                "published restore does not match the verified backup",
            ));
        }
        Ok(())
    })();

    if let Err(error) = publish_result {
        remove_if_exists(destination_database).map_err(|cleanup_error| {
            storage_error(format!(
                "restore failed ({error}); failed replacement cleanup also failed: {cleanup_error}"
            ))
        })?;
        if replaced_existing {
            fs::rename(&rollback, destination_database).map_err(|rollback_error| {
                storage_error(format!(
                    "restore failed ({error}); automatic rollback also failed: {rollback_error}"
                ))
            })?;
            let _ = open_verified_database(destination_database)?;
        }
        sync_directory(parent)?;
        return Err(error);
    }

    let rollback_retained = if replaced_existing {
        match fs::remove_file(&rollback) {
            Ok(()) => sync_directory(parent).is_err(),
            Err(_) => true,
        }
    } else {
        false
    };
    Ok(RestoreReport {
        manifest,
        replaced_existing,
        rollback_retained,
    })
}

#[cfg(unix)]
fn set_owner_only_file(path: &Path) -> Result<(), ContextError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        storage_error(format!(
            "failed to set owner-only permissions on {}: {error}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_owner_only_file(_path: &Path) -> Result<(), ContextError> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_directory(path: &Path) -> Result<(), ContextError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        storage_error(format!(
            "failed to set owner-only permissions on {}: {error}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_owner_only_directory(_path: &Path) -> Result<(), ContextError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ContextError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            storage_error(format!(
                "failed to sync directory {}: {error}",
                path.display()
            ))
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ContextError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::OptionalExtension;
    use std::io::{Seek, SeekFrom};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Arc;

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aiagentos-storage-{label}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn seed(manager: &SqliteContextManager, key: &str, value: &str) {
        manager
            .conn
            .lock()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO agent_kv(agent_id, key, value, updated_at)
                 VALUES ('00000000-0000-0000-0000-000000000001', ?1, ?2, ?3)",
                rusqlite::params![key, value, Utc::now().to_rfc3339()],
            )
            .unwrap();
    }

    fn value(path: &Path, key: &str) -> Option<String> {
        let connection = Connection::open(path).unwrap();
        connection
            .query_row("SELECT value FROM agent_kv WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()
            .unwrap()
    }

    #[test]
    fn online_backup_includes_wal_state_and_verifies() {
        let directory = TestDirectory::new("online");
        let database = directory.path.join("source.db");
        let manager = SqliteContextManager::new(&database).unwrap();
        seed(&manager, "wal-proof", "present");

        let manifest = manager
            .create_backup(&directory.path.join("backups"), "backup_001")
            .unwrap();
        let backup_dir = directory.path.join("backups/backup_001");
        assert_eq!(verify_backup(&backup_dir).unwrap(), manifest);
        assert_eq!(
            value(&backup_dir.join(BACKUP_DATABASE_FILE), "wal-proof").as_deref(),
            Some("present")
        );
        assert!(!companion_path(&backup_dir.join(BACKUP_DATABASE_FILE), "-wal").exists());
    }

    #[test]
    fn online_backup_remains_consistent_while_an_external_writer_commits() {
        let directory = TestDirectory::new("writer");
        let database = directory.path.join("source.db");
        let manager = SqliteContextManager::new(&database).unwrap();
        seed(&manager, "large", &"x".repeat(4 * 1024 * 1024));

        let writes = Arc::new(AtomicUsize::new(0));
        let writer_writes = writes.clone();
        let writer_database = database.clone();
        let writer = std::thread::spawn(move || {
            let connection = Connection::open(writer_database).unwrap();
            connection.busy_timeout(Duration::from_secs(5)).unwrap();
            for index in 0..500 {
                connection
                    .execute(
                        "INSERT OR REPLACE INTO agent_kv(agent_id, key, value, updated_at)
                         VALUES ('00000000-0000-0000-0000-000000000001', ?1, ?2, ?3)",
                        rusqlite::params![
                            format!("writer-{index}"),
                            format!("value-{index}"),
                            Utc::now().to_rfc3339()
                        ],
                    )
                    .unwrap();
                writer_writes.fetch_add(1, AtomicOrdering::SeqCst);
                std::thread::sleep(Duration::from_micros(200));
            }
        });
        while writes.load(AtomicOrdering::SeqCst) == 0 {
            std::thread::yield_now();
        }

        let manifest = manager
            .create_backup(&directory.path.join("backups"), "concurrent")
            .unwrap();
        writer.join().unwrap();
        let backup_dir = directory.path.join("backups/concurrent");
        assert_eq!(verify_backup(&backup_dir).unwrap(), manifest);
        let connection = Connection::open(backup_dir.join(BACKUP_DATABASE_FILE)).unwrap();
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .unwrap();
        let captured_writes: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM agent_kv WHERE key LIKE 'writer-%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(quick_check, "ok");
        assert!(captured_writes > 0);
        assert!(captured_writes <= writes.load(AtomicOrdering::SeqCst) as i64);
    }

    #[test]
    fn backup_rejects_unsafe_names_and_existing_destinations() {
        let directory = TestDirectory::new("paths");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let root = directory.path.join("backups");
        assert!(manager.create_backup(&root, "../escape").is_err());
        manager.create_backup(&root, "once").unwrap();
        assert!(manager.create_backup(&root, "once").is_err());
    }

    #[test]
    fn failed_backup_never_publishes_or_leaves_staging_data() {
        let directory = TestDirectory::new("backup-failure");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let root = directory.path.join("backups");
        let error = manager
            .create_backup(&root, "inject_failure_before_publish")
            .unwrap_err();
        assert!(error.to_string().contains("injected backup failure"));
        assert!(!root.join("inject_failure_before_publish").exists());
        let staging_entries = fs::read_dir(&root)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".staging"))
            .count();
        assert_eq!(staging_entries, 0);
    }

    fn set_backup_age(root: &Path, name: &str, age: chrono::Duration) {
        let manifest_path = root.join(name).join(BACKUP_MANIFEST_FILE);
        let mut manifest = read_manifest(&manifest_path).unwrap();
        manifest.created_at = (Utc::now() - age).to_rfc3339();
        fs::write(manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    }

    #[test]
    fn retention_dry_run_and_confirmation_preserve_the_latest_backups() {
        let directory = TestDirectory::new("retention");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let root = directory.path.join("backups");
        for name in ["oldest", "old", "new", "newest"] {
            manager.create_backup(&root, name).unwrap();
        }
        set_backup_age(&root, "oldest", chrono::Duration::hours(8));
        set_backup_age(&root, "old", chrono::Duration::hours(6));
        set_backup_age(&root, "new", chrono::Duration::minutes(30));
        set_backup_age(&root, "newest", chrono::Duration::minutes(10));
        let policy = BackupRetentionPolicy {
            keep_latest: 2,
            max_age_seconds: 60 * 60,
        };

        let preview = manager
            .apply_backup_retention(&root, policy.clone(), true)
            .unwrap();
        assert!(preview.dry_run);
        assert_eq!(
            preview
                .eligible
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["old", "oldest"],
            "{preview:#?}"
        );
        assert!(preview.deleted.is_empty());
        assert_eq!(
            preview
                .retained
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["newest", "new"]
        );
        for name in ["oldest", "old", "new", "newest"] {
            assert!(root.join(name).exists());
        }

        let applied = manager
            .apply_backup_retention(&root, policy, false)
            .unwrap();
        assert_eq!(applied.deleted, applied.eligible);
        assert!(!root.join("oldest").exists());
        assert!(!root.join("old").exists());
        assert!(root.join("new").exists());
        assert!(root.join("newest").exists());
        assert_eq!(verify_backup(&root.join("new")).unwrap().installation_id, {
            crate::schema::read_storage_metadata(&manager.conn.lock().unwrap())
                .unwrap()
                .installation_id
        });
    }

    #[test]
    fn retention_never_deletes_foreign_corrupt_or_augmented_backups() {
        let directory = TestDirectory::new("retention-safety");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let foreign = SqliteContextManager::new(&directory.path.join("foreign.db")).unwrap();
        let root = directory.path.join("backups");
        manager.create_backup(&root, "current").unwrap();
        manager.create_backup(&root, "augmented").unwrap();
        foreign.create_backup(&root, "foreign").unwrap();
        set_backup_age(&root, "current", chrono::Duration::hours(8));
        set_backup_age(&root, "augmented", chrono::Duration::hours(8));
        set_backup_age(&root, "foreign", chrono::Duration::hours(8));
        fs::write(root.join("augmented/operator-notes.txt"), b"preserve").unwrap();
        fs::create_dir(root.join("corrupt")).unwrap();
        fs::write(root.join("corrupt/manifest.json"), b"not json").unwrap();

        let report = manager
            .apply_backup_retention(
                &root,
                BackupRetentionPolicy {
                    keep_latest: 1,
                    max_age_seconds: 1,
                },
                false,
            )
            .unwrap();
        assert!(report.deleted.is_empty());
        assert_eq!(report.retained.len(), 1, "{report:#?}");
        assert_eq!(report.skipped.len(), 3);
        assert!(report.skipped.iter().any(
            |issue| issue.name == "foreign" && issue.reason.contains("different installation")
        ));
        assert!(report
            .skipped
            .iter()
            .any(|issue| issue.name == "augmented" && issue.reason.contains("unexpected entry")));
        assert!(report
            .skipped
            .iter()
            .any(|issue| issue.name == "corrupt" && issue.reason.contains("verification failed")));
        for name in ["current", "augmented", "foreign", "corrupt"] {
            assert!(root.join(name).exists());
        }
    }

    #[test]
    fn retention_rejects_unsafe_policy_missing_roots_and_concurrent_publication() {
        let directory = TestDirectory::new("retention-validation");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let missing = directory.path.join("missing");
        assert!(manager
            .apply_backup_retention(
                &missing,
                BackupRetentionPolicy {
                    keep_latest: 1,
                    max_age_seconds: 60,
                },
                true,
            )
            .is_err());

        let root = directory.path.join("backups");
        manager.create_backup(&root, "one").unwrap();
        for policy in [
            BackupRetentionPolicy {
                keep_latest: 0,
                max_age_seconds: 60,
            },
            BackupRetentionPolicy {
                keep_latest: 1,
                max_age_seconds: 0,
            },
        ] {
            assert!(manager.apply_backup_retention(&root, policy, true).is_err());
        }

        let _lock = acquire_backup_publication_lock(&root).unwrap();
        let error = manager
            .apply_backup_retention(
                &root,
                BackupRetentionPolicy {
                    keep_latest: 1,
                    max_age_seconds: 60,
                },
                true,
            )
            .unwrap_err();
        assert!(error.to_string().contains("retention pass is active"));
    }

    #[cfg(unix)]
    #[test]
    fn retention_does_not_follow_symlinked_backup_entries() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("retention-symlink");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let root = directory.path.join("backups");
        manager.create_backup(&root, "real").unwrap();
        let outside = directory.path.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("must-survive"), b"proof").unwrap();
        symlink(&outside, root.join("linked")).unwrap();

        let report = manager
            .apply_backup_retention(
                &root,
                BackupRetentionPolicy {
                    keep_latest: 1,
                    max_age_seconds: 1,
                },
                false,
            )
            .unwrap();
        assert!(report
            .skipped
            .iter()
            .any(|issue| issue.name == "linked"
                && issue.reason.contains("not a real backup directory")));
        assert_eq!(fs::read(outside.join("must-survive")).unwrap(), b"proof");
        assert!(root.join("linked").exists());
    }

    #[test]
    fn tampered_database_and_manifest_are_rejected() {
        let directory = TestDirectory::new("tamper");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        seed(&manager, "proof", "original");
        manager
            .create_backup(&directory.path.join("backups"), "tamper")
            .unwrap();
        let backup_dir = directory.path.join("backups/tamper");
        let database = backup_dir.join(BACKUP_DATABASE_FILE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database)
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        let mut last = [0_u8; 1];
        file.read_exact(&mut last).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[last[0] ^ 0xff]).unwrap();
        file.sync_all().unwrap();
        assert!(verify_backup(&backup_dir)
            .unwrap_err()
            .to_string()
            .contains("SHA-256 mismatch"));

        let manifest_path = backup_dir.join(BACKUP_MANIFEST_FILE);
        fs::write(&manifest_path, b"{\"format_version\":1,\"unknown\":true}").unwrap();
        assert!(verify_backup(&backup_dir).is_err());
    }

    #[test]
    fn future_schema_backup_is_rejected_even_with_a_matching_hash() {
        let directory = TestDirectory::new("future");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        manager
            .create_backup(&directory.path.join("backups"), "future")
            .unwrap();
        let backup_dir = directory.path.join("backups/future");
        let database = backup_dir.join(BACKUP_DATABASE_FILE);
        {
            let connection = Connection::open(&database).unwrap();
            connection
                .pragma_update(
                    None,
                    "user_version",
                    crate::schema::CURRENT_SCHEMA_VERSION + 1,
                )
                .unwrap();
        }
        let manifest_path = backup_dir.join(BACKUP_MANIFEST_FILE);
        let mut manifest = read_manifest(&manifest_path).unwrap();
        manifest.byte_count = fs::metadata(&database).unwrap().len();
        manifest.sha256 = sha256_file(&database).unwrap();
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_backup(&backup_dir),
            Err(ContextError::DatabaseTooNew { .. })
        ));
    }

    #[test]
    fn restore_to_fresh_host_reproduces_verified_state() {
        let directory = TestDirectory::new("fresh-restore");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        seed(&source_manager, "restore-proof", "survived");
        source_manager
            .create_backup(&directory.path.join("backups"), "fresh")
            .unwrap();
        let backup_dir = directory.path.join("backups/fresh");
        let destination = directory.path.join("fresh-host/data/agent_os.db");

        let report = restore_backup(&backup_dir, &destination).unwrap();
        assert!(!report.replaced_existing);
        assert!(!report.rollback_retained);
        assert_eq!(
            value(&destination, "restore-proof").as_deref(),
            Some("survived")
        );
        let restored = SqliteContextManager::new(&destination).unwrap();
        crate::schema::verify(&restored.conn.lock().unwrap()).unwrap();
    }

    #[test]
    fn restore_replaces_an_offline_database_but_not_a_running_one() {
        let directory = TestDirectory::new("offline");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        seed(&source_manager, "source", "restored");
        source_manager
            .create_backup(&directory.path.join("backups"), "offline")
            .unwrap();
        let backup_dir = directory.path.join("backups/offline");

        let destination = directory.path.join("destination.db");
        let destination_manager = SqliteContextManager::new(&destination).unwrap();
        seed(&destination_manager, "destination", "original");
        let error = restore_backup(&backup_dir, &destination).unwrap_err();
        assert!(error.to_string().contains("already owned"));
        assert_eq!(
            value(&destination, "destination").as_deref(),
            Some("original")
        );
        drop(destination_manager);

        let report = restore_backup(&backup_dir, &destination).unwrap();
        assert!(report.replaced_existing);
        assert!(!report.rollback_retained);
        assert_eq!(value(&destination, "source").as_deref(), Some("restored"));
        assert_eq!(value(&destination, "destination"), None);
    }

    #[test]
    fn injected_publication_failure_rolls_back_the_original_database() {
        let directory = TestDirectory::new("rollback");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        seed(&source_manager, "source", "replacement");
        source_manager
            .create_backup(&directory.path.join("backups"), "rollback")
            .unwrap();
        let backup_dir = directory.path.join("backups/rollback");

        let destination = directory.path.join("inject-failure.db");
        {
            let destination_manager = SqliteContextManager::new(&destination).unwrap();
            seed(&destination_manager, "destination", "must-survive");
        }
        let error = restore_backup(&backup_dir, &destination).unwrap_err();
        assert!(error.to_string().contains("injected failure"));
        assert_eq!(
            value(&destination, "destination").as_deref(),
            Some("must-survive")
        );
        assert_eq!(value(&destination, "source"), None);
        let reopened = SqliteContextManager::new(&destination).unwrap();
        crate::schema::verify(&reopened.conn.lock().unwrap()).unwrap();
    }

    #[test]
    fn injected_fresh_publication_failure_removes_the_replacement() {
        let directory = TestDirectory::new("fresh-publication-failure");
        let source_manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        source_manager
            .create_backup(&directory.path.join("backups"), "fresh-failure")
            .unwrap();
        let destination = directory.path.join("fresh/inject-failure.db");

        let error = restore_backup(&directory.path.join("backups/fresh-failure"), &destination)
            .unwrap_err();
        assert!(error.to_string().contains("injected failure"));
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn backup_rejects_symlink_roots_and_files() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("symlink");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let real_root = directory.path.join("real-root");
        fs::create_dir(&real_root).unwrap();
        let linked_root = directory.path.join("linked-root");
        symlink(&real_root, &linked_root).unwrap();
        assert!(manager.create_backup(&linked_root, "blocked").is_err());

        let outside_lock = directory.path.join("outside-lock");
        fs::write(&outside_lock, b"must not be opened as the lock").unwrap();
        let publication_lock = real_root.join(".agentos-backup.lock");
        symlink(&outside_lock, &publication_lock).unwrap();
        let error = manager
            .create_backup(&real_root, "lock-blocked")
            .unwrap_err();
        assert!(error.to_string().contains("regular file"));
        assert_eq!(
            fs::read(&outside_lock).unwrap(),
            b"must not be opened as the lock"
        );
        fs::remove_file(&publication_lock).unwrap();

        manager.create_backup(&real_root, "valid").unwrap();
        let backup_dir = real_root.join("valid");
        let database = backup_dir.join(BACKUP_DATABASE_FILE);
        let moved = backup_dir.join("moved.db");
        fs::rename(&database, &moved).unwrap();
        symlink(&moved, &database).unwrap();
        assert!(verify_backup(&backup_dir).is_err());
    }
}
