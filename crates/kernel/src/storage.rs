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
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ring::digest::{self, Context as DigestContext, SHA256};
use ring::rand;
use ring::signature::{self, KeyPair};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::config::BackupScheduleConfig;
use crate::context::SqliteContextManager;
use crate::storage_encryption::StorageEncryptionKey;
use crate::ContextError;

const LEGACY_BACKUP_FORMAT_VERSION: u32 = 1;
const BACKUP_FORMAT_VERSION: u32 = 2;
const BACKUP_DATABASE_FILE: &str = "agent_os.db";
const BACKUP_DATABASE_SHM_FILE: &str = "agent_os.db-shm";
const BACKUP_DATABASE_WAL_FILE: &str = "agent_os.db-wal";
const BACKUP_MANIFEST_FILE: &str = "manifest.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_BACKUP_KEY_BYTES: u64 = 16 * 1024;
const MAX_BACKUP_ROOT_ENTRIES: usize = 10_000;
const BACKUP_AUTHENTICITY_FORMAT_VERSION: u32 = 1;
const BACKUP_TRUST_FORMAT_VERSION: u32 = 1;
pub const BACKUP_RECOVERY_ANCHOR_FORMAT_VERSION: u32 = 1;
const BACKUP_SIGNATURE_ALGORITHM: &str = "ed25519";
const BACKUP_SIGNING_DOMAIN_V1: &[u8] = b"AIAGENTOS-BACKUP-MANIFEST-V1\0";
const BACKUP_SIGNING_DOMAIN_V2: &[u8] = b"AIAGENTOS-BACKUP-MANIFEST-V2\0";
const BACKUP_ENCRYPTION_FORMAT_VERSION: u32 = 1;
const BACKUP_ENCRYPTION_ALGORITHM: &str = "sqlcipher-4";
pub const PORTABLE_STORAGE_FORMAT_VERSION: u32 = 1;
const PORTABLE_STORAGE_DATABASE_FILE: &str = "storage.sqlite3";
const PORTABLE_STORAGE_MANIFEST_FILE: &str = "portable-storage.json";
const PORTABLE_STORAGE_PAYLOAD_FORMAT: &str = "sqlite3-plaintext";
const PORTABLE_STORAGE_CONFIDENTIALITY: &str = "plaintext-owner-only";
const CORRUPT_RECOVERY_FORMAT_VERSION: u32 = 1;
const CORRUPT_RECOVERY_JOURNAL_SUFFIX: &str = ".corrupt-recovery.json";
const MAX_CORRUPT_RECOVERY_JOURNAL_BYTES: u64 = 64 * 1024;

/// Exclusive ownership of one file-backed kernel database.
///
/// The lock is explicitly released when the final in-process owner disappears.
/// Closing the descriptor alone is insufficient on Unix: a concurrently
/// forked child can briefly inherit the descriptor before `exec` applies
/// close-on-exec, extending an otherwise finished lease. Explicit `unlock`
/// releases the lock on the shared open-file description even in that window.
#[derive(Debug)]
pub(crate) struct StorageLease {
    inner: Arc<StorageLeaseInner>,
}

#[derive(Debug)]
struct StorageLeaseInner {
    file: File,
}

impl Drop for StorageLeaseInner {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl StorageLease {
    fn new(file: File) -> Self {
        Self {
            inner: Arc::new(StorageLeaseInner { file }),
        }
    }

    fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            inner: Arc::clone(&self.inner),
        })
    }
}

/// Whole-database encryption identity required to authenticate a backup.
///
/// Only the non-secret key generation identifier is stored in the manifest.
/// Key material remains outside the database and backup failure domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupEncryption {
    pub format_version: u32,
    pub algorithm: String,
    pub key_id: String,
}

/// Optional cryptographic authenticity proof embedded in a backup manifest.
///
/// The public key is deliberately not embedded: verification must use an
/// independently retained [`BackupTrustRoot`] rather than trusting key material
/// supplied by the same backup being verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupAuthenticity {
    pub format_version: u32,
    pub algorithm: String,
    pub key_id: String,
    pub public_key_sha256: String,
    pub signature_hex: String,
}

/// Versioned public trust material retained outside the backup failure domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupTrustRoot {
    pub format_version: u32,
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
}

/// Independently retained identity of one exact, fully verified recovery point.
///
/// A valid backup signature proves provenance but does not distinguish the
/// newest signed backup from an older, still-valid one. Operators retain this
/// non-secret document outside the backup failure domain and supply it during
/// production recovery so a stale or replaced snapshot is rejected before the
/// destination is mutated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRecoveryAnchor {
    pub format_version: u32,
    pub installation_id: String,
    pub backup_format_version: u32,
    pub created_at: String,
    pub byte_count: u64,
    pub database_sha256: String,
    pub manifest_sha256: String,
    pub signing_key_id: String,
    pub signing_public_key_sha256: String,
}

/// In-memory Ed25519 backup signing identity.
///
/// Secret PKCS#8 bytes are never serialized by this type.
pub struct BackupSigningKey {
    key_id: String,
    key_pair: signature::Ed25519KeyPair,
}

impl BackupSigningKey {
    /// Import a bounded Ed25519 PKCS#8 document.
    pub fn from_pkcs8(key_id: impl Into<String>, pkcs8: &[u8]) -> Result<Self, ContextError> {
        let key_id = key_id.into();
        validate_backup_key_id(&key_id)?;
        if pkcs8.is_empty() || pkcs8.len() as u64 > MAX_BACKUP_KEY_BYTES {
            return Err(storage_error("backup signing key has an invalid size"));
        }
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| storage_error("backup signing key is not valid Ed25519 PKCS#8"))?;
        Ok(Self { key_id, key_pair })
    }

    /// Generate a key and return both the identity and its secret PKCS#8 bytes.
    pub fn generate(key_id: impl Into<String>) -> Result<(Self, Vec<u8>), ContextError> {
        let key_id = key_id.into();
        validate_backup_key_id(&key_id)?;
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rand::SystemRandom::new())
            .map_err(|_| storage_error("failed to generate Ed25519 backup signing key"))?;
        let key = Self::from_pkcs8(key_id, pkcs8.as_ref())?;
        Ok((key, pkcs8.as_ref().to_vec()))
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn trust_root(&self) -> BackupTrustRoot {
        BackupTrustRoot {
            format_version: BACKUP_TRUST_FORMAT_VERSION,
            algorithm: BACKUP_SIGNATURE_ALGORITHM.into(),
            key_id: self.key_id.clone(),
            public_key_hex: hex_encode(self.key_pair.public_key().as_ref()),
        }
    }

    fn sign_manifest(&self, manifest: &mut BackupManifest) -> Result<(), ContextError> {
        if manifest.authenticity.is_some() {
            return Err(storage_error("backup manifest is already signed"));
        }
        let trust = self.trust_root();
        let public_key = trust.public_key()?;
        let fingerprint = sha256_bytes(&public_key);
        let message = backup_signing_message(manifest, &self.key_id, &fingerprint)?;
        manifest.authenticity = Some(BackupAuthenticity {
            format_version: BACKUP_AUTHENTICITY_FORMAT_VERSION,
            algorithm: BACKUP_SIGNATURE_ALGORITHM.into(),
            key_id: self.key_id.clone(),
            public_key_sha256: fingerprint,
            signature_hex: hex_encode(self.key_pair.sign(&message).as_ref()),
        });
        Ok(())
    }
}

impl BackupTrustRoot {
    fn public_key(&self) -> Result<Vec<u8>, ContextError> {
        if self.format_version != BACKUP_TRUST_FORMAT_VERSION {
            return Err(storage_error(format!(
                "unsupported backup trust format version {}",
                self.format_version
            )));
        }
        if self.algorithm != BACKUP_SIGNATURE_ALGORITHM {
            return Err(storage_error(format!(
                "unsupported backup signature algorithm {:?}",
                self.algorithm
            )));
        }
        validate_backup_key_id(&self.key_id)?;
        let public_key = hex_decode(&self.public_key_hex)
            .ok_or_else(|| storage_error("backup trust public key is not valid hexadecimal"))?;
        if public_key.len() != 32 {
            return Err(storage_error(
                "backup trust public key must contain exactly 32 bytes",
            ));
        }
        Ok(public_key)
    }

    fn verify_manifest(&self, manifest: &BackupManifest) -> Result<(), ContextError> {
        let authenticity = manifest.authenticity.as_ref().ok_or_else(|| {
            storage_error("backup is unsigned but a trusted signature is required")
        })?;
        validate_authenticity(authenticity)?;
        if authenticity.key_id != self.key_id {
            return Err(storage_error(format!(
                "backup was signed by key {:?}, not trusted key {:?}",
                authenticity.key_id, self.key_id
            )));
        }
        let public_key = self.public_key()?;
        let fingerprint = sha256_bytes(&public_key);
        if authenticity.public_key_sha256 != fingerprint {
            return Err(storage_error(
                "backup signing-key fingerprint does not match the trusted public key",
            ));
        }
        let signature = hex_decode(&authenticity.signature_hex)
            .ok_or_else(|| storage_error("backup signature is not valid hexadecimal"))?;
        if signature.len() != 64 {
            return Err(storage_error(
                "backup Ed25519 signature must contain exactly 64 bytes",
            ));
        }
        let message = backup_signing_message(manifest, &self.key_id, &fingerprint)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&message, &signature)
            .map_err(|_| storage_error("backup manifest signature is invalid"))
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<BackupEncryption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticity: Option<BackupAuthenticity>,
}

/// Versioned, integrity-checked description of a complete installation export.
///
/// The payload is deliberately plaintext so it can be imported under a
/// different storage key. It contains all durable state and must therefore be
/// handled as a secret by the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableStorageManifest {
    pub format_version: u32,
    pub payload_format: String,
    pub confidentiality: String,
    pub database_file: String,
    pub application_id: i64,
    pub schema_version: i64,
    pub min_reader_schema_version: i64,
    pub installation_id: String,
    pub created_at: String,
    pub byte_count: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_storage_key_id: Option<String>,
}

/// Result of atomically publishing a portable installation bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableStorageExportReport {
    pub bundle_dir: PathBuf,
    pub manifest: PortableStorageManifest,
}

/// Result of atomically importing a portable installation bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableStorageImportReport {
    pub bundle_dir: PathBuf,
    pub database_path: PathBuf,
    pub format_version: u32,
    pub schema_version: i64,
    pub installation_id: String,
    pub byte_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_storage_key_id: Option<String>,
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

/// Evidence returned after an authenticated restore also boots the configured
/// kernel and proves every persisted agent was re-admitted to enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasterRecoveryReport {
    pub restore: RestoreReport,
    pub persisted_agent_count: usize,
    pub enforcement_rearmed: bool,
}

/// Evidence returned after a corrupt database was preserved and a trusted
/// backup passed complete configured-kernel qualification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorruptStorageRecoveryReport {
    pub manifest: BackupManifest,
    pub database_path: PathBuf,
    /// Owner-only directory retaining the corrupt database and SQLite
    /// sidecars. Operators must treat it as sensitive and remove it only after
    /// the recovered installation has been independently accepted.
    pub quarantine_dir: PathBuf,
    pub original_wal_preserved: bool,
    pub original_shm_preserved: bool,
    pub resumed_interrupted_recovery: bool,
    /// Whether deletion of the completed journal was confirmed durable in the
    /// destination directory. A journal that reappears after a crash remains
    /// safe to resume because it binds the exact recovery inputs.
    pub journal_cleanup_durable: bool,
    pub persisted_agent_count: usize,
    pub enforcement_rearmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorruptRecoveryJournal {
    format_version: u32,
    database_file: String,
    stage_file: String,
    quarantine_dir: String,
    quarantined_database_file: String,
    quarantined_wal_file: String,
    quarantined_shm_file: String,
    installation_id: String,
    backup_sha256: String,
    backup_byte_count: u64,
    original_wal: bool,
    original_shm: bool,
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

/// Exclusive proof that every backup in the configured managed root was
/// verified and removed before a live subject erasure commits.
///
/// The publication lock remains held for this value's lifetime, so neither a
/// scheduled nor an operator-triggered backup can capture the subject between
/// the purge and the SQLite deletion transaction.
#[derive(Debug)]
pub struct BackupErasureGuard {
    _publication_lock: File,
    root: PathBuf,
    deleted: Vec<BackupRetentionEntry>,
}

impl BackupErasureGuard {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn deleted(&self) -> &[BackupRetentionEntry] {
        &self.deleted
    }

    pub fn deleted_count(&self) -> usize {
        self.deleted.len()
    }
}

/// Result of one automatic backup and retention cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledBackupReport {
    pub backup: BackupManifest,
    pub retention: BackupRetentionReport,
}

/// Bounded operator-visible state for automatic backup maintenance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupMaintenanceStatus {
    pub enabled: bool,
    pub backup_root: Option<String>,
    pub interval_seconds: u64,
    pub run_on_start: bool,
    pub keep_latest: usize,
    pub max_age_seconds: u64,
    pub signing_key_id: Option<String>,
    pub attempts_total: u64,
    pub successes_total: u64,
    pub failures_total: u64,
    pub retention_deleted_total: u64,
    pub erasure_purge_attempts_total: u64,
    pub erasure_purge_successes_total: u64,
    pub erasure_purge_failures_total: u64,
    pub erasure_purge_deleted_total: u64,
    pub consecutive_failures: u64,
    pub last_attempt_at: Option<String>,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub last_backup_name: Option<String>,
    pub last_error: Option<String>,
}

/// Process-local coordinator for scheduled backup policy and health.
///
/// The published backups themselves are durable. This status intentionally
/// resets on process restart and is exported without per-path metric labels.
pub struct BackupMaintenance {
    config: std::sync::RwLock<BackupScheduleConfig>,
    signer: std::sync::RwLock<Option<std::sync::Arc<BackupSigningKey>>>,
    status: std::sync::Mutex<BackupMaintenanceStatus>,
}

impl Default for BackupMaintenance {
    fn default() -> Self {
        Self::new(BackupScheduleConfig::default())
            .expect("the disabled default backup configuration is valid")
    }
}

impl BackupMaintenance {
    pub fn new(config: BackupScheduleConfig) -> Result<Self, ContextError> {
        config.validate().map_err(storage_error)?;
        let signer = load_configured_backup_signer(&config)?;
        let status = Self::status_for_config(&config);
        Ok(Self {
            config: std::sync::RwLock::new(config),
            signer: std::sync::RwLock::new(signer.map(std::sync::Arc::new)),
            status: std::sync::Mutex::new(status),
        })
    }

    fn status_for_config(config: &BackupScheduleConfig) -> BackupMaintenanceStatus {
        BackupMaintenanceStatus {
            enabled: config.enabled,
            backup_root: config
                .root
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            interval_seconds: config.interval_seconds,
            run_on_start: config.run_on_start,
            keep_latest: config.keep_latest,
            max_age_seconds: config.max_age_seconds,
            signing_key_id: config.signing_key_id.clone(),
            ..BackupMaintenanceStatus::default()
        }
    }

    pub fn configure(&self, config: BackupScheduleConfig) -> Result<(), ContextError> {
        config.validate().map_err(storage_error)?;
        // Load and validate the private key before publishing any part of the
        // new configuration. A bad rotation therefore leaves the old signer
        // and policy intact.
        let signer = load_configured_backup_signer(&config)?;
        let next_status = Self::status_for_config(&config);
        *self
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = config;
        *self
            .signer
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = signer.map(std::sync::Arc::new);
        *self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next_status;
        Ok(())
    }

    pub fn config(&self) -> BackupScheduleConfig {
        self.config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Create a manual or scheduled backup using the configured signing key,
    /// if one is present.
    pub fn create_backup(
        &self,
        manager: &SqliteContextManager,
        backup_root: &Path,
        name: &str,
    ) -> Result<BackupManifest, ContextError> {
        let config = self.config();
        let managed_root = config.root.as_deref().ok_or_else(|| {
            storage_error(
                "server-side backup creation requires backup.root to name the managed backup root",
            )
        })?;
        if backup_root != managed_root {
            return Err(storage_error(format!(
                "server-side backup root {} does not match configured managed root {}",
                backup_root.display(),
                managed_root.display()
            )));
        }
        let signer = self
            .signer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match signer {
            Some(signer) => manager.create_signed_backup(backup_root, name, &signer),
            None => manager.create_backup(backup_root, name),
        }
    }

    /// Remove every verified backup from the configured managed root and keep
    /// its publication lock held until the caller completes live erasure.
    ///
    /// A missing configured root means that this kernel cannot create managed
    /// server-side backups, so there is no managed root to purge. Any unsafe,
    /// corrupt, foreign, or unknown root entry fails closed before a live
    /// deletion transaction can begin.
    pub fn begin_erasure_purge(
        &self,
        manager: &SqliteContextManager,
    ) -> Result<Option<BackupErasureGuard>, ContextError> {
        let Some(root) = self.config().root else {
            return Ok(None);
        };
        {
            let mut status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            status.erasure_purge_attempts_total =
                status.erasure_purge_attempts_total.saturating_add(1);
        }
        match manager.begin_managed_backup_erasure(&root) {
            Ok(guard) => {
                let mut status = self
                    .status
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                status.erasure_purge_successes_total =
                    status.erasure_purge_successes_total.saturating_add(1);
                status.erasure_purge_deleted_total = status
                    .erasure_purge_deleted_total
                    .saturating_add(guard.deleted_count() as u64);
                Ok(Some(guard))
            }
            Err(error) => {
                let mut status = self
                    .status
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                status.erasure_purge_failures_total =
                    status.erasure_purge_failures_total.saturating_add(1);
                Err(error)
            }
        }
    }

    pub fn status(&self) -> BackupMaintenanceStatus {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Run one synchronous backup plus confirmed retention pass.
    ///
    /// The scheduler calls this through `spawn_blocking`. If retention fails,
    /// the newly published verified backup remains intact and the complete
    /// cycle is reported as failed so operators can investigate.
    pub fn run_cycle(
        &self,
        manager: &SqliteContextManager,
    ) -> Result<ScheduledBackupReport, ContextError> {
        let config = self.config();
        if !config.enabled {
            return Err(storage_error("scheduled backups are disabled"));
        }
        let root = config
            .root
            .as_deref()
            .ok_or_else(|| storage_error("scheduled backup root is not configured"))?;
        let attempted_at = Utc::now();
        {
            let mut status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            status.attempts_total = status.attempts_total.saturating_add(1);
            status.last_attempt_at = Some(attempted_at.to_rfc3339());
        }

        let name = format!(
            "scheduled_{}_{}",
            attempted_at.format("%Y%m%dT%H%M%S%3fZ"),
            uuid::Uuid::new_v4().simple()
        );
        let result = (|| {
            let backup = self.create_backup(manager, root, &name)?;
            let retention = manager.apply_backup_retention(
                root,
                BackupRetentionPolicy {
                    keep_latest: config.keep_latest,
                    max_age_seconds: config.max_age_seconds,
                },
                false,
            )?;
            Ok(ScheduledBackupReport { backup, retention })
        })();

        let completed_at = Utc::now().to_rfc3339();
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &result {
            Ok(report) => {
                status.successes_total = status.successes_total.saturating_add(1);
                status.retention_deleted_total = status
                    .retention_deleted_total
                    .saturating_add(report.retention.deleted.len() as u64);
                status.consecutive_failures = 0;
                status.last_success_at = Some(completed_at);
                status.last_backup_name = Some(name);
                status.last_error = None;
            }
            Err(error) => {
                status.failures_total = status.failures_total.saturating_add(1);
                status.consecutive_failures = status.consecutive_failures.saturating_add(1);
                status.last_failure_at = Some(completed_at);
                status.last_error = Some(bounded_backup_error(error));
            }
        }
        result
    }

    pub(crate) fn record_worker_failure(&self, message: &str) {
        let now = Utc::now().to_rfc3339();
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.failures_total = status.failures_total.saturating_add(1);
        status.consecutive_failures = status.consecutive_failures.saturating_add(1);
        status.last_failure_at = Some(now);
        status.last_error = Some(bounded_text(message));
    }
}

fn load_configured_backup_signer(
    config: &BackupScheduleConfig,
) -> Result<Option<BackupSigningKey>, ContextError> {
    match (&config.signing_key_path, &config.signing_key_id) {
        (Some(path), Some(key_id)) => load_backup_signing_key(path, key_id).map(Some),
        (None, None) => Ok(None),
        _ => Err(storage_error(
            "backup signing_key_path and signing_key_id must be configured together",
        )),
    }
}

fn validate_backup_key_id(key_id: &str) -> Result<(), ContextError> {
    if key_id.is_empty()
        || key_id.len() > 96
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(storage_error(
            "backup signing key id must be 1-96 ASCII letters, digits, '-', '_' or '.'",
        ));
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_encode(digest::digest(&SHA256, bytes).as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

fn validate_authenticity(authenticity: &BackupAuthenticity) -> Result<(), ContextError> {
    if authenticity.format_version != BACKUP_AUTHENTICITY_FORMAT_VERSION {
        return Err(storage_error(format!(
            "unsupported backup authenticity format version {}",
            authenticity.format_version
        )));
    }
    if authenticity.algorithm != BACKUP_SIGNATURE_ALGORITHM {
        return Err(storage_error(format!(
            "unsupported backup signature algorithm {:?}",
            authenticity.algorithm
        )));
    }
    validate_backup_key_id(&authenticity.key_id)?;
    if hex_decode(&authenticity.public_key_sha256).is_none_or(|fingerprint| fingerprint.len() != 32)
    {
        return Err(storage_error(
            "backup signing-key fingerprint must be a 32-byte SHA-256 value",
        ));
    }
    if hex_decode(&authenticity.signature_hex).is_none_or(|signature| signature.len() != 64) {
        return Err(storage_error(
            "backup Ed25519 signature must contain exactly 64 bytes",
        ));
    }
    Ok(())
}

fn validate_backup_encryption(encryption: &BackupEncryption) -> Result<(), ContextError> {
    if encryption.format_version != BACKUP_ENCRYPTION_FORMAT_VERSION {
        return Err(storage_error(format!(
            "unsupported backup encryption format version {}",
            encryption.format_version
        )));
    }
    if encryption.algorithm != BACKUP_ENCRYPTION_ALGORITHM {
        return Err(storage_error(format!(
            "unsupported backup encryption algorithm {:?}",
            encryption.algorithm
        )));
    }
    if encryption.key_id.is_empty()
        || encryption.key_id.len() > 96
        || !encryption
            .key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(storage_error(
            "backup encryption key id must be 1-96 ASCII letters, digits, '-', '_' or '.'",
        ));
    }
    Ok(())
}

fn backup_signing_message(
    manifest: &BackupManifest,
    key_id: &str,
    fingerprint: &str,
) -> Result<Vec<u8>, ContextError> {
    validate_backup_key_id(key_id)?;
    let mut unsigned = manifest.clone();
    unsigned.authenticity = None;
    let payload = serde_json::to_vec(&unsigned).map_err(|error| {
        storage_error(format!("failed to encode backup signing payload: {error}"))
    })?;
    let key_len = u32::try_from(key_id.len())
        .map_err(|_| storage_error("backup signing key id is too long"))?;
    let fingerprint_len = u32::try_from(fingerprint.len())
        .map_err(|_| storage_error("backup signing-key fingerprint is too long"))?;
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| storage_error("backup signing payload is too large"))?;
    let signing_domain = match manifest.format_version {
        LEGACY_BACKUP_FORMAT_VERSION => BACKUP_SIGNING_DOMAIN_V1,
        BACKUP_FORMAT_VERSION => BACKUP_SIGNING_DOMAIN_V2,
        version => {
            return Err(storage_error(format!(
                "cannot sign unsupported backup format version {version}"
            )))
        }
    };
    let mut message = Vec::with_capacity(
        signing_domain.len() + key_id.len() + fingerprint.len() + payload.len() + 16,
    );
    message.extend_from_slice(signing_domain);
    message.extend_from_slice(&key_len.to_be_bytes());
    message.extend_from_slice(key_id.as_bytes());
    message.extend_from_slice(&fingerprint_len.to_be_bytes());
    message.extend_from_slice(fingerprint.as_bytes());
    message.extend_from_slice(&payload_len.to_be_bytes());
    message.extend_from_slice(&payload);
    Ok(message)
}

fn read_bounded_regular_file(
    path: &Path,
    label: &str,
    max_bytes: u64,
    owner_only: bool,
) -> Result<Vec<u8>, ContextError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|error| {
        storage_error(format!(
            "failed to open {label} {} as a regular non-symlink file: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        storage_error(format!(
            "failed to inspect opened {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(storage_error(format!(
            "{label} {} must be a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(storage_error(format!(
                "{label} {} must not be accessible by group or other users",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    let size = metadata.len();
    if size == 0 || size > max_bytes {
        return Err(storage_error(format!(
            "{label} {} must be between 1 and {max_bytes} bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes).map_err(|error| {
        storage_error(format!(
            "failed to read {label} {}: {error}",
            path.display()
        ))
    })?;
    Ok(bytes)
}

/// Load an owner-only Ed25519 PKCS#8 backup signing key from disk.
pub fn load_backup_signing_key(
    path: &Path,
    key_id: &str,
) -> Result<BackupSigningKey, ContextError> {
    validate_backup_key_id(key_id)?;
    let bytes = read_bounded_regular_file(path, "backup signing key", MAX_BACKUP_KEY_BYTES, true)?;
    BackupSigningKey::from_pkcs8(key_id, &bytes)
}

/// Read and validate a versioned public backup trust root.
pub fn load_backup_trust_root(path: &Path) -> Result<BackupTrustRoot, ContextError> {
    let bytes = read_bounded_regular_file(path, "backup trust root", MAX_MANIFEST_BYTES, false)?;
    let trust: BackupTrustRoot = serde_json::from_slice(&bytes).map_err(|error| {
        storage_error(format!(
            "failed to parse backup trust root {}: {error}",
            path.display()
        ))
    })?;
    trust.public_key()?;
    Ok(trust)
}

fn validate_backup_recovery_anchor(anchor: &BackupRecoveryAnchor) -> Result<(), ContextError> {
    if anchor.format_version != BACKUP_RECOVERY_ANCHOR_FORMAT_VERSION {
        return Err(storage_error(format!(
            "unsupported backup recovery anchor format version {}",
            anchor.format_version
        )));
    }
    if !matches!(
        anchor.backup_format_version,
        LEGACY_BACKUP_FORMAT_VERSION | BACKUP_FORMAT_VERSION
    ) {
        return Err(storage_error(format!(
            "backup recovery anchor references unsupported backup format version {}",
            anchor.backup_format_version
        )));
    }
    uuid::Uuid::parse_str(&anchor.installation_id)
        .map_err(|_| storage_error("backup recovery anchor installation id is not a UUID"))?;
    chrono::DateTime::parse_from_rfc3339(&anchor.created_at).map_err(|error| {
        storage_error(format!(
            "backup recovery anchor creation timestamp is invalid: {error}"
        ))
    })?;
    if anchor.byte_count == 0 {
        return Err(storage_error(
            "backup recovery anchor byte count must be greater than zero",
        ));
    }
    for (label, value) in [
        ("database SHA-256", &anchor.database_sha256),
        ("manifest SHA-256", &anchor.manifest_sha256),
        ("signing-key fingerprint", &anchor.signing_public_key_sha256),
    ] {
        if hex_decode(value).is_none_or(|bytes| bytes.len() != 32) {
            return Err(storage_error(format!(
                "backup recovery anchor {label} must be a 32-byte hexadecimal value"
            )));
        }
    }
    validate_backup_key_id(&anchor.signing_key_id)
}

fn backup_manifest_bytes(backup_dir: &Path) -> Result<Vec<u8>, ContextError> {
    require_real_directory(backup_dir, "backup")?;
    read_bounded_regular_file(
        &backup_dir.join(BACKUP_MANIFEST_FILE),
        "backup manifest",
        MAX_MANIFEST_BYTES,
        false,
    )
}

fn recovery_anchor_for_manifest(
    manifest: &BackupManifest,
    manifest_bytes: &[u8],
) -> Result<BackupRecoveryAnchor, ContextError> {
    let authenticity = manifest.authenticity.as_ref().ok_or_else(|| {
        storage_error("backup is unsigned and cannot produce a trusted recovery anchor")
    })?;
    validate_authenticity(authenticity)?;
    let anchor = BackupRecoveryAnchor {
        format_version: BACKUP_RECOVERY_ANCHOR_FORMAT_VERSION,
        installation_id: manifest.installation_id.clone(),
        backup_format_version: manifest.format_version,
        created_at: manifest.created_at.clone(),
        byte_count: manifest.byte_count,
        database_sha256: manifest.sha256.clone(),
        manifest_sha256: sha256_bytes(manifest_bytes),
        signing_key_id: authenticity.key_id.clone(),
        signing_public_key_sha256: authenticity.public_key_sha256.clone(),
    };
    validate_backup_recovery_anchor(&anchor)?;
    Ok(anchor)
}

/// Read and validate one independently retained backup recovery anchor.
pub fn load_backup_recovery_anchor(path: &Path) -> Result<BackupRecoveryAnchor, ContextError> {
    let bytes =
        read_bounded_regular_file(path, "backup recovery anchor", MAX_MANIFEST_BYTES, false)?;
    let anchor: BackupRecoveryAnchor = serde_json::from_slice(&bytes).map_err(|error| {
        storage_error(format!(
            "failed to parse backup recovery anchor {}: {error}",
            path.display()
        ))
    })?;
    validate_backup_recovery_anchor(&anchor)?;
    Ok(anchor)
}

fn require_anchor_outside_backup(
    backup_dir: &Path,
    anchor_path: &Path,
) -> Result<(), ContextError> {
    let backup = fs::canonicalize(backup_dir).map_err(|error| {
        storage_error(format!(
            "failed to resolve backup directory {}: {error}",
            backup_dir.display()
        ))
    })?;
    let anchor = match fs::canonicalize(anchor_path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = anchor_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent = fs::canonicalize(parent).map_err(|error| {
                storage_error(format!(
                    "failed to resolve backup recovery anchor parent {}: {error}",
                    parent.display()
                ))
            })?;
            let file_name = anchor_path
                .file_name()
                .ok_or_else(|| storage_error("backup recovery anchor path must name a file"))?;
            parent.join(file_name)
        }
        Err(error) => {
            return Err(storage_error(format!(
                "failed to resolve backup recovery anchor {}: {error}",
                anchor_path.display()
            )))
        }
    };
    if anchor.starts_with(&backup) {
        return Err(storage_error(
            "backup recovery anchor must be retained outside the backup directory",
        ));
    }
    Ok(())
}

/// Load an anchor while rejecting obvious co-location with the backup it pins.
///
/// Filesystem separation alone cannot prove an independent failure domain, but
/// rejecting an anchor embedded in the backup prevents the most direct
/// self-authentication mistake. Operators must still retain the anchor in a
/// separately governed inventory or immutable store.
pub fn load_independent_backup_recovery_anchor(
    backup_dir: &Path,
    anchor_path: &Path,
) -> Result<BackupRecoveryAnchor, ContextError> {
    require_anchor_outside_backup(backup_dir, anchor_path)?;
    load_backup_recovery_anchor(anchor_path)
}

fn write_new_owner_only_file(path: &Path, bytes: &[u8], label: &str) -> Result<(), ContextError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_real_directory(parent, &format!("{label} parent"))?;

    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        storage_error(format!(
            "failed to create {label} {}: {error}",
            path.display()
        ))
    })?;
    let persist = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    storage_error(format!(
                        "failed to protect opened {label} {}: {error}",
                        path.display()
                    ))
                })?;
        }
        #[cfg(not(unix))]
        set_owner_only_file(path)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                storage_error(format!(
                    "failed to persist {label} {}: {error}",
                    path.display()
                ))
            })?;
        sync_directory(parent)
    })();
    if persist.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        let _ = sync_directory(parent);
    }
    persist
}

/// Generate a new backup signing key and independently retainable public trust
/// file. Existing files are never overwritten.
pub fn generate_backup_signing_key_files(
    key_id: &str,
    private_key_path: &Path,
    trust_root_path: &Path,
) -> Result<BackupTrustRoot, ContextError> {
    validate_backup_key_id(key_id)?;
    if private_key_path == trust_root_path {
        return Err(storage_error(
            "backup private key and public trust root must use different files",
        ));
    }
    reject_existing_path(private_key_path, "backup private key")?;
    reject_existing_path(trust_root_path, "backup public trust root")?;

    let (key, private_bytes) = BackupSigningKey::generate(key_id)?;
    let trust = key.trust_root();
    let mut trust_bytes = serde_json::to_vec_pretty(&trust)
        .map_err(|error| storage_error(format!("failed to encode backup trust root: {error}")))?;
    trust_bytes.push(b'\n');
    write_new_owner_only_file(private_key_path, &private_bytes, "backup private key")?;
    if let Err(error) =
        write_new_owner_only_file(trust_root_path, &trust_bytes, "backup public trust root")
    {
        let _ = fs::remove_file(private_key_path);
        return Err(error);
    }
    Ok(trust)
}

fn bounded_backup_error(error: &ContextError) -> String {
    bounded_text(&error.to_string())
}

fn bounded_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect()
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

pub(crate) fn acquire_storage_lease(database_path: &Path) -> Result<StorageLease, ContextError> {
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
    Ok(StorageLease::new(lock))
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
    encryption_key: Option<&StorageEncryptionKey>,
) -> Result<(Connection, crate::schema::StorageMetadata), ContextError> {
    require_regular_file(path, "backup database")?;
    let connection =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|error| {
            storage_error(format!(
                "failed to open {} read-only: {error}",
                path.display()
            ))
        })?;
    if let Some(key) = encryption_key {
        key.apply(&connection)?;
    }
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

fn write_portable_storage_manifest(
    path: &Path,
    manifest: &PortableStorageManifest,
) -> Result<(), ContextError> {
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
        storage_error(format!(
            "failed to serialize portable storage manifest: {error}"
        ))
    })?;
    bytes.push(b'\n');
    write_new_owner_only_file(path, &bytes, "portable storage manifest")
}

fn read_portable_storage_manifest(path: &Path) -> Result<PortableStorageManifest, ContextError> {
    let size = require_regular_file(path, "portable storage manifest")?;
    if size > MAX_MANIFEST_BYTES {
        return Err(storage_error(format!(
            "portable storage manifest {} exceeds {MAX_MANIFEST_BYTES} bytes",
            path.display()
        )));
    }
    let file = File::open(path).map_err(|error| {
        storage_error(format!(
            "failed to open portable storage manifest {}: {error}",
            path.display()
        ))
    })?;
    serde_json::from_reader(file).map_err(|error| {
        storage_error(format!(
            "failed to parse portable storage manifest {}: {error}",
            path.display()
        ))
    })
}

fn require_portable_storage_contents(bundle_dir: &Path) -> Result<(), ContextError> {
    let mut found_database = false;
    let mut found_manifest = false;
    let mut entries = 0_usize;
    for entry in fs::read_dir(bundle_dir).map_err(|error| {
        storage_error(format!(
            "failed to enumerate portable storage bundle {}: {error}",
            bundle_dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            storage_error(format!(
                "failed to enumerate portable storage bundle {}: {error}",
                bundle_dir.display()
            ))
        })?;
        entries += 1;
        if entries > 2 {
            return Err(storage_error(
                "portable storage bundle must contain exactly its database and manifest",
            ));
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            storage_error(format!(
                "failed to inspect portable storage entry {}: {error}",
                entry.path().display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(storage_error(
                "portable storage bundle contains a non-regular file or symlink",
            ));
        }
        match entry.file_name().to_str() {
            Some(PORTABLE_STORAGE_DATABASE_FILE) => found_database = true,
            Some(PORTABLE_STORAGE_MANIFEST_FILE) => found_manifest = true,
            _ => {
                return Err(storage_error(format!(
                    "portable storage bundle contains unexpected entry {:?}",
                    entry.file_name()
                )))
            }
        }
    }
    if entries != 2 || !found_database || !found_manifest {
        return Err(storage_error(
            "portable storage bundle is incomplete or contains duplicate entries",
        ));
    }
    Ok(())
}

fn validate_portable_storage_manifest(
    manifest: &PortableStorageManifest,
) -> Result<(), ContextError> {
    if manifest.format_version != PORTABLE_STORAGE_FORMAT_VERSION {
        return Err(storage_error(format!(
            "unsupported portable storage format version {}, expected \
             {PORTABLE_STORAGE_FORMAT_VERSION}",
            manifest.format_version
        )));
    }
    if manifest.payload_format != PORTABLE_STORAGE_PAYLOAD_FORMAT {
        return Err(storage_error(format!(
            "unsupported portable storage payload format {:?}",
            manifest.payload_format
        )));
    }
    if manifest.confidentiality != PORTABLE_STORAGE_CONFIDENTIALITY {
        return Err(storage_error(format!(
            "unsupported portable storage confidentiality declaration {:?}",
            manifest.confidentiality
        )));
    }
    if manifest.database_file != PORTABLE_STORAGE_DATABASE_FILE {
        return Err(storage_error(format!(
            "portable storage database filename {:?} is not supported",
            manifest.database_file
        )));
    }
    if uuid::Uuid::parse_str(&manifest.installation_id).is_err() {
        return Err(storage_error(
            "portable storage installation id is not a UUID",
        ));
    }
    chrono::DateTime::parse_from_rfc3339(&manifest.created_at).map_err(|error| {
        storage_error(format!(
            "portable storage creation timestamp is invalid: {error}"
        ))
    })?;
    if let Some(key_id) = manifest.source_storage_key_id.as_deref() {
        if key_id.is_empty()
            || key_id.len() > 96
            || !key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(storage_error(
                "portable storage source key id has an invalid format",
            ));
        }
    }
    Ok(())
}

fn require_matching_portable_metadata(
    manifest: &PortableStorageManifest,
    metadata: &crate::schema::StorageMetadata,
) -> Result<(), ContextError> {
    if manifest.application_id != metadata.application_id
        || manifest.schema_version != metadata.schema_version
        || manifest.min_reader_schema_version != metadata.min_reader_schema_version
        || manifest.installation_id != metadata.installation_id
    {
        return Err(storage_error(
            "portable storage manifest identity does not match its SQLite payload",
        ));
    }
    Ok(())
}

/// Verify the exact bundle shape, version, complete payload hash, SQLite
/// integrity, schema compatibility, and installation identity.
pub fn verify_portable_storage(bundle_dir: &Path) -> Result<PortableStorageManifest, ContextError> {
    require_real_directory(bundle_dir, "portable storage bundle")?;
    require_portable_storage_contents(bundle_dir)?;
    let manifest =
        read_portable_storage_manifest(&bundle_dir.join(PORTABLE_STORAGE_MANIFEST_FILE))?;
    validate_portable_storage_manifest(&manifest)?;
    let database_path = bundle_dir.join(PORTABLE_STORAGE_DATABASE_FILE);
    let byte_count = require_regular_file(&database_path, "portable storage database")?;
    if byte_count != manifest.byte_count {
        return Err(storage_error(format!(
            "portable storage byte count mismatch: manifest={}, actual={byte_count}",
            manifest.byte_count
        )));
    }
    if sha256_file(&database_path)? != manifest.sha256 {
        return Err(storage_error("portable storage SHA-256 mismatch"));
    }
    let (connection, metadata) = open_verified_database(&database_path, None)?;
    drop(connection);
    require_matching_portable_metadata(&manifest, &metadata)?;
    // Opening the payload must not introduce an untracked SQLite sidecar.
    require_portable_storage_contents(bundle_dir)?;
    Ok(manifest)
}

fn prepare_portable_source(
    database_path: &Path,
    storage_key: Option<&StorageEncryptionKey>,
) -> Result<(Connection, crate::schema::StorageMetadata), ContextError> {
    require_regular_file(database_path, "portable storage source database")?;
    let connection = Connection::open(database_path).map_err(|error| {
        storage_error(format!(
            "failed to open portable storage source {}: {error}",
            database_path.display()
        ))
    })?;
    if let Some(key) = storage_key {
        key.apply(&connection)?;
    }
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| {
            storage_error(format!(
                "failed to set portable storage busy timeout: {error}"
            ))
        })?;
    crate::schema::verify(&connection)?;
    let metadata = crate::schema::read_storage_metadata(&connection)?;
    let (busy, _log_pages, _checkpointed_pages): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| {
            storage_error(format!(
                "failed to checkpoint portable storage source WAL: {error}"
            ))
        })?;
    if busy != 0 {
        return Err(storage_error(
            "portable storage source WAL is busy; stop all database users before export",
        ));
    }
    Ok((connection, metadata))
}

fn sqlcipher_export_to_file(
    source: &Connection,
    destination: &Path,
    destination_key: Option<&StorageEncryptionKey>,
    metadata: &crate::schema::StorageMetadata,
) -> Result<(), ContextError> {
    let destination_text = destination.to_str().ok_or_else(|| {
        storage_error("portable storage database path must be valid UTF-8 for SQLCipher export")
    })?;
    let database_name = if let Some(key) = destination_key {
        source
            .execute("ATTACH DATABASE ?1 AS encrypted", [destination_text])
            .map_err(|error| {
                storage_error(format!(
                    "failed to attach encrypted portable storage destination: {error}"
                ))
            })?;
        key.apply_to_attached(source, "encrypted")?;
        "encrypted"
    } else {
        source
            .execute("ATTACH DATABASE ?1 AS portable KEY ''", [destination_text])
            .map_err(|error| {
                storage_error(format!(
                    "failed to attach plaintext portable storage destination: {error}"
                ))
            })?;
        "portable"
    };
    let export_sql = if destination_key.is_some() {
        "SELECT sqlcipher_export('encrypted')"
    } else {
        "SELECT sqlcipher_export('portable')"
    };
    source
        .query_row(export_sql, [], |_| Ok(()))
        .map_err(|error| storage_error(format!("portable SQLCipher export failed: {error}")))?;
    let attached = rusqlite::DatabaseName::Attached(database_name);
    source
        .pragma_update(Some(attached), "application_id", metadata.application_id)
        .map_err(|error| {
            storage_error(format!(
                "failed to preserve portable storage application id: {error}"
            ))
        })?;
    source
        .pragma_update(Some(attached), "user_version", metadata.schema_version)
        .map_err(|error| {
            storage_error(format!(
                "failed to preserve portable storage schema version: {error}"
            ))
        })?;
    let detach_sql = if destination_key.is_some() {
        "DETACH DATABASE encrypted"
    } else {
        "DETACH DATABASE portable"
    };
    source
        .execute(detach_sql, [])
        .map_err(|error| storage_error(format!("failed to finalize portable storage: {error}")))?;
    set_owner_only_file(destination)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            storage_error(format!(
                "failed to sync portable storage database {}: {error}",
                destination.display()
            ))
        })
}

fn encrypt_portable_payload(
    payload: &Path,
    destination: &Path,
    destination_key: &StorageEncryptionKey,
    metadata: &crate::schema::StorageMetadata,
) -> Result<(), ContextError> {
    let payload_text = payload.to_str().ok_or_else(|| {
        storage_error("portable storage payload path must be valid UTF-8 for SQLCipher import")
    })?;
    let destination_text = destination.to_str().ok_or_else(|| {
        storage_error("portable storage destination path must be valid UTF-8 for SQLCipher import")
    })?;
    let bridge = Connection::open_in_memory().map_err(|error| {
        storage_error(format!(
            "failed to create portable storage import bridge: {error}"
        ))
    })?;
    bridge
        .execute(
            "ATTACH DATABASE ?1 AS portable_source KEY ''",
            [payload_text],
        )
        .map_err(|error| {
            storage_error(format!(
                "failed to attach portable storage import source: {error}"
            ))
        })?;
    bridge
        .query_row(
            "SELECT count(*) FROM portable_source.sqlite_schema",
            [],
            |_| Ok(()),
        )
        .map_err(|error| {
            storage_error(format!(
                "failed to authenticate plaintext portable storage source: {error}"
            ))
        })?;
    bridge
        .execute("ATTACH DATABASE ?1 AS encrypted", [destination_text])
        .map_err(|error| {
            storage_error(format!(
                "failed to attach encrypted portable storage destination: {error}"
            ))
        })?;
    destination_key.apply_to_attached(&bridge, "encrypted")?;
    bridge
        .query_row(
            "SELECT sqlcipher_export('encrypted', 'portable_source')",
            [],
            |_| Ok(()),
        )
        .map_err(|error| storage_error(format!("portable SQLCipher import failed: {error}")))?;
    bridge
        .pragma_update(
            Some(rusqlite::DatabaseName::Attached("encrypted")),
            "application_id",
            metadata.application_id,
        )
        .map_err(|error| {
            storage_error(format!(
                "failed to preserve imported storage application id: {error}"
            ))
        })?;
    bridge
        .pragma_update(
            Some(rusqlite::DatabaseName::Attached("encrypted")),
            "user_version",
            metadata.schema_version,
        )
        .map_err(|error| {
            storage_error(format!(
                "failed to preserve imported storage schema version: {error}"
            ))
        })?;
    bridge
        .execute("DETACH DATABASE encrypted", [])
        .map_err(|error| {
            storage_error(format!(
                "failed to finalize encrypted portable storage import: {error}"
            ))
        })?;
    bridge
        .execute("DETACH DATABASE portable_source", [])
        .map_err(|error| {
            storage_error(format!(
                "failed to release portable storage import source: {error}"
            ))
        })?;
    set_owner_only_file(destination)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            storage_error(format!(
                "failed to sync imported storage database {}: {error}",
                destination.display()
            ))
        })
}

/// Export all durable installation state into an atomically published,
/// owner-only plaintext bundle.
pub fn export_portable_storage(
    database_path: &Path,
    bundle_dir: &Path,
    source_key: Option<&StorageEncryptionKey>,
) -> Result<PortableStorageExportReport, ContextError> {
    let parent = bundle_dir.parent().ok_or_else(|| {
        storage_error("portable storage bundle destination must have a parent directory")
    })?;
    require_real_directory(parent, "portable storage bundle parent")?;
    reject_existing_path(bundle_dir, "portable storage bundle")?;
    let _lease = acquire_storage_lease(database_path)?;
    let (source, metadata) = prepare_portable_source(database_path, source_key)?;

    let staging_dir = parent.join(format!(
        ".portable-storage-{}.staging",
        uuid::Uuid::new_v4()
    ));
    reject_existing_path(&staging_dir, "portable storage staging directory")?;
    fs::create_dir(&staging_dir).map_err(|error| {
        storage_error(format!(
            "failed to create portable storage staging directory {}: {error}",
            staging_dir.display()
        ))
    })?;
    let mut staging_guard = StagingDirectory::new(staging_dir.clone());
    set_owner_only_directory(&staging_dir)?;

    let database_file = staging_dir.join(PORTABLE_STORAGE_DATABASE_FILE);
    sqlcipher_export_to_file(&source, &database_file, None, &metadata)?;
    drop(source);
    let (verified, exported_metadata) = open_verified_database(&database_file, None)?;
    drop(verified);
    if exported_metadata != metadata {
        return Err(storage_error(
            "portable storage identity changed during plaintext export",
        ));
    }
    let byte_count = require_regular_file(&database_file, "portable storage database")?;
    let manifest = PortableStorageManifest {
        format_version: PORTABLE_STORAGE_FORMAT_VERSION,
        payload_format: PORTABLE_STORAGE_PAYLOAD_FORMAT.into(),
        confidentiality: PORTABLE_STORAGE_CONFIDENTIALITY.into(),
        database_file: PORTABLE_STORAGE_DATABASE_FILE.into(),
        application_id: metadata.application_id,
        schema_version: metadata.schema_version,
        min_reader_schema_version: metadata.min_reader_schema_version,
        installation_id: metadata.installation_id,
        created_at: Utc::now().to_rfc3339(),
        byte_count,
        sha256: sha256_file(&database_file)?,
        source_storage_key_id: source_key.map(|key| key.key_id().to_owned()),
    };
    write_portable_storage_manifest(&staging_dir.join(PORTABLE_STORAGE_MANIFEST_FILE), &manifest)?;
    sync_directory(&staging_dir)?;
    let verified_manifest = verify_portable_storage(&staging_dir)?;
    if verified_manifest != manifest {
        return Err(storage_error(
            "portable storage manifest changed before publication",
        ));
    }
    reject_existing_path(bundle_dir, "portable storage bundle")?;
    fs::rename(&staging_dir, bundle_dir).map_err(|error| {
        storage_error(format!(
            "failed to publish portable storage bundle {}: {error}",
            bundle_dir.display()
        ))
    })?;
    if let Err(error) = sync_directory(parent) {
        fs::rename(bundle_dir, &staging_dir).map_err(|rollback_error| {
            storage_error(format!(
                "portable storage publication was not durable ({error}); reverting it also \
                 failed: {rollback_error}"
            ))
        })?;
        return Err(error);
    }
    staging_guard.disarm();
    Ok(PortableStorageExportReport {
        bundle_dir: bundle_dir.to_path_buf(),
        manifest,
    })
}

/// Import a verified portable bundle into a fresh database, optionally
/// encrypting it under a destination key before atomic publication.
pub fn import_portable_storage(
    bundle_dir: &Path,
    destination_database: &Path,
    destination_key: Option<&StorageEncryptionKey>,
) -> Result<PortableStorageImportReport, ContextError> {
    let manifest = verify_portable_storage(bundle_dir)?;
    let parent = destination_database.parent().ok_or_else(|| {
        storage_error("portable storage import destination must have a parent directory")
    })?;
    require_real_directory(parent, "portable storage import parent")?;
    reject_existing_path(destination_database, "portable storage import destination")?;
    let _lease = acquire_storage_lease(destination_database)?;

    let stage = companion_path(
        destination_database,
        &format!(".portable-import-{}.staging", uuid::Uuid::new_v4()),
    );
    reject_existing_path(&stage, "portable storage import staging file")?;
    let mut stage_guard = StagingFile::new(stage.clone());
    let payload = bundle_dir.join(PORTABLE_STORAGE_DATABASE_FILE);
    if let Some(key) = destination_key {
        let (source, metadata) = open_verified_database(&payload, None)?;
        drop(source);
        require_matching_portable_metadata(&manifest, &metadata)?;
        encrypt_portable_payload(&payload, &stage, key, &metadata)?;
    } else {
        copy_to_new_file(&payload, &stage)?;
    }
    set_owner_only_file(&stage)?;
    let (verified, metadata) = open_verified_database(&stage, destination_key)?;
    drop(verified);
    require_matching_portable_metadata(&manifest, &metadata)?;
    // Revalidate the independently supplied bundle immediately before publish.
    if verify_portable_storage(bundle_dir)? != manifest {
        return Err(storage_error(
            "portable storage bundle changed during import",
        ));
    }
    reject_existing_path(destination_database, "portable storage import destination")?;
    fs::rename(&stage, destination_database).map_err(|error| {
        storage_error(format!(
            "failed to publish portable storage import {}: {error}",
            destination_database.display()
        ))
    })?;
    let publication = (|| {
        sync_directory(parent)?;
        let (published, published_metadata) =
            open_verified_database(destination_database, destination_key)?;
        drop(published);
        require_matching_portable_metadata(&manifest, &published_metadata)
    })();
    if let Err(error) = publication {
        fs::rename(destination_database, &stage).map_err(|rollback_error| {
            storage_error(format!(
                "portable storage import failed after publication ({error}); reverting it also \
                 failed: {rollback_error}"
            ))
        })?;
        sync_directory(parent)?;
        return Err(error);
    }
    stage_guard.disarm();
    Ok(PortableStorageImportReport {
        bundle_dir: bundle_dir.to_path_buf(),
        database_path: destination_database.to_path_buf(),
        format_version: manifest.format_version,
        schema_version: manifest.schema_version,
        installation_id: manifest.installation_id,
        byte_count: require_regular_file(
            destination_database,
            "portable storage import destination",
        )?,
        destination_storage_key_id: destination_key.map(|key| key.key_id().to_owned()),
    })
}

/// Verify manifest integrity, the complete database hash, physical SQLite
/// integrity, schema compatibility, foreign keys, and installation identity.
pub fn verify_backup(backup_dir: &Path) -> Result<BackupManifest, ContextError> {
    verify_backup_internal(backup_dir, None, None)
}

/// Verify an encrypted backup with its independently retained storage key.
pub fn verify_backup_with_storage_key(
    backup_dir: &Path,
    storage_key: &StorageEncryptionKey,
) -> Result<BackupManifest, ContextError> {
    verify_backup_internal(backup_dir, None, Some(storage_key))
}

fn verify_backup_internal(
    backup_dir: &Path,
    trust: Option<&BackupTrustRoot>,
    storage_key: Option<&StorageEncryptionKey>,
) -> Result<BackupManifest, ContextError> {
    require_real_directory(backup_dir, "backup")?;
    let manifest_path = backup_dir.join(BACKUP_MANIFEST_FILE);
    let manifest = read_manifest(&manifest_path)?;
    if !matches!(
        manifest.format_version,
        LEGACY_BACKUP_FORMAT_VERSION | BACKUP_FORMAT_VERSION
    ) {
        return Err(storage_error(format!(
            "unsupported backup format version {}, expected {} or {BACKUP_FORMAT_VERSION}",
            manifest.format_version, LEGACY_BACKUP_FORMAT_VERSION
        )));
    }
    if manifest.format_version == LEGACY_BACKUP_FORMAT_VERSION && manifest.encryption.is_some() {
        return Err(storage_error(
            "legacy backup format cannot declare storage encryption",
        ));
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
    if let Some(authenticity) = &manifest.authenticity {
        validate_authenticity(authenticity)?;
    }
    match (&manifest.encryption, storage_key) {
        (Some(encryption), Some(key)) => {
            validate_backup_encryption(encryption)?;
            if encryption.key_id != key.key_id() {
                return Err(storage_error(format!(
                    "backup requires storage key {:?}, not supplied key {:?}",
                    encryption.key_id,
                    key.key_id()
                )));
            }
        }
        (Some(encryption), None) => {
            validate_backup_encryption(encryption)?;
            return Err(storage_error(format!(
                "backup is encrypted with storage key {:?}; supply that independently retained key",
                encryption.key_id
            )));
        }
        (None, Some(_)) => {
            return Err(storage_error(
                "backup manifest declares plaintext storage but an encryption key was supplied",
            ));
        }
        (None, None) => {}
    }

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

    let (_connection, metadata) = open_verified_database(&database_path, storage_key)?;
    if manifest.application_id != metadata.application_id
        || manifest.schema_version != metadata.schema_version
        || manifest.installation_id != metadata.installation_id
    {
        return Err(storage_error(
            "backup manifest identity does not match the SQLite storage metadata",
        ));
    }
    if let Some(trust) = trust {
        trust.verify_manifest(&manifest)?;
    }
    Ok(manifest)
}

/// Verify backup integrity and require an Ed25519 signature from an
/// independently supplied trust root.
pub fn verify_backup_authenticity(
    backup_dir: &Path,
    trust: &BackupTrustRoot,
) -> Result<BackupManifest, ContextError> {
    verify_backup_internal(backup_dir, Some(trust), None)
}

/// Verify an encrypted backup and require its independently retained signing
/// trust root.
pub fn verify_backup_with_storage_key_and_trust(
    backup_dir: &Path,
    storage_key: &StorageEncryptionKey,
    trust: &BackupTrustRoot,
) -> Result<BackupManifest, ContextError> {
    verify_backup_internal(backup_dir, Some(trust), Some(storage_key))
}

fn verify_backup_recovery_anchor_internal(
    backup_dir: &Path,
    storage_key: Option<&StorageEncryptionKey>,
    trust: &BackupTrustRoot,
    anchor: &BackupRecoveryAnchor,
) -> Result<BackupManifest, ContextError> {
    validate_backup_recovery_anchor(anchor)?;
    let manifest_before = backup_manifest_bytes(backup_dir)?;
    let manifest = verify_backup_internal(backup_dir, Some(trust), storage_key)?;
    let manifest_after = backup_manifest_bytes(backup_dir)?;
    if manifest_before != manifest_after {
        return Err(storage_error(
            "backup manifest changed during recovery-anchor verification",
        ));
    }
    let observed = recovery_anchor_for_manifest(&manifest, &manifest_after)?;
    if observed != *anchor {
        return Err(storage_error(
            "backup does not match the independently retained recovery anchor",
        ));
    }
    Ok(manifest)
}

/// Verify a signed backup against one independently retained exact recovery
/// point. `storage_key` is required when the manifest declares SQLCipher.
pub fn verify_backup_with_recovery_anchor(
    backup_dir: &Path,
    storage_key: Option<&StorageEncryptionKey>,
    trust: &BackupTrustRoot,
    anchor: &BackupRecoveryAnchor,
) -> Result<BackupManifest, ContextError> {
    verify_backup_recovery_anchor_internal(backup_dir, storage_key, trust, anchor)
}

/// Verify a signed backup and publish a non-overwriting, owner-only recovery
/// anchor outside that backup directory.
pub fn generate_backup_recovery_anchor(
    backup_dir: &Path,
    storage_key: Option<&StorageEncryptionKey>,
    trust: &BackupTrustRoot,
    anchor_path: &Path,
) -> Result<BackupRecoveryAnchor, ContextError> {
    require_anchor_outside_backup(backup_dir, anchor_path)?;
    reject_existing_path(anchor_path, "backup recovery anchor")?;
    let manifest_before = backup_manifest_bytes(backup_dir)?;
    let manifest = verify_backup_internal(backup_dir, Some(trust), storage_key)?;
    let manifest_after = backup_manifest_bytes(backup_dir)?;
    if manifest_before != manifest_after {
        return Err(storage_error(
            "backup manifest changed while creating a recovery anchor",
        ));
    }
    let anchor = recovery_anchor_for_manifest(&manifest, &manifest_after)?;
    let mut encoded = serde_json::to_vec_pretty(&anchor).map_err(|error| {
        storage_error(format!("failed to encode backup recovery anchor: {error}"))
    })?;
    encoded.push(b'\n');
    write_new_owner_only_file(anchor_path, &encoded, "backup recovery anchor")?;
    let persisted = load_independent_backup_recovery_anchor(backup_dir, anchor_path);
    match persisted {
        Ok(persisted) if persisted == anchor => Ok(anchor),
        Ok(_) => {
            let _ = fs::remove_file(anchor_path);
            let parent = anchor_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let _ = sync_directory(parent);
            Err(storage_error(
                "persisted backup recovery anchor failed exact verification",
            ))
        }
        Err(error) => {
            let _ = fs::remove_file(anchor_path);
            let parent = anchor_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let _ = sync_directory(parent);
            Err(error)
        }
    }
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
    storage_key: Option<&StorageEncryptionKey>,
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
    let staged_manifest = verify_backup_internal(&tombstone, None, storage_key)?;
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
        self.create_backup_internal(backup_root, name, None)
    }

    /// Create and atomically publish a signed WAL-consistent online backup.
    pub fn create_signed_backup(
        &self,
        backup_root: &Path,
        name: &str,
        signer: &BackupSigningKey,
    ) -> Result<BackupManifest, ContextError> {
        self.create_backup_internal(backup_root, name, Some(signer))
    }

    fn create_backup_internal(
        &self,
        backup_root: &Path,
        name: &str,
        signer: Option<&BackupSigningKey>,
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
            let encryption_key = self.storage_encryption_key();
            {
                let connection = self
                    .conn
                    .lock()
                    .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
                let mut destination = Connection::open(&database_path).map_err(|error| {
                    storage_error(format!("failed to create backup database: {error}"))
                })?;
                if let Some(key) = encryption_key.as_deref() {
                    key.apply(&destination)?;
                }
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

            let (verified, metadata) =
                open_verified_database(&database_path, encryption_key.as_deref())?;
            // Windows does not allow the staging directory to be renamed while
            // this read-only SQLite handle remains open.
            drop(verified);
            let byte_count = require_regular_file(&database_path, "backup database")?;
            let mut manifest = BackupManifest {
                format_version: BACKUP_FORMAT_VERSION,
                database_file: BACKUP_DATABASE_FILE.to_string(),
                application_id: metadata.application_id,
                schema_version: metadata.schema_version,
                installation_id: metadata.installation_id,
                created_at: Utc::now().to_rfc3339(),
                byte_count,
                sha256: sha256_file(&database_path)?,
                encryption: encryption_key.as_deref().map(|key| BackupEncryption {
                    format_version: BACKUP_ENCRYPTION_FORMAT_VERSION,
                    algorithm: BACKUP_ENCRYPTION_ALGORITHM.into(),
                    key_id: key.key_id().into(),
                }),
                authenticity: None,
            };
            if let Some(signer) = signer {
                signer.sign_manifest(&mut manifest)?;
            }
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

    fn backup_key_for_manifest(
        &self,
        manifest: &BackupManifest,
    ) -> Result<Option<std::sync::Arc<StorageEncryptionKey>>, ContextError> {
        match manifest.encryption.as_ref() {
            Some(encryption) => self
                .storage_backup_encryption_key(&encryption.key_id)
                .map(Some)
                .ok_or_else(|| {
                    storage_error(format!(
                        "backup requires unavailable retired storage key {:?}",
                        encryption.key_id
                    ))
                }),
            None => Ok(None),
        }
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
            let declared_manifest = match read_manifest(&entry.path().join(BACKUP_MANIFEST_FILE)) {
                Ok(manifest) => manifest,
                Err(error) => {
                    skipped.push(BackupRetentionIssue {
                        name,
                        reason: format!("verification failed: {error}"),
                    });
                    continue;
                }
            };
            let verification_key = match self.backup_key_for_manifest(&declared_manifest) {
                Ok(key) => key,
                Err(error) => {
                    skipped.push(BackupRetentionIssue {
                        name,
                        reason: format!("verification failed: {error}"),
                    });
                    continue;
                }
            };
            let manifest =
                match verify_backup_internal(&entry.path(), None, verification_key.as_deref()) {
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
                let verification_key = self.backup_key_for_manifest(manifest)?;
                delete_verified_backup(backup_root, entry, manifest, verification_key.as_deref())?;
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

    /// Preflight and remove every backup from one managed installation root.
    ///
    /// Unlike age-based retention, erasure cannot skip an entry and continue:
    /// an unverified directory might still contain recoverable subject data.
    /// The complete root is therefore validated before the first deletion, and
    /// any unknown, unsafe, corrupt, foreign, or unavailable-key entry aborts
    /// the operation while the live database remains untouched.
    pub fn begin_managed_backup_erasure(
        &self,
        backup_root: &Path,
    ) -> Result<BackupErasureGuard, ContextError> {
        prepare_backup_root(backup_root)?;
        let publication_lock = acquire_backup_publication_lock(backup_root)?;
        let installation_id = {
            let connection = self
                .conn
                .lock()
                .map_err(|_| storage_error("SQLite connection mutex is poisoned"))?;
            crate::schema::read_storage_metadata(&connection)?.installation_id
        };
        let mut verified = Vec::new();
        let mut scanned = 0_usize;

        for entry in fs::read_dir(backup_root).map_err(|error| {
            storage_error(format!(
                "failed to enumerate managed backup root {}: {error}",
                backup_root.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                storage_error(format!(
                    "failed to enumerate managed backup root {}: {error}",
                    backup_root.display()
                ))
            })?;
            scanned += 1;
            if scanned > MAX_BACKUP_ROOT_ENTRIES {
                return Err(storage_error(format!(
                    "managed backup root exceeds the scan limit of {MAX_BACKUP_ROOT_ENTRIES} entries"
                )));
            }
            let name = bounded_entry_name(&entry);
            if name == ".agentos-backup.lock" {
                continue;
            }
            validate_backup_name(&name).map_err(|_| {
                storage_error(format!(
                    "managed backup root contains unknown entry {name:?}; erasure is refused"
                ))
            })?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                storage_error(format!(
                    "failed to inspect managed backup entry {name:?}: {error}"
                ))
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(storage_error(format!(
                    "managed backup entry {name:?} is not a real backup directory"
                )));
            }
            let declared_manifest = read_manifest(&entry.path().join(BACKUP_MANIFEST_FILE))
                .map_err(|error| {
                    storage_error(format!(
                        "managed backup {name:?} cannot be verified for erasure: {error}"
                    ))
                })?;
            let verification_key =
                self.backup_key_for_manifest(&declared_manifest)
                    .map_err(|error| {
                        storage_error(format!(
                            "managed backup {name:?} cannot be verified for erasure: {error}"
                        ))
                    })?;
            let manifest = verify_backup_internal(&entry.path(), None, verification_key.as_deref())
                .map_err(|error| {
                    storage_error(format!(
                        "managed backup {name:?} cannot be verified for erasure: {error}"
                    ))
                })?;
            if manifest.installation_id != installation_id {
                return Err(storage_error(format!(
                    "managed backup {name:?} belongs to a different installation; erasure is refused"
                )));
            }
            require_removable_backup_contents(&entry.path()).map_err(|error| {
                storage_error(format!(
                    "managed backup {name:?} cannot be removed safely: {error}"
                ))
            })?;
            verified.push((
                BackupRetentionEntry {
                    name,
                    created_at: manifest.created_at.clone(),
                    byte_count: manifest.byte_count,
                },
                manifest,
            ));
        }

        verified.sort_by(|(left, _), (right, _)| left.name.cmp(&right.name));
        let mut deleted = Vec::with_capacity(verified.len());
        for (entry, manifest) in &verified {
            let verification_key = self.backup_key_for_manifest(manifest)?;
            delete_verified_backup(backup_root, entry, manifest, verification_key.as_deref())?;
            deleted.push(entry.clone());
        }

        for entry in fs::read_dir(backup_root).map_err(|error| {
            storage_error(format!(
                "failed to verify managed backup root after erasure purge: {error}"
            ))
        })? {
            let entry = entry.map_err(|error| {
                storage_error(format!(
                    "failed to verify managed backup root after erasure purge: {error}"
                ))
            })?;
            if bounded_entry_name(&entry) != ".agentos-backup.lock" {
                return Err(storage_error(
                    "managed backup root changed during erasure purge",
                ));
            }
        }
        sync_directory(backup_root)?;
        Ok(BackupErasureGuard {
            _publication_lock: publication_lock,
            root: backup_root.to_path_buf(),
            deleted,
        })
    }
}

fn checkpoint_existing_database(
    path: &Path,
    storage_key: Option<&StorageEncryptionKey>,
) -> Result<(), ContextError> {
    require_regular_file(path, "restore destination database")?;
    let connection = Connection::open(path).map_err(|error| {
        storage_error(format!(
            "failed to open restore destination {}: {error}",
            path.display()
        ))
    })?;
    if let Some(key) = storage_key {
        key.apply(&connection)?;
    }
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
    restore_backup_internal(
        backup_dir,
        destination_database,
        None,
        None,
        None,
        |_, lease| Ok(lease),
    )
    .map(|(report, _lease)| report)
}

/// Restore a backup only after it passes integrity and trusted-signature
/// verification.
pub fn restore_backup_with_trust(
    backup_dir: &Path,
    destination_database: &Path,
    trust: &BackupTrustRoot,
) -> Result<RestoreReport, ContextError> {
    restore_backup_internal(
        backup_dir,
        destination_database,
        Some(trust),
        None,
        None,
        |_, lease| Ok(lease),
    )
    .map(|(report, _lease)| report)
}

/// Restore an encrypted backup while authenticating both the snapshot and any
/// existing destination with the independently retained storage key.
pub fn restore_backup_with_storage_key(
    backup_dir: &Path,
    destination_database: &Path,
    storage_key: &StorageEncryptionKey,
) -> Result<RestoreReport, ContextError> {
    restore_backup_internal(
        backup_dir,
        destination_database,
        None,
        Some(storage_key),
        None,
        |_, lease| Ok(lease),
    )
    .map(|(report, _lease)| report)
}

/// Restore an encrypted, signed backup only after both storage-key and
/// trusted-signature verification succeed.
pub fn restore_backup_with_storage_key_and_trust(
    backup_dir: &Path,
    destination_database: &Path,
    storage_key: &StorageEncryptionKey,
    trust: &BackupTrustRoot,
) -> Result<RestoreReport, ContextError> {
    restore_backup_internal(
        backup_dir,
        destination_database,
        Some(trust),
        Some(storage_key),
        None,
        |_, lease| Ok(lease),
    )
    .map(|(report, _lease)| report)
}

/// Restore one exact signed recovery point pinned by independent anchor
/// custody. The anchor is rechecked immediately before any existing
/// destination is moved.
pub fn restore_backup_with_recovery_anchor(
    backup_dir: &Path,
    destination_database: &Path,
    storage_key: Option<&StorageEncryptionKey>,
    trust: &BackupTrustRoot,
    anchor: &BackupRecoveryAnchor,
) -> Result<RestoreReport, ContextError> {
    restore_backup_internal(
        backup_dir,
        destination_database,
        Some(trust),
        storage_key,
        Some(anchor),
        |_, lease| Ok(lease),
    )
    .map(|(report, _lease)| report)
}

/// Restore a trusted backup to the database selected by `config`, then boot the
/// complete configured kernel before discarding the previous database.
///
/// This compatibility path authenticates provenance but does not pin an exact
/// recovery point. Production operators should use
/// [`recover_backup_from_config_with_anchor`]. If schema verification,
/// configured key loading, service recovery, budget reconstruction, or any
/// persisted agent's enforcement re-admission fails, a replacement restore is
/// rolled back and a fresh-host destination is removed.
pub fn recover_backup_from_config(
    backup_dir: &Path,
    config: &crate::config::Config,
    trust: &BackupTrustRoot,
) -> Result<DisasterRecoveryReport, ContextError> {
    recover_backup_from_config_internal(backup_dir, config, trust, None)
}

/// Production disaster recovery for one exact independently anchored signed
/// backup. This rejects an older or replaced valid snapshot before mutation.
pub fn recover_backup_from_config_with_anchor(
    backup_dir: &Path,
    config: &crate::config::Config,
    trust: &BackupTrustRoot,
    anchor: &BackupRecoveryAnchor,
) -> Result<DisasterRecoveryReport, ContextError> {
    recover_backup_from_config_internal(backup_dir, config, trust, Some(anchor))
}

fn recover_backup_from_config_internal(
    backup_dir: &Path,
    config: &crate::config::Config,
    trust: &BackupTrustRoot,
    anchor: Option<&BackupRecoveryAnchor>,
) -> Result<DisasterRecoveryReport, ContextError> {
    if !config.data_dir.is_absolute() {
        return Err(storage_error(
            "disaster recovery requires an absolute configured data_dir",
        ));
    }
    let destination_database = config.data_dir.join(BACKUP_DATABASE_FILE);
    let storage_key = config
        .storage_encryption
        .key_path
        .as_deref()
        .map(crate::storage_encryption::load_storage_encryption_key)
        .transpose()?;
    let (restore, (persisted_agent_count, _qualified_kernel)) = restore_backup_internal(
        backup_dir,
        &destination_database,
        Some(trust),
        storage_key.as_ref(),
        anchor,
        |_, storage_lease| qualify_recovered_database(config, storage_lease),
    )?;
    Ok(DisasterRecoveryReport {
        restore,
        persisted_agent_count,
        enforcement_rearmed: true,
    })
}

fn qualify_recovered_database(
    config: &crate::config::Config,
    storage_lease: StorageLease,
) -> Result<(usize, crate::AgentKernelImpl), ContextError> {
    let kernel = crate::AgentKernelImpl::from_config_with_storage_lease(config, storage_lease)
        .map_err(|error| {
            storage_error(format!(
                "restored database failed configured kernel qualification: {error}"
            ))
        })?;
    let persisted = kernel.context_manager.load_all_agents()?;
    for agent in &persisted {
        kernel.get_agent_status(agent.id).map_err(|error| {
            storage_error(format!(
                "restored agent {} was not re-admitted to enforcement: {error}",
                agent.id
            ))
        })?;
    }
    Ok((persisted.len(), kernel))
}

/// Replace an unreadable configured database with a signed backup while
/// preserving every original SQLite file for forensic custody.
///
/// This deliberately does not weaken [`restore_backup`]. The destination must
/// exist, must fail complete AIagentOS database verification, and must be
/// offline. The caller supplies the expected installation UUID independently
/// so a signed backup from another installation cannot be substituted merely
/// because corruption made the local identity unreadable.
///
/// A durable journal makes interruption resumable. On an ordinary error after
/// quarantine begins, the corrupt database is restored automatically and the
/// failed candidate is retained in the quarantine directory.
pub fn recover_corrupt_storage_from_config(
    backup_dir: &Path,
    config: &crate::config::Config,
    trust: &BackupTrustRoot,
    expected_installation_id: &str,
) -> Result<CorruptStorageRecoveryReport, ContextError> {
    recover_corrupt_storage_from_config_internal(
        backup_dir,
        config,
        trust,
        None,
        expected_installation_id,
    )
}

/// Recover corrupt storage from one exact independently anchored signed backup.
pub fn recover_corrupt_storage_from_config_with_anchor(
    backup_dir: &Path,
    config: &crate::config::Config,
    trust: &BackupTrustRoot,
    anchor: &BackupRecoveryAnchor,
    expected_installation_id: &str,
) -> Result<CorruptStorageRecoveryReport, ContextError> {
    recover_corrupt_storage_from_config_internal(
        backup_dir,
        config,
        trust,
        Some(anchor),
        expected_installation_id,
    )
}

fn recover_corrupt_storage_from_config_internal(
    backup_dir: &Path,
    config: &crate::config::Config,
    trust: &BackupTrustRoot,
    recovery_anchor: Option<&BackupRecoveryAnchor>,
    expected_installation_id: &str,
) -> Result<CorruptStorageRecoveryReport, ContextError> {
    if !config.data_dir.is_absolute() {
        return Err(storage_error(
            "corrupt storage recovery requires an absolute configured data_dir",
        ));
    }
    uuid::Uuid::parse_str(expected_installation_id)
        .map_err(|_| storage_error("expected installation id must be a UUID"))?;
    let destination = config.data_dir.join(BACKUP_DATABASE_FILE);
    let parent = destination
        .parent()
        .ok_or_else(|| storage_error("recovery destination must have a parent directory"))?;
    require_real_directory(parent, "corrupt recovery destination parent")?;
    let storage_key = config
        .storage_encryption
        .key_path
        .as_deref()
        .map(crate::storage_encryption::load_storage_encryption_key)
        .transpose()?;
    let manifest = match recovery_anchor {
        Some(anchor) => {
            verify_backup_recovery_anchor_internal(backup_dir, storage_key.as_ref(), trust, anchor)?
        }
        None => verify_backup_internal(backup_dir, Some(trust), storage_key.as_ref())?,
    };
    if manifest.installation_id != expected_installation_id {
        return Err(storage_error(format!(
            "trusted backup installation id {} does not match expected installation id",
            manifest.installation_id
        )));
    }

    let storage_lease = acquire_storage_lease(&destination)?;
    let journal_path = companion_path(&destination, CORRUPT_RECOVERY_JOURNAL_SUFFIX);
    let (journal, resumed) = match optional_regular_file_exists(
        &journal_path,
        "corrupt recovery journal",
    )? {
        true => (
            load_corrupt_recovery_journal(
                &journal_path,
                &destination,
                &manifest,
                expected_installation_id,
            )?,
            true,
        ),
        false => {
            require_regular_file(&destination, "corrupt recovery destination database")?;
            if destination_verifies_without_mutation(&destination, storage_key.as_ref())? {
                return Err(storage_error(
                    "corrupt recovery refuses a healthy verified destination; use normal offline restore",
                ));
            }
            let original_wal = optional_regular_file_exists(
                &companion_path(&destination, "-wal"),
                "corrupt destination WAL",
            )?;
            let original_shm = optional_regular_file_exists(
                &companion_path(&destination, "-shm"),
                "corrupt destination SHM",
            )?;
            let operation_id = uuid::Uuid::new_v4();
            let database_file = recovery_filename(&destination, "database")?;
            let stage_file = format!(".{database_file}.corrupt-recovery-{operation_id}.staging");
            let quarantine_dir =
                format!(".{database_file}.corrupt-recovery-{operation_id}.quarantine");
            let quarantine_path = parent.join(&quarantine_dir);
            reject_existing_path(&quarantine_path, "corrupt recovery quarantine")?;
            fs::create_dir(&quarantine_path).map_err(|error| {
                storage_error(format!(
                    "failed to create corrupt recovery quarantine {}: {error}",
                    quarantine_path.display()
                ))
            })?;
            let journal = CorruptRecoveryJournal {
                format_version: CORRUPT_RECOVERY_FORMAT_VERSION,
                database_file,
                stage_file,
                quarantine_dir,
                quarantined_database_file: "corrupt-database.sqlite3".to_owned(),
                quarantined_wal_file: "corrupt-database.sqlite3-wal".to_owned(),
                quarantined_shm_file: "corrupt-database.sqlite3-shm".to_owned(),
                installation_id: manifest.installation_id.clone(),
                backup_sha256: manifest.sha256.clone(),
                backup_byte_count: manifest.byte_count,
                original_wal,
                original_shm,
            };
            if let Err(error) = (|| {
                set_owner_only_directory(&quarantine_path)?;
                sync_directory(parent)?;
                write_corrupt_recovery_journal(&journal_path, &journal)
            })() {
                let _ = fs::remove_dir(&quarantine_path);
                return Err(error);
            }
            (journal, false)
        }
    };

    let quarantine = parent.join(&journal.quarantine_dir);
    require_real_directory(&quarantine, "corrupt recovery quarantine")?;
    verify_owner_only_directory(&quarantine)?;
    let stage = parent.join(&journal.stage_file);
    let quarantined_database = quarantine.join(&journal.quarantined_database_file);
    let source_wal = companion_path(&destination, "-wal");
    let source_shm = companion_path(&destination, "-shm");
    let quarantined_wal = quarantine.join(&journal.quarantined_wal_file);
    let quarantined_shm = quarantine.join(&journal.quarantined_shm_file);
    let mut mutation_started = quarantined_database.exists();

    let recovery = (|| {
        let destination_exists =
            optional_regular_file_exists(&destination, "corrupt recovery destination database")?;
        let quarantined_exists =
            optional_regular_file_exists(&quarantined_database, "quarantined database")?;
        if destination_exists && quarantined_exists {
            preserve_interrupted_candidate_sidecar(
                &source_wal,
                &quarantine.join("interrupted-candidate.sqlite3-wal"),
                "WAL",
            )?;
            preserve_interrupted_candidate_sidecar(
                &source_shm,
                &quarantine.join("interrupted-candidate.sqlite3-shm"),
                "SHM",
            )?;
            verify_recovery_candidate(&destination, &manifest, storage_key.as_ref())?;
            validate_quarantined_original_sidecar(&quarantined_wal, journal.original_wal, "WAL")?;
            validate_quarantined_original_sidecar(&quarantined_shm, journal.original_shm, "SHM")?;
        } else if destination_exists {
            fs::rename(&destination, &quarantined_database).map_err(|error| {
                storage_error(format!(
                    "failed to quarantine corrupt database {}: {error}",
                    destination.display()
                ))
            })?;
            mutation_started = true;
        } else if !quarantined_exists {
            return Err(storage_error(
                "corrupt recovery journal exists but neither original nor quarantined database exists",
            ));
        }

        if !(destination_exists && quarantined_exists) {
            reconcile_quarantined_sidecar(
                &source_wal,
                &quarantined_wal,
                journal.original_wal,
                "WAL",
            )?;
            reconcile_quarantined_sidecar(
                &source_shm,
                &quarantined_shm,
                journal.original_shm,
                "SHM",
            )?;
        }
        sync_directory(&quarantine)?;
        sync_directory(parent)?;

        if !destination.exists() {
            if optional_regular_file_exists(&stage, "corrupt recovery staging database")? {
                verify_recovery_candidate(&stage, &manifest, storage_key.as_ref())?;
            } else {
                copy_to_new_file(&backup_dir.join(BACKUP_DATABASE_FILE), &stage)?;
                verify_recovery_candidate(&stage, &manifest, storage_key.as_ref())?;
            }
            fs::rename(&stage, &destination).map_err(|error| {
                storage_error(format!(
                    "failed to publish corrupt recovery database {}: {error}",
                    destination.display()
                ))
            })?;
            sync_directory(parent)?;
        }
        verify_recovery_candidate(&destination, &manifest, storage_key.as_ref())?;
        let qualification_lease = storage_lease.try_clone().map_err(|error| {
            storage_error(format!(
                "failed to retain storage lease during corrupt recovery qualification: {error}"
            ))
        })?;
        qualify_recovered_database(config, qualification_lease)
    })();

    let (persisted_agent_count, qualified_kernel) = match recovery {
        Ok(qualified) => qualified,
        Err(error) if mutation_started => {
            return match rollback_corrupt_recovery(
                parent,
                &destination,
                &stage,
                &quarantine,
                &quarantined_database,
                &quarantined_wal,
                &quarantined_shm,
                journal.original_wal,
                journal.original_shm,
                &journal_path,
            ) {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(storage_error(format!(
                    "corrupt storage recovery failed ({error}); automatic rollback also failed: \
                     {rollback_error}; inspect recovery state and journal path {}",
                    journal_path.display()
                ))),
            };
        }
        Err(error) => return Err(error),
    };

    fs::remove_file(&journal_path).map_err(|error| {
        storage_error(format!(
            "recovered database qualified but recovery journal {} could not be removed: {error}",
            journal_path.display()
        ))
    })?;
    let journal_cleanup_durable = sync_directory(parent).is_ok();
    drop(qualified_kernel);
    Ok(CorruptStorageRecoveryReport {
        manifest,
        database_path: destination,
        quarantine_dir: quarantine,
        original_wal_preserved: journal.original_wal,
        original_shm_preserved: journal.original_shm,
        resumed_interrupted_recovery: resumed,
        journal_cleanup_durable,
        persisted_agent_count,
        enforcement_rearmed: true,
    })
}

fn recovery_filename(path: &Path, label: &str) -> Result<String, ContextError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| storage_error(format!("{label} path requires a non-empty UTF-8 filename")))
}

fn validate_recovery_basename(name: &str, label: &str) -> Result<(), ContextError> {
    if name.is_empty()
        || name.len() > 512
        || Path::new(name).file_name().and_then(|value| value.to_str()) != Some(name)
    {
        return Err(storage_error(format!(
            "corrupt recovery journal {label} filename is invalid"
        )));
    }
    Ok(())
}

fn write_corrupt_recovery_journal(
    path: &Path,
    journal: &CorruptRecoveryJournal,
) -> Result<(), ContextError> {
    let mut encoded = serde_json::to_vec_pretty(journal).map_err(|error| {
        storage_error(format!(
            "failed to encode corrupt recovery journal: {error}"
        ))
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_CORRUPT_RECOVERY_JOURNAL_BYTES {
        return Err(storage_error("corrupt recovery journal exceeds size limit"));
    }
    write_new_owner_only_file(path, &encoded, "corrupt recovery journal")
}

fn load_corrupt_recovery_journal(
    path: &Path,
    destination: &Path,
    manifest: &BackupManifest,
    expected_installation_id: &str,
) -> Result<CorruptRecoveryJournal, ContextError> {
    let encoded = read_bounded_regular_file(
        path,
        "corrupt recovery journal",
        MAX_CORRUPT_RECOVERY_JOURNAL_BYTES,
        true,
    )?;
    let journal: CorruptRecoveryJournal = serde_json::from_slice(&encoded)
        .map_err(|_| storage_error("corrupt recovery journal is not valid bounded JSON"))?;
    if journal.format_version != CORRUPT_RECOVERY_FORMAT_VERSION {
        return Err(storage_error(format!(
            "unsupported corrupt recovery journal version {}",
            journal.format_version
        )));
    }
    for (label, name) in [
        ("database", &journal.database_file),
        ("stage", &journal.stage_file),
        ("quarantine", &journal.quarantine_dir),
        ("quarantined database", &journal.quarantined_database_file),
        ("quarantined WAL", &journal.quarantined_wal_file),
        ("quarantined SHM", &journal.quarantined_shm_file),
    ] {
        validate_recovery_basename(name, label)?;
    }
    if journal.database_file != recovery_filename(destination, "database")?
        || journal.installation_id != expected_installation_id
        || journal.installation_id != manifest.installation_id
        || journal.backup_sha256 != manifest.sha256
        || journal.backup_byte_count != manifest.byte_count
    {
        return Err(storage_error(
            "corrupt recovery journal does not match the destination or trusted backup",
        ));
    }
    if path != companion_path(destination, CORRUPT_RECOVERY_JOURNAL_SUFFIX) {
        return Err(storage_error(
            "corrupt recovery journal path does not match the destination",
        ));
    }
    let operation_prefix = format!(".{}.corrupt-recovery-", journal.database_file);
    let stage_operation = journal
        .stage_file
        .strip_prefix(&operation_prefix)
        .and_then(|value| value.strip_suffix(".staging"));
    let quarantine_operation = journal
        .quarantine_dir
        .strip_prefix(&operation_prefix)
        .and_then(|value| value.strip_suffix(".quarantine"));
    if stage_operation != quarantine_operation
        || stage_operation
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .is_none()
        || journal.quarantined_database_file != "corrupt-database.sqlite3"
        || journal.quarantined_wal_file != "corrupt-database.sqlite3-wal"
        || journal.quarantined_shm_file != "corrupt-database.sqlite3-shm"
    {
        return Err(storage_error(
            "corrupt recovery journal contains non-canonical recovery paths",
        ));
    }
    let mut identities = [
        journal.database_file.as_str(),
        journal.stage_file.as_str(),
        journal.quarantine_dir.as_str(),
        journal.quarantined_database_file.as_str(),
        journal.quarantined_wal_file.as_str(),
        journal.quarantined_shm_file.as_str(),
    ];
    identities.sort_unstable();
    if identities.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(storage_error(
            "corrupt recovery journal contains overlapping file identities",
        ));
    }
    Ok(journal)
}

fn optional_regular_file_exists(path: &Path, label: &str) -> Result<bool, ContextError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(storage_error(format!(
                "{label} {} must be a regular non-symlink file",
                path.display()
            )))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))),
    }
}

fn reconcile_quarantined_sidecar(
    source: &Path,
    quarantined: &Path,
    expected: bool,
    label: &str,
) -> Result<(), ContextError> {
    let source_exists =
        optional_regular_file_exists(source, &format!("corrupt destination {label}"))?;
    let quarantined_exists =
        optional_regular_file_exists(quarantined, &format!("quarantined {label}"))?;
    match (expected, source_exists, quarantined_exists) {
        (true, true, false) => fs::rename(source, quarantined).map_err(|error| {
            storage_error(format!(
                "failed to quarantine corrupt destination {label}: {error}"
            ))
        }),
        (true, false, true) | (false, false, false) => Ok(()),
        (true, false, false) => Err(storage_error(format!(
            "journaled corrupt destination {label} is missing from both active and quarantine paths"
        ))),
        (true, true, true) => Err(storage_error(format!(
            "corrupt destination {label} exists at both active and quarantine paths"
        ))),
        (false, true, _) | (false, false, true) => Err(storage_error(format!(
            "unexpected corrupt destination {label} conflicts with recovery journal"
        ))),
    }
}

fn validate_quarantined_original_sidecar(
    quarantined: &Path,
    expected: bool,
    label: &str,
) -> Result<(), ContextError> {
    let exists = optional_regular_file_exists(quarantined, &format!("quarantined {label}"))?;
    if exists == expected {
        Ok(())
    } else {
        Err(storage_error(format!(
            "quarantined original {label} does not match the recovery journal"
        )))
    }
}

fn preserve_interrupted_candidate_sidecar(
    source: &Path,
    forensic_destination: &Path,
    label: &str,
) -> Result<(), ContextError> {
    if !optional_regular_file_exists(source, &format!("interrupted candidate {label}"))? {
        return Ok(());
    }
    reject_existing_path(
        forensic_destination,
        &format!("interrupted candidate {label} forensic file"),
    )?;
    fs::rename(source, forensic_destination).map_err(|error| {
        storage_error(format!(
            "failed to preserve interrupted recovery candidate {label}: {error}"
        ))
    })
}

fn verify_recovery_candidate(
    path: &Path,
    manifest: &BackupManifest,
    storage_key: Option<&StorageEncryptionKey>,
) -> Result<(), ContextError> {
    let (_connection, metadata) = open_verified_database(path, storage_key)?;
    if metadata.installation_id != manifest.installation_id
        || fs::metadata(path)
            .map_err(|error| {
                storage_error(format!("failed to inspect {}: {error}", path.display()))
            })?
            .len()
            != manifest.byte_count
        || sha256_file(path)? != manifest.sha256
    {
        return Err(storage_error(
            "corrupt recovery candidate does not match the trusted backup",
        ));
    }
    Ok(())
}

fn destination_verifies_without_mutation(
    destination: &Path,
    storage_key: Option<&StorageEncryptionKey>,
) -> Result<bool, ContextError> {
    let parent = destination
        .parent()
        .ok_or_else(|| storage_error("recovery destination must have a parent directory"))?;
    let inspection_dir = parent.join(format!(
        ".corrupt-recovery-inspection-{}",
        uuid::Uuid::new_v4()
    ));
    reject_existing_path(&inspection_dir, "corrupt recovery inspection directory")?;
    fs::create_dir(&inspection_dir).map_err(|error| {
        storage_error(format!(
            "failed to create corrupt recovery inspection directory {}: {error}",
            inspection_dir.display()
        ))
    })?;
    set_owner_only_directory(&inspection_dir)?;
    let inspection_guard = StagingDirectory::new(inspection_dir.clone());
    let inspection_database = inspection_dir.join(BACKUP_DATABASE_FILE);
    copy_to_new_file(destination, &inspection_database)?;
    for suffix in ["-wal", "-shm"] {
        let source = companion_path(destination, suffix);
        if optional_regular_file_exists(&source, "corrupt recovery SQLite sidecar")? {
            copy_to_new_file(&source, &companion_path(&inspection_database, suffix))?;
        }
    }
    let verified = open_verified_database(&inspection_database, storage_key).is_ok();
    drop(inspection_guard);
    Ok(verified)
}

#[allow(clippy::too_many_arguments)]
fn rollback_corrupt_recovery(
    parent: &Path,
    destination: &Path,
    stage: &Path,
    quarantine: &Path,
    quarantined_database: &Path,
    quarantined_wal: &Path,
    quarantined_shm: &Path,
    original_wal: bool,
    original_shm: bool,
    journal_path: &Path,
) -> Result<(), ContextError> {
    preserve_failed_recovery_file(destination, &quarantine.join("failed-replacement.sqlite3"))?;
    preserve_failed_recovery_file(
        &companion_path(destination, "-wal"),
        &quarantine.join("failed-replacement.sqlite3-wal"),
    )?;
    preserve_failed_recovery_file(
        &companion_path(destination, "-shm"),
        &quarantine.join("failed-replacement.sqlite3-shm"),
    )?;
    preserve_failed_recovery_file(stage, &quarantine.join("failed-staging.sqlite3"))?;
    fs::rename(quarantined_database, destination).map_err(|error| {
        storage_error(format!(
            "failed to restore quarantined database {}: {error}",
            destination.display()
        ))
    })?;
    if original_wal {
        fs::rename(quarantined_wal, companion_path(destination, "-wal")).map_err(|error| {
            storage_error(format!("failed to restore quarantined WAL: {error}"))
        })?;
    }
    if original_shm {
        fs::rename(quarantined_shm, companion_path(destination, "-shm")).map_err(|error| {
            storage_error(format!("failed to restore quarantined SHM: {error}"))
        })?;
    }
    sync_directory(quarantine)?;
    sync_directory(parent)?;
    fs::remove_file(journal_path).map_err(|error| {
        storage_error(format!(
            "failed to remove rolled-back corrupt recovery journal {}: {error}",
            journal_path.display()
        ))
    })?;
    // The restored database and sidecars were synced before journal removal.
    // If this final sync fails, a crash may resurrect the journal; resuming it
    // remains safe because it binds the exact backup and observed files.
    let _ = sync_directory(parent);
    Ok(())
}

fn preserve_failed_recovery_file(source: &Path, destination: &Path) -> Result<(), ContextError> {
    if !optional_regular_file_exists(source, "failed recovery file")? {
        return Ok(());
    }
    reject_existing_path(destination, "failed recovery quarantine file")?;
    fs::rename(source, destination).map_err(|error| {
        storage_error(format!(
            "failed to preserve recovery candidate {}: {error}",
            source.display()
        ))
    })
}

#[cfg(unix)]
fn verify_owner_only_directory(path: &Path) -> Result<(), ContextError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        storage_error(format!(
            "failed to inspect recovery quarantine {}: {error}",
            path.display()
        ))
    })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(storage_error(format!(
            "recovery quarantine {} must not be accessible by group or other users",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_owner_only_directory(_path: &Path) -> Result<(), ContextError> {
    Ok(())
}

fn restore_backup_internal<T>(
    backup_dir: &Path,
    destination_database: &Path,
    trust: Option<&BackupTrustRoot>,
    storage_key: Option<&StorageEncryptionKey>,
    recovery_anchor: Option<&BackupRecoveryAnchor>,
    qualify_published: impl FnOnce(&BackupManifest, StorageLease) -> Result<T, ContextError>,
) -> Result<(RestoreReport, T), ContextError> {
    let manifest = match (trust, recovery_anchor) {
        (Some(trust), Some(anchor)) => {
            verify_backup_recovery_anchor_internal(backup_dir, storage_key, trust, anchor)?
        }
        (None, Some(_)) => {
            return Err(storage_error(
                "backup recovery anchor requires an independently supplied signing trust root",
            ))
        }
        (_, None) => verify_backup_internal(backup_dir, trust, storage_key)?,
    };
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
    let storage_lease = acquire_storage_lease(destination_database)?;
    let qualification_lease = storage_lease.try_clone().map_err(|error| {
        storage_error(format!(
            "failed to retain storage lease during restore qualification: {error}"
        ))
    })?;

    let stage = companion_path(
        destination_database,
        &format!(".restore-{}.staging", uuid::Uuid::new_v4()),
    );
    reject_existing_path(&stage, "restore staging file")?;
    let mut stage_guard = StagingFile::new(stage.clone());
    copy_to_new_file(&backup_dir.join(BACKUP_DATABASE_FILE), &stage)?;
    let stage_result = (|| {
        let (_connection, metadata) = open_verified_database(&stage, storage_key)?;
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

    // Pin the independently retained recovery point through the last
    // non-mutating boundary. A backup directory changed after preflight cannot
    // cause us to move an existing destination.
    if let Some(anchor) = recovery_anchor {
        let trust = trust.expect("recovery anchor requires trust");
        if verify_backup_recovery_anchor_internal(backup_dir, storage_key, trust, anchor)?
            != manifest
        {
            return Err(storage_error(
                "backup identity changed before anchored restore publication",
            ));
        }
    }

    let replaced_existing = destination_database.exists();
    let rollback = companion_path(
        destination_database,
        &format!(".rollback-{}", uuid::Uuid::new_v4()),
    );
    if replaced_existing {
        checkpoint_existing_database(destination_database, storage_key)?;
        reject_existing_path(&rollback, "restore rollback file")?;
        fs::rename(destination_database, &rollback).map_err(|error| {
            storage_error(format!(
                "failed to preserve restore rollback database {}: {error}",
                rollback.display()
            ))
        })?;
    }

    let mut qualification = None;
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
        let (_connection, metadata) = open_verified_database(destination_database, storage_key)?;
        if metadata.installation_id != manifest.installation_id
            || sha256_file(destination_database)? != manifest.sha256
        {
            return Err(storage_error(
                "published restore does not match the verified backup",
            ));
        }
        qualification = Some(qualify_published(&manifest, qualification_lease)?);
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
            let _ = open_verified_database(destination_database, storage_key)?;
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
    Ok((
        RestoreReport {
            manifest,
            replaced_existing,
            rollback_retained,
        },
        qualification.expect("successful restore must run post-publication qualification"),
    ))
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

    fn encrypted_test_key(key_id: &str, fill: u8) -> StorageEncryptionKey {
        StorageEncryptionKey::from_bytes(key_id, [fill; 32]).unwrap()
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
    fn legacy_v1_plaintext_and_signed_manifests_remain_verifiable() {
        let directory = TestDirectory::new("legacy-manifest");
        let database = directory.path.join("source.db");
        let manager = SqliteContextManager::new(&database).unwrap();
        let backup_root = directory.path.join("backups");
        let backup_dir = backup_root.join("legacy_001");
        let mut manifest = manager.create_backup(&backup_root, "legacy_001").unwrap();
        manifest.format_version = LEGACY_BACKUP_FORMAT_VERSION;
        let (signer, _) = BackupSigningKey::generate("legacy-signer").unwrap();
        signer.sign_manifest(&mut manifest).unwrap();
        fs::write(
            backup_dir.join(BACKUP_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_backup_authenticity(&backup_dir, &signer.trust_root()).unwrap(),
            manifest
        );

        manifest.authenticity = None;
        manifest.encryption = Some(BackupEncryption {
            format_version: BACKUP_ENCRYPTION_FORMAT_VERSION,
            algorithm: BACKUP_ENCRYPTION_ALGORITHM.into(),
            key_id: "invalid-v1-encryption".into(),
        });
        fs::write(
            backup_dir.join(BACKUP_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(verify_backup(&backup_dir)
            .unwrap_err()
            .to_string()
            .contains("legacy backup format cannot declare"));
    }

    #[test]
    fn encrypted_backup_verification_retention_and_fresh_host_restore_require_the_key() {
        let directory = TestDirectory::new("encrypted-lifecycle");
        let database = directory.path.join("source.db");
        let manager = SqliteContextManager::new_encrypted(
            &database,
            encrypted_test_key("storage-generation-1", 0x31),
        )
        .unwrap();
        let secret = "backup-secret-that-must-remain-encrypted";
        seed(&manager, "encrypted-backup-proof", secret);

        let backup_root = directory.path.join("backups");
        let manifest = manager.create_backup(&backup_root, "backup_001").unwrap();
        assert_eq!(
            manifest.encryption,
            Some(BackupEncryption {
                format_version: BACKUP_ENCRYPTION_FORMAT_VERSION,
                algorithm: BACKUP_ENCRYPTION_ALGORITHM.into(),
                key_id: "storage-generation-1".into(),
            })
        );
        let backup_dir = backup_root.join("backup_001");
        let backup_database = backup_dir.join(BACKUP_DATABASE_FILE);
        let backup_bytes = fs::read(&backup_database).unwrap();
        assert!(!backup_bytes
            .windows(secret.len())
            .any(|window| window == secret.as_bytes()));
        let unkeyed_error = verify_backup(&backup_dir).unwrap_err().to_string();
        assert!(unkeyed_error.contains("supply that independently retained key"));
        let wrong_error = verify_backup_with_storage_key(
            &backup_dir,
            &encrypted_test_key("storage-generation-wrong", 0x42),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_error.contains("not supplied key"));
        assert_eq!(
            verify_backup_with_storage_key(
                &backup_dir,
                &encrypted_test_key("storage-generation-1", 0x31)
            )
            .unwrap(),
            manifest
        );
        let unkeyed_connection = Connection::open(&backup_database).unwrap();
        assert!(unkeyed_connection
            .query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
                row.get::<_, i64>(0)
            })
            .is_err());

        manager.create_backup(&backup_root, "backup_002").unwrap();
        let retention = manager
            .apply_backup_retention(
                &backup_root,
                BackupRetentionPolicy {
                    keep_latest: 1,
                    max_age_seconds: 60,
                },
                true,
            )
            .unwrap();
        assert!(retention.skipped.is_empty(), "{:?}", retention.skipped);
        assert_eq!(retention.retained.len(), 2);

        let restored = directory.path.join("fresh-host/agent_os.db");
        restore_backup_with_storage_key(
            &backup_dir,
            &restored,
            &encrypted_test_key("storage-generation-1", 0x31),
        )
        .unwrap();
        let restored_manager = SqliteContextManager::new_encrypted(
            &restored,
            encrypted_test_key("storage-generation-1", 0x31),
        )
        .unwrap();
        let restored_value: String = restored_manager
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM agent_kv WHERE key = 'encrypted-backup-proof'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restored_value, secret);
    }

    #[test]
    fn retention_uses_explicit_retired_keys_after_database_rotation() {
        let directory = TestDirectory::new("retired-key-retention");
        let database = directory.path.join("source.db");
        let backup_root = directory.path.join("backups");
        {
            let manager = SqliteContextManager::new_encrypted(
                &database,
                encrypted_test_key("storage-generation-1", 0x51),
            )
            .unwrap();
            manager.create_backup(&backup_root, "old_key").unwrap();
        }
        crate::storage_encryption::rotate_database_encryption_key(
            &database,
            &encrypted_test_key("storage-generation-1", 0x51),
            &encrypted_test_key("storage-generation-2", 0x52),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(1_100));
        let manager = SqliteContextManager::new_encrypted_with_retired_keys(
            &database,
            encrypted_test_key("storage-generation-2", 0x52),
            vec![encrypted_test_key("storage-generation-1", 0x51)],
        )
        .unwrap();
        manager.create_backup(&backup_root, "current_key").unwrap();
        let report = manager
            .apply_backup_retention(
                &backup_root,
                BackupRetentionPolicy {
                    keep_latest: 1,
                    max_age_seconds: 1,
                },
                false,
            )
            .unwrap();
        assert!(report.skipped.is_empty(), "{:?}", report.skipped);
        assert_eq!(
            report
                .deleted
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["old_key"]
        );
        assert!(!backup_root.join("old_key").exists());
        assert!(backup_root.join("current_key").exists());
    }

    #[test]
    fn managed_erasure_purges_every_verified_backup_and_holds_publication_lock() {
        let directory = TestDirectory::new("managed-erasure");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let root = directory.path.join("backups");
        manager.create_backup(&root, "first").unwrap();
        manager.create_backup(&root, "second").unwrap();

        let guard = manager.begin_managed_backup_erasure(&root).unwrap();
        assert_eq!(
            guard
                .deleted()
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert!(!root.join("first").exists());
        assert!(!root.join("second").exists());
        let error = manager.create_backup(&root, "racing").unwrap_err();
        assert!(error.to_string().contains("another backup publication"));

        drop(guard);
        manager.create_backup(&root, "clean").unwrap();
        assert!(root.join("clean").exists());
    }

    #[test]
    fn managed_erasure_fails_closed_before_deleting_any_backup_on_unknown_or_foreign_entry() {
        let directory = TestDirectory::new("managed-erasure-refusal");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let foreign = SqliteContextManager::new(&directory.path.join("foreign.db")).unwrap();
        let root = directory.path.join("backups");
        manager.create_backup(&root, "owned").unwrap();
        foreign.create_backup(&root, "foreign").unwrap();

        let error = manager.begin_managed_backup_erasure(&root).unwrap_err();
        assert!(error.to_string().contains("different installation"));
        assert!(root.join("owned").exists());
        assert!(root.join("foreign").exists());

        fs::remove_dir_all(root.join("foreign")).unwrap();
        fs::write(root.join("operator_notes"), b"not a backup").unwrap();
        let error = manager.begin_managed_backup_erasure(&root).unwrap_err();
        assert!(error.to_string().contains("not a real backup directory"));
        assert!(root.join("owned").exists());
        assert!(root.join("operator_notes").exists());
    }

    #[test]
    fn managed_erasure_uses_retired_storage_keys_to_remove_rotated_backups() {
        let directory = TestDirectory::new("managed-erasure-retired-key");
        let database = directory.path.join("source.db");
        let root = directory.path.join("backups");
        {
            let manager = SqliteContextManager::new_encrypted(
                &database,
                encrypted_test_key("storage-generation-1", 0x61),
            )
            .unwrap();
            manager.create_backup(&root, "old_key").unwrap();
        }
        crate::storage_encryption::rotate_database_encryption_key(
            &database,
            &encrypted_test_key("storage-generation-1", 0x61),
            &encrypted_test_key("storage-generation-2", 0x62),
        )
        .unwrap();
        let manager = SqliteContextManager::new_encrypted_with_retired_keys(
            &database,
            encrypted_test_key("storage-generation-2", 0x62),
            vec![encrypted_test_key("storage-generation-1", 0x61)],
        )
        .unwrap();
        manager.create_backup(&root, "current_key").unwrap();

        let guard = manager.begin_managed_backup_erasure(&root).unwrap();
        assert_eq!(guard.deleted_count(), 2);
        assert!(!root.join("old_key").exists());
        assert!(!root.join("current_key").exists());
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
    fn scheduled_cycle_publishes_verified_backup_applies_retention_and_reports_health() {
        let directory = TestDirectory::new("scheduled-cycle");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        seed(&manager, "scheduled-proof", "survived");
        let root = directory.path.join("backups");
        manager.create_backup(&root, "expired").unwrap();
        set_backup_age(&root, "expired", chrono::Duration::hours(8));

        let maintenance = BackupMaintenance::new(BackupScheduleConfig {
            enabled: true,
            root: Some(root.clone()),
            interval_seconds: 60,
            run_on_start: true,
            keep_latest: 1,
            max_age_seconds: 60,
            ..BackupScheduleConfig::default()
        })
        .unwrap();
        let report = maintenance.run_cycle(&manager).unwrap();
        assert_eq!(report.retention.deleted.len(), 1);
        assert_eq!(report.retention.deleted[0].name, "expired");
        assert!(!root.join("expired").exists());

        let scheduled_name = maintenance
            .status()
            .last_backup_name
            .expect("last successful backup name");
        assert_eq!(
            verify_backup(&root.join(scheduled_name)).unwrap(),
            report.backup
        );
        let status = maintenance.status();
        assert_eq!(status.attempts_total, 1);
        assert_eq!(status.successes_total, 1);
        assert_eq!(status.failures_total, 0);
        assert_eq!(status.retention_deleted_total, 1);
        assert_eq!(status.consecutive_failures, 0);
        assert!(status.last_success_at.is_some());
        assert!(status.last_error.is_none());
    }

    #[test]
    fn server_backup_creation_requires_the_exact_configured_managed_root() {
        let directory = TestDirectory::new("managed-root");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let requested = directory.path.join("requested");
        let unconfigured = BackupMaintenance::default();
        let error = unconfigured
            .create_backup(&manager, &requested, "unconfigured")
            .unwrap_err();
        assert!(error.to_string().contains("backup.root"));
        assert!(!requested.exists());

        let configured_root = directory.path.join("configured");
        let maintenance = BackupMaintenance::new(BackupScheduleConfig {
            root: Some(configured_root.clone()),
            ..BackupScheduleConfig::default()
        })
        .unwrap();
        let error = maintenance
            .create_backup(&manager, &requested, "wrong_root")
            .unwrap_err();
        assert!(error.to_string().contains("does not match configured"));
        assert!(!requested.exists());
        maintenance
            .create_backup(&manager, &configured_root, "managed")
            .unwrap();
        assert!(configured_root.join("managed").exists());
    }

    #[test]
    fn scheduled_cycle_failure_is_bounded_visible_and_preserves_prior_backup() {
        let directory = TestDirectory::new("scheduled-failure");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let root = directory.path.join("backups");
        manager.create_backup(&root, "known_good").unwrap();
        let blocked = directory.path.join("not-a-directory");
        fs::write(&blocked, b"block backup root").unwrap();
        let maintenance = BackupMaintenance::new(BackupScheduleConfig {
            enabled: true,
            root: Some(blocked),
            interval_seconds: 60,
            run_on_start: true,
            keep_latest: 1,
            max_age_seconds: 60,
            ..BackupScheduleConfig::default()
        })
        .unwrap();

        assert!(maintenance.run_cycle(&manager).is_err());
        assert!(verify_backup(&root.join("known_good")).is_ok());
        let status = maintenance.status();
        assert_eq!(status.attempts_total, 1);
        assert_eq!(status.successes_total, 0);
        assert_eq!(status.failures_total, 1);
        assert_eq!(status.consecutive_failures, 1);
        assert!(status.last_failure_at.is_some());
        let error = status.last_error.expect("bounded failure");
        assert!(error.len() <= 512);
        assert!(!error.chars().any(char::is_control));
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
    fn signed_backup_requires_the_independently_retained_matching_trust_root() {
        let directory = TestDirectory::new("signed");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        seed(&manager, "signed-proof", "present");
        let (signer, _) = BackupSigningKey::generate("release-2026.1").unwrap();
        let (wrong_signer, _) = BackupSigningKey::generate("release-other").unwrap();
        let root = directory.path.join("backups");
        let manifest = manager
            .create_signed_backup(&root, "signed_001", &signer)
            .unwrap();
        let backup_dir = root.join("signed_001");

        assert_eq!(verify_backup(&backup_dir).unwrap(), manifest);
        assert_eq!(
            verify_backup_authenticity(&backup_dir, &signer.trust_root()).unwrap(),
            manifest
        );
        assert!(
            verify_backup_authenticity(&backup_dir, &wrong_signer.trust_root())
                .unwrap_err()
                .to_string()
                .contains("not trusted key")
        );

        // Hash-only verification cannot detect a rewritten but internally
        // consistent metadata field. Trusted signature verification must.
        let manifest_path = backup_dir.join(BACKUP_MANIFEST_FILE);
        let mut rewritten = read_manifest(&manifest_path).unwrap();
        rewritten.created_at = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&rewritten).unwrap(),
        )
        .unwrap();
        assert!(verify_backup(&backup_dir).is_ok());
        assert!(
            verify_backup_authenticity(&backup_dir, &signer.trust_root())
                .unwrap_err()
                .to_string()
                .contains("signature is invalid")
        );
    }

    #[test]
    fn recovery_anchor_pins_one_exact_signed_backup_and_never_overwrites() {
        let directory = TestDirectory::new("recovery-anchor");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let (signer, _) = BackupSigningKey::generate("release-anchor-1").unwrap();
        let backup_root = directory.path.join("backups");
        seed(&manager, "generation", "one");
        let first = manager
            .create_signed_backup(&backup_root, "backup_001", &signer)
            .unwrap();
        seed(&manager, "generation", "two");
        manager
            .create_signed_backup(&backup_root, "backup_002", &signer)
            .unwrap();

        let first_dir = backup_root.join("backup_001");
        let second_dir = backup_root.join("backup_002");
        let anchor_path = directory.path.join("recovery-points/backup_001.json");
        fs::create_dir(anchor_path.parent().unwrap()).unwrap();
        let anchor =
            generate_backup_recovery_anchor(&first_dir, None, &signer.trust_root(), &anchor_path)
                .unwrap();
        assert_eq!(anchor.installation_id, first.installation_id);
        assert_eq!(
            load_independent_backup_recovery_anchor(&first_dir, &anchor_path).unwrap(),
            anchor
        );
        assert_eq!(
            verify_backup_with_recovery_anchor(&first_dir, None, &signer.trust_root(), &anchor)
                .unwrap(),
            first
        );
        let stale_or_substituted =
            verify_backup_with_recovery_anchor(&second_dir, None, &signer.trust_root(), &anchor)
                .unwrap_err();
        assert!(stale_or_substituted
            .to_string()
            .contains("does not match the independently retained recovery anchor"));
        assert!(generate_backup_recovery_anchor(
            &first_dir,
            None,
            &signer.trust_root(),
            &anchor_path,
        )
        .unwrap_err()
        .to_string()
        .contains("already exists"));
        assert!(generate_backup_recovery_anchor(
            &first_dir,
            None,
            &signer.trust_root(),
            &first_dir.join("self-anchor.json"),
        )
        .unwrap_err()
        .to_string()
        .contains("outside the backup directory"));
        let mut unknown: serde_json::Value =
            serde_json::to_value(&anchor).expect("encode anchor value");
        unknown["unknown"] = serde_json::Value::Bool(true);
        let malformed_path = directory.path.join("recovery-points/unknown.json");
        fs::write(&malformed_path, serde_json::to_vec(&unknown).unwrap()).unwrap();
        assert!(load_backup_recovery_anchor(&malformed_path)
            .unwrap_err()
            .to_string()
            .contains("unknown field"));
        let colocated = first_dir.join("copied-anchor.json");
        fs::copy(&anchor_path, &colocated).unwrap();
        assert!(
            load_independent_backup_recovery_anchor(&first_dir, &colocated)
                .unwrap_err()
                .to_string()
                .contains("outside the backup directory")
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                &anchor_path,
                directory.path.join("recovery-points/anchor-link.json"),
            )
            .unwrap();
            assert!(load_backup_recovery_anchor(
                &directory.path.join("recovery-points/anchor-link.json")
            )
            .is_err());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&anchor_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn anchored_restore_rejects_substitution_before_destination_mutation() {
        let directory = TestDirectory::new("anchored-restore");
        let source = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let destination_manager =
            SqliteContextManager::new(&directory.path.join("destination.db")).unwrap();
        seed(&destination_manager, "custody", "must-remain");
        drop(destination_manager);
        let (signer, _) = BackupSigningKey::generate("anchored-restore-1").unwrap();
        let backup_root = directory.path.join("backups");
        seed(&source, "recovery", "first");
        source
            .create_signed_backup(&backup_root, "first", &signer)
            .unwrap();
        seed(&source, "recovery", "second");
        source
            .create_signed_backup(&backup_root, "second", &signer)
            .unwrap();
        let anchor_path = directory.path.join("anchors/first.json");
        fs::create_dir(anchor_path.parent().unwrap()).unwrap();
        let anchor = generate_backup_recovery_anchor(
            &backup_root.join("first"),
            None,
            &signer.trust_root(),
            &anchor_path,
        )
        .unwrap();

        let destination = directory.path.join("destination.db");
        let error = restore_backup_with_recovery_anchor(
            &backup_root.join("second"),
            &destination,
            None,
            &signer.trust_root(),
            &anchor,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match the independently retained recovery anchor"));
        assert_eq!(
            value(&destination, "custody").as_deref(),
            Some("must-remain")
        );
        assert!(!directory.path.read_dir().unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".rollback-")));
    }

    #[test]
    fn recovery_anchor_supports_encrypted_signed_backup_restore() {
        let directory = TestDirectory::new("encrypted-recovery-anchor");
        let key = encrypted_test_key("anchor-storage-1", 0x91);
        let manager = SqliteContextManager::new_encrypted(
            &directory.path.join("source.db"),
            encrypted_test_key("anchor-storage-1", 0x91),
        )
        .unwrap();
        seed(&manager, "encrypted-anchor", "survived");
        let (signer, _) = BackupSigningKey::generate("encrypted-anchor-1").unwrap();
        let backup_root = directory.path.join("backups");
        manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        let backup_dir = backup_root.join("qualified");
        let anchor_path = directory.path.join("anchors/qualified.json");
        fs::create_dir(anchor_path.parent().unwrap()).unwrap();
        let anchor = generate_backup_recovery_anchor(
            &backup_dir,
            Some(&key),
            &signer.trust_root(),
            &anchor_path,
        )
        .unwrap();
        assert!(verify_backup_with_recovery_anchor(
            &backup_dir,
            None,
            &signer.trust_root(),
            &anchor,
        )
        .is_err());

        let destination = directory.path.join("fresh/agent_os.db");
        restore_backup_with_recovery_anchor(
            &backup_dir,
            &destination,
            Some(&key),
            &signer.trust_root(),
            &anchor,
        )
        .unwrap();
        let restored = SqliteContextManager::new_encrypted(&destination, key).unwrap();
        drop(restored);
    }

    #[test]
    fn unsigned_backup_is_rejected_when_authenticity_is_required() {
        let directory = TestDirectory::new("unsigned");
        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let root = directory.path.join("backups");
        manager.create_backup(&root, "unsigned_001").unwrap();
        let (signer, _) = BackupSigningKey::generate("release-2026.1").unwrap();
        let error = verify_backup_authenticity(&root.join("unsigned_001"), &signer.trust_root())
            .unwrap_err();
        assert!(error.to_string().contains("unsigned"));
    }

    #[test]
    fn generated_signing_files_are_loadable_non_overwriting_and_drive_maintenance() {
        let directory = TestDirectory::new("signing-files");
        let private_key = directory.path.join("backup-signing.pk8");
        let trust_file = directory.path.join("backup-trust.json");
        let trust =
            generate_backup_signing_key_files("release-2026.1", &private_key, &trust_file).unwrap();
        assert_eq!(load_backup_trust_root(&trust_file).unwrap(), trust);
        assert_eq!(
            load_backup_signing_key(&private_key, "release-2026.1")
                .unwrap()
                .trust_root(),
            trust
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&private_key, directory.path.join("signing-link.pk8"))
                .unwrap();
            assert!(load_backup_signing_key(
                &directory.path.join("signing-link.pk8"),
                "release-2026.1"
            )
            .is_err());
        }
        assert!(generate_backup_signing_key_files(
            "release-2026.2",
            &private_key,
            &directory.path.join("other-trust.json"),
        )
        .is_err());

        let manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        let root = directory.path.join("backups");
        let maintenance = BackupMaintenance::new(BackupScheduleConfig {
            enabled: true,
            root: Some(root.clone()),
            interval_seconds: 60,
            run_on_start: true,
            keep_latest: 1,
            max_age_seconds: 60,
            signing_key_path: Some(private_key.clone()),
            signing_key_id: Some("release-2026.1".into()),
        })
        .unwrap();
        let report = maintenance.run_cycle(&manager).unwrap();
        assert_eq!(
            maintenance.status().signing_key_id.as_deref(),
            Some("release-2026.1")
        );
        let name = maintenance.status().last_backup_name.unwrap();
        assert_eq!(
            verify_backup_authenticity(&root.join(name), &trust).unwrap(),
            report.backup
        );
        assert!(maintenance
            .configure(BackupScheduleConfig {
                signing_key_path: Some(directory.path.join("missing-rotation.pk8")),
                signing_key_id: Some("release-2026.2".into()),
                ..maintenance.config()
            })
            .is_err());
        assert_eq!(
            maintenance.status().signing_key_id.as_deref(),
            Some("release-2026.1")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private_key, fs::Permissions::from_mode(0o644)).unwrap();
            let error = match load_backup_signing_key(&private_key, "release-2026.1") {
                Ok(_) => panic!("group- or other-readable signing key must be rejected"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("group or other"));
        }
    }

    #[test]
    fn trusted_restore_rejects_wrong_key_before_mutation_and_accepts_matching_key() {
        let directory = TestDirectory::new("trusted-restore");
        let source_manager = SqliteContextManager::new(&directory.path.join("source.db")).unwrap();
        seed(&source_manager, "trusted-restore", "survived");
        let (signer, _) = BackupSigningKey::generate("release-2026.1").unwrap();
        let (wrong, _) = BackupSigningKey::generate("release-other").unwrap();
        let backup_root = directory.path.join("backups");
        source_manager
            .create_signed_backup(&backup_root, "signed_restore", &signer)
            .unwrap();
        let destination = directory.path.join("fresh/agent_os.db");
        assert!(restore_backup_with_trust(
            &backup_root.join("signed_restore"),
            &destination,
            &wrong.trust_root(),
        )
        .is_err());
        assert!(!destination.exists());

        let report = restore_backup_with_trust(
            &backup_root.join("signed_restore"),
            &destination,
            &signer.trust_root(),
        )
        .unwrap();
        assert!(!report.replaced_existing);
        assert_eq!(
            value(&destination, "trusted-restore").as_deref(),
            Some("survived")
        );
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
    fn final_storage_lease_owner_unlocks_an_inherited_descriptor() {
        let directory = TestDirectory::new("inherited-storage-lease");
        let database = directory.path.join("agent_os.db");
        let lease = acquire_storage_lease(&database).unwrap();
        let inherited_descriptor = lease.inner.file.try_clone().unwrap();

        let competing_owner = acquire_storage_lease(&database).unwrap_err();
        assert!(competing_owner.to_string().contains("already owned"));

        // Model a descriptor inherited across fork before close-on-exec takes
        // effect. The final Rust owner must explicitly unlock rather than rely
        // on closing its descriptor, because the duplicate remains open.
        drop(lease);
        let replacement = acquire_storage_lease(&database).unwrap();
        drop(replacement);
        drop(inherited_descriptor);
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
    fn post_publication_qualification_failure_rolls_back_the_original_database() {
        let directory = TestDirectory::new("qualification-rollback");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        seed(&source_manager, "source", "unqualified");
        source_manager
            .create_backup(&directory.path.join("backups"), "qualification")
            .unwrap();
        let backup_dir = directory.path.join("backups/qualification");

        let destination = directory.path.join("destination.db");
        {
            let destination_manager = SqliteContextManager::new(&destination).unwrap();
            seed(&destination_manager, "destination", "must-survive");
        }
        let error = restore_backup_internal(
            &backup_dir,
            &destination,
            None,
            None,
            None,
            |_, _qualification_lease| {
                Err::<File, ContextError>(storage_error(
                    "injected configured-kernel qualification failure",
                ))
            },
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("configured-kernel qualification failure"));
        assert_eq!(
            value(&destination, "destination").as_deref(),
            Some("must-survive")
        );
        assert_eq!(value(&destination, "source"), None);
        let reopened = SqliteContextManager::new(&destination).unwrap();
        crate::schema::verify(&reopened.conn.lock().unwrap()).unwrap();
    }

    fn recovery_config(data_dir: &Path) -> crate::config::Config {
        crate::config::Config {
            llm_provider: "local".to_owned(),
            default_model: "qualification".to_owned(),
            data_dir: data_dir.to_path_buf(),
            ..crate::config::Config::default()
        }
    }

    #[test]
    fn corrupt_recovery_preserves_original_files_and_qualifies_backup() {
        let directory = TestDirectory::new("corrupt-recovery");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        seed(&source_manager, "recovery-proof", "survived");
        let (signer, _) = BackupSigningKey::generate("corrupt-recovery").unwrap();
        let backup_root = directory.path.join("backups");
        let manifest = source_manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        drop(source_manager);

        let data_dir = directory.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let destination = data_dir.join(BACKUP_DATABASE_FILE);
        let corrupt_bytes = b"corrupt database evidence";
        let wal_bytes = b"corrupt wal evidence";
        let shm_bytes = b"corrupt shm evidence";
        fs::write(&destination, corrupt_bytes).unwrap();
        fs::write(companion_path(&destination, "-wal"), wal_bytes).unwrap();
        fs::write(companion_path(&destination, "-shm"), shm_bytes).unwrap();

        let report = recover_corrupt_storage_from_config(
            &backup_root.join("qualified"),
            &recovery_config(&data_dir),
            &signer.trust_root(),
            &manifest.installation_id,
        )
        .unwrap();
        assert!(report.enforcement_rearmed);
        assert_eq!(report.persisted_agent_count, 0);
        assert!(report.original_wal_preserved);
        assert!(report.original_shm_preserved);
        assert!(!report.resumed_interrupted_recovery);
        assert_eq!(
            fs::read(report.quarantine_dir.join("corrupt-database.sqlite3")).unwrap(),
            corrupt_bytes
        );
        assert_eq!(
            fs::read(report.quarantine_dir.join("corrupt-database.sqlite3-wal")).unwrap(),
            wal_bytes
        );
        assert_eq!(
            fs::read(report.quarantine_dir.join("corrupt-database.sqlite3-shm")).unwrap(),
            shm_bytes
        );
        assert_eq!(
            value(&destination, "recovery-proof").as_deref(),
            Some("survived")
        );
        assert!(!companion_path(&destination, CORRUPT_RECOVERY_JOURNAL_SUFFIX).exists());
    }

    #[test]
    fn corrupt_recovery_rejects_healthy_or_wrong_installation_without_mutation() {
        let directory = TestDirectory::new("corrupt-recovery-refusal");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        seed(&source_manager, "proof", "trusted");
        let (signer, _) = BackupSigningKey::generate("corrupt-refusal").unwrap();
        let backup_root = directory.path.join("backups");
        let manifest = source_manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        drop(source_manager);

        let data_dir = directory.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let destination = data_dir.join(BACKUP_DATABASE_FILE);
        fs::write(&destination, b"must remain corrupt").unwrap();
        let wrong_id = uuid::Uuid::new_v4().to_string();
        let error = recover_corrupt_storage_from_config(
            &backup_root.join("qualified"),
            &recovery_config(&data_dir),
            &signer.trust_root(),
            &wrong_id,
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match expected"));
        assert_eq!(fs::read(&destination).unwrap(), b"must remain corrupt");
        assert!(!companion_path(&destination, CORRUPT_RECOVERY_JOURNAL_SUFFIX).exists());

        fs::remove_file(&destination).unwrap();
        let healthy = SqliteContextManager::new(&destination).unwrap();
        drop(healthy);
        let healthy_bytes = fs::read(&destination).unwrap();
        let error = recover_corrupt_storage_from_config(
            &backup_root.join("qualified"),
            &recovery_config(&data_dir),
            &signer.trust_root(),
            &manifest.installation_id,
        )
        .unwrap_err();
        assert!(error.to_string().contains("refuses a healthy"));
        assert_eq!(fs::read(&destination).unwrap(), healthy_bytes);
        assert!(!companion_path(&destination, CORRUPT_RECOVERY_JOURNAL_SUFFIX).exists());
    }

    #[test]
    fn corrupt_recovery_qualification_failure_restores_original_and_keeps_candidate() {
        let directory = TestDirectory::new("corrupt-recovery-rollback");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        let (signer, _) = BackupSigningKey::generate("corrupt-rollback").unwrap();
        let backup_root = directory.path.join("backups");
        let manifest = source_manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        drop(source_manager);

        let data_dir = directory.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let destination = data_dir.join(BACKUP_DATABASE_FILE);
        fs::write(&destination, b"original corrupt evidence").unwrap();
        let mut config = recovery_config(&data_dir);
        config.service_dir = Some(directory.path.join("missing-services"));
        let error = recover_corrupt_storage_from_config(
            &backup_root.join("qualified"),
            &config,
            &signer.trust_root(),
            &manifest.installation_id,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("failed configured kernel qualification"));
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"original corrupt evidence"
        );
        assert!(!companion_path(&destination, CORRUPT_RECOVERY_JOURNAL_SUFFIX).exists());
        let quarantines: Vec<_> = fs::read_dir(&data_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".quarantine"))
            .collect();
        assert_eq!(quarantines.len(), 1);
        assert!(quarantines[0]
            .path()
            .join("failed-replacement.sqlite3")
            .exists());
    }

    #[test]
    fn corrupt_recovery_resumes_published_candidate_and_separates_new_sidecars() {
        let directory = TestDirectory::new("corrupt-recovery-resume");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        seed(&source_manager, "resume-proof", "survived");
        let (signer, _) = BackupSigningKey::generate("corrupt-resume").unwrap();
        let backup_root = directory.path.join("backups");
        let manifest = source_manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        drop(source_manager);

        let data_dir = directory.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let destination = data_dir.join(BACKUP_DATABASE_FILE);
        fs::write(&destination, b"interrupted corrupt evidence").unwrap();
        let operation_id = uuid::Uuid::new_v4();
        let journal = CorruptRecoveryJournal {
            format_version: CORRUPT_RECOVERY_FORMAT_VERSION,
            database_file: BACKUP_DATABASE_FILE.to_owned(),
            stage_file: format!(".{BACKUP_DATABASE_FILE}.corrupt-recovery-{operation_id}.staging"),
            quarantine_dir: format!(
                ".{BACKUP_DATABASE_FILE}.corrupt-recovery-{operation_id}.quarantine"
            ),
            quarantined_database_file: "corrupt-database.sqlite3".to_owned(),
            quarantined_wal_file: "corrupt-database.sqlite3-wal".to_owned(),
            quarantined_shm_file: "corrupt-database.sqlite3-shm".to_owned(),
            installation_id: manifest.installation_id.clone(),
            backup_sha256: manifest.sha256.clone(),
            backup_byte_count: manifest.byte_count,
            original_wal: false,
            original_shm: false,
        };
        let quarantine = data_dir.join(&journal.quarantine_dir);
        fs::create_dir(&quarantine).unwrap();
        set_owner_only_directory(&quarantine).unwrap();
        write_corrupt_recovery_journal(
            &companion_path(&destination, CORRUPT_RECOVERY_JOURNAL_SUFFIX),
            &journal,
        )
        .unwrap();
        fs::rename(
            &destination,
            quarantine.join(&journal.quarantined_database_file),
        )
        .unwrap();
        fs::copy(
            backup_root.join("qualified").join(BACKUP_DATABASE_FILE),
            &destination,
        )
        .unwrap();
        fs::write(
            companion_path(&destination, "-wal"),
            b"interrupted candidate wal",
        )
        .unwrap();
        fs::write(
            companion_path(&destination, "-shm"),
            b"interrupted candidate shm",
        )
        .unwrap();
        sync_directory(&data_dir).unwrap();

        let report = recover_corrupt_storage_from_config(
            &backup_root.join("qualified"),
            &recovery_config(&data_dir),
            &signer.trust_root(),
            &manifest.installation_id,
        )
        .unwrap();
        assert!(report.resumed_interrupted_recovery);
        assert_eq!(
            value(&destination, "resume-proof").as_deref(),
            Some("survived")
        );
        assert_eq!(
            fs::read(report.quarantine_dir.join("corrupt-database.sqlite3")).unwrap(),
            b"interrupted corrupt evidence"
        );
        assert_eq!(
            fs::read(
                report
                    .quarantine_dir
                    .join("interrupted-candidate.sqlite3-wal")
            )
            .unwrap(),
            b"interrupted candidate wal"
        );
        assert_eq!(
            fs::read(
                report
                    .quarantine_dir
                    .join("interrupted-candidate.sqlite3-shm")
            )
            .unwrap(),
            b"interrupted candidate shm"
        );
    }

    #[test]
    fn corrupt_recovery_supports_encrypted_backups_and_excludes_a_running_owner() {
        let directory = TestDirectory::new("corrupt-recovery-encrypted");
        let key_path = directory.path.join("storage-key.json");
        crate::storage_encryption::generate_storage_encryption_key_file(
            "corrupt-recovery-generation",
            &key_path,
        )
        .unwrap();
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new_encrypted(
            &source,
            crate::storage_encryption::load_storage_encryption_key(&key_path).unwrap(),
        )
        .unwrap();
        seed(&source_manager, "encrypted-recovery-proof", "survived");
        let (signer, _) = BackupSigningKey::generate("encrypted-corrupt-recovery").unwrap();
        let backup_root = directory.path.join("backups");
        let manifest = source_manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        drop(source_manager);

        let data_dir = directory.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let destination = data_dir.join(BACKUP_DATABASE_FILE);
        fs::copy(&source, &destination).unwrap();
        let mut file = OpenOptions::new().write(true).open(&destination).unwrap();
        file.seek(SeekFrom::Start(64)).unwrap();
        file.write_all(b"corrupted encrypted page").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut config = recovery_config(&data_dir);
        config.storage_encryption.required = true;
        config.storage_encryption.key_path = Some(key_path);

        let lease = acquire_storage_lease(&destination).unwrap();
        let error = recover_corrupt_storage_from_config(
            &backup_root.join("qualified"),
            &config,
            &signer.trust_root(),
            &manifest.installation_id,
        )
        .unwrap_err();
        assert!(error.to_string().contains("already owned"));
        drop(lease);

        let report = recover_corrupt_storage_from_config(
            &backup_root.join("qualified"),
            &config,
            &signer.trust_root(),
            &manifest.installation_id,
        )
        .unwrap();
        assert_eq!(
            report
                .manifest
                .encryption
                .as_ref()
                .map(|encryption| encryption.key_id.as_str()),
            Some("corrupt-recovery-generation")
        );
        let recovered = SqliteContextManager::new_encrypted(
            &destination,
            crate::storage_encryption::load_storage_encryption_key(
                config.storage_encryption.key_path.as_ref().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            recovered
                .conn
                .lock()
                .unwrap()
                .query_row(
                    "SELECT value FROM agent_kv WHERE key = 'encrypted-recovery-proof'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "survived"
        );
    }

    #[test]
    fn corrupt_recovery_journal_rejects_unknown_or_unsafe_state() {
        let directory = TestDirectory::new("corrupt-recovery-journal");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        let (signer, _) = BackupSigningKey::generate("corrupt-journal").unwrap();
        let backup_root = directory.path.join("backups");
        let manifest = source_manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        drop(source_manager);
        let destination = directory.path.join(BACKUP_DATABASE_FILE);
        let journal_path = companion_path(&destination, CORRUPT_RECOVERY_JOURNAL_SUFFIX);
        let journal = CorruptRecoveryJournal {
            format_version: CORRUPT_RECOVERY_FORMAT_VERSION,
            database_file: BACKUP_DATABASE_FILE.to_owned(),
            stage_file: ".agent_os.db.corrupt-recovery-test.staging".to_owned(),
            quarantine_dir: ".agent_os.db.corrupt-recovery-test.quarantine".to_owned(),
            quarantined_database_file: "corrupt-database.sqlite3".to_owned(),
            quarantined_wal_file: "corrupt-database.sqlite3-wal".to_owned(),
            quarantined_shm_file: "corrupt-database.sqlite3-shm".to_owned(),
            installation_id: manifest.installation_id.clone(),
            backup_sha256: manifest.sha256.clone(),
            backup_byte_count: manifest.byte_count,
            original_wal: false,
            original_shm: false,
        };
        let mut encoded = serde_json::to_value(&journal).unwrap();
        encoded["unexpected"] = serde_json::json!(true);
        let mut bytes = serde_json::to_vec_pretty(&encoded).unwrap();
        bytes.push(b'\n');
        write_new_owner_only_file(&journal_path, &bytes, "test recovery journal").unwrap();
        assert!(load_corrupt_recovery_journal(
            &journal_path,
            &destination,
            &manifest,
            &manifest.installation_id,
        )
        .unwrap_err()
        .to_string()
        .contains("not valid bounded JSON"));
        fs::remove_file(&journal_path).unwrap();

        let mut unsafe_journal = journal;
        unsafe_journal.stage_file = "../outside".to_owned();
        write_corrupt_recovery_journal(&journal_path, &unsafe_journal).unwrap();
        assert!(load_corrupt_recovery_journal(
            &journal_path,
            &destination,
            &manifest,
            &manifest.installation_id,
        )
        .unwrap_err()
        .to_string()
        .contains("filename is invalid"));
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_recovery_rejects_symlink_sidecar_without_touching_target() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("corrupt-recovery-symlink");
        let source = directory.path.join("source.db");
        let source_manager = SqliteContextManager::new(&source).unwrap();
        let (signer, _) = BackupSigningKey::generate("corrupt-symlink").unwrap();
        let backup_root = directory.path.join("backups");
        let manifest = source_manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        drop(source_manager);
        let data_dir = directory.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let destination = data_dir.join(BACKUP_DATABASE_FILE);
        fs::write(&destination, b"corrupt database").unwrap();
        let outside = directory.path.join("outside-wal");
        fs::write(&outside, b"must remain untouched").unwrap();
        symlink(&outside, companion_path(&destination, "-wal")).unwrap();

        let error = recover_corrupt_storage_from_config(
            &backup_root.join("qualified"),
            &recovery_config(&data_dir),
            &signer.trust_root(),
            &manifest.installation_id,
        )
        .unwrap_err();
        assert!(error.to_string().contains("regular non-symlink"));
        assert_eq!(fs::read(&outside).unwrap(), b"must remain untouched");
        assert_eq!(fs::read(&destination).unwrap(), b"corrupt database");
        assert!(!companion_path(&destination, CORRUPT_RECOVERY_JOURNAL_SUFFIX).exists());
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

    #[test]
    fn portable_storage_moves_complete_encrypted_state_to_a_distinct_key() {
        let directory = TestDirectory::new("portable-encrypted");
        let source = directory.path.join("source.db");
        let secret = "portable-secret-state";
        {
            let manager = SqliteContextManager::new_encrypted(
                &source,
                encrypted_test_key("source-generation", 0x41),
            )
            .unwrap();
            seed(&manager, "portable-proof", secret);
        }

        let bundle = directory.path.join("portable-bundle");
        let export = export_portable_storage(
            &source,
            &bundle,
            Some(&encrypted_test_key("source-generation", 0x41)),
        )
        .unwrap();
        assert_eq!(
            export.manifest.source_storage_key_id.as_deref(),
            Some("source-generation")
        );
        assert_eq!(verify_portable_storage(&bundle).unwrap(), export.manifest);
        assert_eq!(
            value(
                &bundle.join(PORTABLE_STORAGE_DATABASE_FILE),
                "portable-proof"
            )
            .as_deref(),
            Some(secret)
        );

        let destination = directory.path.join("imported.db");
        let import = import_portable_storage(
            &bundle,
            &destination,
            Some(&encrypted_test_key("destination-generation", 0x52)),
        )
        .unwrap();
        assert_eq!(
            import.destination_storage_key_id.as_deref(),
            Some("destination-generation")
        );
        assert_eq!(import.installation_id, export.manifest.installation_id);
        assert!(open_verified_database(
            &destination,
            Some(&encrypted_test_key("source-generation", 0x41))
        )
        .is_err());
        let imported = SqliteContextManager::new_encrypted(
            &destination,
            encrypted_test_key("destination-generation", 0x52),
        )
        .unwrap();
        let imported_value: String = imported
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM agent_kv WHERE key = 'portable-proof'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(imported_value, secret);
    }

    #[test]
    fn portable_storage_plaintext_round_trip_is_fresh_only_and_offline() {
        let directory = TestDirectory::new("portable-plaintext");
        let source = directory.path.join("source.db");
        let manager = SqliteContextManager::new(&source).unwrap();
        seed(&manager, "portable-proof", "plain");
        let blocked_bundle = directory.path.join("blocked-bundle");
        let error = export_portable_storage(&source, &blocked_bundle, None).unwrap_err();
        assert!(error.to_string().contains("already owned"));
        assert!(!blocked_bundle.exists());
        drop(manager);

        let bundle = directory.path.join("portable-bundle");
        export_portable_storage(&source, &bundle, None).unwrap();
        let destination = directory.path.join("imported.db");
        import_portable_storage(&bundle, &destination, None).unwrap();
        assert_eq!(
            value(&destination, "portable-proof").as_deref(),
            Some("plain")
        );

        let error = import_portable_storage(&bundle, &destination, None).unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(
            value(&destination, "portable-proof").as_deref(),
            Some("plain")
        );
    }

    #[test]
    fn portable_storage_rejects_tampering_without_publishing_a_destination() {
        let directory = TestDirectory::new("portable-tampering");
        let source = directory.path.join("source.db");
        {
            let manager = SqliteContextManager::new(&source).unwrap();
            seed(&manager, "portable-proof", "untampered");
        }
        let bundle = directory.path.join("portable-bundle");
        export_portable_storage(&source, &bundle, None).unwrap();

        let manifest_path = bundle.join(PORTABLE_STORAGE_MANIFEST_FILE);
        let original_manifest = fs::read(&manifest_path).unwrap();
        let mut unknown_manifest: serde_json::Value =
            serde_json::from_slice(&original_manifest).unwrap();
        unknown_manifest["unexpected"] = serde_json::json!(true);
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&unknown_manifest).unwrap(),
        )
        .unwrap();
        let destination = directory.path.join("must-not-exist.db");
        assert!(import_portable_storage(&bundle, &destination, None).is_err());
        assert!(!destination.exists());
        fs::write(&manifest_path, &original_manifest).unwrap();

        let unexpected = bundle.join("unexpected.txt");
        fs::write(&unexpected, b"not allowed").unwrap();
        assert!(import_portable_storage(&bundle, &destination, None).is_err());
        assert!(!destination.exists());
        fs::remove_file(unexpected).unwrap();

        let database = bundle.join(PORTABLE_STORAGE_DATABASE_FILE);
        let mut file = OpenOptions::new().write(true).open(&database).unwrap();
        file.seek(SeekFrom::Start(64)).unwrap();
        file.write_all(b"tampered").unwrap();
        file.sync_all().unwrap();
        assert!(verify_portable_storage(&bundle)
            .unwrap_err()
            .to_string()
            .contains("SHA-256 mismatch"));
        assert!(import_portable_storage(&bundle, &destination, None).is_err());
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn portable_storage_is_owner_only_and_rejects_symlink_payloads() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TestDirectory::new("portable-permissions");
        let source = directory.path.join("source.db");
        drop(SqliteContextManager::new(&source).unwrap());
        let bundle = directory.path.join("portable-bundle");
        export_portable_storage(&source, &bundle, None).unwrap();
        assert_eq!(
            fs::metadata(&bundle).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(bundle.join(PORTABLE_STORAGE_DATABASE_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(bundle.join(PORTABLE_STORAGE_MANIFEST_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let database = bundle.join(PORTABLE_STORAGE_DATABASE_FILE);
        let moved = directory.path.join("moved.sqlite3");
        fs::rename(&database, &moved).unwrap();
        symlink(&moved, &database).unwrap();
        assert!(verify_portable_storage(&bundle).is_err());
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
