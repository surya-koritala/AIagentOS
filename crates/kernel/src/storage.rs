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
const BACKUP_SIGNATURE_ALGORITHM: &str = "ed25519";
const BACKUP_SIGNING_DOMAIN_V1: &[u8] = b"AIAGENTOS-BACKUP-MANIFEST-V1\0";
const BACKUP_SIGNING_DOMAIN_V2: &[u8] = b"AIAGENTOS-BACKUP-MANIFEST-V2\0";
const BACKUP_ENCRYPTION_FORMAT_VERSION: u32 = 1;
const BACKUP_ENCRYPTION_ALGORITHM: &str = "sqlcipher-4";

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

fn write_new_owner_only_file(path: &Path, bytes: &[u8], label: &str) -> Result<(), ContextError> {
    let parent = path
        .parent()
        .ok_or_else(|| storage_error(format!("{label} path must have a parent directory")))?;
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
    restore_backup_internal(backup_dir, destination_database, None, None)
}

/// Restore a backup only after it passes integrity and trusted-signature
/// verification.
pub fn restore_backup_with_trust(
    backup_dir: &Path,
    destination_database: &Path,
    trust: &BackupTrustRoot,
) -> Result<RestoreReport, ContextError> {
    restore_backup_internal(backup_dir, destination_database, Some(trust), None)
}

/// Restore an encrypted backup while authenticating both the snapshot and any
/// existing destination with the independently retained storage key.
pub fn restore_backup_with_storage_key(
    backup_dir: &Path,
    destination_database: &Path,
    storage_key: &StorageEncryptionKey,
) -> Result<RestoreReport, ContextError> {
    restore_backup_internal(backup_dir, destination_database, None, Some(storage_key))
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
    )
}

fn restore_backup_internal(
    backup_dir: &Path,
    destination_database: &Path,
    trust: Option<&BackupTrustRoot>,
    storage_key: Option<&StorageEncryptionKey>,
) -> Result<RestoreReport, ContextError> {
    let manifest = verify_backup_internal(backup_dir, trust, storage_key)?;
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
