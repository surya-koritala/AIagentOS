//! Signed `.agent` packages, tenant-scoped registry, and transactional installs.
//!
//! The archive is deliberately small and boring: a bounded binary envelope
//! around canonical JSON. It does not compress, so archive bombs are impossible,
//! and the JSON payload is not parsed until its SHA-256 digest and Ed25519
//! signature have been verified against a durable trust root.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ring::{digest, rand, signature};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

use crate::agent_package::AgentManifest;
use crate::context::SqliteContextManager;

const ARCHIVE_MAGIC: &[u8; 16] = b"AIAgentOS.agent\0";
const ARCHIVE_FORMAT_VERSION: u16 = 1;
const FIXED_HEADER_BYTES: usize = 16 + 2 + 2 + 2 + 8 + 32 + 64;
/// An archive is intentionally bounded below normal wire-request limits.
pub const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 12 * 1024 * 1024;
const MAX_FILES: usize = 1_024;
const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: usize = 8 * 1024 * 1024;
const REGISTRY_REQUESTS_PER_MINUTE: i64 = 120;
const SIGNING_DOMAIN: &[u8] = b"AIAgentOS signed package v1\0";

/// Metadata that participates in dependency resolution and policy admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub name: String,
    pub version: Version,
    pub description: String,
    pub publisher: String,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<PackageDep>,
    #[serde(default)]
    pub capabilities_required: Vec<String>,
    #[serde(default)]
    pub tools_required: Vec<String>,
}

/// A semver dependency. Optional dependencies are installed only when a
/// matching version is present in the same tenant registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDep {
    pub name: String,
    pub requirement: VersionReq,
    #[serde(default)]
    pub optional: bool,
}

/// Kind of content carried in the package. Executable/native payloads are not
/// supported: packages are data that drive the kernel's existing Rust runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageFileKind {
    Prompt,
    Asset,
    Policy,
}

/// One archive entry. Paths are relative canonical slash-separated paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    pub path: String,
    pub kind: PackageFileKind,
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`, populated canonically when signing and checked when
    /// verifying.
    pub checksum_sha256: String,
}

/// SPDX-shaped component inventory embedded in every archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub checksum_sha256: Option<String>,
}

/// Minimal, deterministic SBOM representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSbom {
    pub format: String,
    pub components: Vec<SbomComponent>,
}

/// The signed archive payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePayload {
    pub schema_version: u16,
    pub package: PackageManifest,
    pub agent: AgentManifest,
    #[serde(default)]
    pub files: Vec<PackageFile>,
    pub sbom: PackageSbom,
}

/// A trusted key record returned by the durable store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageTrustKey {
    pub tenant_id: String,
    pub key_id: String,
    pub publisher: String,
    pub public_key: Vec<u8>,
    pub status: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub superseded_by: Option<String>,
}

/// Operator-supplied trust-root mutation.
#[derive(Debug, Clone)]
pub struct PackageTrustInput {
    pub publisher: String,
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub supersedes: Option<String>,
}

/// A generated/imported Ed25519 signing identity. Secret key bytes are never
/// serialized by this type.
pub struct PackageSigningKey {
    publisher: String,
    key_id: String,
    key_pair: signature::Ed25519KeyPair,
}

impl PackageSigningKey {
    /// Import an Ed25519 PKCS#8 document.
    pub fn from_pkcs8(
        publisher: impl Into<String>,
        key_id: impl Into<String>,
        pkcs8: &[u8],
    ) -> Result<Self, PackageError> {
        let publisher = publisher.into();
        let key_id = key_id.into();
        validate_identity("publisher", &publisher)?;
        validate_identity("key id", &key_id)?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| PackageError::Crypto("invalid Ed25519 PKCS#8 key".into()))?;
        Ok(Self {
            publisher,
            key_id,
            key_pair,
        })
    }

    /// Generate a key and return both the signing identity and its PKCS#8
    /// document. Callers are responsible for protecting the returned secret.
    pub fn generate(
        publisher: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Result<(Self, Vec<u8>), PackageError> {
        let rng = rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| PackageError::Crypto("Ed25519 key generation failed".into()))?;
        let key = Self::from_pkcs8(publisher, key_id, pkcs8.as_ref())?;
        Ok((key, pkcs8.as_ref().to_vec()))
    }

    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key(&self) -> Vec<u8> {
        use ring::signature::KeyPair;
        self.key_pair.public_key().as_ref().to_vec()
    }
}

/// A package that has passed envelope, digest, signature, schema, and content
/// validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPackage {
    pub payload: PackagePayload,
    pub digest: String,
    pub key_id: String,
    pub publisher: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("invalid package: {0}")]
    Invalid(String),
    #[error("package archive integrity check failed")]
    Integrity,
    #[error("package signature is invalid")]
    Signature,
    #[error("package signing key is not trusted")]
    Untrusted,
    #[error("package signing key is revoked or outside its validity window")]
    Revoked,
    #[error("package access denied")]
    AccessDenied,
    #[error("package not found")]
    NotFound,
    #[error("package version already exists")]
    Duplicate,
    #[error("package dependency error: {0}")]
    Dependency(String),
    #[error("package policy denied: {0}")]
    Policy(String),
    #[error("package registry rate limit exceeded")]
    RateLimited,
    #[error("package persistence failed: {0}")]
    Persistence(String),
    #[error("package cryptography failed: {0}")]
    Crypto(String),
}

/// Build and verify bounded `.agent` archives.
pub struct PackageArchive;

impl PackageArchive {
    /// Normalize, validate, serialize, hash, and sign a package.
    pub fn sign(
        mut payload: PackagePayload,
        signer: &PackageSigningKey,
    ) -> Result<Vec<u8>, PackageError> {
        normalize_payload(&mut payload);
        validate_payload(&payload)?;
        if payload.package.publisher != signer.publisher {
            return Err(PackageError::Invalid(
                "package publisher does not match signing identity".into(),
            ));
        }
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|error| PackageError::Invalid(error.to_string()))?;
        if payload_bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(PackageError::Invalid("package payload is too large".into()));
        }
        let checksum = digest::digest(&digest::SHA256, &payload_bytes);
        let message = signing_message(
            &signer.key_id,
            &signer.publisher,
            checksum.as_ref(),
            &payload_bytes,
        );
        let signed = signer.key_pair.sign(&message);

        let key_len = u16::try_from(signer.key_id.len())
            .map_err(|_| PackageError::Invalid("key id is too long".into()))?;
        let publisher_len = u16::try_from(signer.publisher.len())
            .map_err(|_| PackageError::Invalid("publisher is too long".into()))?;
        let payload_len = u64::try_from(payload_bytes.len())
            .map_err(|_| PackageError::Invalid("package payload is too large".into()))?;
        let capacity = FIXED_HEADER_BYTES
            .checked_add(signer.key_id.len())
            .and_then(|size| size.checked_add(signer.publisher.len()))
            .and_then(|size| size.checked_add(payload_bytes.len()))
            .ok_or_else(|| PackageError::Invalid("package size overflow".into()))?;
        if capacity > MAX_ARCHIVE_BYTES {
            return Err(PackageError::Invalid("package archive is too large".into()));
        }

        let mut archive = Vec::with_capacity(capacity);
        archive.extend_from_slice(ARCHIVE_MAGIC);
        archive.extend_from_slice(&ARCHIVE_FORMAT_VERSION.to_be_bytes());
        archive.extend_from_slice(&key_len.to_be_bytes());
        archive.extend_from_slice(&publisher_len.to_be_bytes());
        archive.extend_from_slice(&payload_len.to_be_bytes());
        archive.extend_from_slice(checksum.as_ref());
        archive.extend_from_slice(signed.as_ref());
        archive.extend_from_slice(signer.key_id.as_bytes());
        archive.extend_from_slice(signer.publisher.as_bytes());
        archive.extend_from_slice(&payload_bytes);
        Ok(archive)
    }

    /// Verify with an explicit trust record. The payload is deserialized only
    /// after the digest and signature succeed.
    pub fn verify(
        archive: &[u8],
        trust: &PackageTrustKey,
        now: DateTime<Utc>,
    ) -> Result<VerifiedPackage, PackageError> {
        let envelope = parse_envelope(archive)?;
        if envelope.key_id != trust.key_id || envelope.publisher != trust.publisher {
            return Err(PackageError::Untrusted);
        }
        if trust.status != "trusted" || !key_valid_at(trust, now)? {
            return Err(PackageError::Revoked);
        }
        let actual = digest::digest(&digest::SHA256, envelope.payload);
        if !constant_time_equal(actual.as_ref(), envelope.checksum) {
            return Err(PackageError::Integrity);
        }
        let message = signing_message(
            envelope.key_id,
            envelope.publisher,
            envelope.checksum,
            envelope.payload,
        );
        signature::UnparsedPublicKey::new(&signature::ED25519, &trust.public_key)
            .verify(&message, envelope.signature)
            .map_err(|_| PackageError::Signature)?;

        let payload: PackagePayload = serde_json::from_slice(envelope.payload)
            .map_err(|error| PackageError::Invalid(error.to_string()))?;
        let mut canonical = payload.clone();
        normalize_payload(&mut canonical);
        if canonical != payload {
            return Err(PackageError::Invalid(
                "signed package payload is not canonical".into(),
            ));
        }
        validate_payload(&payload)?;
        if payload.package.publisher != envelope.publisher {
            return Err(PackageError::Invalid(
                "signed publisher does not match payload publisher".into(),
            ));
        }
        Ok(VerifiedPackage {
            payload,
            digest: hex_encode(actual.as_ref()),
            key_id: envelope.key_id.to_string(),
            publisher: envelope.publisher.to_string(),
        })
    }

    /// Read only the bounded identity fields needed to find a trust root.
    pub fn identity(archive: &[u8]) -> Result<(&str, &str), PackageError> {
        let envelope = parse_envelope(archive)?;
        Ok((envelope.key_id, envelope.publisher))
    }
}

struct ArchiveEnvelope<'a> {
    key_id: &'a str,
    publisher: &'a str,
    checksum: &'a [u8],
    signature: &'a [u8],
    payload: &'a [u8],
}

fn parse_envelope(archive: &[u8]) -> Result<ArchiveEnvelope<'_>, PackageError> {
    if archive.len() < FIXED_HEADER_BYTES || archive.len() > MAX_ARCHIVE_BYTES {
        return Err(PackageError::Invalid("invalid archive length".into()));
    }
    if &archive[..16] != ARCHIVE_MAGIC {
        return Err(PackageError::Invalid("invalid archive magic".into()));
    }
    let format = u16::from_be_bytes([archive[16], archive[17]]);
    if format != ARCHIVE_FORMAT_VERSION {
        return Err(PackageError::Invalid(format!(
            "unsupported archive format version {format}"
        )));
    }
    let key_len = usize::from(u16::from_be_bytes([archive[18], archive[19]]));
    let publisher_len = usize::from(u16::from_be_bytes([archive[20], archive[21]]));
    let payload_len =
        usize::try_from(u64::from_be_bytes(archive[22..30].try_into().map_err(
            |_| PackageError::Invalid("truncated archive header".into()),
        )?))
        .map_err(|_| PackageError::Invalid("payload length overflow".into()))?;
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(PackageError::Invalid("package payload is too large".into()));
    }
    let expected = FIXED_HEADER_BYTES
        .checked_add(key_len)
        .and_then(|size| size.checked_add(publisher_len))
        .and_then(|size| size.checked_add(payload_len))
        .ok_or_else(|| PackageError::Invalid("archive length overflow".into()))?;
    if expected != archive.len() {
        return Err(PackageError::Invalid("archive length mismatch".into()));
    }
    let checksum = &archive[30..62];
    let signature = &archive[62..126];
    let key_start = FIXED_HEADER_BYTES;
    let publisher_start = key_start + key_len;
    let payload_start = publisher_start + publisher_len;
    let key_id = std::str::from_utf8(&archive[key_start..publisher_start])
        .map_err(|_| PackageError::Invalid("key id is not UTF-8".into()))?;
    let publisher = std::str::from_utf8(&archive[publisher_start..payload_start])
        .map_err(|_| PackageError::Invalid("publisher is not UTF-8".into()))?;
    validate_identity("key id", key_id)?;
    validate_identity("publisher", publisher)?;
    Ok(ArchiveEnvelope {
        key_id,
        publisher,
        checksum,
        signature,
        payload: &archive[payload_start..],
    })
}

fn signing_message(key_id: &str, publisher: &str, checksum: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIGNING_DOMAIN.len() + key_id.len() + publisher.len() + checksum.len() + payload.len() + 16,
    );
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(&(key_id.len() as u32).to_be_bytes());
    message.extend_from_slice(key_id.as_bytes());
    message.extend_from_slice(&(publisher.len() as u32).to_be_bytes());
    message.extend_from_slice(publisher.as_bytes());
    message.extend_from_slice(checksum);
    message.extend_from_slice(payload);
    message
}

fn normalize_payload(payload: &mut PackagePayload) {
    payload.package.dependencies.sort_by(|left, right| {
        (&left.name, left.requirement.to_string(), left.optional).cmp(&(
            &right.name,
            right.requirement.to_string(),
            right.optional,
        ))
    });
    payload.package.capabilities_required.sort();
    payload.package.capabilities_required.dedup();
    payload.package.tools_required.sort();
    payload.package.tools_required.dedup();
    payload.agent.tools.sort();
    payload.agent.tools.dedup();
    payload
        .files
        .sort_by(|left, right| (&left.path, left.kind).cmp(&(&right.path, right.kind)));
    for file in &mut payload.files {
        file.checksum_sha256 = hex_encode(digest::digest(&digest::SHA256, &file.bytes).as_ref());
    }
    payload
        .sbom
        .components
        .sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
}

fn validate_payload(payload: &PackagePayload) -> Result<(), PackageError> {
    if payload.schema_version != 1 {
        return Err(PackageError::Invalid(
            "payload schema_version must be 1".into(),
        ));
    }
    validate_package_name(&payload.package.name)?;
    validate_identity("publisher", &payload.package.publisher)?;
    if payload.package.name != payload.agent.name {
        return Err(PackageError::Invalid(
            "package and agent names must match".into(),
        ));
    }
    payload
        .agent
        .validate()
        .map_err(|error| PackageError::Invalid(error.to_string()))?;
    if payload.package.description.len() > 65_536 {
        return Err(PackageError::Invalid("description is too large".into()));
    }
    if payload.package.dependencies.len() > 256 {
        return Err(PackageError::Invalid("too many dependencies".into()));
    }
    let mut dependencies = BTreeSet::new();
    for dependency in &payload.package.dependencies {
        validate_package_name(&dependency.name)?;
        if dependency.name == payload.package.name {
            return Err(PackageError::Dependency(
                "a package cannot depend on itself".into(),
            ));
        }
        if !dependencies.insert(&dependency.name) {
            return Err(PackageError::Dependency(format!(
                "duplicate dependency {}",
                dependency.name
            )));
        }
    }
    let required_tools: BTreeSet<_> = payload.package.tools_required.iter().collect();
    let agent_tools: BTreeSet<_> = payload.agent.tools.iter().collect();
    if required_tools != agent_tools {
        return Err(PackageError::Invalid(
            "package tool declarations must exactly match the agent manifest".into(),
        ));
    }
    for capability in &payload.package.capabilities_required {
        validate_capability(capability)?;
    }
    if payload.files.len() > MAX_FILES {
        return Err(PackageError::Invalid("too many package files".into()));
    }
    let mut total = 0usize;
    let mut paths = BTreeSet::new();
    for file in &payload.files {
        validate_archive_path(&file.path)?;
        if file.bytes.len() > MAX_FILE_BYTES {
            return Err(PackageError::Invalid(format!(
                "package file {} is too large",
                file.path
            )));
        }
        total = total
            .checked_add(file.bytes.len())
            .ok_or_else(|| PackageError::Invalid("package file size overflow".into()))?;
        if total > MAX_TOTAL_FILE_BYTES {
            return Err(PackageError::Invalid(
                "package files exceed the total size limit".into(),
            ));
        }
        if !paths.insert(&file.path) {
            return Err(PackageError::Invalid(format!(
                "duplicate package path {}",
                file.path
            )));
        }
        let actual = hex_encode(digest::digest(&digest::SHA256, &file.bytes).as_ref());
        if !constant_time_equal(actual.as_bytes(), file.checksum_sha256.as_bytes()) {
            return Err(PackageError::Integrity);
        }
    }
    if payload.sbom.format != "SPDX-2.3" {
        return Err(PackageError::Invalid("SBOM format must be SPDX-2.3".into()));
    }
    if payload.sbom.components.len() > 4_096 {
        return Err(PackageError::Invalid("too many SBOM components".into()));
    }
    Ok(())
}

fn validate_archive_path(path: &str) -> Result<(), PackageError> {
    if path.is_empty()
        || path.len() > 512
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
        || path.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.contains(':')
                || part.chars().any(char::is_control)
        })
    {
        return Err(PackageError::Invalid("unsafe package path".into()));
    }
    Ok(())
}

fn validate_identity(label: &str, value: &str) -> Result<(), PackageError> {
    if value.is_empty()
        || value.len() > 128
        || value
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "-_.@".contains(character)))
    {
        return Err(PackageError::Invalid(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_package_name(value: &str) -> Result<(), PackageError> {
    validate_identity("package name", value)
}

fn validate_capability(value: &str) -> Result<(), PackageError> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| {
            !(character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_')
        })
    {
        return Err(PackageError::Invalid("invalid capability name".into()));
    }
    Ok(())
}

fn key_valid_at(key: &PackageTrustKey, now: DateTime<Utc>) -> Result<bool, PackageError> {
    let from = DateTime::parse_from_rfc3339(&key.valid_from)
        .map_err(|_| PackageError::Persistence("invalid key valid_from timestamp".into()))?
        .with_timezone(&Utc);
    let until = key
        .valid_until
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|_| PackageError::Persistence("invalid key valid_until timestamp".into()))?
        .map(|value| value.with_timezone(&Utc));
    Ok(now >= from && until.is_none_or(|until| now < until))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |different, (left, right)| different | (left ^ right))
        == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Encode an archive for the newline-delimited JSON wire protocol.
pub fn archive_to_hex(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

/// Decode an archive from the wire protocol with a strict pre-allocation bound.
pub fn archive_from_hex(encoded: &str) -> Result<Vec<u8>, PackageError> {
    if encoded.len() > MAX_ARCHIVE_BYTES * 2 || !encoded.len().is_multiple_of(2) {
        return Err(PackageError::Invalid(
            "invalid encoded archive length".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit(digit: u8) -> Result<u8, PackageError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err(PackageError::Invalid(
            "archive encoding is not hexadecimal".into(),
        )),
    }
}

/// Exact dependency lock used for reproducible installs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageLock {
    pub schema_version: u16,
    pub packages: Vec<LockedPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedPackage {
    pub name: String,
    pub version: Version,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSummary {
    pub name: String,
    pub version: Version,
    pub publisher: String,
    pub digest: String,
    pub description: String,
    pub yanked: bool,
    pub published_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub tenant_id: String,
    pub name: String,
    pub version: Version,
    pub digest: String,
    pub lock: PackageLock,
    pub manifest: PackageManifest,
    pub installed_at: String,
}

/// The operator ceiling applied to an install. A package may request less, but
/// never more. Tenant wire calls use [`InstallPolicy::tenant_default`].
#[derive(Debug, Clone)]
pub struct InstallPolicy {
    pub max_profile: String,
    pub allowed_capabilities: BTreeSet<String>,
    pub allowed_tools: Option<BTreeSet<String>>,
}

impl InstallPolicy {
    pub fn tenant_default() -> Self {
        Self {
            max_profile: "standard".into(),
            allowed_capabilities: [
                "CAP_FILE_READ",
                "CAP_FILE_WRITE",
                "CAP_NET",
                "CAP_LLM_QUERY",
                "CAP_IPC",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            allowed_tools: None,
        }
    }

    pub fn system_default() -> Self {
        Self {
            max_profile: "elevated".into(),
            allowed_capabilities: [
                "CAP_FILE_READ",
                "CAP_FILE_WRITE",
                "CAP_NET",
                "CAP_LLM_QUERY",
                "CAP_IPC",
                "CAP_APP_CONTROL",
                "CAP_PROCESS_MANAGE",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            allowed_tools: None,
        }
    }

    fn admits(&self, payload: &PackagePayload) -> Result<(), PackageError> {
        if profile_rank(&payload.agent.profile) > profile_rank(&self.max_profile) {
            return Err(PackageError::Policy(format!(
                "profile {} exceeds operator ceiling {}",
                payload.agent.profile, self.max_profile
            )));
        }
        for capability in &payload.package.capabilities_required {
            if !self.allowed_capabilities.contains(capability) {
                return Err(PackageError::Policy(format!(
                    "capability {capability} is outside operator policy"
                )));
            }
        }
        if let Some(allowed_tools) = &self.allowed_tools {
            for tool in &payload.package.tools_required {
                if !allowed_tools.contains(tool) {
                    return Err(PackageError::Policy(format!(
                        "tool {tool} is outside operator policy"
                    )));
                }
            }
        }
        Ok(())
    }
}

fn profile_rank(profile: &str) -> u8 {
    match profile {
        "read-only" => 0,
        "standard" => 1,
        "elevated" => 2,
        "full-access" => 3,
        _ => u8::MAX,
    }
}

/// Durable registry and installation database. It shares the kernel SQLite
/// connection, so normal database backup/restore includes trust, artifacts,
/// locks, audit history, and installed state.
#[derive(Clone)]
pub struct PackageRegistry {
    store: Arc<SqliteContextManager>,
}

impl Default for PackageRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageRegistry {
    /// Standalone in-memory registry for embedding and tests.
    pub fn new() -> Self {
        let store =
            SqliteContextManager::in_memory().expect("package registry schema must initialize");
        Self::from_store(Arc::new(store))
    }

    pub fn from_store(store: Arc<SqliteContextManager>) -> Self {
        Self { store }
    }

    pub fn trust_key(
        &self,
        tenant_id: &str,
        actor: &str,
        input: &PackageTrustInput,
    ) -> Result<(), PackageError> {
        validate_scope(tenant_id, actor)?;
        self.admit_request(tenant_id, actor)?;
        validate_identity("publisher", &input.publisher)?;
        validate_identity("key id", &input.key_id)?;
        if input.public_key.len() != 32 {
            return Err(PackageError::Invalid(
                "Ed25519 public key must be 32 bytes".into(),
            ));
        }
        if input
            .valid_until
            .is_some_and(|until| until <= input.valid_from)
        {
            return Err(PackageError::Invalid(
                "key validity end must be after its start".into(),
            ));
        }
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        if let Some(old) = input.supersedes.as_deref() {
            let updated = transaction
                .execute(
                    "UPDATE package_trust_keys SET superseded_by = ?1
                     WHERE tenant_id = ?2 AND key_id = ?3 AND publisher = ?4",
                    params![input.key_id, tenant_id, old, input.publisher],
                )
                .map_err(persistence)?;
            if updated != 1 {
                return Err(PackageError::NotFound);
            }
        }
        transaction
            .execute(
                "INSERT INTO package_trust_keys
                 (tenant_id, key_id, publisher, public_key, status, valid_from,
                  valid_until, superseded_by, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'trusted', ?5, ?6, NULL, ?7)",
                params![
                    tenant_id,
                    input.key_id,
                    input.publisher,
                    input.public_key,
                    input.valid_from.to_rfc3339(),
                    input.valid_until.map(|value| value.to_rfc3339()),
                    Utc::now().to_rfc3339()
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    PackageError::Duplicate
                } else {
                    persistence(error)
                }
            })?;
        write_audit(
            &transaction,
            tenant_id,
            actor,
            "trust-key",
            None,
            None,
            "success",
            None,
            Some(&input.key_id),
        )?;
        transaction.commit().map_err(persistence)
    }

    pub fn revoke_key(
        &self,
        tenant_id: &str,
        actor: &str,
        key_id: &str,
    ) -> Result<(), PackageError> {
        validate_scope(tenant_id, actor)?;
        self.admit_request(tenant_id, actor)?;
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let updated = transaction
            .execute(
                "UPDATE package_trust_keys SET status = 'revoked'
                 WHERE tenant_id = ?1 AND key_id = ?2 AND status = 'trusted'",
                params![tenant_id, key_id],
            )
            .map_err(persistence)?;
        if updated != 1 {
            return Err(PackageError::NotFound);
        }
        write_audit(
            &transaction,
            tenant_id,
            actor,
            "revoke-key",
            None,
            None,
            "success",
            None,
            Some(key_id),
        )?;
        transaction.commit().map_err(persistence)
    }

    /// Authenticated publish. `actor` must be the signed publisher (trusted
    /// system callers may use the reserved `system` actor).
    pub fn publish(
        &self,
        tenant_id: &str,
        actor: &str,
        archive: &[u8],
    ) -> Result<PackageSummary, PackageError> {
        validate_scope(tenant_id, actor)?;
        self.admit_request(tenant_id, actor)?;
        let (key_id, publisher) = PackageArchive::identity(archive)?;
        if actor != publisher && actor != "system" {
            return Err(PackageError::AccessDenied);
        }
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let trust = read_trust_key(&transaction, tenant_id, key_id)?;
        let verified = PackageArchive::verify(archive, &trust, Utc::now())?;
        let manifest_json = serde_json::to_string(&verified.payload)
            .map_err(|error| PackageError::Invalid(error.to_string()))?;
        let published_at = Utc::now().to_rfc3339();
        let summary = PackageSummary {
            name: verified.payload.package.name.clone(),
            version: verified.payload.package.version.clone(),
            publisher: verified.publisher.clone(),
            digest: verified.digest.clone(),
            description: verified.payload.package.description.clone(),
            yanked: false,
            published_at: published_at.clone(),
        };
        transaction
            .execute(
                "INSERT INTO package_artifacts
                 (tenant_id, name, version, publisher, digest, archive, manifest_json,
                  yanked, published_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)",
                params![
                    tenant_id,
                    summary.name,
                    summary.version.to_string(),
                    summary.publisher,
                    summary.digest,
                    archive,
                    manifest_json,
                    published_at
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    PackageError::Duplicate
                } else {
                    persistence(error)
                }
            })?;
        append_transparency(
            &transaction,
            tenant_id,
            actor,
            "publish",
            &summary.name,
            &summary.version.to_string(),
            &summary.digest,
        )?;
        write_audit(
            &transaction,
            tenant_id,
            actor,
            "publish",
            Some(&summary.name),
            Some(&summary.version.to_string()),
            "success",
            Some(&summary.digest),
            None,
        )?;
        transaction.commit().map_err(persistence)?;
        Ok(summary)
    }

    pub fn yank(
        &self,
        tenant_id: &str,
        actor: &str,
        name: &str,
        version: &Version,
    ) -> Result<(), PackageError> {
        validate_scope(tenant_id, actor)?;
        self.admit_request(tenant_id, actor)?;
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let row: Option<(String, String)> = transaction
            .query_row(
                "SELECT publisher, digest FROM package_artifacts
                 WHERE tenant_id = ?1 AND name = ?2 AND version = ?3",
                params![tenant_id, name, version.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(persistence)?;
        let Some((publisher, package_digest)) = row else {
            return Err(PackageError::NotFound);
        };
        if actor != publisher && actor != "system" {
            return Err(PackageError::AccessDenied);
        }
        transaction
            .execute(
                "UPDATE package_artifacts SET yanked = 1
                 WHERE tenant_id = ?1 AND name = ?2 AND version = ?3",
                params![tenant_id, name, version.to_string()],
            )
            .map_err(persistence)?;
        append_transparency(
            &transaction,
            tenant_id,
            actor,
            "yank",
            name,
            &version.to_string(),
            &package_digest,
        )?;
        write_audit(
            &transaction,
            tenant_id,
            actor,
            "yank",
            Some(name),
            Some(&version.to_string()),
            "success",
            Some(&package_digest),
            None,
        )?;
        transaction.commit().map_err(persistence)
    }

    pub fn fetch(
        &self,
        tenant_id: &str,
        actor: &str,
        name: &str,
        version: &Version,
    ) -> Result<Vec<u8>, PackageError> {
        validate_scope(tenant_id, actor)?;
        self.admit_request(tenant_id, actor)?;
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let archive: Vec<u8> = transaction
            .query_row(
                "SELECT archive FROM package_artifacts
                 WHERE tenant_id = ?1 AND name = ?2 AND version = ?3 AND yanked = 0",
                params![tenant_id, name, version.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(persistence)?
            .ok_or(PackageError::NotFound)?;
        let (key_id, _) = PackageArchive::identity(&archive)?;
        let trust = read_trust_key(&transaction, tenant_id, key_id)?;
        PackageArchive::verify(&archive, &trust, Utc::now())?;
        write_audit(
            &transaction,
            tenant_id,
            actor,
            "fetch",
            Some(name),
            Some(&version.to_string()),
            "success",
            None,
            None,
        )?;
        transaction.commit().map_err(persistence)?;
        Ok(archive)
    }

    pub fn search(
        &self,
        tenant_id: &str,
        actor: &str,
        query: &str,
    ) -> Result<Vec<PackageSummary>, PackageError> {
        validate_scope(tenant_id, actor)?;
        self.admit_request(tenant_id, actor)?;
        if query.len() > 256 {
            return Err(PackageError::Invalid("search query is too long".into()));
        }
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let mut statement = transaction
            .prepare(
                "SELECT name, version, publisher, digest, manifest_json, yanked, published_at
                 FROM package_artifacts
                 WHERE tenant_id = ?1
                 ORDER BY name, version
                 LIMIT 1000",
            )
            .map_err(persistence)?;
        let rows = statement
            .query_map([tenant_id], |row| {
                let manifest_json: String = row.get(4)?;
                let payload: PackagePayload =
                    serde_json::from_str(&manifest_json).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            manifest_json.len(),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                let version_text: String = row.get(1)?;
                let version = Version::parse(&version_text).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        version_text.len(),
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok(PackageSummary {
                    name: row.get(0)?,
                    version,
                    publisher: row.get(2)?,
                    digest: row.get(3)?,
                    description: payload.package.description,
                    yanked: row.get::<_, i64>(5)? != 0,
                    published_at: row.get(6)?,
                })
            })
            .map_err(persistence)?;
        let mut summaries = Vec::new();
        let normalized_query = query.to_lowercase();
        for row in rows {
            let summary = row.map_err(persistence)?;
            if summary.name.to_lowercase().contains(&normalized_query)
                || summary
                    .description
                    .to_lowercase()
                    .contains(&normalized_query)
            {
                summaries.push(summary);
                if summaries.len() == 200 {
                    break;
                }
            }
        }
        drop(statement);
        transaction.commit().map_err(persistence)?;
        Ok(summaries)
    }

    pub fn resolve(
        &self,
        tenant_id: &str,
        name: &str,
        requirement: &VersionReq,
    ) -> Result<PackageLock, PackageError> {
        validate_identity("tenant id", tenant_id)?;
        let conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        resolve_locked(&conn, tenant_id, name, requirement)
    }

    pub fn install(
        &self,
        tenant_id: &str,
        actor: &str,
        name: &str,
        requirement: &VersionReq,
        policy: &InstallPolicy,
    ) -> Result<InstalledPackage, PackageError> {
        self.install_internal(tenant_id, actor, name, requirement, policy, false)
    }

    fn install_internal(
        &self,
        tenant_id: &str,
        actor: &str,
        name: &str,
        requirement: &VersionReq,
        policy: &InstallPolicy,
        fail_before_commit: bool,
    ) -> Result<InstalledPackage, PackageError> {
        validate_scope(tenant_id, actor)?;
        self.admit_request(tenant_id, actor)?;
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let lock = resolve_locked(&transaction, tenant_id, name, requirement)?;
        let mut root = None;
        for locked in &lock.packages {
            let archive: Vec<u8> = transaction
                .query_row(
                    "SELECT archive FROM package_artifacts
                     WHERE tenant_id = ?1 AND name = ?2 AND version = ?3
                       AND digest = ?4 AND yanked = 0",
                    params![
                        tenant_id,
                        locked.name,
                        locked.version.to_string(),
                        locked.digest
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(persistence)?
                .ok_or(PackageError::NotFound)?;
            let (key_id, _) = PackageArchive::identity(&archive)?;
            let trust = read_trust_key(&transaction, tenant_id, key_id)?;
            let verified = PackageArchive::verify(&archive, &trust, Utc::now())?;
            policy.admits(&verified.payload)?;
            if verified.digest != locked.digest {
                return Err(PackageError::Integrity);
            }
            let manifest_json = serde_json::to_string(&verified.payload)
                .map_err(|error| PackageError::Persistence(error.to_string()))?;

            let previous = read_installed(&transaction, tenant_id, &locked.name)?;
            let previous_json = serde_json::to_string(&previous)
                .map_err(|error| PackageError::Persistence(error.to_string()))?;
            transaction
                .execute(
                    "INSERT INTO package_install_history
                     (tenant_id, name, snapshot_json, action, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        tenant_id,
                        locked.name,
                        previous_json,
                        if previous.is_some() {
                            "upgrade"
                        } else {
                            "install"
                        },
                        Utc::now().to_rfc3339()
                    ],
                )
                .map_err(persistence)?;
            let installed_at = Utc::now().to_rfc3339();
            let lock_json = serde_json::to_string(&lock)
                .map_err(|error| PackageError::Persistence(error.to_string()))?;
            transaction
                .execute(
                    "INSERT INTO package_installations
                     (tenant_id, name, version, digest, lock_json, manifest_json, installed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(tenant_id, name) DO UPDATE SET
                       version = excluded.version,
                       digest = excluded.digest,
                       lock_json = excluded.lock_json,
                       manifest_json = excluded.manifest_json,
                       installed_at = excluded.installed_at",
                    params![
                        tenant_id,
                        locked.name,
                        locked.version.to_string(),
                        locked.digest,
                        lock_json,
                        manifest_json,
                        installed_at
                    ],
                )
                .map_err(persistence)?;
            if locked.name == name {
                root = Some(InstalledPackage {
                    tenant_id: tenant_id.to_string(),
                    name: locked.name.clone(),
                    version: locked.version.clone(),
                    digest: locked.digest.clone(),
                    lock: lock.clone(),
                    manifest: verified.payload.package,
                    installed_at,
                });
            }
        }
        if fail_before_commit {
            return Err(PackageError::Persistence(
                "injected crash before package transaction commit".into(),
            ));
        }
        let root = root.ok_or(PackageError::NotFound)?;
        write_audit(
            &transaction,
            tenant_id,
            actor,
            "install",
            Some(name),
            Some(&root.version.to_string()),
            "success",
            Some(&root.digest),
            None,
        )?;
        transaction.commit().map_err(persistence)?;
        Ok(root)
    }

    pub fn rollback(
        &self,
        tenant_id: &str,
        actor: &str,
        name: &str,
    ) -> Result<InstalledPackage, PackageError> {
        validate_scope(tenant_id, actor)?;
        self.admit_request(tenant_id, actor)?;
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let row: Option<(i64, String)> = transaction
            .query_row(
                "SELECT id, snapshot_json FROM package_install_history
                 WHERE tenant_id = ?1 AND name = ?2 AND snapshot_json != 'null'
                 ORDER BY id DESC LIMIT 1",
                params![tenant_id, name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(persistence)?;
        let Some((history_id, snapshot_json)) = row else {
            return Err(PackageError::NotFound);
        };
        let snapshot: InstalledPackage = serde_json::from_str(&snapshot_json)
            .map_err(|error| PackageError::Persistence(error.to_string()))?;
        let current =
            read_installed(&transaction, tenant_id, name)?.ok_or(PackageError::NotFound)?;
        let current_json = serde_json::to_string(&Some(current))
            .map_err(|error| PackageError::Persistence(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO package_install_history
                 (tenant_id, name, snapshot_json, action, created_at)
                 VALUES (?1, ?2, ?3, 'rollback', ?4)",
                params![tenant_id, name, current_json, Utc::now().to_rfc3339()],
            )
            .map_err(persistence)?;
        let restored_payload =
            self.verified_payload_by_digest(&transaction, tenant_id, &snapshot.digest)?;
        transaction
            .execute(
                "UPDATE package_installations
                 SET version = ?1, digest = ?2, lock_json = ?3,
                     manifest_json = ?4, installed_at = ?5
                 WHERE tenant_id = ?6 AND name = ?7",
                params![
                    snapshot.version.to_string(),
                    snapshot.digest,
                    serde_json::to_string(&snapshot.lock)
                        .map_err(|error| PackageError::Persistence(error.to_string()))?,
                    serde_json::to_string(&restored_payload)
                        .map_err(|error| PackageError::Persistence(error.to_string()))?,
                    Utc::now().to_rfc3339(),
                    tenant_id,
                    name
                ],
            )
            .map_err(persistence)?;
        transaction
            .execute(
                "DELETE FROM package_install_history WHERE id = ?1",
                [history_id],
            )
            .map_err(persistence)?;
        write_audit(
            &transaction,
            tenant_id,
            actor,
            "rollback",
            Some(name),
            Some(&snapshot.version.to_string()),
            "success",
            Some(&snapshot.digest),
            None,
        )?;
        transaction.commit().map_err(persistence)?;
        Ok(snapshot)
    }

    pub fn remove(&self, tenant_id: &str, actor: &str, name: &str) -> Result<(), PackageError> {
        validate_scope(tenant_id, actor)?;
        self.admit_request(tenant_id, actor)?;
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let installed =
            read_installed(&transaction, tenant_id, name)?.ok_or(PackageError::NotFound)?;
        let mut statement = transaction
            .prepare(
                "SELECT name, manifest_json FROM package_installations
                 WHERE tenant_id = ?1 AND name != ?2",
            )
            .map_err(persistence)?;
        let rows = statement
            .query_map(params![tenant_id, name], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(persistence)?;
        for row in rows {
            let (dependent, manifest_json) = row.map_err(persistence)?;
            let payload: PackagePayload = serde_json::from_str(&manifest_json)
                .map_err(|error| PackageError::Persistence(error.to_string()))?;
            if payload
                .package
                .dependencies
                .iter()
                .any(|dependency| !dependency.optional && dependency.name == name)
            {
                return Err(PackageError::Dependency(format!(
                    "{name} is required by {dependent}"
                )));
            }
        }
        drop(statement);
        transaction
            .execute(
                "DELETE FROM package_installations WHERE tenant_id = ?1 AND name = ?2",
                params![tenant_id, name],
            )
            .map_err(persistence)?;
        write_audit(
            &transaction,
            tenant_id,
            actor,
            "remove",
            Some(name),
            Some(&installed.version.to_string()),
            "success",
            Some(&installed.digest),
            None,
        )?;
        transaction.commit().map_err(persistence)
    }

    pub fn list_installed(&self, tenant_id: &str) -> Result<Vec<InstalledPackage>, PackageError> {
        validate_identity("tenant id", tenant_id)?;
        let conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let mut statement = conn
            .prepare(
                "SELECT name, version, digest, lock_json, manifest_json, installed_at
                 FROM package_installations WHERE tenant_id = ?1 ORDER BY name",
            )
            .map_err(persistence)?;
        let rows = statement
            .query_map([tenant_id], |row| installed_from_row(tenant_id, row))
            .map_err(persistence)?;
        let mut installed = Vec::new();
        for row in rows {
            installed.push(row.map_err(persistence)?);
        }
        Ok(installed)
    }

    pub fn installed_agent_manifest(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> Result<AgentManifest, PackageError> {
        let conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let installed = read_installed(&conn, tenant_id, name)?.ok_or(PackageError::NotFound)?;
        Ok(self
            .verified_payload_by_digest(&conn, tenant_id, &installed.digest)?
            .agent)
    }

    fn verified_payload_by_digest(
        &self,
        transaction: &rusqlite::Connection,
        tenant_id: &str,
        package_digest: &str,
    ) -> Result<PackagePayload, PackageError> {
        let archive: Vec<u8> = transaction
            .query_row(
                "SELECT archive FROM package_artifacts
                 WHERE tenant_id = ?1 AND digest = ?2 AND yanked = 0",
                params![tenant_id, package_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(persistence)?
            .ok_or(PackageError::NotFound)?;
        let (key_id, _) = PackageArchive::identity(&archive)?;
        let trust = read_trust_key(transaction, tenant_id, key_id)?;
        Ok(PackageArchive::verify(&archive, &trust, Utc::now())?.payload)
    }

    fn admit_request(&self, tenant_id: &str, actor: &str) -> Result<(), PackageError> {
        let mut conn = self
            .store
            .conn
            .lock()
            .map_err(|_| PackageError::Persistence("database lock poisoned".into()))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        check_rate_limit(&transaction, tenant_id, actor)?;
        transaction.commit().map_err(persistence)
    }
}

fn validate_scope(tenant_id: &str, actor: &str) -> Result<(), PackageError> {
    validate_identity("tenant id", tenant_id)?;
    validate_identity("actor", actor)
}

fn read_trust_key(
    connection: &rusqlite::Connection,
    tenant_id: &str,
    key_id: &str,
) -> Result<PackageTrustKey, PackageError> {
    connection
        .query_row(
            "SELECT tenant_id, key_id, publisher, public_key, status, valid_from,
                    valid_until, superseded_by
             FROM package_trust_keys WHERE tenant_id = ?1 AND key_id = ?2",
            params![tenant_id, key_id],
            |row| {
                Ok(PackageTrustKey {
                    tenant_id: row.get(0)?,
                    key_id: row.get(1)?,
                    publisher: row.get(2)?,
                    public_key: row.get(3)?,
                    status: row.get(4)?,
                    valid_from: row.get(5)?,
                    valid_until: row.get(6)?,
                    superseded_by: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(persistence)?
        .ok_or(PackageError::Untrusted)
}

fn check_rate_limit(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    actor: &str,
) -> Result<(), PackageError> {
    let now = Utc::now().timestamp();
    let window = now - now.rem_euclid(60);
    let current: Option<(i64, i64)> = transaction
        .query_row(
            "SELECT window_started_at, requests FROM package_rate_limits
             WHERE tenant_id = ?1 AND actor = ?2",
            params![tenant_id, actor],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(persistence)?;
    match current {
        Some((stored_window, requests))
            if stored_window == window && requests >= REGISTRY_REQUESTS_PER_MINUTE =>
        {
            Err(PackageError::RateLimited)
        }
        Some((stored_window, requests)) if stored_window == window => {
            transaction
                .execute(
                    "UPDATE package_rate_limits SET requests = ?1
                     WHERE tenant_id = ?2 AND actor = ?3",
                    params![requests + 1, tenant_id, actor],
                )
                .map_err(persistence)?;
            Ok(())
        }
        _ => {
            transaction
                .execute(
                    "INSERT INTO package_rate_limits
                     (tenant_id, actor, window_started_at, requests)
                     VALUES (?1, ?2, ?3, 1)
                     ON CONFLICT(tenant_id, actor) DO UPDATE SET
                       window_started_at = excluded.window_started_at,
                       requests = 1",
                    params![tenant_id, actor, window],
                )
                .map_err(persistence)?;
            Ok(())
        }
    }
}

fn append_transparency(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    actor: &str,
    action: &str,
    name: &str,
    version: &str,
    package_digest: &str,
) -> Result<(), PackageError> {
    let previous: Option<String> = transaction
        .query_row(
            "SELECT entry_hash FROM package_transparency
             WHERE tenant_id = ?1 ORDER BY sequence DESC LIMIT 1",
            [tenant_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(persistence)?;
    let previous = previous.unwrap_or_else(|| "0".repeat(64));
    let created_at = Utc::now().to_rfc3339();
    let material = format!(
        "{previous}\0{tenant_id}\0{action}\0{name}\0{version}\0{package_digest}\0{actor}\0{created_at}"
    );
    let entry_hash = hex_encode(digest::digest(&digest::SHA256, material.as_bytes()).as_ref());
    transaction
        .execute(
            "INSERT INTO package_transparency
             (tenant_id, action, name, version, digest, previous_hash, entry_hash,
              actor, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                tenant_id,
                action,
                name,
                version,
                package_digest,
                previous,
                entry_hash,
                actor,
                created_at
            ],
        )
        .map_err(persistence)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_audit(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    actor: &str,
    action: &str,
    name: Option<&str>,
    version: Option<&str>,
    outcome: &str,
    package_digest: Option<&str>,
    detail: Option<&str>,
) -> Result<(), PackageError> {
    transaction
        .execute(
            "INSERT INTO package_audit
             (tenant_id, actor, action, name, version, outcome, digest, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                tenant_id,
                actor,
                action,
                name,
                version,
                outcome,
                package_digest,
                detail,
                Utc::now().to_rfc3339()
            ],
        )
        .map_err(persistence)?;
    Ok(())
}

fn resolve_locked(
    connection: &rusqlite::Connection,
    tenant_id: &str,
    name: &str,
    requirement: &VersionReq,
) -> Result<PackageLock, PackageError> {
    let mut selected = HashMap::new();
    let mut visiting = BTreeSet::new();
    resolve_one(
        connection,
        tenant_id,
        name,
        requirement,
        false,
        &mut selected,
        &mut visiting,
    )?;
    let mut packages: Vec<_> = selected.into_values().collect();
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(PackageLock {
        schema_version: 1,
        packages,
    })
}

fn resolve_one(
    connection: &rusqlite::Connection,
    tenant_id: &str,
    name: &str,
    requirement: &VersionReq,
    optional: bool,
    selected: &mut HashMap<String, LockedPackage>,
    visiting: &mut BTreeSet<String>,
) -> Result<(), PackageError> {
    if let Some(existing) = selected.get(name) {
        if requirement.matches(&existing.version) {
            return Ok(());
        }
        return Err(PackageError::Dependency(format!(
            "conflicting requirements for {name}: selected {}, additional requirement {requirement}",
            existing.version
        )));
    }
    if !visiting.insert(name.to_string()) {
        return Err(PackageError::Dependency(format!(
            "dependency cycle includes {name}"
        )));
    }
    let candidate = select_candidate(connection, tenant_id, name, requirement)?;
    let Some((locked, payload)) = candidate else {
        visiting.remove(name);
        if optional {
            return Ok(());
        }
        return Err(PackageError::Dependency(format!(
            "no tenant-scoped version of {name} matches {requirement}"
        )));
    };
    let mut dependencies = payload.package.dependencies.clone();
    dependencies.sort_by(|left, right| left.name.cmp(&right.name));
    for dependency in dependencies {
        resolve_one(
            connection,
            tenant_id,
            &dependency.name,
            &dependency.requirement,
            dependency.optional,
            selected,
            visiting,
        )?;
    }
    visiting.remove(name);
    selected.insert(name.to_string(), locked);
    Ok(())
}

fn select_candidate(
    connection: &rusqlite::Connection,
    tenant_id: &str,
    name: &str,
    requirement: &VersionReq,
) -> Result<Option<(LockedPackage, PackagePayload)>, PackageError> {
    let mut statement = connection
        .prepare(
            "SELECT version, digest, archive FROM package_artifacts
             WHERE tenant_id = ?1 AND name = ?2 AND yanked = 0",
        )
        .map_err(persistence)?;
    let rows = statement
        .query_map(params![tenant_id, name], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(persistence)?;
    let mut candidates = Vec::new();
    for row in rows {
        let (version_text, package_digest, archive) = row.map_err(persistence)?;
        let version = Version::parse(&version_text)
            .map_err(|error| PackageError::Persistence(error.to_string()))?;
        if requirement.matches(&version) {
            let (key_id, _) = PackageArchive::identity(&archive)?;
            let trust = read_trust_key(connection, tenant_id, key_id)?;
            let verified = PackageArchive::verify(&archive, &trust, Utc::now())?;
            if verified.digest != package_digest
                || verified.payload.package.name != name
                || verified.payload.package.version != version
            {
                return Err(PackageError::Integrity);
            }
            candidates.push((
                LockedPackage {
                    name: name.to_string(),
                    version,
                    digest: package_digest,
                },
                verified.payload,
            ));
        }
    }
    candidates.sort_by(|left, right| right.0.version.cmp(&left.0.version));
    Ok(candidates.into_iter().next())
}

fn read_installed(
    connection: &rusqlite::Connection,
    tenant_id: &str,
    name: &str,
) -> Result<Option<InstalledPackage>, PackageError> {
    connection
        .query_row(
            "SELECT name, version, digest, lock_json, manifest_json, installed_at
             FROM package_installations WHERE tenant_id = ?1 AND name = ?2",
            params![tenant_id, name],
            |row| installed_from_row(tenant_id, row),
        )
        .optional()
        .map_err(persistence)
}

fn installed_from_row(
    tenant_id: &str,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<InstalledPackage> {
    let version_text: String = row.get(1)?;
    let lock_json: String = row.get(3)?;
    let manifest_json: String = row.get(4)?;
    let version = Version::parse(&version_text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            version_text.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    let lock: PackageLock = serde_json::from_str(&lock_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            lock_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    let payload: PackagePayload = serde_json::from_str(&manifest_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            manifest_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(InstalledPackage {
        tenant_id: tenant_id.to_string(),
        name: row.get(0)?,
        version,
        digest: row.get(2)?,
        lock,
        manifest: payload.package,
        installed_at: row.get(5)?,
    })
}

fn persistence(error: rusqlite::Error) -> PackageError {
    PackageError::Persistence(error.to_string())
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                ..
            },
            _
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::DEFAULT_TENANT;
    use std::thread;

    fn payload(name: &str, version: &str, publisher: &str) -> PackagePayload {
        PackagePayload {
            schema_version: 1,
            package: PackageManifest {
                name: name.into(),
                version: Version::parse(version).unwrap(),
                description: format!("{name} package"),
                publisher: publisher.into(),
                license: Some("AGPL-3.0-only".into()),
                dependencies: Vec::new(),
                capabilities_required: vec!["CAP_FILE_READ".into()],
                tools_required: Vec::new(),
            },
            agent: AgentManifest {
                name: name.into(),
                description: format!("{name} agent"),
                task: "perform the signed package task".into(),
                entry: Some("start".into()),
                provider: "stub".into(),
                profile: "read-only".into(),
                priority: 3,
                nice: None,
                tools: Vec::new(),
                memory: Vec::new(),
            },
            files: vec![PackageFile {
                path: "prompts/system.txt".into(),
                kind: PackageFileKind::Prompt,
                bytes: b"You are a signed package.".to_vec(),
                checksum_sha256: String::new(),
            }],
            sbom: PackageSbom {
                format: "SPDX-2.3".into(),
                components: vec![SbomComponent {
                    name: "kernel-api".into(),
                    version: "1".into(),
                    license: Some("AGPL-3.0-only".into()),
                    checksum_sha256: None,
                }],
            },
        }
    }

    fn registry_with_key(tenant: &str, publisher: &str) -> (PackageRegistry, PackageSigningKey) {
        let registry = PackageRegistry::new();
        let (key, _) = PackageSigningKey::generate(publisher, "release-1").unwrap();
        registry
            .trust_key(
                tenant,
                "system",
                &PackageTrustInput {
                    publisher: publisher.into(),
                    key_id: key.key_id().into(),
                    public_key: key.public_key(),
                    valid_from: Utc::now() - chrono::Duration::minutes(1),
                    valid_until: None,
                    supersedes: None,
                },
            )
            .unwrap();
        (registry, key)
    }

    #[test]
    fn signed_archive_is_deterministic_and_verifies_before_parsing() {
        let (key, _) = PackageSigningKey::generate("alice", "release-1").unwrap();
        let archive_a =
            PackageArchive::sign(payload("researcher", "1.0.0", "alice"), &key).unwrap();
        let archive_b =
            PackageArchive::sign(payload("researcher", "1.0.0", "alice"), &key).unwrap();
        assert_eq!(archive_a, archive_b);
        let trust = PackageTrustKey {
            tenant_id: "tenant-a".into(),
            key_id: key.key_id().into(),
            publisher: "alice".into(),
            public_key: key.public_key(),
            status: "trusted".into(),
            valid_from: (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
            valid_until: None,
            superseded_by: None,
        };
        let verified = PackageArchive::verify(&archive_a, &trust, Utc::now()).unwrap();
        assert_eq!(verified.payload.package.name, "researcher");
        let mut expired = trust.clone();
        expired.valid_from = (Utc::now() - chrono::Duration::minutes(2)).to_rfc3339();
        expired.valid_until = Some((Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());
        assert!(matches!(
            PackageArchive::verify(&archive_a, &expired, Utc::now()),
            Err(PackageError::Revoked)
        ));

        let mut tampered = archive_a;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            PackageArchive::verify(&tampered, &trust, Utc::now()),
            Err(PackageError::Integrity)
        ));
    }

    #[test]
    fn unsafe_paths_and_oversized_archives_fail_closed() {
        let (key, _) = PackageSigningKey::generate("alice", "release-1").unwrap();
        let mut unsafe_payload = payload("unsafe", "1.0.0", "alice");
        unsafe_payload.files[0].path = "../escape".into();
        assert!(matches!(
            PackageArchive::sign(unsafe_payload, &key),
            Err(PackageError::Invalid(_))
        ));
        assert!(matches!(
            PackageArchive::identity(&vec![0; MAX_ARCHIVE_BYTES + 1]),
            Err(PackageError::Invalid(_))
        ));
    }

    #[test]
    fn recomputed_checksum_cannot_bypass_signature_verification() {
        let (key, _) = PackageSigningKey::generate("alice", "release-1").unwrap();
        let mut archive =
            PackageArchive::sign(payload("researcher", "1.0.0", "alice"), &key).unwrap();
        *archive.last_mut().unwrap() ^= 1;
        let envelope = parse_envelope(&archive).unwrap();
        let recomputed = digest::digest(&digest::SHA256, envelope.payload);
        archive[30..62].copy_from_slice(recomputed.as_ref());
        let trust = PackageTrustKey {
            tenant_id: "tenant-a".into(),
            key_id: key.key_id().into(),
            publisher: "alice".into(),
            public_key: key.public_key(),
            status: "trusted".into(),
            valid_from: (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
            valid_until: None,
            superseded_by: None,
        };
        assert!(matches!(
            PackageArchive::verify(&archive, &trust, Utc::now()),
            Err(PackageError::Signature)
        ));
    }

    #[test]
    fn publish_fetch_revoke_and_tenant_isolation() {
        let (registry, key) = registry_with_key("tenant-a", "alice");
        let archive = PackageArchive::sign(payload("researcher", "1.0.0", "alice"), &key).unwrap();
        registry.publish("tenant-a", "alice", &archive).unwrap();
        assert_eq!(
            registry
                .fetch(
                    "tenant-a",
                    "reader",
                    "researcher",
                    &Version::parse("1.0.0").unwrap()
                )
                .unwrap(),
            archive
        );
        assert!(matches!(
            registry.fetch(
                "tenant-b",
                "reader",
                "researcher",
                &Version::parse("1.0.0").unwrap()
            ),
            Err(PackageError::NotFound | PackageError::Untrusted)
        ));
        let withdrawn = PackageArchive::sign(payload("withdrawn", "1.0.0", "alice"), &key).unwrap();
        registry.publish("tenant-a", "alice", &withdrawn).unwrap();
        registry
            .yank(
                "tenant-a",
                "alice",
                "withdrawn",
                &Version::parse("1.0.0").unwrap(),
            )
            .unwrap();
        assert!(matches!(
            registry.fetch(
                "tenant-a",
                "reader",
                "withdrawn",
                &Version::parse("1.0.0").unwrap()
            ),
            Err(PackageError::NotFound)
        ));
        registry
            .revoke_key("tenant-a", "system", key.key_id())
            .unwrap();
        assert!(matches!(
            registry.fetch(
                "tenant-a",
                "reader",
                "researcher",
                &Version::parse("1.0.0").unwrap()
            ),
            Err(PackageError::Revoked)
        ));
    }

    #[test]
    fn deterministic_solver_detects_conflicts_and_cycles() {
        let (registry, key) = registry_with_key("tenant-a", "alice");
        for version in ["1.0.0", "1.2.0"] {
            let archive = PackageArchive::sign(payload("base", version, "alice"), &key).unwrap();
            registry.publish("tenant-a", "alice", &archive).unwrap();
        }
        let mut app = payload("app", "2.0.0", "alice");
        app.package.dependencies.push(PackageDep {
            name: "base".into(),
            requirement: VersionReq::parse("^1.0").unwrap(),
            optional: false,
        });
        registry
            .publish(
                "tenant-a",
                "alice",
                &PackageArchive::sign(app, &key).unwrap(),
            )
            .unwrap();
        let lock = registry
            .resolve("tenant-a", "app", &VersionReq::STAR)
            .unwrap();
        assert_eq!(lock.packages.len(), 2);
        assert_eq!(
            lock.packages
                .iter()
                .find(|package| package.name == "base")
                .unwrap()
                .version,
            Version::parse("1.2.0").unwrap()
        );

        let mut cycle_a = payload("cycle-a", "1.0.0", "alice");
        cycle_a.package.dependencies.push(PackageDep {
            name: "cycle-b".into(),
            requirement: VersionReq::STAR,
            optional: false,
        });
        let mut cycle_b = payload("cycle-b", "1.0.0", "alice");
        cycle_b.package.dependencies.push(PackageDep {
            name: "cycle-a".into(),
            requirement: VersionReq::STAR,
            optional: false,
        });
        for cycle in [cycle_a, cycle_b] {
            registry
                .publish(
                    "tenant-a",
                    "alice",
                    &PackageArchive::sign(cycle, &key).unwrap(),
                )
                .unwrap();
        }
        assert!(matches!(
            registry.resolve("tenant-a", "cycle-a", &VersionReq::STAR),
            Err(PackageError::Dependency(message)) if message.contains("cycle")
        ));

        let mut left = payload("left", "1.0.0", "alice");
        left.package.dependencies.push(PackageDep {
            name: "base".into(),
            requirement: VersionReq::parse("<1.1").unwrap(),
            optional: false,
        });
        let mut right = payload("right", "1.0.0", "alice");
        right.package.dependencies.push(PackageDep {
            name: "base".into(),
            requirement: VersionReq::parse(">=1.2").unwrap(),
            optional: false,
        });
        let mut conflict = payload("conflict", "1.0.0", "alice");
        conflict.package.dependencies = vec![
            PackageDep {
                name: "left".into(),
                requirement: VersionReq::STAR,
                optional: false,
            },
            PackageDep {
                name: "right".into(),
                requirement: VersionReq::STAR,
                optional: false,
            },
        ];
        for package in [left, right, conflict] {
            registry
                .publish(
                    "tenant-a",
                    "alice",
                    &PackageArchive::sign(package, &key).unwrap(),
                )
                .unwrap();
        }
        assert!(matches!(
            registry.resolve("tenant-a", "conflict", &VersionReq::STAR),
            Err(PackageError::Dependency(message)) if message.contains("conflicting")
        ));
    }

    #[test]
    fn dependency_confusion_and_privilege_escalation_fail_closed() {
        let store = Arc::new(SqliteContextManager::in_memory().unwrap());
        let registry = PackageRegistry::from_store(store);
        let (key_a, _) = PackageSigningKey::generate("alice", "release-a").unwrap();
        let (key_b, _) = PackageSigningKey::generate("bob", "release-b").unwrap();
        for (tenant, publisher, key) in [("tenant-a", "alice", &key_a), ("tenant-b", "bob", &key_b)]
        {
            registry
                .trust_key(
                    tenant,
                    "system",
                    &PackageTrustInput {
                        publisher: publisher.into(),
                        key_id: key.key_id().into(),
                        public_key: key.public_key(),
                        valid_from: Utc::now() - chrono::Duration::minutes(1),
                        valid_until: None,
                        supersedes: None,
                    },
                )
                .unwrap();
        }
        registry
            .publish(
                "tenant-b",
                "bob",
                &PackageArchive::sign(payload("shared-name", "9.9.9", "bob"), &key_b).unwrap(),
            )
            .unwrap();
        let mut app = payload("tenant-app", "1.0.0", "alice");
        app.package.dependencies.push(PackageDep {
            name: "shared-name".into(),
            requirement: VersionReq::STAR,
            optional: false,
        });
        registry
            .publish(
                "tenant-a",
                "alice",
                &PackageArchive::sign(app, &key_a).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            registry.install(
                "tenant-a",
                "operator",
                "tenant-app",
                &VersionReq::STAR,
                &InstallPolicy::tenant_default(),
            ),
            Err(PackageError::Dependency(_))
        ));

        let mut privileged = payload("privileged", "1.0.0", "alice");
        privileged.agent.profile = "elevated".into();
        privileged.package.capabilities_required = vec!["CAP_PROCESS_MANAGE".into()];
        registry
            .publish(
                "tenant-a",
                "alice",
                &PackageArchive::sign(privileged, &key_a).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            registry.install(
                "tenant-a",
                "operator",
                "privileged",
                &VersionReq::STAR,
                &InstallPolicy::tenant_default(),
            ),
            Err(PackageError::Policy(_))
        ));
        assert!(registry.list_installed("tenant-a").unwrap().is_empty());
    }

    #[test]
    fn key_rotation_records_supersession_and_keeps_new_releases_available() {
        let registry = PackageRegistry::new();
        let (old, _) = PackageSigningKey::generate("alice", "release-old").unwrap();
        let (new, _) = PackageSigningKey::generate("alice", "release-new").unwrap();
        registry
            .trust_key(
                "tenant-a",
                "system",
                &PackageTrustInput {
                    publisher: "alice".into(),
                    key_id: old.key_id().into(),
                    public_key: old.public_key(),
                    valid_from: Utc::now() - chrono::Duration::minutes(1),
                    valid_until: None,
                    supersedes: None,
                },
            )
            .unwrap();
        registry
            .trust_key(
                "tenant-a",
                "system",
                &PackageTrustInput {
                    publisher: "alice".into(),
                    key_id: new.key_id().into(),
                    public_key: new.public_key(),
                    valid_from: Utc::now() - chrono::Duration::minutes(1),
                    valid_until: None,
                    supersedes: Some(old.key_id().into()),
                },
            )
            .unwrap();
        registry
            .publish(
                "tenant-a",
                "alice",
                &PackageArchive::sign(payload("rotated", "2.0.0", "alice"), &new).unwrap(),
            )
            .unwrap();
        registry
            .revoke_key("tenant-a", "system", old.key_id())
            .unwrap();
        assert!(registry
            .fetch(
                "tenant-a",
                "reader",
                "rotated",
                &Version::parse("2.0.0").unwrap()
            )
            .is_ok());
        let connection = registry.store.conn.lock().unwrap();
        let superseded_by: String = connection
            .query_row(
                "SELECT superseded_by FROM package_trust_keys
                 WHERE tenant_id = 'tenant-a' AND key_id = 'release-old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(superseded_by, "release-new");
    }

    #[test]
    fn transparency_audit_and_rate_limits_are_durable_and_enforced() {
        let (registry, key) = registry_with_key("tenant-a", "alice");
        for version in ["1.0.0", "2.0.0"] {
            registry
                .publish(
                    "tenant-a",
                    "alice",
                    &PackageArchive::sign(payload("logged", version, "alice"), &key).unwrap(),
                )
                .unwrap();
        }
        let connection = registry.store.conn.lock().unwrap();
        let transparency: Vec<(String, String)> = {
            let mut statement = connection
                .prepare(
                    "SELECT previous_hash, entry_hash FROM package_transparency
                     WHERE tenant_id = 'tenant-a' ORDER BY sequence",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(transparency.len(), 2);
        assert_eq!(transparency[0].0, "0".repeat(64));
        assert_eq!(transparency[1].0, transparency[0].1);
        let audit_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM package_audit WHERE tenant_id = 'tenant-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(audit_count >= 3, "trust plus two publishes must be audited");

        let now = Utc::now().timestamp();
        let window = now - now.rem_euclid(60);
        connection
            .execute(
                "INSERT INTO package_rate_limits
                 (tenant_id, actor, window_started_at, requests)
                 VALUES ('tenant-a', 'flooder', ?1, ?2)",
                params![window, REGISTRY_REQUESTS_PER_MINUTE],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            registry.search("tenant-a", "flooder", "logged"),
            Err(PackageError::RateLimited)
        ));

        let rejected = PackageRegistry::new();
        for _ in 0..REGISTRY_REQUESTS_PER_MINUTE {
            assert!(matches!(
                rejected.publish("tenant-a", "attacker", b"not-an-archive"),
                Err(PackageError::Invalid(_))
            ));
        }
        assert!(matches!(
            rejected.publish("tenant-a", "attacker", b"not-an-archive"),
            Err(PackageError::RateLimited)
        ));
    }

    #[test]
    fn install_upgrade_rollback_remove_is_transactional() {
        let (registry, key) = registry_with_key(DEFAULT_TENANT, "alice");
        for version in ["1.0.0", "2.0.0"] {
            registry
                .publish(
                    DEFAULT_TENANT,
                    "alice",
                    &PackageArchive::sign(payload("runner", version, "alice"), &key).unwrap(),
                )
                .unwrap();
        }
        let v1 = registry
            .install(
                DEFAULT_TENANT,
                "operator",
                "runner",
                &VersionReq::parse("=1.0.0").unwrap(),
                &InstallPolicy::tenant_default(),
            )
            .unwrap();
        assert_eq!(v1.version, Version::parse("1.0.0").unwrap());
        let v2 = registry
            .install(
                DEFAULT_TENANT,
                "operator",
                "runner",
                &VersionReq::parse("=2.0.0").unwrap(),
                &InstallPolicy::tenant_default(),
            )
            .unwrap();
        assert_eq!(v2.version, Version::parse("2.0.0").unwrap());
        let restored = registry
            .rollback(DEFAULT_TENANT, "operator", "runner")
            .unwrap();
        assert_eq!(restored.version, Version::parse("1.0.0").unwrap());
        registry
            .remove(DEFAULT_TENANT, "operator", "runner")
            .unwrap();
        assert!(registry.list_installed(DEFAULT_TENANT).unwrap().is_empty());
    }

    #[test]
    fn crash_before_commit_leaves_no_partial_install() {
        let (registry, key) = registry_with_key("tenant-a", "alice");
        registry
            .publish(
                "tenant-a",
                "alice",
                &PackageArchive::sign(payload("atomic", "1.0.0", "alice"), &key).unwrap(),
            )
            .unwrap();
        assert!(registry
            .install_internal(
                "tenant-a",
                "operator",
                "atomic",
                &VersionReq::STAR,
                &InstallPolicy::tenant_default(),
                true,
            )
            .is_err());
        assert!(registry.list_installed("tenant-a").unwrap().is_empty());
    }

    #[test]
    fn concurrent_installations_serialize_without_corruption() {
        let store = Arc::new(SqliteContextManager::in_memory().unwrap());
        let registry = Arc::new(PackageRegistry::from_store(store));
        let (key, _) = PackageSigningKey::generate("alice", "release-1").unwrap();
        registry
            .trust_key(
                "tenant-a",
                "system",
                &PackageTrustInput {
                    publisher: "alice".into(),
                    key_id: key.key_id().into(),
                    public_key: key.public_key(),
                    valid_from: Utc::now() - chrono::Duration::minutes(1),
                    valid_until: None,
                    supersedes: None,
                },
            )
            .unwrap();
        registry
            .publish(
                "tenant-a",
                "alice",
                &PackageArchive::sign(payload("parallel", "1.0.0", "alice"), &key).unwrap(),
            )
            .unwrap();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let registry = registry.clone();
            workers.push(thread::spawn(move || {
                registry.install(
                    "tenant-a",
                    "operator",
                    "parallel",
                    &VersionReq::STAR,
                    &InstallPolicy::tenant_default(),
                )
            }));
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        let installed = registry.list_installed("tenant-a").unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].name, "parallel");
    }

    #[test]
    fn installed_state_survives_restart_and_backup_boundary() {
        let path =
            std::env::temp_dir().join(format!("agentos-package-{}.db", uuid::Uuid::new_v4()));
        let store = Arc::new(SqliteContextManager::new(&path).unwrap());
        let registry = PackageRegistry::from_store(store);
        let (key, _) = PackageSigningKey::generate("alice", "release-1").unwrap();
        registry
            .trust_key(
                "tenant-a",
                "system",
                &PackageTrustInput {
                    publisher: "alice".into(),
                    key_id: key.key_id().into(),
                    public_key: key.public_key(),
                    valid_from: Utc::now() - chrono::Duration::minutes(1),
                    valid_until: None,
                    supersedes: None,
                },
            )
            .unwrap();
        registry
            .publish(
                "tenant-a",
                "alice",
                &PackageArchive::sign(payload("durable", "1.0.0", "alice"), &key).unwrap(),
            )
            .unwrap();
        registry
            .install(
                "tenant-a",
                "operator",
                "durable",
                &VersionReq::STAR,
                &InstallPolicy::tenant_default(),
            )
            .unwrap();
        drop(registry);

        let backup_path = std::env::temp_dir().join(format!(
            "agentos-package-backup-{}.db",
            uuid::Uuid::new_v4()
        ));
        std::fs::copy(&path, &backup_path).unwrap();
        let reopened =
            PackageRegistry::from_store(Arc::new(SqliteContextManager::new(&backup_path).unwrap()));
        assert_eq!(reopened.list_installed("tenant-a").unwrap().len(), 1);
        assert_eq!(
            reopened
                .search("tenant-a", "reader", "durable")
                .unwrap()
                .len(),
            1
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_file(&backup_path);
        let _ = std::fs::remove_file(backup_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(backup_path.with_extension("db-shm"));
    }
}
