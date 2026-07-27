//! Authenticated publication and recovery of immutable backups in an
//! S3-compatible object store.
//!
//! The object store is never a trust root. Publication requires a signed local
//! backup plus an independently retained recovery anchor. Recovery requires the
//! same independent public trust root and anchor before a downloaded snapshot
//! can be atomically published on disk.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode, Url};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use zeroize::Zeroizing;

use crate::storage::{
    verify_backup_with_recovery_anchor, BackupManifest, BackupRecoveryAnchor, BackupTrustRoot,
    BACKUP_DATABASE_FILE, BACKUP_MANIFEST_FILE,
};
use crate::storage_encryption::StorageEncryptionKey;
use crate::ContextError;

const REPORT_SCHEMA_VERSION: u32 = 1;
const SERVICE: &str = "s3";
const SIGNING_ALGORITHM: &str = "AWS4-HMAC-SHA256";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const LOCK_MODE: &str = "COMPLIANCE";
const MIN_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_PUBLICATION_REPORT_BYTES: u64 = 128 * 1024;
const MAX_REMOTE_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const MAX_ERROR_REQUEST_ID_BYTES: usize = 256;
const MAX_ACCESS_KEY_BYTES: usize = 256;
const MAX_SECRET_BYTES: usize = 4096;
const MAX_REGION_BYTES: usize = 128;
const MAX_BUCKET_BYTES: usize = 63;
const MAX_PREFIX_BYTES: usize = 512;
const MAX_PREFIX_SEGMENT_BYTES: usize = 96;

/// S3 credentials loaded from the standard AWS environment variables.
///
/// Secret values are zeroized on drop and are never included in reports or
/// error messages.
pub struct S3Credentials {
    access_key: String,
    secret_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl S3Credentials {
    pub fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Result<Self, ContextError> {
        let access_key = access_key.into();
        let secret_key = secret_key.into();
        validate_credential_component("AWS access key", &access_key, MAX_ACCESS_KEY_BYTES)?;
        validate_credential_component("AWS secret key", &secret_key, MAX_SECRET_BYTES)?;
        if let Some(token) = session_token.as_deref() {
            validate_credential_component("AWS session token", token, MAX_SECRET_BYTES)?;
        }
        Ok(Self {
            access_key,
            secret_key: Zeroizing::new(secret_key),
            session_token: session_token.map(Zeroizing::new),
        })
    }

    /// Load `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and the optional
    /// `AWS_SESSION_TOKEN`.
    pub fn from_env() -> Result<Self, ContextError> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| remote_error("AWS_ACCESS_KEY_ID is required"))?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| remote_error("AWS_SECRET_ACCESS_KEY is required"))?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        Self::new(access_key, secret_key, session_token)
    }
}

fn validate_credential_component(
    label: &str,
    value: &str,
    maximum: usize,
) -> Result<(), ContextError> {
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(|character| character.is_control())
    {
        return Err(remote_error(format!("{label} has an invalid value")));
    }
    Ok(())
}

/// Validated path-style S3 destination.
#[derive(Clone)]
pub struct RemoteBackupConfig {
    endpoint: Url,
    endpoint_origin: String,
    bucket: String,
    prefix: String,
    region: String,
}

impl RemoteBackupConfig {
    /// Create a destination. Plain HTTP is accepted only when explicitly
    /// enabled and the endpoint resolves syntactically to loopback.
    pub fn new(
        endpoint: &str,
        bucket: &str,
        prefix: &str,
        region: &str,
        allow_loopback_http: bool,
    ) -> Result<Self, ContextError> {
        let endpoint = Url::parse(endpoint)
            .map_err(|error| remote_error(format!("invalid object-store endpoint: {error}")))?;
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            return Err(remote_error(
                "object-store endpoint must be an origin URL without credentials, path, query, or fragment",
            ));
        }
        match endpoint.scheme() {
            "https" => {}
            "http"
                if allow_loopback_http
                    && endpoint
                        .host_str()
                        .is_some_and(is_syntactic_loopback_host) => {}
            "http" => {
                return Err(remote_error(
                    "plain HTTP object storage is allowed only for an explicitly enabled loopback qualification endpoint",
                ))
            }
            _ => {
                return Err(remote_error(
                    "object-store endpoint must use https (or explicitly enabled loopback http)",
                ))
            }
        }
        validate_bucket(bucket)?;
        validate_prefix(prefix)?;
        validate_region(region)?;
        let endpoint_origin = endpoint.origin().ascii_serialization();
        Ok(Self {
            endpoint,
            endpoint_origin,
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            region: region.to_string(),
        })
    }

    pub fn endpoint_origin(&self) -> &str {
        &self.endpoint_origin
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    fn object_key(&self, file_name: &str) -> String {
        format!("{}/{file_name}", self.prefix)
    }

    fn object_url(&self, key: &str, version_id: Option<&str>) -> Result<Url, ContextError> {
        let mut url = self.endpoint.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| remote_error("object-store endpoint cannot be used as a base URL"))?;
            segments.pop_if_empty();
            segments.push(&self.bucket);
            for segment in key.split('/') {
                segments.push(segment);
            }
        }
        if let Some(version_id) = version_id {
            validate_version_id(version_id)?;
            url.query_pairs_mut().append_pair("versionId", version_id);
        }
        Ok(url)
    }
}

fn is_syntactic_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn validate_bucket(bucket: &str) -> Result<(), ContextError> {
    let bytes = bucket.as_bytes();
    if !(3..=MAX_BUCKET_BYTES).contains(&bytes.len())
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(byte))
        || !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || bucket.contains("..")
        || bucket.contains(".-")
        || bucket.contains("-.")
    {
        return Err(remote_error(
            "object-store bucket must be a 3-63 character lowercase DNS-style name",
        ));
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<(), ContextError> {
    if prefix.is_empty()
        || prefix.len() > MAX_PREFIX_BYTES
        || prefix.starts_with('/')
        || prefix.ends_with('/')
    {
        return Err(remote_error(
            "remote backup prefix must be a non-empty relative path of at most 512 bytes",
        ));
    }
    for segment in prefix.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.len() > MAX_PREFIX_SEGMENT_BYTES
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(remote_error(
                "remote backup prefix segments must be 1-96 ASCII letters, digits, '-', '_' or '.'",
            ));
        }
    }
    Ok(())
}

fn validate_region(region: &str) -> Result<(), ContextError> {
    if region.is_empty()
        || region.len() > MAX_REGION_BYTES
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(remote_error(
            "object-store region must be 1-128 ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(())
}

fn validate_version_id(version_id: &str) -> Result<(), ContextError> {
    if version_id.is_empty()
        || version_id == "null"
        || version_id.len() > 1024
        || version_id.chars().any(|character| character.is_control())
    {
        return Err(remote_error(
            "object-store version identifier has an invalid value",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteObjectEvidence {
    pub key: String,
    pub byte_count: u64,
    pub sha256: String,
    pub version_id: String,
    pub retention_mode: String,
    pub retain_until: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBackupPublicationReport {
    pub schema_version: u32,
    pub qualification_class: String,
    pub endpoint_origin: String,
    pub bucket: String,
    pub prefix: String,
    pub manifest: BackupManifest,
    pub objects: Vec<RemoteObjectEvidence>,
    pub publication_elapsed_ms: u64,
    pub production_claim_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBackupRecoveryReport {
    pub schema_version: u32,
    pub qualification_class: String,
    pub endpoint_origin: String,
    pub bucket: String,
    pub prefix: String,
    pub destination: PathBuf,
    pub manifest: BackupManifest,
    pub objects: Vec<RemoteObjectEvidence>,
    pub downloaded_bytes: u64,
    pub recovery_elapsed_ms: u64,
    pub recovery_point_age_seconds: u64,
    pub production_claim_allowed: bool,
}

/// Load and validate a bounded publication receipt. The receipt is a locator,
/// not a trust root: recovery still verifies the downloaded bytes against the
/// independent backup trust root and recovery anchor.
pub fn load_remote_backup_publication_report(
    path: &Path,
) -> Result<RemoteBackupPublicationReport, ContextError> {
    let bytes = read_bounded_regular_file(
        path,
        "remote backup publication report",
        MAX_PUBLICATION_REPORT_BYTES,
    )?;
    let report: RemoteBackupPublicationReport =
        serde_json::from_slice(&bytes).map_err(|error| {
            remote_error(format!(
                "failed to parse remote backup publication report {}: {error}",
                path.display()
            ))
        })?;
    validate_publication_report_shape(&report)?;
    Ok(report)
}

fn validate_publication_report_shape(
    report: &RemoteBackupPublicationReport,
) -> Result<(), ContextError> {
    if report.schema_version != REPORT_SCHEMA_VERSION
        || report.qualification_class != "immutable_remote_backup_publication"
        || report.production_claim_allowed
    {
        return Err(remote_error(
            "remote backup publication report has an unsupported classification",
        ));
    }
    Url::parse(&report.endpoint_origin)
        .map_err(|_| remote_error("publication report endpoint origin is invalid"))?;
    validate_bucket(&report.bucket)?;
    validate_prefix(&report.prefix)?;
    if report.objects.len() != 2 {
        return Err(remote_error(
            "remote backup publication report must contain exactly two objects",
        ));
    }
    let expected_database_key = format!("{}/{}", report.prefix, BACKUP_DATABASE_FILE);
    let expected_manifest_key = format!("{}/{}", report.prefix, BACKUP_MANIFEST_FILE);
    let mut keys = report
        .objects
        .iter()
        .map(|object| object.key.as_str())
        .collect::<Vec<_>>();
    keys.sort_unstable();
    let mut expected = vec![
        expected_database_key.as_str(),
        expected_manifest_key.as_str(),
    ];
    expected.sort_unstable();
    if keys != expected {
        return Err(remote_error(
            "remote backup publication report contains unexpected object keys",
        ));
    }
    for object in &report.objects {
        validate_version_id(&object.version_id)?;
        if object.byte_count == 0
            || hex_decode(&object.sha256).is_none_or(|digest| digest.len() != 32)
            || object.retention_mode != LOCK_MODE
        {
            return Err(remote_error(
                "remote backup publication object evidence is invalid",
            ));
        }
        DateTime::parse_from_rfc3339(&object.retain_until)
            .map_err(|_| remote_error("publication object retain-until date is invalid"))?;
    }
    Ok(())
}

fn publication_objects_for_anchor<'a>(
    report: &'a RemoteBackupPublicationReport,
    config: &RemoteBackupConfig,
    anchor: &BackupRecoveryAnchor,
) -> Result<(&'a RemoteObjectEvidence, &'a RemoteObjectEvidence), ContextError> {
    validate_publication_report_shape(report)?;
    if report.endpoint_origin != config.endpoint_origin
        || report.bucket != config.bucket
        || report.prefix != config.prefix
    {
        return Err(remote_error(
            "publication report does not match the requested object-store location",
        ));
    }
    if report.manifest.installation_id != anchor.installation_id
        || report.manifest.created_at != anchor.created_at
        || report.manifest.byte_count != anchor.byte_count
        || report.manifest.sha256 != anchor.database_sha256
    {
        return Err(remote_error(
            "publication report manifest does not match the independent recovery anchor",
        ));
    }
    if anchor.byte_count > MAX_REMOTE_OBJECT_BYTES {
        return Err(remote_error(
            "remote backup database exceeds the supported 5 GiB single-object limit",
        ));
    }
    let database_key = config.object_key(BACKUP_DATABASE_FILE);
    let manifest_key = config.object_key(BACKUP_MANIFEST_FILE);
    let database = report
        .objects
        .iter()
        .find(|object| object.key == database_key)
        .ok_or_else(|| remote_error("publication report omitted the backup database"))?;
    let manifest = report
        .objects
        .iter()
        .find(|object| object.key == manifest_key)
        .ok_or_else(|| remote_error("publication report omitted the backup manifest"))?;
    if database.byte_count != anchor.byte_count
        || database.sha256 != anchor.database_sha256
        || manifest.byte_count > MAX_MANIFEST_BYTES
        || manifest.sha256 != anchor.manifest_sha256
    {
        return Err(remote_error(
            "publication report object evidence does not match the independent recovery anchor",
        ));
    }
    Ok((database, manifest))
}

struct S3Client<'a> {
    http: reqwest::Client,
    config: &'a RemoteBackupConfig,
    credentials: &'a S3Credentials,
}

impl<'a> S3Client<'a> {
    fn new(
        config: &'a RemoteBackupConfig,
        credentials: &'a S3Credentials,
    ) -> Result<Self, ContextError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15 * 60))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("aiagentos/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                remote_error(format!("failed to initialize object-store client: {error}"))
            })?;
        Ok(Self {
            http,
            config,
            credentials,
        })
    }

    async fn put_path(
        &self,
        key: &str,
        path: &Path,
        byte_count: u64,
        sha256: &str,
        retain_until: DateTime<Utc>,
    ) -> Result<RemoteObjectEvidence, ContextError> {
        let file = tokio::fs::File::open(path).await.map_err(|error| {
            remote_error(format!(
                "failed to open verified backup payload {}: {error}",
                path.display()
            ))
        })?;
        let body = reqwest::Body::wrap_stream(ReaderStream::new(file));
        self.put_object(key, body, byte_count, sha256, retain_until)
            .await
    }

    async fn put_bytes(
        &self,
        key: &str,
        bytes: Vec<u8>,
        sha256: &str,
        retain_until: DateTime<Utc>,
    ) -> Result<RemoteObjectEvidence, ContextError> {
        let byte_count = bytes.len() as u64;
        self.put_object(
            key,
            reqwest::Body::from(bytes),
            byte_count,
            sha256,
            retain_until,
        )
        .await
    }

    async fn put_object(
        &self,
        key: &str,
        body: reqwest::Body,
        byte_count: u64,
        sha256: &str,
        retain_until: DateTime<Utc>,
    ) -> Result<RemoteObjectEvidence, ContextError> {
        let checksum = checksum_base64(sha256)?;
        let retain_until_text = retain_until.to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut headers = BTreeMap::from([
            ("if-none-match".into(), "*".into()),
            ("x-amz-checksum-sha256".into(), checksum),
            ("x-amz-sdk-checksum-algorithm".into(), "SHA256".into()),
            ("x-amz-meta-agentos-sha256".into(), sha256.to_string()),
            ("x-amz-object-lock-mode".into(), LOCK_MODE.into()),
            (
                "x-amz-object-lock-retain-until-date".into(),
                retain_until_text,
            ),
        ]);
        let url = self.config.object_url(key, None)?;
        sign_headers(
            &Method::PUT,
            &url,
            &mut headers,
            sha256,
            &self.config.region,
            self.credentials,
            Utc::now(),
        )?;
        let response = self
            .http
            .request(Method::PUT, url)
            .headers(to_header_map(&headers)?)
            .header(reqwest::header::CONTENT_LENGTH, byte_count)
            .body(body)
            .send()
            .await
            .map_err(|error| redacted_transport_error("upload", key, error))?;
        if !response.status().is_success() && response.status() != StatusCode::PRECONDITION_FAILED {
            return Err(status_error("upload", key, &response));
        }
        let version_id = response
            .headers()
            .get("x-amz-version-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        self.head_and_validate(key, byte_count, sha256, retain_until, version_id.as_deref())
            .await
    }

    async fn head_and_validate(
        &self,
        key: &str,
        byte_count: u64,
        sha256: &str,
        minimum_retain_until: DateTime<Utc>,
        expected_version_id: Option<&str>,
    ) -> Result<RemoteObjectEvidence, ContextError> {
        let response = self
            .request_without_body(Method::HEAD, key, expected_version_id)
            .await?;
        if !response.status().is_success() {
            return Err(status_error("inspect", key, &response));
        }
        let headers = response.headers();
        let observed_bytes = required_header(headers, "content-length")?
            .parse::<u64>()
            .map_err(|_| remote_error("object-store content-length is invalid"))?;
        if observed_bytes != byte_count {
            return Err(remote_error(format!(
                "remote object {key:?} has {observed_bytes} bytes; expected {byte_count}"
            )));
        }
        let observed_sha = required_header(headers, "x-amz-meta-agentos-sha256")?;
        if observed_sha != sha256 {
            return Err(remote_error(format!(
                "remote object {key:?} does not match the independently verified SHA-256"
            )));
        }
        let retention_mode = required_header(headers, "x-amz-object-lock-mode")?;
        if retention_mode != LOCK_MODE {
            return Err(remote_error(format!(
                "remote object {key:?} is not protected by COMPLIANCE object lock"
            )));
        }
        let retain_until = required_header(headers, "x-amz-object-lock-retain-until-date")?;
        let observed_retain_until = DateTime::parse_from_rfc3339(&retain_until)
            .map_err(|_| remote_error("object-store retain-until date is invalid"))?
            .with_timezone(&Utc);
        if observed_retain_until < minimum_retain_until {
            return Err(remote_error(format!(
                "remote object {key:?} retention expires before the requested instant"
            )));
        }
        let version_id = required_header(headers, "x-amz-version-id")?;
        validate_version_id(&version_id)?;
        if expected_version_id.is_some_and(|expected| expected != version_id) {
            return Err(remote_error(format!(
                "remote object {key:?} returned a different immutable version identifier"
            )));
        }
        Ok(RemoteObjectEvidence {
            key: key.to_string(),
            byte_count,
            sha256: sha256.to_string(),
            version_id,
            retention_mode,
            retain_until: observed_retain_until.to_rfc3339_opts(SecondsFormat::Secs, true),
        })
    }

    async fn download_to(
        &self,
        key: &str,
        destination: &Path,
        byte_count: u64,
        sha256: &str,
        minimum_retain_until: DateTime<Utc>,
        version_id: &str,
    ) -> Result<RemoteObjectEvidence, ContextError> {
        let evidence = self
            .head_and_validate(
                key,
                byte_count,
                sha256,
                minimum_retain_until,
                Some(version_id),
            )
            .await?;
        let mut response = self
            .request_without_body(Method::GET, key, Some(version_id))
            .await?;
        if !response.status().is_success() {
            return Err(status_error("download", key, &response));
        }
        let mut options = tokio::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut output = options.open(destination).await.map_err(|error| {
            remote_error(format!(
                "failed to create remote-backup staging file {}: {error}",
                destination.display()
            ))
        })?;
        let mut digest_context = digest::Context::new(&digest::SHA256);
        let mut received = 0_u64;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| redacted_transport_error("download", key, error))?
        {
            received = received
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| remote_error("downloaded object size overflowed"))?;
            if received > byte_count {
                return Err(remote_error(format!(
                    "remote object {key:?} exceeded its verified byte count"
                )));
            }
            digest_context.update(&chunk);
            output.write_all(&chunk).await.map_err(|error| {
                remote_error(format!(
                    "failed to write remote-backup staging file {}: {error}",
                    destination.display()
                ))
            })?;
        }
        if received != byte_count {
            return Err(remote_error(format!(
                "remote object {key:?} returned {received} bytes; expected {byte_count}"
            )));
        }
        let observed_sha = hex_encode(digest_context.finish().as_ref());
        if observed_sha != sha256 {
            return Err(remote_error(format!(
                "remote object {key:?} failed SHA-256 verification"
            )));
        }
        output.sync_all().await.map_err(|error| {
            remote_error(format!(
                "failed to sync remote-backup staging file {}: {error}",
                destination.display()
            ))
        })?;
        Ok(evidence)
    }

    async fn request_without_body(
        &self,
        method: Method,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<reqwest::Response, ContextError> {
        let url = self.config.object_url(key, version_id)?;
        let mut headers = BTreeMap::new();
        sign_headers(
            &method,
            &url,
            &mut headers,
            EMPTY_SHA256,
            &self.config.region,
            self.credentials,
            Utc::now(),
        )?;
        self.http
            .request(method, url)
            .headers(to_header_map(&headers)?)
            .send()
            .await
            .map_err(|error| redacted_transport_error("request", key, error))
    }
}

/// Publish one independently authenticated backup as two immutable object
/// versions. The database is uploaded first and the manifest last, so the
/// manifest acts as the recovery-point commit marker. Re-running after a
/// partial failure succeeds only when existing objects match exactly.
pub async fn publish_remote_backup(
    backup_dir: &Path,
    storage_key: Option<&StorageEncryptionKey>,
    trust: &BackupTrustRoot,
    anchor: &BackupRecoveryAnchor,
    config: &RemoteBackupConfig,
    credentials: &S3Credentials,
    retain_until: DateTime<Utc>,
) -> Result<RemoteBackupPublicationReport, ContextError> {
    let retain_until = retain_until
        .with_nanosecond(0)
        .ok_or_else(|| remote_error("COMPLIANCE retention timestamp is invalid"))?;
    require_retention_window(retain_until)?;
    let started = Instant::now();
    let manifest = verify_backup_with_recovery_anchor(backup_dir, storage_key, trust, anchor)?;
    if manifest.byte_count > MAX_REMOTE_OBJECT_BYTES {
        return Err(remote_error(
            "remote backup database exceeds the supported 5 GiB single-object limit",
        ));
    }
    let manifest_path = backup_dir.join(BACKUP_MANIFEST_FILE);
    let manifest_bytes =
        read_bounded_regular_file(&manifest_path, "backup manifest", MAX_MANIFEST_BYTES)?;
    let manifest_sha256 = sha256_bytes(&manifest_bytes);
    if manifest_sha256 != anchor.manifest_sha256 {
        return Err(remote_error(
            "backup manifest does not match the independent recovery anchor",
        ));
    }

    let client = S3Client::new(config, credentials)?;
    let database_key = config.object_key(BACKUP_DATABASE_FILE);
    let manifest_key = config.object_key(BACKUP_MANIFEST_FILE);
    let database = client
        .put_path(
            &database_key,
            &backup_dir.join(BACKUP_DATABASE_FILE),
            manifest.byte_count,
            &manifest.sha256,
            retain_until,
        )
        .await?;
    let manifest_object = client
        .put_bytes(
            &manifest_key,
            manifest_bytes,
            &manifest_sha256,
            retain_until,
        )
        .await?;
    Ok(RemoteBackupPublicationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        qualification_class: "immutable_remote_backup_publication".into(),
        endpoint_origin: config.endpoint_origin.clone(),
        bucket: config.bucket.clone(),
        prefix: config.prefix.clone(),
        manifest,
        objects: vec![database, manifest_object],
        publication_elapsed_ms: elapsed_millis(started),
        production_claim_allowed: false,
    })
}

/// Create current-key delete markers for the checked-in disposable
/// qualification. Recovery must subsequently use the exact locked version IDs
/// retained in the publication receipt.
#[cfg(feature = "qualification")]
#[doc(hidden)]
pub async fn qualification_create_delete_markers(
    config: &RemoteBackupConfig,
    credentials: &S3Credentials,
) -> Result<Vec<String>, ContextError> {
    let client = S3Client::new(config, credentials)?;
    let mut delete_marker_versions = Vec::with_capacity(2);
    for file_name in [BACKUP_DATABASE_FILE, BACKUP_MANIFEST_FILE] {
        let key = config.object_key(file_name);
        let response = client
            .request_without_body(Method::DELETE, &key, None)
            .await?;
        if !response.status().is_success() {
            return Err(status_error("create delete marker", &key, &response));
        }
        if required_header(response.headers(), "x-amz-delete-marker")? != "true" {
            return Err(remote_error(format!(
                "object store did not create a delete marker for {key:?}"
            )));
        }
        let version_id = required_header(response.headers(), "x-amz-version-id")?;
        validate_version_id(&version_id)?;
        delete_marker_versions.push(version_id);
    }
    Ok(delete_marker_versions)
}

/// Download an immutable recovery point, verify it against independently
/// supplied trust and anchor material, and atomically publish it at
/// `destination`.
pub async fn fetch_remote_backup(
    destination: &Path,
    storage_key: Option<&StorageEncryptionKey>,
    trust: &BackupTrustRoot,
    anchor: &BackupRecoveryAnchor,
    publication: &RemoteBackupPublicationReport,
    config: &RemoteBackupConfig,
    credentials: &S3Credentials,
) -> Result<RemoteBackupRecoveryReport, ContextError> {
    reject_existing_destination(destination)?;
    let (published_database, published_manifest) =
        publication_objects_for_anchor(publication, config, anchor)?;
    let started = Instant::now();
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_real_directory(parent, "remote-backup destination parent")?;
    let staging = parent.join(format!(
        ".{}.{}.remote-backup-staging",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("backup"),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&staging).map_err(|error| {
        remote_error(format!(
            "failed to create remote-backup staging directory {}: {error}",
            staging.display()
        ))
    })?;
    set_owner_only_directory(&staging)?;
    let mut guard = StagingDirectory::new(staging.clone());

    let minimum_retain_until = Utc::now();
    let client = S3Client::new(config, credentials)?;
    let manifest_key = config.object_key(BACKUP_MANIFEST_FILE);
    let database_key = config.object_key(BACKUP_DATABASE_FILE);
    let manifest_object = client
        .download_to(
            &manifest_key,
            &staging.join(BACKUP_MANIFEST_FILE),
            published_manifest.byte_count,
            &anchor.manifest_sha256,
            minimum_retain_until,
            &published_manifest.version_id,
        )
        .await?;
    if manifest_object.byte_count > MAX_MANIFEST_BYTES {
        return Err(remote_error(
            "remote backup manifest exceeds the size limit",
        ));
    }
    let manifest_bytes = read_bounded_regular_file(
        &staging.join(BACKUP_MANIFEST_FILE),
        "downloaded backup manifest",
        MAX_MANIFEST_BYTES,
    )?;
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| remote_error(format!("downloaded backup manifest is invalid: {error}")))?;
    if manifest.byte_count != anchor.byte_count || manifest.sha256 != anchor.database_sha256 {
        return Err(remote_error(
            "downloaded backup manifest does not match the independent recovery anchor",
        ));
    }
    let database = client
        .download_to(
            &database_key,
            &staging.join(BACKUP_DATABASE_FILE),
            anchor.byte_count,
            &anchor.database_sha256,
            minimum_retain_until,
            &published_database.version_id,
        )
        .await?;

    let verified = verify_backup_with_recovery_anchor(&staging, storage_key, trust, anchor)?;
    let created_at = DateTime::parse_from_rfc3339(&verified.created_at)
        .map_err(|error| remote_error(format!("backup creation timestamp is invalid: {error}")))?
        .with_timezone(&Utc);
    let age = Utc::now().signed_duration_since(created_at);
    if age < chrono::Duration::zero() {
        return Err(remote_error(
            "backup creation timestamp is in the future; recovery age cannot be measured",
        ));
    }
    sync_directory(&staging)?;
    reject_existing_destination(destination)?;
    fs::rename(&staging, destination).map_err(|error| {
        remote_error(format!(
            "failed to atomically publish fetched backup {}: {error}",
            destination.display()
        ))
    })?;
    sync_directory(parent)?;
    guard.disarm();

    Ok(RemoteBackupRecoveryReport {
        schema_version: REPORT_SCHEMA_VERSION,
        qualification_class: "immutable_remote_backup_recovery".into(),
        endpoint_origin: config.endpoint_origin.clone(),
        bucket: config.bucket.clone(),
        prefix: config.prefix.clone(),
        destination: destination.to_path_buf(),
        manifest: verified,
        downloaded_bytes: manifest_object
            .byte_count
            .saturating_add(database.byte_count),
        objects: vec![database, manifest_object],
        recovery_elapsed_ms: elapsed_millis(started),
        recovery_point_age_seconds: age.num_seconds() as u64,
        production_claim_allowed: false,
    })
}

fn require_retention_window(retain_until: DateTime<Utc>) -> Result<(), ContextError> {
    let minimum = Utc::now()
        + chrono::Duration::from_std(MIN_RETENTION)
            .map_err(|_| remote_error("minimum retention duration is invalid"))?;
    if retain_until < minimum {
        return Err(remote_error(
            "COMPLIANCE retention must extend at least 24 hours into the future",
        ));
    }
    Ok(())
}

fn sign_headers(
    method: &Method,
    url: &Url,
    headers: &mut BTreeMap<String, String>,
    payload_sha256: &str,
    region: &str,
    credentials: &S3Credentials,
    now: DateTime<Utc>,
) -> Result<(), ContextError> {
    let host = canonical_host(url)?;
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    headers.insert("host".into(), host);
    headers.insert("x-amz-content-sha256".into(), payload_sha256.into());
    headers.insert("x-amz-date".into(), amz_date.clone());
    if let Some(token) = credentials.session_token.as_deref() {
        headers.insert("x-amz-security-token".into(), token.to_string());
    }
    for (name, value) in headers.iter() {
        if name.is_empty()
            || name.bytes().any(|byte| {
                !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && !matches!(byte, b'-')
            })
            || value.chars().any(|character| character.is_control())
        {
            return Err(remote_error("object-store signing header is invalid"));
        }
    }
    let signed_headers = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", normalize_header_value(value)))
        .collect::<String>();
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri(url),
        canonical_query(url),
        canonical_headers,
        signed_headers,
        payload_sha256
    );
    let scope = format!("{date}/{region}/{SERVICE}/aws4_request");
    let string_to_sign = format!(
        "{SIGNING_ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_bytes(canonical_request.as_bytes())
    );
    let date_key = hmac_sha256(
        format!("AWS4{}", credentials.secret_key.as_str()).as_bytes(),
        date.as_bytes(),
    );
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, SERVICE.as_bytes());
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    let signature = hex_encode(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    headers.insert(
        "authorization".into(),
        format!(
            "{SIGNING_ALGORITHM} Credential={}/{scope},SignedHeaders={signed_headers},Signature={signature}",
            credentials.access_key
        ),
    );
    Ok(())
}

fn canonical_uri(url: &Url) -> String {
    let path = url.path();
    if path.is_empty() {
        "/".into()
    } else {
        path.into()
    }
}

fn canonical_query(url: &Url) -> String {
    let mut pairs = url
        .query_pairs()
        .map(|(name, value)| (aws_uri_encode(&name), aws_uri_encode(&value)))
        .collect::<Vec<_>>();
    pairs.sort_unstable();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_uri_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn canonical_host(url: &Url) -> Result<String, ContextError> {
    let host = url
        .host_str()
        .ok_or_else(|| remote_error("object-store endpoint has no host"))?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_ascii_lowercase()
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn normalize_header_value(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, value).as_ref().to_vec()
}

fn checksum_base64(sha256: &str) -> Result<String, ContextError> {
    let bytes = hex_decode(sha256)
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| remote_error("object SHA-256 must be 32-byte lowercase hexadecimal"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn to_header_map(values: &BTreeMap<String, String>) -> Result<HeaderMap, ContextError> {
    let mut headers = HeaderMap::with_capacity(values.len());
    for (name, value) in values {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| remote_error("object-store request header name is invalid"))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| remote_error("object-store request header value is invalid"))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

fn required_header(headers: &HeaderMap, name: &'static str) -> Result<String, ContextError> {
    headers
        .get(name)
        .ok_or_else(|| remote_error(format!("object-store response omitted {name}")))?
        .to_str()
        .map(str::to_owned)
        .map_err(|_| remote_error(format!("object-store response {name} is invalid")))
}

fn status_error(operation: &str, key: &str, response: &reqwest::Response) -> ContextError {
    let request_id = response
        .headers()
        .get("x-amz-request-id")
        .or_else(|| response.headers().get("x-minio-deployment-id"))
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .chars()
                .filter(|character| !character.is_control())
                .take(MAX_ERROR_REQUEST_ID_BYTES)
                .collect::<String>()
        });
    match request_id {
        Some(request_id) => remote_error(format!(
            "object-store {operation} failed for {key:?} with HTTP {} (request {request_id})",
            response.status()
        )),
        None => remote_error(format!(
            "object-store {operation} failed for {key:?} with HTTP {}",
            response.status()
        )),
    }
}

fn redacted_transport_error(operation: &str, key: &str, error: reqwest::Error) -> ContextError {
    let class = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection failure"
    } else if error.is_body() {
        "body transfer failure"
    } else {
        "transport failure"
    };
    remote_error(format!("object-store {operation} {class} for {key:?}"))
}

fn read_bounded_regular_file(
    path: &Path,
    label: &str,
    maximum: u64,
) -> Result<Vec<u8>, ContextError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        remote_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(remote_error(format!(
            "{label} {} must be a non-empty regular file of at most {maximum} bytes",
            path.display()
        )));
    }
    fs::read(path).map_err(|error| {
        remote_error(format!(
            "failed to read {label} {}: {error}",
            path.display()
        ))
    })
}

fn reject_existing_destination(path: &Path) -> Result<(), ContextError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(remote_error(format!(
            "remote-backup destination {} already exists",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(remote_error(format!(
            "failed to inspect remote-backup destination {}: {error}",
            path.display()
        ))),
    }
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), ContextError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        remote_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(remote_error(format!(
            "{label} {} must be a real directory",
            path.display()
        )));
    }
    Ok(())
}

fn set_owner_only_directory(path: &Path) -> Result<(), ContextError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            remote_error(format!(
                "failed to protect remote-backup directory {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ContextError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            remote_error(format!(
                "failed to sync remote-backup directory {}: {error}",
                path.display()
            ))
        })
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_encode(digest::digest(&digest::SHA256, bytes).as_ref())
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
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
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

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn remote_error(message: impl Into<String>) -> ContextError {
    ContextError::StorageError(format!("remote backup: {}", message.into()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::SqliteContextManager;
    use crate::storage::{
        generate_backup_recovery_anchor, restore_backup_with_recovery_anchor, BackupSigningKey,
    };
    use crate::AgentId;
    use wiremock::matchers::{header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "agentos-remote-backup-test-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn mount_object(
        server: &MockServer,
        object_path: &str,
        bytes: &[u8],
        sha256: &str,
        retain_until: &str,
        head_count: u64,
    ) {
        Mock::given(method("PUT"))
            .and(path(object_path))
            .and(header_exists("authorization"))
            .and(header_exists("x-amz-checksum-sha256"))
            .and(header_exists("x-amz-object-lock-mode"))
            .respond_with(
                ResponseTemplate::new(200).insert_header("x-amz-version-id", "immutable-version-1"),
            )
            .expect(1)
            .mount(server)
            .await;
        let head = ResponseTemplate::new(200)
            .insert_header("content-length", bytes.len().to_string())
            .insert_header("x-amz-meta-agentos-sha256", sha256)
            .insert_header("x-amz-object-lock-mode", LOCK_MODE)
            .insert_header("x-amz-object-lock-retain-until-date", retain_until)
            .insert_header("x-amz-version-id", "immutable-version-1");
        Mock::given(method("HEAD"))
            .and(path(object_path))
            .and(query_param("versionId", "immutable-version-1"))
            .and(header_exists("authorization"))
            .respond_with(head)
            .expect(head_count)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(object_path))
            .and(query_param("versionId", "immutable-version-1"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .expect(1)
            .mount(server)
            .await;
    }

    #[test]
    fn config_rejects_unsafe_endpoints_and_keys() {
        assert!(RemoteBackupConfig::new(
            "http://object.example",
            "backups",
            "install/recovery",
            "us-east-1",
            false
        )
        .is_err());
        assert!(RemoteBackupConfig::new(
            "http://127.0.0.1:9000",
            "backups",
            "install/recovery",
            "us-east-1",
            false
        )
        .is_err());
        assert!(RemoteBackupConfig::new(
            "http://127.0.0.1:9000",
            "backups",
            "install/recovery",
            "us-east-1",
            true
        )
        .is_ok());
        assert!(RemoteBackupConfig::new(
            "https://user:secret@example.test",
            "backups",
            "install/recovery",
            "us-east-1",
            false
        )
        .is_err());
        assert!(RemoteBackupConfig::new(
            "https://example.test/path",
            "backups",
            "install/recovery",
            "us-east-1",
            false
        )
        .is_err());
        assert!(RemoteBackupConfig::new(
            "https://example.test",
            "Bad_Bucket",
            "install/recovery",
            "us-east-1",
            false
        )
        .is_err());
        assert!(RemoteBackupConfig::new(
            "https://example.test",
            "backups",
            "install/../recovery",
            "us-east-1",
            false
        )
        .is_err());
    }

    #[test]
    fn signer_matches_the_published_aws_s3_get_vector() {
        let credentials = S3Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
        )
        .unwrap();
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let mut headers = BTreeMap::from([("range".into(), "bytes=0-9".into())]);
        sign_headers(
            &Method::GET,
            &url,
            &mut headers,
            EMPTY_SHA256,
            "us-east-1",
            &credentials,
            DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        assert_eq!(
            headers.get("authorization").unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn credentials_and_checksums_fail_closed() {
        assert!(S3Credentials::new("", "secret", None).is_err());
        assert!(S3Credentials::new("access", "line\nbreak", None).is_err());
        assert!(checksum_base64("not-a-digest").is_err());
        assert_eq!(
            checksum_base64(EMPTY_SHA256).unwrap(),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
    }

    #[tokio::test]
    async fn signed_backup_round_trips_through_locked_remote_objects() {
        let root = TempDirectory::new();
        let database = root.0.join("source.sqlite3");
        let manager = SqliteContextManager::new(&database).unwrap();
        let agent_id = AgentId::new_v4();
        manager
            .kv_put(agent_id, "remote-proof", "survived")
            .unwrap();
        let (signer, _) = BackupSigningKey::generate("remote-test").unwrap();
        let trust = signer.trust_root();
        let backup_root = root.0.join("backups");
        let manifest = manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        let backup_dir = backup_root.join("qualified");
        let anchor_path = root.0.join("recovery-anchor.json");
        let anchor =
            generate_backup_recovery_anchor(&backup_dir, None, &trust, &anchor_path).unwrap();
        let manifest_bytes = fs::read(backup_dir.join(BACKUP_MANIFEST_FILE)).unwrap();
        let database_bytes = fs::read(backup_dir.join(BACKUP_DATABASE_FILE)).unwrap();
        assert_eq!(database_bytes.len() as u64, manifest.byte_count);

        let server = MockServer::start().await;
        let retain_until = Utc::now() + chrono::Duration::days(2);
        let retain_until_text = retain_until.to_rfc3339_opts(SecondsFormat::Secs, true);
        mount_object(
            &server,
            "/qualified-backups/install-1/backup-1/agent_os.db",
            &database_bytes,
            &manifest.sha256,
            &retain_until_text,
            2,
        )
        .await;
        mount_object(
            &server,
            "/qualified-backups/install-1/backup-1/manifest.json",
            &manifest_bytes,
            &anchor.manifest_sha256,
            &retain_until_text,
            2,
        )
        .await;

        let config = RemoteBackupConfig::new(
            &server.uri(),
            "qualified-backups",
            "install-1/backup-1",
            "us-east-1",
            true,
        )
        .unwrap();
        let credentials = S3Credentials::new("test-access", "test-secret", None).unwrap();
        let publication = publish_remote_backup(
            &backup_dir,
            None,
            &trust,
            &anchor,
            &config,
            &credentials,
            retain_until,
        )
        .await
        .unwrap();
        assert_eq!(publication.objects.len(), 2);
        assert!(publication
            .objects
            .iter()
            .all(|object| object.retention_mode == LOCK_MODE));
        assert!(!publication.production_claim_allowed);

        let mut substituted_publication = publication.clone();
        substituted_publication
            .objects
            .iter_mut()
            .find(|object| object.key.ends_with(BACKUP_DATABASE_FILE))
            .unwrap()
            .sha256 = "00".repeat(32);
        let rejected_destination = root.0.join("substituted-backup");
        let substitution_error = fetch_remote_backup(
            &rejected_destination,
            None,
            &trust,
            &anchor,
            &substituted_publication,
            &config,
            &credentials,
        )
        .await
        .unwrap_err();
        assert!(substitution_error
            .to_string()
            .contains("does not match the independent recovery anchor"));
        assert!(!rejected_destination.exists());

        let fetched = root.0.join("fetched-backup");
        let recovery = fetch_remote_backup(
            &fetched,
            None,
            &trust,
            &anchor,
            &publication,
            &config,
            &credentials,
        )
        .await
        .unwrap();
        assert_eq!(recovery.manifest, manifest);
        assert_eq!(
            recovery.downloaded_bytes,
            database_bytes.len() as u64 + manifest_bytes.len() as u64
        );
        assert!(!recovery.production_claim_allowed);

        drop(manager);
        let restored_database = root.0.join("restored.sqlite3");
        restore_backup_with_recovery_anchor(&fetched, &restored_database, None, &trust, &anchor)
            .unwrap();
        let restored = SqliteContextManager::new(&restored_database).unwrap();
        assert_eq!(
            restored.kv_get(agent_id, "remote-proof").unwrap(),
            Some("survived".into())
        );
    }

    #[tokio::test]
    async fn publication_rejects_object_store_without_compliance_evidence() {
        let root = TempDirectory::new();
        let manager = SqliteContextManager::new(&root.0.join("source.sqlite3")).unwrap();
        let (signer, _) = BackupSigningKey::generate("remote-test").unwrap();
        let trust = signer.trust_root();
        let backup_root = root.0.join("backups");
        manager
            .create_signed_backup(&backup_root, "qualified", &signer)
            .unwrap();
        let backup_dir = backup_root.join("qualified");
        let anchor =
            generate_backup_recovery_anchor(&backup_dir, None, &trust, &root.0.join("anchor.json"))
                .unwrap();

        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", anchor.byte_count.to_string())
                    .insert_header("x-amz-meta-agentos-sha256", &anchor.database_sha256)
                    .insert_header("x-amz-version-id", "version-without-lock"),
            )
            .mount(&server)
            .await;
        let config = RemoteBackupConfig::new(
            &server.uri(),
            "qualified-backups",
            "install-1/backup-1",
            "us-east-1",
            true,
        )
        .unwrap();
        let credentials = S3Credentials::new("test-access", "test-secret", None).unwrap();
        let error = publish_remote_backup(
            &backup_dir,
            None,
            &trust,
            &anchor,
            &config,
            &credentials,
            Utc::now() + chrono::Duration::days(2),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("omitted x-amz-object-lock-mode"));
    }
}
