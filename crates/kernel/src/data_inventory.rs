//! Machine-readable inventory of every supported storage boundary.
//!
//! The SQLite catalog is enforced against the live schema by `context` tests.
//! Non-SQLite entries describe the kernel-owned file/process boundaries and
//! the external systems an operator must govern separately. Entries contain
//! policy metadata only; no path, credential, tenant identifier, or content is
//! read from the running system.

use serde::{Deserialize, Serialize};

/// Version of the public inventory document shape.
pub const STORAGE_DATA_INVENTORY_SCHEMA_VERSION: u32 = 1;

/// One static policy record used to build the owned public wire document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticDataInventoryEntry {
    pub id: &'static str,
    pub persistence: &'static str,
    pub owner: &'static str,
    pub tenant_key: &'static str,
    pub sensitivity: &'static str,
    pub retention: &'static str,
    pub encryption: &'static str,
    pub backup: &'static str,
    pub deletion: &'static str,
}

/// One non-secret policy entry returned to trusted system operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataInventoryEntry {
    pub id: String,
    pub persistence: String,
    pub owner: String,
    pub tenant_key: String,
    pub sensitivity: String,
    pub retention: String,
    pub encryption: String,
    pub backup: String,
    pub deletion: String,
}

impl From<&StaticDataInventoryEntry> for DataInventoryEntry {
    fn from(entry: &StaticDataInventoryEntry) -> Self {
        Self {
            id: entry.id.into(),
            persistence: entry.persistence.into(),
            owner: entry.owner.into(),
            tenant_key: entry.tenant_key.into(),
            sensitivity: entry.sensitivity.into(),
            retention: entry.retention.into(),
            encryption: entry.encryption.into(),
            backup: entry.backup.into(),
            deletion: entry.deletion.into(),
        }
    }
}

/// Complete, versioned storage-boundary policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDataInventory {
    pub schema_version: u32,
    pub database_schema_version: i64,
    pub entries: Vec<DataInventoryEntry>,
}

macro_rules! sqlite_entry {
    (
        $table:literal,
        $owner:literal,
        $tenant_key:literal,
        $sensitivity:literal,
        $retention:literal,
        $encryption:literal,
        $deletion:literal
    ) => {
        StaticDataInventoryEntry {
            id: concat!("sqlite/", $table),
            persistence: "durable-sqlite",
            owner: $owner,
            tenant_key: $tenant_key,
            sensitivity: $sensitivity,
            retention: $retention,
            encryption: concat!(
                "SQLCipher whole-database encryption when configured; otherwise ",
                $encryption
            ),
            backup: "included in every verified database backup",
            deletion: $deletion,
        }
    };
}

/// Canonical policy for every logical table or view owned by the kernel.
///
/// A schema-introspection regression compares this catalog with
/// `sqlite_schema`, excluding only SQLite's private FTS5 shadow tables.
pub const SQLITE_DATA_INVENTORY: &[StaticDataInventoryEntry] = &[
    sqlite_entry!(
        "contexts",
        "agent",
        "agents.tenant_id via agent_id",
        "confidential prompt and context content",
        "until agent erasure",
        "not encrypted; owner-only database file permissions",
        "erase with agent or tenant"
    ),
    sqlite_entry!(
        "facts",
        "agent",
        "agents.tenant_id via agent_id",
        "confidential memory content and embeddings",
        "until explicit fact, agent, or tenant deletion",
        "not encrypted; owner-only database file permissions",
        "erase with fact, agent, or tenant and rebuild index"
    ),
    sqlite_entry!(
        "conversations",
        "agent",
        "agents.tenant_id via agent_id",
        "confidential conversation content",
        "until agent erasure",
        "not encrypted; owner-only database file permissions",
        "erase with agent or tenant"
    ),
    sqlite_entry!(
        "conversations_fts",
        "agent",
        "agents.tenant_id via agent_id",
        "confidential searchable conversation content",
        "until source conversation deletion",
        "not encrypted; owner-only database file permissions",
        "erase before source conversation"
    ),
    sqlite_entry!(
        "usage_log",
        "agent",
        "tenant_id and agent_id",
        "tenant metering and model metadata",
        "until agent or tenant erasure",
        "not encrypted; owner-only database file permissions",
        "erase subject rows; shared quota ledger remains"
    ),
    sqlite_entry!(
        "agent_kv",
        "agent",
        "agents.tenant_id via agent_id",
        "confidential agent key/value content",
        "until key, agent, or tenant deletion",
        "not encrypted; owner-only database file permissions",
        "erase with key, agent, or tenant"
    ),
    sqlite_entry!(
        "context_spills",
        "agent and tenant",
        "tenant_id",
        "confidential spilled context content",
        "bounded per-agent retention, then agent or tenant erasure",
        "not encrypted; owner-only database file permissions",
        "erase with agent or tenant"
    ),
    sqlite_entry!(
        "context_pressure",
        "agent",
        "agents.tenant_id via agent_id",
        "operational counters and last-error class",
        "until agent erasure",
        "not encrypted; owner-only database file permissions",
        "erase with agent or tenant"
    ),
    sqlite_entry!(
        "context_snapshots",
        "agent",
        "agents.tenant_id via agent_id",
        "confidential context snapshot content",
        "until explicit snapshot, agent, or tenant deletion",
        "not encrypted; owner-only database file permissions",
        "erase with snapshot, agent, or tenant"
    ),
    sqlite_entry!(
        "generation_checkpoints",
        "agent and tenant",
        "tenant_id",
        "confidential prompts, partial output, and tool state",
        "bounded per-agent retention, then completion or erasure",
        "not encrypted; owner-only database file permissions",
        "erase with checkpoint, agent, or tenant"
    ),
    sqlite_entry!(
        "agents",
        "agent and tenant",
        "tenant_id",
        "agent identity, task, provider, and policy metadata",
        "until agent or tenant erasure",
        "not encrypted; owner-only database file permissions",
        "erase last after owned child rows"
    ),
    sqlite_entry!(
        "loaded_package_instances",
        "agent and tenant",
        "tenant_id",
        "package identity and live instance metadata",
        "until agent, package, or tenant removal",
        "not encrypted; owner-only database file permissions",
        "erase with agent or tenant"
    ),
    sqlite_entry!(
        "package_trust_keys",
        "tenant",
        "tenant_id",
        "public package verification keys and validity metadata",
        "until revocation or tenant erasure",
        "public verification material; integrity protected by database",
        "erase with tenant"
    ),
    sqlite_entry!(
        "package_artifacts",
        "tenant",
        "tenant_id",
        "signed package archive, manifest, and publisher metadata",
        "until yank plus policy removal or tenant erasure",
        "signed but not confidential; database file permissions apply",
        "erase with tenant"
    ),
    sqlite_entry!(
        "package_installations",
        "tenant",
        "tenant_id",
        "installed package lock and dependency metadata",
        "until uninstall or tenant erasure",
        "not encrypted; owner-only database file permissions",
        "erase with tenant"
    ),
    sqlite_entry!(
        "package_install_history",
        "tenant",
        "tenant_id",
        "package transition history",
        "until tenant erasure",
        "not encrypted; owner-only database file permissions",
        "erase with tenant"
    ),
    sqlite_entry!(
        "package_rate_limits",
        "tenant and user actor",
        "tenant_id",
        "pseudonymous actor rate-limit state",
        "until tenant erasure or user-actor deletion",
        "not encrypted; owner-only database file permissions",
        "erase tenant rows and erased user actor limiter"
    ),
    sqlite_entry!(
        "package_transparency",
        "tenant; user actor becomes pseudonymous after user erasure",
        "tenant_id",
        "signed package transparency metadata",
        "until tenant erasure",
        "hash chained but not confidential",
        "erase with tenant; retain pseudonymous actor on user erasure"
    ),
    sqlite_entry!(
        "package_audit",
        "tenant; user actor becomes pseudonymous after user erasure",
        "tenant_id",
        "package security audit metadata",
        "until tenant erasure",
        "hash chained but not confidential",
        "erase with tenant; retain pseudonymous actor on user erasure"
    ),
    sqlite_entry!(
        "operator_tunables",
        "system",
        "none",
        "global operational configuration",
        "until superseded; current record retained",
        "not confidential; database integrity and file permissions",
        "retain on tenant, user, and agent erasure"
    ),
    sqlite_entry!(
        "operator_tunable_audit",
        "system",
        "none",
        "global operator mutation audit",
        "indefinite until a future explicit audit-retention policy",
        "not confidential; database integrity and file permissions",
        "retain on tenant, user, and agent erasure"
    ),
    sqlite_entry!(
        "service_runtime",
        "system with optional agent reference",
        "none; optional agent reference",
        "service desired state and bounded failure metadata",
        "while service definition is managed",
        "not encrypted; owner-only database file permissions",
        "clear erased agent reference; retain system service state"
    ),
    sqlite_entry!(
        "service_history",
        "system with optional agent reference",
        "none; optional agent reference",
        "service transition and failure metadata",
        "bounded per-service history",
        "not encrypted; owner-only database file permissions",
        "clear erased agent reference; retain system history"
    ),
    sqlite_entry!(
        "tenants",
        "tenant",
        "tenant_id",
        "tenant identity metadata",
        "until tenant erasure",
        "not encrypted; owner-only database file permissions",
        "erase last after tenant-owned rows"
    ),
    sqlite_entry!(
        "users",
        "user and tenant",
        "tenant_id",
        "user identity and role metadata",
        "until user or tenant erasure",
        "not encrypted; owner-only database file permissions",
        "erase with user or tenant"
    ),
    sqlite_entry!(
        "api_keys",
        "user and tenant",
        "tenant_id",
        "credential digest and identity binding",
        "until revocation, user erasure, or tenant erasure",
        "one-way SHA-256 digest; database file otherwise not encrypted",
        "erase with revocation, user, or tenant"
    ),
    sqlite_entry!(
        "sessions",
        "user and tenant",
        "tenant_id",
        "session credential digest and identity binding",
        "until expiry, revocation, user erasure, or tenant erasure",
        "one-way SHA-256 digest; database file otherwise not encrypted",
        "erase with expiry/revocation, user, or tenant"
    ),
    sqlite_entry!(
        "quota_epoch_floor",
        "system",
        "none",
        "global accounting epoch metadata",
        "indefinite enforcement floor",
        "not confidential; database integrity and file permissions",
        "retain"
    ),
    sqlite_entry!(
        "quota_epochs",
        "system plus tenant and agent scopes",
        "scope_key contains stable tenant/cgroup scope",
        "resource usage and quota aggregates",
        "indefinite until a future accounting-retention policy",
        "not encrypted; owner-only database file permissions",
        "erase subject cgroup scopes; retain shared scopes"
    ),
    sqlite_entry!(
        "quota_receipts",
        "system",
        "scope links carry tenant and agent ownership",
        "provider usage, cost, model, and idempotency metadata",
        "indefinite enforcement and reconciliation record",
        "not encrypted; owner-only database file permissions",
        "retain non-content accounting receipt"
    ),
    sqlite_entry!(
        "quota_receipt_scopes",
        "system plus tenant and agent scopes",
        "scope_key contains stable tenant/cgroup scope",
        "resource-accounting scope linkage",
        "with referenced quota receipt",
        "not encrypted; owner-only database file permissions",
        "erase subject cgroup scopes"
    ),
    sqlite_entry!(
        "quota_refunded_receipts",
        "system",
        "none",
        "non-content accounting idempotency tombstone",
        "indefinite to prevent duplicate refunds",
        "not confidential; database integrity and file permissions",
        "retain"
    ),
    sqlite_entry!(
        "quota_migration_fence",
        "system",
        "none",
        "schema migration fence metadata",
        "indefinite",
        "not confidential; database integrity and file permissions",
        "retain"
    ),
    sqlite_entry!(
        "cluster_node_identity",
        "system",
        "none",
        "node Ed25519 private key and identity metadata",
        "for installation lifetime or explicit node re-provisioning",
        "not encrypted; owner-only database file permissions",
        "retain; rotate only through explicit recovery procedure"
    ),
    sqlite_entry!(
        "cluster_node_control",
        "system",
        "none",
        "node availability and profile metadata",
        "current state for installation lifetime",
        "not confidential; database integrity and file permissions",
        "retain"
    ),
    sqlite_entry!(
        "cluster_node_control_audit",
        "system",
        "none",
        "node-control audit metadata",
        "indefinite until an explicit audit-retention policy",
        "not confidential; database integrity and file permissions",
        "retain"
    ),
    sqlite_entry!(
        "cluster_membership_authority",
        "system",
        "none",
        "membership authority public verification key",
        "for authority lifetime and verification history",
        "public verification material; integrity protected by database",
        "retain"
    ),
    sqlite_entry!(
        "cluster_join_challenges",
        "system",
        "none",
        "short-lived authentication challenge material",
        "until expiry or successful reconciliation",
        "not encrypted; owner-only database file permissions",
        "expire and remove during reconciliation"
    ),
    sqlite_entry!(
        "cluster_members",
        "system",
        "none",
        "node public identity, profile, and membership state",
        "until membership removal or authority reset",
        "public identity metadata; integrity protected by database",
        "retain until explicit membership removal"
    ),
    sqlite_entry!(
        "cluster_membership_audit",
        "system",
        "none",
        "cluster membership audit metadata",
        "indefinite until an explicit audit-retention policy",
        "not confidential; database integrity and file permissions",
        "retain"
    ),
    sqlite_entry!(
        "storage_meta",
        "system",
        "none",
        "installation identity and schema compatibility metadata",
        "for database lifetime",
        "not confidential; database integrity and file permissions",
        "retain"
    ),
    sqlite_entry!(
        "schema_migrations",
        "system",
        "none",
        "applied migration ledger",
        "for database lifetime",
        "not confidential; database integrity and file permissions",
        "retain"
    ),
    sqlite_entry!(
        "deletion_receipts",
        "system",
        "none; receipts intentionally omit subject identifiers",
        "privacy-safe deletion proof and per-table counts",
        "indefinite until an explicit receipt-retention policy",
        "not confidential; no subject or content identifiers",
        "retain non-identifying proof"
    ),
];

macro_rules! boundary_entry {
    (
        $id:literal,
        $persistence:literal,
        $owner:literal,
        $tenant_key:literal,
        $sensitivity:literal,
        $retention:literal,
        $encryption:literal,
        $backup:literal,
        $deletion:literal
    ) => {
        StaticDataInventoryEntry {
            id: $id,
            persistence: $persistence,
            owner: $owner,
            tenant_key: $tenant_key,
            sensitivity: $sensitivity,
            retention: $retention,
            encryption: $encryption,
            backup: $backup,
            deletion: $deletion,
        }
    };
}

/// File, process-memory, and external boundaries outside logical SQLite rows.
pub const NON_SQLITE_DATA_INVENTORY: &[StaticDataInventoryEntry] = &[
    boundary_entry!(
        "file/sqlite-wal-and-shm",
        "durable-file-sidecar",
        "system",
        "same mixed tenancy as database",
        "may contain any recently committed database page",
        "for active database lifetime; checkpointed by SQLite",
        "encrypted with the database by SQLCipher when configured; otherwise owner-only file permissions",
        "not copied directly; online backup consolidates committed state",
        "removed only with an offline database retirement"
    ),
    boundary_entry!(
        "file/storage-encryption-key",
        "durable-file",
        "system operator",
        "none",
        "cryptographic secret protecting database, WAL, and encrypted backups",
        "retain through database and dependent-backup lifetime",
        "owner-only Unix permissions; raw key bytes never enter SQL text",
        "never embedded in or copied with database backups",
        "rotate offline; retire only after every dependent backup expires"
    ),
    boundary_entry!(
        "file/operator-configuration",
        "durable-file",
        "system operator",
        "none",
        "may contain cleartext provider API keys and policy paths",
        "until operator replacement or decommissioning",
        "not application-encrypted; operator must enforce owner-only storage",
        "excluded from database backup; recover separately",
        "operator-owned secure deletion"
    ),
    boundary_entry!(
        "file/tls-private-key",
        "durable-file",
        "system operator",
        "none",
        "cryptographic secret",
        "until certificate rotation or decommissioning",
        "not application-encrypted; operator secret-store responsibility",
        "excluded from database backup; recover separately",
        "operator rotation and secure deletion"
    ),
    boundary_entry!(
        "file/backup-signing-private-key",
        "durable-file",
        "system operator",
        "none",
        "cryptographic secret",
        "until signer rotation or decommissioning",
        "owner-only Unix permissions; not otherwise encrypted",
        "never embedded in or copied with a backup",
        "operator rotation and secure deletion after recovery window"
    ),
    boundary_entry!(
        "file/backup-public-trust-root",
        "durable-file",
        "independent recovery operator",
        "none",
        "public verification key and key identifier",
        "retain for every backup signed by the key",
        "public material; integrity and independent custody required",
        "retained separately from the backup failure domain",
        "remove only after every dependent backup expires"
    ),
    boundary_entry!(
        "file/published-database-backups",
        "durable-file",
        "system operator",
        "same mixed tenancy as database snapshot",
        "contains all database sensitivity classes",
        "configured keep-latest and maximum-age policy",
        "inherits SQLCipher encryption and key id from encrypted source; optional Ed25519 authenticity is independent",
        "is the local backup artifact",
        "confirmed verified-retention operation; remote copies are separate"
    ),
    boundary_entry!(
        "file/service-definitions",
        "durable-file",
        "system operator",
        "none",
        "service task and policy configuration",
        "while service is configured",
        "not application-encrypted; operator file permissions",
        "excluded from database backup; recover separately",
        "operator-owned deletion"
    ),
    boundary_entry!(
        "file/managed-agent-workspaces",
        "durable-file",
        "agent and tenant",
        "workspace assignment derived from agent tenant",
        "potentially confidential tool input and output",
        "sandbox/workspace policy; no kernel-wide retention guarantee",
        "host or rootless-container isolation; not application-encrypted",
        "excluded from database backup",
        "sandbox cleanup or explicit external workspace policy"
    ),
    boundary_entry!(
        "file/on-device-models",
        "durable-file",
        "system operator",
        "none",
        "operator-provisioned model artifacts",
        "until model replacement or decommissioning",
        "not confidential by kernel policy; digest/format validation applies",
        "excluded from database backup",
        "operator-owned deletion"
    ),
    boundary_entry!(
        "ephemeral/agent-runtime",
        "ephemeral-memory",
        "agent and tenant",
        "live agent tenant binding",
        "tasks, active context, outputs, and lifecycle state",
        "until coordinated stop/erasure or process exit",
        "process memory only; no application memory encryption",
        "not backed up directly; committed state is in SQLite",
        "coordinated lifecycle cleanup or process exit"
    ),
    boundary_entry!(
        "ephemeral/scheduler-and-admission",
        "ephemeral-memory",
        "system with tenant and agent scopes",
        "live scope and agent identifiers",
        "queue positions, permits, usage estimates, and cancellation state",
        "until request completion/cancellation or process exit",
        "process memory only",
        "not backed up; durable quota receipts cover committed accounting",
        "RAII release, coordinated cleanup, or process exit"
    ),
    boundary_entry!(
        "ephemeral/credential-leases-and-auth-cache",
        "ephemeral-memory",
        "user and tenant",
        "credential-bound principal",
        "credential digests, principal identity, leases, and revocation state",
        "until lease drain, revocation, erasure, or process exit",
        "process memory only; raw presented secret is not retained",
        "not backed up",
        "credential drain/eviction or process exit"
    ),
    boundary_entry!(
        "ephemeral/provider-routing-state",
        "ephemeral-memory",
        "system with tenant request association",
        "request tenant while in flight",
        "health, circuit, retry, failover, request, and usage state",
        "until bounded health window/request completion or process exit",
        "process memory only; diagnostics are redacted",
        "not backed up; reconciled accounting is durable",
        "request completion, circuit reset, or process exit"
    ),
    boundary_entry!(
        "ephemeral/observability",
        "ephemeral-memory",
        "system",
        "bounded labels omit tenant and content identifiers",
        "metrics counters, bounded diagnostics, and audit broadcast events",
        "process lifetime unless an operator exports them",
        "process memory only; redaction and bounded-cardinality policy",
        "not backed up by AI Agent OS",
        "process exit; exported copies follow sink policy"
    ),
    boundary_entry!(
        "ephemeral/stream-and-cancellation-buffers",
        "ephemeral-memory",
        "agent and tenant request",
        "authenticated request binding",
        "partial model output, tool events, request ids, and cancellation handles",
        "until terminal frame, cancellation, timeout, or disconnect",
        "process memory and encrypted transport when TLS is configured",
        "not backed up; explicit checkpoints are durable",
        "terminal cleanup or process exit"
    ),
    boundary_entry!(
        "ephemeral/sandbox-runtime",
        "ephemeral-process",
        "agent and tenant",
        "sandbox owner agent tenant",
        "process metadata, namespaces, cgroups, mounts, and tool I/O",
        "until coordinated agent/tool cleanup or process exit",
        "rootless-container isolation; host memory is not encrypted",
        "not backed up",
        "forced cleanup on cancellation/stop/erasure or process exit"
    ),
    boundary_entry!(
        "external/provider-request-and-retention",
        "external-system",
        "provider account and requesting tenant",
        "provider policy and request tenant",
        "prompts, tool schemas, model outputs, and provider metadata",
        "provider contract and account policy",
        "provider transport/storage policy; outside kernel control",
        "excluded from AI Agent OS backup",
        "provider-side deletion/export policy; not erased by local hot-delete"
    ),
    boundary_entry!(
        "external/remote-backup-copies",
        "external-system",
        "recovery operator",
        "same mixed tenancy as database snapshot",
        "contains all database sensitivity classes",
        "external object-store lifecycle policy",
        "external encryption policy; signed manifest may prove authenticity",
        "external disaster-recovery copy",
        "external lifecycle/deletion policy; not erased locally"
    ),
    boundary_entry!(
        "external/log-metric-and-trace-sinks",
        "external-system",
        "system operator",
        "export configuration; kernel labels are tenant-safe by contract",
        "redacted operational telemetry",
        "external sink retention policy",
        "transport and storage policy of external sink",
        "excluded from AI Agent OS backup",
        "external sink deletion policy"
    ),
    boundary_entry!(
        "external/container-model-and-package-registries",
        "external-system",
        "system operator or publisher",
        "none unless external registry adds tenancy",
        "images, models, packages, signatures, and provenance",
        "external registry policy",
        "registry policy; signed/digest-pinned artifacts where supported",
        "excluded from database backup",
        "external registry lifecycle policy"
    ),
    boundary_entry!(
        "external/browser-peripheral-and-tool-services",
        "external-system",
        "external service account and requesting tenant",
        "external integration policy",
        "tool inputs, outputs, sessions, cookies, and device state",
        "external integration policy",
        "external transport/storage policy",
        "excluded from AI Agent OS backup",
        "external integration deletion policy; not erased locally"
    ),
];

/// Build the stable, owned public document without inspecting runtime content.
pub fn storage_data_inventory() -> StorageDataInventory {
    StorageDataInventory {
        schema_version: STORAGE_DATA_INVENTORY_SCHEMA_VERSION,
        database_schema_version: crate::schema::CURRENT_SCHEMA_VERSION,
        entries: SQLITE_DATA_INVENTORY
            .iter()
            .chain(NON_SQLITE_DATA_INVENTORY.iter())
            .map(DataInventoryEntry::from)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn inventory_is_unique_complete_bounded_and_json_roundtrips() {
        let inventory = storage_data_inventory();
        assert_eq!(
            inventory.schema_version,
            STORAGE_DATA_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(
            inventory.database_schema_version,
            crate::schema::CURRENT_SCHEMA_VERSION
        );

        let mut ids = BTreeSet::new();
        for entry in &inventory.entries {
            assert!(ids.insert(entry.id.as_str()), "duplicate id {}", entry.id);
            assert!(entry.id.len() <= 96, "{} id is unbounded", entry.id);
            for (field, value) in [
                ("persistence", &entry.persistence),
                ("owner", &entry.owner),
                ("tenant_key", &entry.tenant_key),
                ("sensitivity", &entry.sensitivity),
                ("retention", &entry.retention),
                ("encryption", &entry.encryption),
                ("backup", &entry.backup),
                ("deletion", &entry.deletion),
            ] {
                assert!(!value.trim().is_empty(), "{} has no {field}", entry.id);
                assert!(
                    value.len() <= 192,
                    "{} {field} exceeds the public bound",
                    entry.id
                );
            }
        }
        for persistence in [
            "durable-sqlite",
            "durable-file",
            "ephemeral-memory",
            "ephemeral-process",
            "external-system",
        ] {
            assert!(
                inventory
                    .entries
                    .iter()
                    .any(|entry| entry.persistence == persistence),
                "missing {persistence} boundary"
            );
        }
        assert!(
            inventory
                .entries
                .iter()
                .any(|entry| entry.encryption.contains("not encrypted")),
            "the inventory must expose unresolved encryption boundaries"
        );

        let encoded = serde_json::to_vec(&inventory).unwrap();
        assert!(encoded.len() < 128 * 1024);
        let decoded: StorageDataInventory = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, inventory);
    }
}
