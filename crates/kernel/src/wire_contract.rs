//! Versioned, machine-readable public wire contract.
//!
//! These schemas describe the stable top-level newline-JSON envelopes. Nested
//! domain objects are deliberately represented as JSON objects/arrays: their
//! concrete examples live in the versioned conformance fixtures, while the
//! operation tag, required fields, primitive types, errors, and transport
//! bounds remain discoverable directly from a running server.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::syscall_server::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::wire_io::{
    DEFAULT_MAX_CONNECTIONS, GRACEFUL_CLOSE_TIMEOUT, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT,
    MAX_JSON_FRAME_BYTES, RECOMMENDED_KEEPALIVE_INTERVAL, REQUEST_TIMEOUT,
    STREAM_EVENT_BUFFER_CAPACITY,
};

/// Stable feature identifiers announced by `hello`.
pub const WIRE_FEATURES: &[&str] = &[
    "agent_enforcement_introspection",
    "agent_gate_statistics",
    "authorized_cluster_membership",
    "cluster_principal_auth",
    crate::cluster_operation_receipts::FEATURE,
    "bounded_certificate_rollout",
    "cluster_ownership_leases",
    "backup_retention",
    "bounded_json_frames",
    "connection_keepalive",
    "context_pressure",
    "data_inventory",
    "data_erasure",
    "durable_node_identity",
    "durable_generation_checkpoints",
    "memory_lifecycle",
    "mutual_tls",
    "node_admission_control",
    "operator_control",
    "protocol_description",
    "request_deadlines",
    "request_id_cancellation",
    "scheduled_backups",
    "graceful_connection_close",
    "service_supervision",
    "signed_packages",
    "tenant_bound_auth",
    "tenant_identity_administration",
    "tls",
    "token_streaming",
    "typed_errors",
    "tool_vfs",
    "workspace_vfs",
    "namespace_mounts",
    "data_vfs",
    "durable_cloning",
    "model_discovery",
    "image_input",
];

/// A complete top-level protocol contract returned by `describe_protocol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDescription {
    pub schema_version: String,
    pub protocol_version: u32,
    pub min_protocol_version: u32,
    pub features: Vec<String>,
    pub transport: TransportDescription,
    pub request_schema: Value,
    pub reply_schema: Value,
    pub mcp_schema: Value,
    /// Schema for the nested event object carried by `stream_event` replies.
    pub event_schema: Value,
}

/// Machine-readable bounds shared by the syscall and MCP newline-JSON servers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportDescription {
    pub framing: String,
    pub encoding: String,
    pub max_frame_bytes: usize,
    pub default_max_connections: usize,
    pub handshake_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub recommended_keepalive_interval_ms: u64,
    pub graceful_close_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub stream_event_buffer_capacity: usize,
    pub request_ordering: String,
    pub unknown_field_behavior: String,
    pub unknown_operation_behavior: String,
    pub idle_close_behavior: String,
    pub graceful_close_behavior: String,
}

#[derive(Clone, Copy)]
enum JsonKind {
    String,
    Integer,
    Boolean,
    Object,
    Array,
    Any,
    StringOrNull,
    IntegerOrNull,
    ObjectOrNull,
    StringOrArray,
}

impl JsonKind {
    fn schema(self) -> Value {
        match self {
            Self::String => json!({"type": "string"}),
            Self::Integer => json!({"type": "integer"}),
            Self::Boolean => json!({"type": "boolean"}),
            Self::Object => json!({"type": "object"}),
            Self::Array => json!({"type": "array"}),
            Self::Any => json!({}),
            Self::StringOrNull => json!({"type": ["string", "null"]}),
            Self::IntegerOrNull => json!({"type": ["integer", "null"]}),
            Self::ObjectOrNull => json!({"type": ["object", "null"]}),
            Self::StringOrArray => json!({"type": ["string", "array"]}),
        }
    }
}

#[derive(Clone, Copy)]
struct Field {
    name: &'static str,
    kind: JsonKind,
    required: bool,
}

impl Field {
    const fn required(name: &'static str, kind: JsonKind) -> Self {
        Self {
            name,
            kind,
            required: true,
        }
    }

    const fn optional(name: &'static str, kind: JsonKind) -> Self {
        Self {
            name,
            kind,
            required: false,
        }
    }
}

#[derive(Clone, Copy)]
struct Variant {
    tag: &'static str,
    fields: &'static [Field],
}

const S: JsonKind = JsonKind::String;
const I: JsonKind = JsonKind::Integer;
const B: JsonKind = JsonKind::Boolean;
const O: JsonKind = JsonKind::Object;
const A: JsonKind = JsonKind::Array;
const X: JsonKind = JsonKind::Any;
const N: JsonKind = JsonKind::StringOrNull;
const NI: JsonKind = JsonKind::IntegerOrNull;
const ON: JsonKind = JsonKind::ObjectOrNull;
const SA: JsonKind = JsonKind::StringOrArray;

const REQUEST_VARIANTS: &[Variant] = &[
    Variant {
        tag: "create_tenant",
        fields: &[Field::required("name", S)],
    },
    Variant {
        tag: "list_tenants",
        fields: &[],
    },
    Variant {
        tag: "revoke_tenant",
        fields: &[
            Field::required("tenant_id", S),
            Field::optional("confirm", B),
        ],
    },
    Variant {
        tag: "create_user",
        fields: &[
            Field::required("username", S),
            Field::required("email", S),
            Field::required("role", S),
        ],
    },
    Variant {
        tag: "list_users",
        fields: &[],
    },
    Variant {
        tag: "revoke_user",
        fields: &[Field::required("user_id", S), Field::optional("confirm", B)],
    },
    Variant {
        tag: "issue_api_key",
        fields: &[Field::required("user_id", S), Field::required("name", S)],
    },
    Variant {
        tag: "list_api_keys",
        fields: &[],
    },
    Variant {
        tag: "revoke_api_key",
        fields: &[Field::required("key_id", S), Field::optional("confirm", B)],
    },
    Variant {
        tag: "create_user_for_tenant",
        fields: &[
            Field::required("tenant_id", S),
            Field::required("username", S),
            Field::required("email", S),
            Field::required("role", S),
        ],
    },
    Variant {
        tag: "list_users_for_tenant",
        fields: &[Field::required("tenant_id", S)],
    },
    Variant {
        tag: "issue_api_key_for_tenant",
        fields: &[
            Field::required("tenant_id", S),
            Field::required("user_id", S),
            Field::required("name", S),
        ],
    },
    Variant {
        tag: "list_api_keys_for_tenant",
        fields: &[Field::required("tenant_id", S)],
    },
    Variant {
        tag: "vfs_open_data",
        fields: &[
            Field::required("agent_id", S),
            Field::required("path", S),
            Field::required("rights", A),
        ],
    },
    Variant {
        tag: "vfs_dup_data",
        fields: &[
            Field::required("agent_id", S),
            Field::required("handle", S),
            Field::required("rights", A),
        ],
    },
    Variant {
        tag: "vfs_read_data",
        fields: &[
            Field::required("agent_id", S),
            Field::required("handle", S),
            Field::optional("args", O),
        ],
    },
    Variant {
        tag: "vfs_write_data",
        fields: &[
            Field::required("agent_id", S),
            Field::required("handle", S),
            Field::required("args", O),
        ],
    },
    Variant {
        tag: "vfs_list_data",
        fields: &[Field::required("agent_id", S), Field::required("handle", S)],
    },
    Variant {
        tag: "vfs_stat_data",
        fields: &[Field::required("agent_id", S), Field::required("handle", S)],
    },
    Variant {
        tag: "vfs_namespace_mounts",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "vfs_mount_entries",
        fields: &[Field::required("agent_id", S), Field::required("path", S)],
    },
    Variant {
        tag: "vfs_mount",
        fields: &[
            Field::required("agent_id", S),
            Field::required("expected_table_id", S),
            Field::required("expected_generation", I),
            Field::required("path", S),
            Field::required("kind", S),
        ],
    },
    Variant {
        tag: "vfs_unmount",
        fields: &[
            Field::required("agent_id", S),
            Field::required("expected_table_id", S),
            Field::required("expected_generation", I),
            Field::required("path", S),
            Field::required("mount_id", S),
        ],
    },
    Variant {
        tag: "vfs_workspace_mounts",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "vfs_open_workspace",
        fields: &[
            Field::required("agent_id", S),
            Field::required("request", O),
        ],
    },
    Variant {
        tag: "vfs_open_at",
        fields: &[
            Field::required("agent_id", S),
            Field::required("parent", S),
            Field::required("request", O),
        ],
    },
    Variant {
        tag: "vfs_dup_workspace",
        fields: &[
            Field::required("agent_id", S),
            Field::required("handle", S),
            Field::required("rights", A),
        ],
    },
    Variant {
        tag: "vfs_read_workspace",
        fields: &[
            Field::required("agent_id", S),
            Field::required("handle", S),
            Field::optional("offset", I),
            Field::optional("max_bytes", I),
        ],
    },
    Variant {
        tag: "vfs_write_workspace",
        fields: &[
            Field::required("agent_id", S),
            Field::required("handle", S),
            Field::required("data_base64", S),
        ],
    },
    Variant {
        tag: "vfs_list_workspace",
        fields: &[Field::required("agent_id", S), Field::required("handle", S)],
    },
    Variant {
        tag: "vfs_stat_workspace",
        fields: &[Field::required("agent_id", S), Field::required("handle", S)],
    },
    Variant {
        tag: "create_agent",
        fields: &[
            Field::optional("agent_id", N),
            Field::optional("ownership_proof", ON),
            Field::required("name", S),
            Field::required("task", S),
            Field::optional("provider", S),
            Field::optional("profile", S),
            Field::optional("priority", I),
        ],
    },
    Variant {
        tag: "list_agents",
        fields: &[],
    },
    Variant {
        tag: "clone_agent",
        fields: &[
            Field::required("agent_id", S),
            Field::required("child_agent_id", S),
            Field::optional("child_ownership_proof", ON),
            Field::required("name", S),
            Field::optional("drop_capabilities", A),
        ],
    },
    Variant {
        tag: "pause_agent",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "resume_agent",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "stop_agent",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "kill_agent",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "get_agent_status",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "wait_agent",
        fields: &[
            Field::required("agent_id", S),
            Field::required("timeout_ms", I),
        ],
    },
    Variant {
        tag: "list_generation_checkpoints",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "resume_generation_checkpoint",
        fields: &[
            Field::required("agent_id", S),
            Field::required("checkpoint_id", S),
        ],
    },
    Variant {
        tag: "delete_generation_checkpoint",
        fields: &[
            Field::required("agent_id", S),
            Field::required("checkpoint_id", S),
        ],
    },
    Variant {
        tag: "send_message",
        fields: &[
            Field::required("agent_id", S),
            Field::required("message", S),
        ],
    },
    Variant {
        tag: "send_message_content",
        fields: &[
            Field::required("agent_id", S),
            Field::required("content", SA),
        ],
    },
    Variant {
        tag: "send_message_content_stream",
        fields: &[
            Field::required("request_id", S),
            Field::required("agent_id", S),
            Field::required("content", SA),
        ],
    },
    Variant {
        tag: "send_message_stream",
        fields: &[
            Field::required("request_id", S),
            Field::required("agent_id", S),
            Field::required("message", S),
        ],
    },
    Variant {
        tag: "cancel_request",
        fields: &[
            Field::required("request_id", S),
            Field::required("agent_id", S),
        ],
    },
    Variant {
        tag: "call_tool",
        fields: &[
            Field::required("agent_id", S),
            Field::required("tool", S),
            Field::optional("args", X),
        ],
    },
    Variant {
        tag: "gate_stats",
        fields: &[],
    },
    Variant {
        tag: "vfs_mounts",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "vfs_open",
        fields: &[Field::required("agent_id", S), Field::required("path", S)],
    },
    Variant {
        tag: "vfs_invoke",
        fields: &[
            Field::required("agent_id", S),
            Field::required("handle", S),
            Field::optional("args", X),
        ],
    },
    Variant {
        tag: "vfs_close",
        fields: &[Field::required("agent_id", S), Field::required("handle", S)],
    },
    Variant {
        tag: "agent_info",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "list_providers",
        fields: &[],
    },
    Variant {
        tag: "list_provider_models",
        fields: &[Field::required("provider_id", S)],
    },
    Variant {
        tag: "memory_store",
        fields: &[
            Field::required("agent_id", S),
            Field::required("content", S),
            Field::optional("category", N),
        ],
    },
    Variant {
        tag: "memory_query",
        fields: &[Field::required("agent_id", S), Field::required("query", S)],
    },
    Variant {
        tag: "memory_update",
        fields: &[
            Field::required("agent_id", S),
            Field::required("fact_id", S),
            Field::required("content", S),
        ],
    },
    Variant {
        tag: "memory_delete",
        fields: &[
            Field::required("agent_id", S),
            Field::required("fact_id", S),
        ],
    },
    Variant {
        tag: "memory_reindex",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "storage_put",
        fields: &[
            Field::required("agent_id", S),
            Field::required("key", S),
            Field::required("value", S),
        ],
    },
    Variant {
        tag: "storage_get",
        fields: &[Field::required("agent_id", S), Field::required("key", S)],
    },
    Variant {
        tag: "storage_list",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "context_pressure",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "storage_delete",
        fields: &[Field::required("agent_id", S), Field::required("key", S)],
    },
    Variant {
        tag: "snapshot_context",
        fields: &[Field::required("agent_id", S), Field::required("label", S)],
    },
    Variant {
        tag: "restore_snapshot",
        fields: &[Field::required("agent_id", S), Field::required("label", S)],
    },
    Variant {
        tag: "list_snapshots",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "delete_snapshot",
        fields: &[Field::required("agent_id", S), Field::required("label", S)],
    },
    Variant {
        tag: "hello",
        fields: &[Field::required("protocol_version", I)],
    },
    Variant {
        tag: "authenticate",
        fields: &[Field::required("token", S)],
    },
    Variant {
        tag: "describe_protocol",
        fields: &[],
    },
    Variant {
        tag: "ping",
        fields: &[],
    },
    Variant {
        tag: "load_package",
        fields: &[Field::required("manifest_toml", S)],
    },
    Variant {
        tag: "trust_package_key",
        fields: &[
            Field::required("publisher", S),
            Field::required("key_id", S),
            Field::required("public_key_hex", S),
            Field::required("valid_from", S),
            Field::optional("valid_until", N),
            Field::optional("supersedes", N),
        ],
    },
    Variant {
        tag: "revoke_package_key",
        fields: &[Field::required("key_id", S)],
    },
    Variant {
        tag: "publish_package",
        fields: &[Field::required("archive_hex", S)],
    },
    Variant {
        tag: "yank_package",
        fields: &[Field::required("name", S), Field::required("version", S)],
    },
    Variant {
        tag: "fetch_package",
        fields: &[Field::required("name", S), Field::required("version", S)],
    },
    Variant {
        tag: "search_packages",
        fields: &[Field::required("query", S)],
    },
    Variant {
        tag: "install_package",
        fields: &[
            Field::required("name", S),
            Field::optional("requirement", S),
        ],
    },
    Variant {
        tag: "rollback_package",
        fields: &[Field::required("name", S)],
    },
    Variant {
        tag: "rollback_package_exact",
        fields: &[
            Field::required("name", S),
            Field::required("expected_version", S),
            Field::required("expected_digest", S),
        ],
    },
    Variant {
        tag: "remove_package",
        fields: &[Field::required("name", S)],
    },
    Variant {
        tag: "remove_package_exact",
        fields: &[
            Field::required("name", S),
            Field::required("expected_version", S),
            Field::required("expected_digest", S),
        ],
    },
    Variant {
        tag: "list_installed_packages",
        fields: &[],
    },
    Variant {
        tag: "run_installed_package",
        fields: &[Field::required("name", S)],
    },
    Variant {
        tag: "node_info",
        fields: &[],
    },
    Variant {
        tag: "prove_node_identity",
        fields: &[Field::required("challenge_hex", S)],
    },
    Variant {
        tag: "set_node_availability",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("availability", S),
            Field::required("expected_generation", I),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "set_node_profile",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("profile", O),
            Field::required("expected_generation", I),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "list_node_control_audit",
        fields: &[Field::optional("limit", I)],
    },
    Variant {
        tag: "issue_cluster_join_challenge",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("ttl_seconds", I),
        ],
    },
    Variant {
        tag: "submit_signed_authority_command",
        fields: &[Field::required("command", O)],
    },
    Variant {
        tag: "get_authority_principal_registry",
        fields: &[],
    },
    Variant {
        tag: "register_cluster_member",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("registration", O),
            Field::required("challenge_hex", S),
            Field::required("signature_hex", S),
            Field::optional("expected_generation", N),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "prepare_cluster_member_certificate_rollout",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("registration", O),
            Field::required("challenge_hex", S),
            Field::required("signature_hex", S),
            Field::required("expected_generation", I),
            Field::required("prepare_ttl_seconds", I),
            Field::required("minimum_overlap_seconds", I),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "abort_cluster_member_certificate_rollout",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("node_id", S),
            Field::required("expected_generation", I),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "finalize_cluster_member_certificate_rollout",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("node_id", S),
            Field::required("expected_generation", I),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "set_cluster_member_state",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("node_id", S),
            Field::required("state", S),
            Field::required("expected_generation", I),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "get_cluster_membership",
        fields: &[],
    },
    Variant {
        tag: "list_cluster_membership_audit",
        fields: &[Field::optional("limit", I)],
    },
    Variant {
        tag: "list_cluster_certificate_rollout_audit",
        fields: &[Field::optional("limit", I)],
    },
    Variant {
        tag: "claim_cluster_agent_ownership",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("agent_id", S),
            Field::required("owner_node_id", S),
            Field::required("ttl_seconds", I),
            Field::optional("expected_fencing_token", JsonKind::IntegerOrNull),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "renew_cluster_agent_ownership",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("agent_id", S),
            Field::required("owner_node_id", S),
            Field::required("fencing_token", I),
            Field::required("ttl_seconds", I),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "release_cluster_agent_ownership",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("agent_id", S),
            Field::required("owner_node_id", S),
            Field::required("fencing_token", I),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "get_cluster_agent_ownership",
        fields: &[
            Field::required("agent_id", S),
            Field::optional("require_active", B),
        ],
    },
    Variant {
        tag: "list_cluster_agent_ownerships",
        fields: &[
            Field::optional("after_agent_id", N),
            Field::optional("limit", I),
        ],
    },
    Variant {
        tag: "list_cluster_agent_ownership_audit",
        fields: &[Field::optional("agent_id", N), Field::optional("limit", I)],
    },
    Variant {
        tag: "install_agent_mutation_fence",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("agent_id", S),
            Field::required("cluster_id", S),
            Field::required("owner_node_id", S),
            Field::required("authority_term", I),
            Field::required("authority_generation", I),
            Field::required("fencing_token", I),
            Field::required("proof_expires_at", S),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "retire_agent_mutation_fence",
        fields: &[
            Field::optional("operation_id", S),
            Field::required("agent_id", S),
            Field::required("cluster_id", S),
            Field::required("owner_node_id", S),
            Field::required("authority_term", I),
            Field::required("authority_generation", I),
            Field::required("fencing_token", I),
            Field::required("proof_expires_at", S),
            Field::required("reason", S),
        ],
    },
    Variant {
        tag: "get_agent_mutation_fence",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "list_agent_mutation_fence_audit",
        fields: &[Field::optional("agent_id", N), Field::optional("limit", I)],
    },
    Variant {
        tag: "fenced_agent_mutation",
        fields: &[
            Field::required("agent_id", S),
            Field::required("proof", O),
            Field::required("mutation", O),
        ],
    },
    Variant {
        tag: "metrics",
        fields: &[],
    },
    Variant {
        tag: "operator_snapshot",
        fields: &[],
    },
    Variant {
        tag: "list_operator_tunables",
        fields: &[],
    },
    Variant {
        tag: "set_operator_tunable",
        fields: &[
            Field::required("name", S),
            Field::required("value", I),
            Field::required("expected_revision", I),
        ],
    },
    Variant {
        tag: "rollback_operator_tunable",
        fields: &[
            Field::required("name", S),
            Field::required("target_revision", I),
            Field::required("expected_revision", I),
        ],
    },
    Variant {
        tag: "list_operator_tunable_audit",
        fields: &[Field::optional("name", N), Field::optional("limit", I)],
    },
    Variant {
        tag: "create_storage_backup",
        fields: &[
            Field::required("backup_root", S),
            Field::required("name", S),
        ],
    },
    Variant {
        tag: "enforce_storage_backup_retention",
        fields: &[
            Field::required("backup_root", S),
            Field::required("keep_latest", I),
            Field::required("max_age_seconds", I),
            Field::required("dry_run", B),
            Field::required("confirm", B),
        ],
    },
    Variant {
        tag: "storage_backup_status",
        fields: &[],
    },
    Variant {
        tag: "storage_data_inventory",
        fields: &[],
    },
    Variant {
        tag: "erase_data",
        fields: &[Field::required("target", O), Field::required("confirm", B)],
    },
    Variant {
        tag: "list_services",
        fields: &[],
    },
    Variant {
        tag: "start_service",
        fields: &[Field::required("name", S)],
    },
    Variant {
        tag: "stop_service",
        fields: &[Field::required("name", S)],
    },
    Variant {
        tag: "restart_service",
        fields: &[Field::required("name", S)],
    },
    Variant {
        tag: "reload_services",
        fields: &[],
    },
    Variant {
        tag: "list_service_history",
        fields: &[Field::optional("name", N), Field::optional("limit", I)],
    },
];

/// Generate one deterministic, syntactically valid request fixture for every
/// operation available in `protocol_version`.
///
/// These values are conformance inputs, not executable examples: identifiers,
/// credentials, package material, and other strings are inert placeholders.
/// Keeping generation beside the schema prevents the versioned, language-
/// neutral fixture sets from silently drifting away from the Rust wire types.
pub fn conformance_request_fixtures(protocol_version: u32) -> Result<Vec<Value>, String> {
    if !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&protocol_version) {
        return Err(format!(
            "unsupported protocol version {protocol_version}; expected {MIN_PROTOCOL_VERSION}..={PROTOCOL_VERSION}"
        ));
    }
    Ok(REQUEST_VARIANTS
        .iter()
        .filter(|variant| {
            protocol_version >= 2
                || !matches!(
                    variant.tag,
                    "send_message_stream"
                        | "submit_signed_authority_command"
                        | "get_authority_principal_registry"
                        | "list_provider_models"
                        | "send_message_content"
                        | "send_message_content_stream"
                        | "cancel_request"
                        | "enforce_storage_backup_retention"
                        | "storage_backup_status"
                        | "storage_data_inventory"
                        | "ping"
                        | "erase_data"
                        | "prove_node_identity"
                        | "set_node_availability"
                        | "set_node_profile"
                        | "list_node_control_audit"
                        | "issue_cluster_join_challenge"
                        | "register_cluster_member"
                        | "prepare_cluster_member_certificate_rollout"
                        | "abort_cluster_member_certificate_rollout"
                        | "finalize_cluster_member_certificate_rollout"
                        | "set_cluster_member_state"
                        | "get_cluster_membership"
                        | "list_cluster_membership_audit"
                        | "list_cluster_certificate_rollout_audit"
                        | "claim_cluster_agent_ownership"
                        | "renew_cluster_agent_ownership"
                        | "release_cluster_agent_ownership"
                        | "get_cluster_agent_ownership"
                        | "list_cluster_agent_ownerships"
                        | "list_cluster_agent_ownership_audit"
                        | "install_agent_mutation_fence"
                        | "retire_agent_mutation_fence"
                        | "get_agent_mutation_fence"
                        | "list_agent_mutation_fence_audit"
                        | "fenced_agent_mutation"
                )
        })
        .map(|variant| {
            let mut request = Map::new();
            request.insert("op".into(), Value::String(variant.tag.into()));
            for field in variant.fields {
                if protocol_version == 1
                    && variant.tag == "create_agent"
                    && matches!(field.name, "agent_id" | "ownership_proof")
                {
                    continue;
                }
                let value = match (field.name, field.kind) {
                    ("protocol_version", JsonKind::Integer) => {
                        Value::Number(protocol_version.into())
                    }
                    ("agent_id", JsonKind::String) => {
                        Value::String("00000000-0000-0000-0000-000000000001".into())
                    }
                    ("child_agent_id", JsonKind::String) => {
                        Value::String("00000000-0000-0000-0000-000000000005".into())
                    }
                    ("owner_node_id", JsonKind::String) => {
                        Value::String("00000000-0000-0000-0000-000000000004".into())
                    }
                    ("checkpoint_id", JsonKind::String) => {
                        Value::String("00000000-0000-0000-0000-000000000002".into())
                    }
                    ("fact_id", JsonKind::String) => {
                        Value::String("00000000-0000-0000-0000-000000000003".into())
                    }
                    ("public_key_hex" | "archive_hex" | "challenge_hex", JsonKind::String) => {
                        Value::String("00".into())
                    }
                    ("signature_hex", JsonKind::String) => Value::String("00".into()),
                    ("availability", JsonKind::String) => Value::String("active".into()),
                    ("state", JsonKind::String) => Value::String("left".into()),
                    ("kind", JsonKind::String) => Value::String("tools".into()),
                    ("request", JsonKind::Object) => serde_json::json!({"path":if variant.tag == "vfs_open_at" { "file.bin" } else { "/workspace/file.bin" },"kind":"file","rights":["read","stat"],"allow_missing":false}),
                    ("command", JsonKind::Object) => serde_json::json!({"Authorized": {
                        "command": {"IssueJoinChallenge": {
                            "operation_id":"00000000-0000-0000-0000-000000000006", "challenge_hex":"00", "ttl_seconds":5,
                            "proposed_at":"2026-01-01T00:00:00Z"
                        }},
                        "principal_proof": {"version":1,"cluster_id":"00000000-0000-0000-0000-000000000005",
                            "principal_id":"00000000-0000-0000-0000-000000000007", "principal_generation":1,
                            "operation_id":"00000000-0000-0000-0000-000000000006", "command_sha256":"00".repeat(32),
                            "issued_at":"2026-01-01T00:00:00Z", "expires_at":"2026-01-01T00:00:30Z", "signature_hex":"00".repeat(64)}
                    }}),
                    ("registration", JsonKind::Object) => serde_json::json!({
                        "node_id": "00000000-0000-0000-0000-000000000004",
                        "fingerprint": "0000000000000000000000000000000000000000000000000000000000000000",
                        "public_key": "0000000000000000000000000000000000000000000000000000000000000000",
                        "endpoint": "127.0.0.1:7443",
                        "server_version": "0.3.0",
                        "min_protocol_version": 1,
                        "protocol_version": 2
                    }),
                    ("target", JsonKind::Object) => serde_json::json!({
                        "kind": "agent",
                        "agent_id": "00000000-0000-0000-0000-000000000001"
                    }),
                    ("proof", JsonKind::Object) => serde_json::json!({
                        "cluster_id": "00000000-0000-0000-0000-000000000005",
                        "owner_node_id": "00000000-0000-0000-0000-000000000004",
                        "authority_term": 1,
                        "authority_generation": 1,
                        "fencing_token": 1,
                        "proof_expires_at": "2026-01-01T00:00:00Z"
                    }),
                    ("mutation", JsonKind::Object) => serde_json::json!({
                        "op": "pause_agent",
                        "agent_id": "00000000-0000-0000-0000-000000000001"
                    }),
                    ("valid_from", JsonKind::String) => {
                        Value::String("2026-01-01T00:00:00Z".into())
                    }
                    ("proof_expires_at", JsonKind::String) => {
                        Value::String("2026-01-01T00:00:00Z".into())
                    }
                    ("manifest_toml", JsonKind::String) => {
                        Value::String("name = \"fixture\"\nversion = \"0.1.0\"".into())
                    }
                    ("role", JsonKind::String) => Value::String("user".into()),
                    (_, JsonKind::String) => Value::String("fixture".into()),
                    (_, JsonKind::Integer) => Value::Number(1.into()),
                    (_, JsonKind::Boolean) => Value::Bool(true),
                    (_, JsonKind::Object) | (_, JsonKind::Any) => Value::Object(Map::new()),
                    (_, JsonKind::Array) => Value::Array(Vec::new()),
                    (_, JsonKind::StringOrArray) => serde_json::json!([{"type":"text","text":"fixture"}]),
                    (
                        _,
                        JsonKind::StringOrNull
                        | JsonKind::IntegerOrNull
                        | JsonKind::ObjectOrNull,
                    ) => Value::Null,
                };
                request.insert(field.name.into(), value);
            }
            Value::Object(request)
        })
        .collect())
}

const REPLY_VARIANTS: &[Variant] = &[
    Variant {
        tag: "tenant_created",
        fields: &[Field::required("id", S)],
    },
    Variant {
        tag: "tenants",
        fields: &[Field::required("tenants", A)],
    },
    Variant {
        tag: "tenant_revoked",
        fields: &[Field::required("existed", B)],
    },
    Variant {
        tag: "user_created",
        fields: &[Field::required("id", S)],
    },
    Variant {
        tag: "users",
        fields: &[Field::required("users", A)],
    },
    Variant {
        tag: "user_revoked",
        fields: &[Field::required("existed", B)],
    },
    Variant {
        tag: "api_key_issued",
        fields: &[Field::required("key_id", S), Field::required("key", S)],
    },
    Variant {
        tag: "api_keys",
        fields: &[Field::required("keys", A)],
    },
    Variant {
        tag: "api_key_revoked",
        fields: &[Field::required("existed", B)],
    },
    Variant {
        tag: "vfs_data_opened",
        fields: &[Field::required("handle", O)],
    },
    Variant {
        tag: "workspace_opened",
        fields: &[Field::required("handle", O)],
    },
    Variant {
        tag: "workspace_read",
        fields: &[Field::required("chunk", O)],
    },
    Variant {
        tag: "workspace_written",
        fields: &[Field::required("written_bytes", I)],
    },
    Variant {
        tag: "workspace_stat",
        fields: &[Field::required("metadata", O)],
    },
    Variant {
        tag: "agent_created",
        fields: &[Field::required("id", S)],
    },
    Variant {
        tag: "agent_cloned",
        fields: &[Field::required("result", O)],
    },
    Variant {
        tag: "agents",
        fields: &[Field::required("agents", A)],
    },
    Variant {
        tag: "agent_status",
        fields: &[
            Field::required("state", S),
            Field::optional("checkpoint_id", N),
            Field::optional("resumed_content", N),
            Field::optional("resumed_tool_calls", NI),
            Field::optional("resumed_tokens", NI),
        ],
    },
    Variant {
        tag: "generation_checkpoints",
        fields: &[Field::required("checkpoints", A)],
    },
    Variant {
        tag: "generation_checkpoint_deleted",
        fields: &[Field::required("existed", B)],
    },
    Variant {
        tag: "message",
        fields: &[
            Field::required("content", S),
            Field::required("tool_calls", I),
            Field::required("tokens", I),
        ],
    },
    Variant {
        tag: "stream_event",
        fields: &[
            Field::required("request_id", S),
            Field::required("sequence", I),
            Field::required("event", O),
        ],
    },
    Variant {
        tag: "stream_completed",
        fields: &[
            Field::required("request_id", S),
            Field::required("content", S),
            Field::required("tool_calls", I),
            Field::required("tokens", I),
        ],
    },
    Variant {
        tag: "stream_failed",
        fields: &[
            Field::required("request_id", S),
            Field::required("code", S),
            Field::required("message", S),
            Field::required("retryable", B),
        ],
    },
    Variant {
        tag: "request_cancellation",
        fields: &[
            Field::required("request_id", S),
            Field::required("accepted", B),
        ],
    },
    Variant {
        tag: "tool_result",
        fields: &[Field::required("data", X)],
    },
    Variant {
        tag: "vfs_mounts",
        fields: &[Field::required("view", O)],
    },
    Variant {
        tag: "vfs_namespace_mounts",
        fields: &[Field::required("view", O)],
    },
    Variant {
        tag: "vfs_opened",
        fields: &[Field::required("handle", O)],
    },
    Variant {
        tag: "vfs_closed",
        fields: &[],
    },
    Variant {
        tag: "gate_stats",
        fields: &[
            Field::required("allowed", I),
            Field::required("denied_capability", I),
            Field::required("denied_mac", I),
            Field::required("denied_approval", I),
            Field::required("denied_cgroup", I),
            Field::required("denied_namespace", I),
            Field::required("denied_unknown", I),
            Field::required("audited", I),
        ],
    },
    Variant {
        tag: "agent_info",
        fields: &[
            Field::required("pid", I),
            Field::required("capabilities", A),
            Field::required("namespaces", A),
            Field::optional("gate_decisions", O),
        ],
    },
    Variant {
        tag: "providers",
        fields: &[Field::required("providers", A)],
    },
    Variant {
        tag: "provider_models",
        fields: &[Field::required("catalog", O)],
    },
    Variant {
        tag: "memory_stored",
        fields: &[Field::required("id", S)],
    },
    Variant {
        tag: "memory",
        fields: &[Field::required("facts", A)],
    },
    Variant {
        tag: "memory_updated",
        fields: &[Field::required("updated", B)],
    },
    Variant {
        tag: "memory_deleted",
        fields: &[Field::required("deleted", B)],
    },
    Variant {
        tag: "memory_reindexed",
        fields: &[Field::required("count", I)],
    },
    Variant {
        tag: "storage_ok",
        fields: &[],
    },
    Variant {
        tag: "storage_value",
        fields: &[Field::required("value", N)],
    },
    Variant {
        tag: "storage_keys",
        fields: &[Field::required("keys", A)],
    },
    Variant {
        tag: "context_pressure",
        fields: &[Field::required("stats", O)],
    },
    Variant {
        tag: "storage_deleted",
        fields: &[Field::required("existed", B)],
    },
    Variant {
        tag: "snapshot_saved",
        fields: &[],
    },
    Variant {
        tag: "snapshot_restored",
        fields: &[Field::required("tokens", I)],
    },
    Variant {
        tag: "snapshots",
        fields: &[Field::required("labels", A)],
    },
    Variant {
        tag: "snapshot_deleted",
        fields: &[Field::required("existed", B)],
    },
    Variant {
        tag: "hello",
        fields: &[
            Field::required("protocol_version", I),
            Field::required("min_protocol_version", I),
            Field::required("server_version", S),
            Field::optional("features", A),
        ],
    },
    Variant {
        tag: "pong",
        fields: &[],
    },
    Variant {
        tag: "authenticated",
        fields: &[],
    },
    Variant {
        tag: "protocol_description",
        fields: &[Field::required("description", O)],
    },
    Variant {
        tag: "package_key_updated",
        fields: &[],
    },
    Variant {
        tag: "package_published",
        fields: &[Field::required("package", O)],
    },
    Variant {
        tag: "package_archive",
        fields: &[Field::required("archive_hex", S)],
    },
    Variant {
        tag: "packages",
        fields: &[Field::required("packages", A)],
    },
    Variant {
        tag: "package_installed",
        fields: &[Field::required("package", O)],
    },
    Variant {
        tag: "installed_packages",
        fields: &[Field::required("packages", A)],
    },
    Variant {
        tag: "package_mutation_complete",
        fields: &[],
    },
    Variant {
        tag: "node_info",
        fields: &[
            Field::required("agent_count", I),
            Field::required("running_agents", I),
            Field::required("live_agents", I),
            Field::required("queued_agents", I),
            Field::required("paused_agents", I),
            Field::required("stopped_agents", I),
            Field::required("active_turns", I),
            Field::required("waiting_turns", I),
            Field::required("turn_capacity", I),
            Field::required("llm_requests_in_flight", I),
            Field::required("llm_requests_waiting", I),
            Field::required("llm_core_capacity", I),
            Field::optional("control", O),
        ],
    },
    Variant {
        tag: "node_identity_proof",
        fields: &[
            Field::required("node_id", S),
            Field::required("fingerprint", S),
            Field::required("public_key", S),
            Field::required("signature_hex", S),
        ],
    },
    Variant {
        tag: "node_control_updated",
        fields: &[Field::required("control", O)],
    },
    Variant {
        tag: "node_control_audit",
        fields: &[Field::required("entries", A)],
    },
    Variant {
        tag: "cluster_join_challenge",
        fields: &[Field::required("challenge", O)],
    },
    Variant {
        tag: "authority_command_committed",
        fields: &[Field::required("response", O)],
    },
    Variant {
        tag: "authority_principal_registry",
        fields: &[Field::required("principals", A)],
    },
    Variant {
        tag: "cluster_member_updated",
        fields: &[Field::required("member", O)],
    },
    Variant {
        tag: "cluster_certificate_rollout_updated",
        fields: &[
            Field::required("member", O),
            Field::optional("rollout", JsonKind::ObjectOrNull),
        ],
    },
    Variant {
        tag: "cluster_membership",
        fields: &[Field::required("membership", O)],
    },
    Variant {
        tag: "cluster_membership_audit",
        fields: &[Field::required("entries", A)],
    },
    Variant {
        tag: "cluster_certificate_rollout_audit",
        fields: &[Field::required("entries", A)],
    },
    Variant {
        tag: "cluster_agent_ownership",
        fields: &[Field::optional("ownership", JsonKind::ObjectOrNull)],
    },
    Variant {
        tag: "cluster_agent_ownerships",
        fields: &[Field::required("ownerships", A)],
    },
    Variant {
        tag: "cluster_agent_ownership_audit",
        fields: &[Field::required("entries", A)],
    },
    Variant {
        tag: "agent_mutation_fence",
        fields: &[Field::optional("fence", JsonKind::ObjectOrNull)],
    },
    Variant {
        tag: "agent_mutation_fence_audit",
        fields: &[Field::required("entries", A)],
    },
    Variant {
        tag: "metrics",
        fields: &[
            Field::required("prometheus", S),
            Field::required("agent_count", I),
            Field::required("tokens_consumed", I),
        ],
    },
    Variant {
        tag: "operator_snapshot",
        fields: &[Field::required("snapshot", O)],
    },
    Variant {
        tag: "operator_tunables",
        fields: &[Field::required("tunables", A)],
    },
    Variant {
        tag: "operator_tunable",
        fields: &[Field::required("tunable", O)],
    },
    Variant {
        tag: "operator_tunable_audit",
        fields: &[Field::required("entries", A)],
    },
    Variant {
        tag: "storage_backup_created",
        fields: &[Field::required("manifest", O)],
    },
    Variant {
        tag: "storage_backup_retention",
        fields: &[Field::required("report", O)],
    },
    Variant {
        tag: "storage_backup_status",
        fields: &[Field::required("maintenance", O)],
    },
    Variant {
        tag: "storage_data_inventory",
        fields: &[Field::required("inventory", O)],
    },
    Variant {
        tag: "data_erased",
        fields: &[Field::required("receipt", ON)],
    },
    Variant {
        tag: "services",
        fields: &[Field::required("services", A)],
    },
    Variant {
        tag: "service",
        fields: &[Field::required("service", O)],
    },
    Variant {
        tag: "service_configuration_reloaded",
        fields: &[Field::required("boot_order", A)],
    },
    Variant {
        tag: "service_history",
        fields: &[Field::required("entries", A)],
    },
    Variant {
        tag: "error",
        fields: &[Field::required("message", S)],
    },
    Variant {
        tag: "typed_error",
        fields: &[
            Field::required("code", S),
            Field::required("message", S),
            Field::required("retryable", B),
        ],
    },
];

const EVENT_VARIANTS: &[Variant] = &[
    Variant {
        tag: "started",
        fields: &[],
    },
    Variant {
        tag: "token",
        fields: &[Field::required("delta", S)],
    },
    Variant {
        tag: "tool_call_started",
        fields: &[Field::required("name", S)],
    },
    Variant {
        tag: "tool_call_completed",
        fields: &[Field::required("name", S)],
    },
    Variant {
        tag: "context_pressure",
        fields: &[
            Field::required("active_tokens", I),
            Field::required("budget_tokens", I),
            Field::required("evicted_messages", I),
            Field::required("spill_key", S),
        ],
    },
];

fn tagged_union_schema(title: &str, tag: &str, variants: &[Variant]) -> Value {
    let one_of = variants
        .iter()
        .map(|variant| {
            let mut properties = Map::new();
            properties.insert(tag.to_string(), json!({"const": variant.tag}));
            let mut required = vec![tag];
            for field in variant.fields {
                properties.insert(field.name.to_string(), field.kind.schema());
                if field.required {
                    required.push(field.name);
                }
            }
            json!({
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": true
            })
        })
        .collect::<Vec<_>>();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "oneOf": one_of
    })
}

fn mcp_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AI Agent OS MCP JSON-RPC request",
        "type": "object",
        "properties": {
            "jsonrpc": {"const": "2.0"},
            "id": {},
            "method": {
                "enum": ["initialize", "ping", "agentos/authenticate", "tools/list", "tools/call"]
            },
            "params": {"type": ["object", "null"]}
        },
        "required": ["jsonrpc", "method"],
        "additionalProperties": false
    })
}

/// Build the current public contract without reading mutable runtime state.
pub fn protocol_description() -> ProtocolDescription {
    ProtocolDescription {
        schema_version: format!("{PROTOCOL_VERSION}.0.0"),
        protocol_version: PROTOCOL_VERSION,
        min_protocol_version: MIN_PROTOCOL_VERSION,
        features: WIRE_FEATURES
            .iter()
            .map(|feature| (*feature).to_string())
            .collect(),
        transport: TransportDescription {
            framing: "newline-delimited-json".into(),
            encoding: "utf-8".into(),
            max_frame_bytes: MAX_JSON_FRAME_BYTES,
            default_max_connections: DEFAULT_MAX_CONNECTIONS,
            handshake_timeout_ms: HANDSHAKE_TIMEOUT.as_millis() as u64,
            idle_timeout_ms: IDLE_TIMEOUT.as_millis() as u64,
            recommended_keepalive_interval_ms: RECOMMENDED_KEEPALIVE_INTERVAL.as_millis() as u64,
            graceful_close_timeout_ms: GRACEFUL_CLOSE_TIMEOUT.as_millis() as u64,
            request_timeout_ms: REQUEST_TIMEOUT.as_millis() as u64,
            stream_event_buffer_capacity: STREAM_EVENT_BUFFER_CAPACITY,
            request_ordering:
                "one ordinary request/reply or one ordered stream at a time per connection".into(),
            unknown_field_behavior: "ignored for known operations; additive fields are compatible"
                .into(),
            unknown_operation_behavior: "invalid_request; connection remains usable".into(),
            idle_close_behavior:
                "server write side is shut down without an application error after the idle deadline"
                    .into(),
            graceful_close_behavior:
                "after all replies are consumed, client half-closes output and waits for peer EOF"
                    .into(),
        },
        request_schema: tagged_union_schema("AI Agent OS syscall request", "op", REQUEST_VARIANTS),
        reply_schema: tagged_union_schema("AI Agent OS syscall reply", "status", REPLY_VARIANTS),
        mcp_schema: mcp_schema(),
        event_schema: tagged_union_schema(
            "AI Agent OS message stream event",
            "event",
            EVENT_VARIANTS,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(schema: &Value, tag: &str) -> Vec<String> {
        schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|variant| {
                variant["properties"][tag]["const"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn agent_gate_statistics_is_an_additive_discoverable_reply_field() {
        let description = protocol_description();
        assert_eq!(description.protocol_version, 2);
        assert!(description
            .features
            .contains(&"agent_gate_statistics".to_string()));
        let agent_info = description.reply_schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| variant["properties"]["status"]["const"] == "agent_info")
            .unwrap();
        assert_eq!(agent_info["properties"]["gate_decisions"]["type"], "object");
        assert!(!agent_info["required"]
            .as_array()
            .unwrap()
            .contains(&json!("gate_decisions")));
        let reply = crate::syscall_server::SyscallReply::AgentInfo {
            pid: 1,
            capabilities: vec![],
            namespaces: vec![],
            gate_decisions: crate::syscall_gate::GateStats::default(),
        };
        let encoded = serde_json::to_value(reply).unwrap();
        let counters = encoded["gate_decisions"].as_object().unwrap();
        assert_eq!(counters.len(), 8);
        for field in [
            "allowed",
            "denied_capability",
            "denied_mac",
            "denied_approval",
            "denied_cgroup",
            "denied_namespace",
            "denied_unknown",
            "audited",
        ] {
            assert_eq!(counters[field], 0);
        }
    }

    #[test]
    fn schemas_have_unique_request_reply_and_event_tags() {
        let description = protocol_description();
        for (schema, tag) in [
            (&description.request_schema, "op"),
            (&description.reply_schema, "status"),
            (&description.event_schema, "event"),
        ] {
            let values = tags(schema, tag);
            let unique = values.iter().collect::<std::collections::HashSet<_>>();
            assert_eq!(unique.len(), values.len(), "duplicate {tag} schema tag");
        }
    }

    #[test]
    fn contract_declares_security_and_resource_bounds() {
        let description = protocol_description();
        assert!(description.features.contains(&"typed_errors".to_string()));
        assert!(description
            .features
            .contains(&"tenant_bound_auth".to_string()));
        assert!(description
            .features
            .contains(&"bounded_json_frames".to_string()));
        assert!(description
            .features
            .contains(&"request_id_cancellation".to_string()));
        assert!(description
            .features
            .contains(&"token_streaming".to_string()));
        assert!(description
            .features
            .contains(&"connection_keepalive".to_string()));
        assert!(description
            .features
            .contains(&"graceful_connection_close".to_string()));
        assert_eq!(description.transport.max_frame_bytes, MAX_JSON_FRAME_BYTES);
        assert_eq!(
            description.transport.recommended_keepalive_interval_ms,
            RECOMMENDED_KEEPALIVE_INTERVAL.as_millis() as u64
        );
        assert_eq!(
            description.transport.graceful_close_timeout_ms,
            GRACEFUL_CLOSE_TIMEOUT.as_millis() as u64
        );
        assert_eq!(
            description.transport.stream_event_buffer_capacity,
            STREAM_EVENT_BUFFER_CAPACITY
        );
        assert_eq!(
            tags(&description.event_schema, "event"),
            vec![
                "started",
                "token",
                "tool_call_started",
                "tool_call_completed",
                "context_pressure"
            ]
        );
    }

    #[test]
    fn versioned_golden_fixtures_parse_with_the_public_types() {
        let agent: crate::syscall_server::SyscallReply =
            serde_json::from_str(include_str!("../../../protocol/v2/agent-info.json")).unwrap();
        assert!(matches!(
            agent,
            crate::syscall_server::SyscallReply::AgentInfo {
                gate_decisions: crate::syscall_gate::GateStats {
                    allowed: 1,
                    denied_unknown: 6,
                    denied_namespace: 7,
                    ..
                },
                ..
            }
        ));

        let v1: crate::syscall_server::SyscallReply =
            serde_json::from_str(include_str!("../../../protocol/v1/error.json")).unwrap();
        assert!(matches!(
            v1,
            crate::syscall_server::SyscallReply::Error { .. }
        ));

        let hello: crate::syscall_server::SyscallReply =
            serde_json::from_str(include_str!("../../../protocol/v2/hello.json")).unwrap();
        assert!(matches!(
            hello,
            crate::syscall_server::SyscallReply::Hello { .. }
        ));

        let typed: crate::syscall_server::SyscallReply =
            serde_json::from_str(include_str!("../../../protocol/v2/typed-error.json")).unwrap();
        assert!(matches!(
            typed,
            crate::syscall_server::SyscallReply::TypedError {
                code: crate::syscall_server::WireErrorCode::AuthorizationDenied,
                retryable: false,
                ..
            }
        ));

        let describe: crate::syscall_server::Syscall = serde_json::from_str(include_str!(
            "../../../protocol/v2/describe-protocol-request.json"
        ))
        .unwrap();
        assert!(matches!(
            describe,
            crate::syscall_server::Syscall::DescribeProtocol
        ));

        let stream: crate::syscall_server::Syscall = serde_json::from_str(include_str!(
            "../../../protocol/v2/send-message-stream.json"
        ))
        .unwrap();
        assert!(matches!(
            stream,
            crate::syscall_server::Syscall::SendMessageStream { .. }
        ));
        let cancel: crate::syscall_server::Syscall =
            serde_json::from_str(include_str!("../../../protocol/v2/cancel-request.json")).unwrap();
        assert!(matches!(
            cancel,
            crate::syscall_server::Syscall::CancelRequest { .. }
        ));
        let event: crate::syscall_server::SyscallReply =
            serde_json::from_str(include_str!("../../../protocol/v2/stream-event.json")).unwrap();
        assert!(matches!(
            event,
            crate::syscall_server::SyscallReply::StreamEvent {
                sequence: 0,
                event: crate::syscall_server::MessageStreamEvent::Token { .. },
                ..
            }
        ));
        let completed: crate::syscall_server::SyscallReply =
            serde_json::from_str(include_str!("../../../protocol/v2/stream-completed.json"))
                .unwrap();
        assert!(matches!(
            completed,
            crate::syscall_server::SyscallReply::StreamCompleted { .. }
        ));
        let failed: crate::syscall_server::SyscallReply =
            serde_json::from_str(include_str!("../../../protocol/v2/stream-failed.json")).unwrap();
        assert!(matches!(
            failed,
            crate::syscall_server::SyscallReply::StreamFailed {
                code: crate::syscall_server::WireErrorCode::Cancelled,
                retryable: false,
                ..
            }
        ));
        let cancelled: crate::syscall_server::SyscallReply = serde_json::from_str(include_str!(
            "../../../protocol/v2/request-cancellation.json"
        ))
        .unwrap();
        assert!(matches!(
            cancelled,
            crate::syscall_server::SyscallReply::RequestCancellation { accepted: true, .. }
        ));
        let ping: crate::syscall_server::Syscall =
            serde_json::from_str(include_str!("../../../protocol/v2/ping.json")).unwrap();
        assert!(matches!(ping, crate::syscall_server::Syscall::Ping));
        let pong: crate::syscall_server::SyscallReply =
            serde_json::from_str(include_str!("../../../protocol/v2/pong.json")).unwrap();
        assert!(matches!(pong, crate::syscall_server::SyscallReply::Pong));

        let mcp: crate::mcp_server::JsonRpcRequest =
            serde_json::from_str(include_str!("../../../protocol/mcp/initialize.json")).unwrap();
        assert_eq!(mcp.jsonrpc, "2.0");
        assert_eq!(mcp.method, "initialize");
        let mcp_ping: crate::mcp_server::JsonRpcRequest =
            serde_json::from_str(include_str!("../../../protocol/mcp/ping.json")).unwrap();
        assert_eq!(mcp_ping.method, "ping");
        let mcp_pong: crate::mcp_server::JsonRpcResponse =
            serde_json::from_str(include_str!("../../../protocol/mcp/ping-response.json")).unwrap();
        assert_eq!(mcp_pong.result, Some(json!({})));
    }

    #[test]
    fn generated_request_fixtures_cover_every_operation_in_each_supported_version() {
        for (version, source) in [
            (1, include_str!("../../../protocol/v1/requests.json")),
            (2, include_str!("../../../protocol/v2/requests.json")),
        ] {
            let committed: Vec<Value> = serde_json::from_str(source).unwrap();
            let generated = conformance_request_fixtures(version).unwrap();
            assert_eq!(
                committed, generated,
                "protocol/v{version}/requests.json is stale; regenerate it with the export-wire-fixtures example"
            );
            for request in &committed {
                serde_json::from_value::<crate::syscall_server::Syscall>(request.clone())
                    .unwrap_or_else(|error| {
                        panic!("invalid v{version} fixture {request}: {error}")
                    });
            }
        }
        assert_eq!(conformance_request_fixtures(1).unwrap().len(), 97);
        assert_eq!(conformance_request_fixtures(2).unwrap().len(), 133);
        assert!(conformance_request_fixtures(0).is_err());
        assert!(conformance_request_fixtures(PROTOCOL_VERSION + 1).is_err());
    }

    #[test]
    fn model_discovery_wire_contract_is_v2_typed_and_identifier_only() {
        let description = protocol_description();
        assert!(description.features.contains(&"model_discovery".into()));
        let requests = tags(&description.request_schema, "op");
        let replies = tags(&description.reply_schema, "status");
        assert!(requests.contains(&"list_provider_models".into()));
        assert!(replies.contains(&"provider_models".into()));
        let catalog: crate::syscall_server::SyscallReply =
            serde_json::from_str(include_str!("../../../protocol/v2/provider-models.json"))
                .unwrap();
        assert!(
            matches!(catalog, crate::syscall_server::SyscallReply::ProviderModels { catalog }
            if catalog.provider_id == "openai" && catalog.models == ["fixture-model"])
        );
        let unsupported: crate::syscall_server::SyscallReply = serde_json::from_str(include_str!(
            "../../../protocol/v2/unsupported-model-discovery.json"
        ))
        .unwrap();
        assert!(matches!(
            unsupported,
            crate::syscall_server::SyscallReply::TypedError {
                code: crate::syscall_server::WireErrorCode::Unsupported,
                retryable: false,
                ..
            }
        ));
    }
}
