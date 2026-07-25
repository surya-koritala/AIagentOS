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
    DEFAULT_MAX_CONNECTIONS, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT, MAX_JSON_FRAME_BYTES, REQUEST_TIMEOUT,
};

/// Stable feature identifiers announced by `hello`.
pub const WIRE_FEATURES: &[&str] = &[
    "agent_enforcement_introspection",
    "bounded_json_frames",
    "context_pressure",
    "durable_generation_checkpoints",
    "memory_lifecycle",
    "operator_control",
    "protocol_description",
    "request_deadlines",
    "service_supervision",
    "signed_packages",
    "tenant_bound_auth",
    "tls",
    "typed_errors",
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
    /// Streaming/event frames are not advertised until their public contract is
    /// implemented. An empty schema is an explicit capability result.
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
    pub request_timeout_ms: u64,
    pub request_ordering: String,
    pub unknown_field_behavior: String,
    pub unknown_operation_behavior: String,
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

const REQUEST_VARIANTS: &[Variant] = &[
    Variant {
        tag: "create_agent",
        fields: &[
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
        tag: "agent_info",
        fields: &[Field::required("agent_id", S)],
    },
    Variant {
        tag: "list_providers",
        fields: &[],
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
        tag: "remove_package",
        fields: &[Field::required("name", S)],
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

const REPLY_VARIANTS: &[Variant] = &[
    Variant {
        tag: "agent_created",
        fields: &[Field::required("id", S)],
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
        tag: "tool_result",
        fields: &[Field::required("data", X)],
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
        ],
    },
    Variant {
        tag: "providers",
        fields: &[Field::required("providers", A)],
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
        ],
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
                "enum": ["initialize", "agentos/authenticate", "tools/list", "tools/call"]
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
            request_timeout_ms: REQUEST_TIMEOUT.as_millis() as u64,
            request_ordering: "one request and one reply at a time per connection".into(),
            unknown_field_behavior: "ignored for known operations; additive fields are compatible"
                .into(),
            unknown_operation_behavior: "invalid_request; connection remains usable".into(),
        },
        request_schema: tagged_union_schema("AI Agent OS syscall request", "op", REQUEST_VARIANTS),
        reply_schema: tagged_union_schema("AI Agent OS syscall reply", "status", REPLY_VARIANTS),
        mcp_schema: mcp_schema(),
        event_schema: json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "AI Agent OS event frame",
            "not": {},
            "description": "No event or streaming frame is advertised by protocol v2."
        }),
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
    fn schemas_have_unique_operation_and_reply_tags() {
        let description = protocol_description();
        for (schema, tag) in [
            (&description.request_schema, "op"),
            (&description.reply_schema, "status"),
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
        assert_eq!(description.transport.max_frame_bytes, MAX_JSON_FRAME_BYTES);
        assert!(description.event_schema.get("not").is_some());
    }

    #[test]
    fn versioned_golden_fixtures_parse_with_the_public_types() {
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

        let mcp: crate::mcp_server::JsonRpcRequest =
            serde_json::from_str(include_str!("../../../protocol/mcp/initialize.json")).unwrap();
        assert_eq!(mcp.jsonrpc, "2.0");
        assert_eq!(mcp.method, "initialize");
    }
}
