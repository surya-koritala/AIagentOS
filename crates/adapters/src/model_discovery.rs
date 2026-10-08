//! Keyless-testable model listing; never use account or administration APIs.

use std::collections::BTreeSet;

use kernel::model_discovery::{
    normalize_model_ids, MAX_DISCOVERED_MODELS, MAX_MODEL_DISCOVERY_BYTES,
    MAX_MODEL_DISCOVERY_PAGES, MODEL_DISCOVERY_TIMEOUT,
};
use kernel::ConnectorError;
use serde_json::Value;
use tokio_stream::StreamExt;

#[derive(Clone, Copy)]
pub(crate) enum DiscoveryApi {
    OpenAi,
    Anthropic,
    Gemini,
    Ollama,
}

fn protocol_error(message: &str) -> ConnectorError {
    ConnectorError::ProtocolError(format!("model discovery: {message}"))
}

/// All diagnostics are fixed text: a provider can echo credentials in any
/// response field, request ID, malformed JSON, redirect, or transport URL.
pub(crate) async fn discover(
    provider: &str,
    base_url: &str,
    api: DiscoveryApi,
    api_key: &str,
) -> Result<Vec<String>, ConnectorError> {
    tokio::time::timeout(MODEL_DISCOVERY_TIMEOUT, discover_inner(provider, base_url, api, api_key))
        .await
        .map_err(|_| ConnectorError::timeout(provider.into(), "model discovery deadline exceeded", None))?
}

async fn discover_inner(
    provider: &str,
    base_url: &str,
    api: DiscoveryApi,
    api_key: &str,
) -> Result<Vec<String>, ConnectorError> {
    let mut endpoint = reqwest::Url::parse(base_url)
        .map_err(|_| protocol_error("invalid configured endpoint"))?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(protocol_error("invalid configured endpoint"));
    }
    let suffix = match api {
        DiscoveryApi::OpenAi | DiscoveryApi::Anthropic => "/models",
        DiscoveryApi::Gemini => "/v1beta/models",
        DiscoveryApi::Ollama => "/api/tags",
    };
    endpoint.set_path(&format!("{}{suffix}", endpoint.path().trim_end_matches('/')));
    // A separate client prevents x-api-key/x-goog-api-key from following a
    // redirect to another origin. System proxy configuration remains honored.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ConnectorError::ConnectionFailed("model discovery transport setup failed".into()))?;
    let mut bytes_received = 0usize;
    let mut models = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    for _ in 0..MAX_MODEL_DISCOVERY_PAGES {
        let mut request = client.get(endpoint.clone());
        match api {
            DiscoveryApi::OpenAi => {
                if !api_key.is_empty() {
                    request = request.bearer_auth(api_key);
                }
            }
            DiscoveryApi::Anthropic => {
                request = request.header("x-api-key", api_key)
                    .header("anthropic-version", "2023-06-01")
                    .query(&[("limit", "1000")]);
                if let Some(cursor) = &cursor {
                    request = request.query(&[("after_id", cursor)]);
                }
            }
            DiscoveryApi::Gemini => {
                request = request.header("x-goog-api-key", api_key).query(&[("pageSize", "1000")]);
                if let Some(cursor) = &cursor {
                    request = request.query(&[("pageToken", cursor)]);
                }
            }
            DiscoveryApi::Ollama => {}
        }
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() {
                ConnectorError::timeout(provider.into(), "model discovery transport timed out", None)
            } else {
                ConnectorError::ConnectionFailed("model discovery transport failed".into())
            }
        })?;
        if !response.status().is_success() {
            // Do not consume, echo or interpret diagnostic/account bodies.
            return Err(crate::http_status_error(provider, response.status(), None, None,
                crate::retry_after_ms(response.headers())));
        }
        let remaining = MAX_MODEL_DISCOVERY_BYTES.saturating_sub(bytes_received);
        if response.content_length().is_some_and(|length| length > remaining as u64) {
            return Err(protocol_error("response byte limit exceeded"));
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ConnectorError::ConnectionFailed("model discovery response interrupted".into()))?;
            if chunk.len() > MAX_MODEL_DISCOVERY_BYTES.saturating_sub(bytes_received) {
                return Err(protocol_error("response byte limit exceeded"));
            }
            bytes_received += chunk.len();
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| protocol_error("malformed JSON response"))?;
        let (field, id_field) = match api {
            DiscoveryApi::OpenAi | DiscoveryApi::Anthropic => ("data", "id"),
            DiscoveryApi::Gemini => ("models", "name"),
            DiscoveryApi::Ollama => ("models", "model"),
        };
        let entries = value.get(field).and_then(Value::as_array)
            .ok_or_else(|| protocol_error("missing model array"))?;
        if entries.len() > MAX_DISCOVERED_MODELS.saturating_sub(models.len()) {
            return Err(protocol_error("model count limit exceeded"));
        }
        for entry in entries {
            let id = if matches!(api, DiscoveryApi::Ollama) && entry.get(id_field).is_none() {
                entry.get("name")
            } else {
                entry.get(id_field)
            }.and_then(Value::as_str).ok_or_else(|| protocol_error("missing model identifier"))?;
            let id = if matches!(api, DiscoveryApi::Gemini) {
                id.strip_prefix("models/").ok_or_else(|| protocol_error("invalid model resource name"))?
            } else { id };
            if !api_key.is_empty() && id.contains(api_key) {
                return Err(protocol_error("credential echoed in model identifier"));
            }
            models.push(id.to_string());
        }
        let next = match api {
            DiscoveryApi::Anthropic => {
                let has_more = value.get("has_more").and_then(Value::as_bool)
                    .ok_or_else(|| protocol_error("missing pagination state"))?;
                if has_more {
                    Some(value.get("last_id").and_then(Value::as_str)
                        .ok_or_else(|| protocol_error("missing pagination cursor"))?)
                } else { None }
            }
            DiscoveryApi::Gemini => match value.get("nextPageToken") {
                None => None,
                Some(Value::String(token)) if token.is_empty() => None,
                Some(Value::String(token)) => Some(token.as_str()),
                _ => return Err(protocol_error("invalid pagination cursor")),
            },
            _ => {
                if value.get("has_more") == Some(&Value::Bool(true)) {
                    return Err(protocol_error("unsupported pagination state"));
                }
                None
            }
        };
        let Some(next) = next else { return normalize_model_ids(models); };
        if entries.is_empty() || next.is_empty() || next.len() > 4096 || !next.bytes().all(|byte| byte.is_ascii_graphic())
            || !seen_cursors.insert(next.to_string())
        {
            return Err(protocol_error("invalid or repeated pagination cursor"));
        }
        // Validate IDs on every page, but preserve the raw count until the
        // terminal normalization so duplicates cannot evade the total ceiling.
        normalize_model_ids(models.clone())?;
        cursor = Some(next.to_string());
    }
    Err(protocol_error("pagination limit exceeded"))
}
