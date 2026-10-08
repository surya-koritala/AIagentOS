//! Bounded, identifier-only model catalogs for configured providers.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{ConnectorError, ProviderId};

pub const MAX_DISCOVERED_MODELS: usize = 1024;
pub const MAX_MODEL_ID_BYTES: usize = 256;
pub const MAX_MODEL_DISCOVERY_BYTES: usize = 1024 * 1024;
pub const MAX_MODEL_DISCOVERY_PAGES: usize = 16;
pub const MODEL_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// An explicit operator lookup. No credentials, endpoints, account ownership,
/// display metadata, or local paths are included in the public result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelCatalog {
    pub provider_id: ProviderId,
    pub models: Vec<String>,
}

/// Preserve provider spelling while validating, sorting and deduplicating IDs.
/// The count limit applies before deduplication so repeated entries cannot
/// evade the response bound. Invalid catalogs fail instead of being truncated.
pub fn normalize_model_ids(mut models: Vec<String>) -> Result<Vec<String>, ConnectorError> {
    if models.len() > MAX_DISCOVERED_MODELS {
        return Err(ConnectorError::ProtocolError(
            "model discovery exceeded the model count limit".into(),
        ));
    }
    for id in &models {
        if id.is_empty()
            || id.len() > MAX_MODEL_ID_BYTES
            || !id.as_bytes()[0].is_ascii_alphanumeric()
            || !id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
            })
            || id.contains("://")
            || id
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(ConnectorError::ProtocolError(
                "model discovery returned an invalid identifier".into(),
            ));
        }
    }
    models.sort();
    models.dedup();
    Ok(models)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_discovery_normalization_preserves_namespaces_and_deduplicates() {
        assert_eq!(
            normalize_model_ids(vec![
                "org/Model:latest".into(),
                "a-model".into(),
                "a-model".into()
            ])
            .unwrap(),
            vec!["a-model", "org/Model:latest"]
        );
    }

    #[test]
    fn model_discovery_rejects_untrusted_identifiers_and_raw_count_overflow() {
        for id in [
            "",
            "../model",
            "a\nsecret",
            "a model",
            "https://account.test/model",
            "a//b",
            "a/../b",
        ] {
            let error = normalize_model_ids(vec![id.into()])
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                "Protocol error: model discovery returned an invalid identifier"
            );
        }
        assert!(normalize_model_ids(vec!["a".repeat(MAX_MODEL_ID_BYTES + 1)]).is_err());
        assert!(normalize_model_ids(vec!["a".into(); MAX_DISCOVERED_MODELS + 1]).is_err());
    }
}
