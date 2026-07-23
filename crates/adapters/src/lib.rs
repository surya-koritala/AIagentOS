//! LLM Provider Adapters for the AI Agent OS.

/// Convert an untrusted provider usage counter without allowing narrowing to
/// wrap a large JSON integer into an apparently small charge.
pub(crate) fn saturating_usage_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Read an unsigned provider usage field and clamp it to the kernel's public
/// `u32` telemetry domain. Missing, negative, and non-integer values remain
/// backward-compatible zeros.
pub(crate) fn json_usage_u32(value: &serde_json::Value) -> u32 {
    saturating_usage_u32(value.as_u64().unwrap_or(0))
}

/// Sum two wide provider counters before clamping. Both the addition and the
/// narrowing conversion are saturating.
pub(crate) fn saturating_usage_sum(left: u64, right: u64) -> u32 {
    saturating_usage_u32(left.saturating_add(right))
}

/// Preserve retry semantics when translating provider HTTP failures.
///
/// Timeouts, throttling, and server failures are transient. Other 4xx
/// responses are request/authentication failures and must not be retried by a
/// connector that honors [`kernel::connector::is_transient`].
pub(crate) fn http_status_error(
    status: reqwest::StatusCode,
    detail: Option<&str>,
) -> kernel::ConnectorError {
    let message = match detail.filter(|text| !text.is_empty()) {
        Some(text) => format!("HTTP {status} - {text}"),
        None => format!("HTTP {status}"),
    };
    if status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        kernel::ConnectorError::ConnectionFailed(message)
    } else {
        kernel::ConnectorError::ProtocolError(message)
    }
}

#[cfg(test)]
mod usage_conversion_tests {
    #[test]
    fn oversized_counters_and_sums_saturate() {
        assert_eq!(
            super::saturating_usage_u32(u64::from(u32::MAX) + 1),
            u32::MAX
        );
        assert_eq!(super::saturating_usage_sum(u64::MAX, 1), u32::MAX);
        assert_eq!(
            super::json_usage_u32(&serde_json::json!(u64::MAX)),
            u32::MAX
        );
    }

    #[test]
    fn http_status_translation_preserves_retry_classification() {
        let throttled = super::http_status_error(reqwest::StatusCode::TOO_MANY_REQUESTS, None);
        let server_failure =
            super::http_status_error(reqwest::StatusCode::SERVICE_UNAVAILABLE, None);
        let invalid_request = super::http_status_error(reqwest::StatusCode::BAD_REQUEST, None);

        assert!(kernel::connector::is_transient(&throttled));
        assert!(kernel::connector::is_transient(&server_failure));
        assert!(!kernel::connector::is_transient(&invalid_request));
    }
}

pub mod anthropic;
pub mod azure_openai;
pub mod deepseek;
pub mod gemini;
pub mod groq;
pub mod huggingface;
pub mod local;
/// In-process, pure-Rust GGUF inference. Heavy; only compiled with `--features
/// candle`. The on-device counterpart to [`local`].
#[cfg(feature = "candle")]
pub mod on_device;
pub mod openai;
pub mod streaming;
pub mod vllm;

#[cfg(test)]
mod openai_tests;

#[cfg(test)]
mod anthropic_tests;

#[cfg(test)]
mod groq_tests;

#[cfg(test)]
mod deepseek_tests;

#[cfg(test)]
mod gemini_tests;

#[cfg(test)]
mod vllm_tests;

#[cfg(test)]
mod huggingface_tests;

#[cfg(test)]
mod output_bound_tests;
