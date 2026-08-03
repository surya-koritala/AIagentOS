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

const MAX_PROVIDER_ERROR_BYTES: usize = 8 * 1024;
const MAX_PROVIDER_REQUEST_ID_BYTES: usize = 256;

fn redacted_detail(detail: Option<&str>) -> String {
    let Some(detail) = detail.filter(|detail| !detail.trim().is_empty()) else {
        return "provider returned no diagnostic body".into();
    };
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(detail) else {
        return "unstructured provider diagnostic redacted".into();
    };

    fn redact(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    let key = key.to_ascii_lowercase();
                    if [
                        "api_key",
                        "apikey",
                        "authorization",
                        "token",
                        "secret",
                        "password",
                        "prompt",
                        "input",
                    ]
                    .iter()
                    .any(|sensitive| key.contains(sensitive))
                    {
                        *value = serde_json::Value::String("[REDACTED]".into());
                    } else {
                        redact(value);
                    }
                }
            }
            serde_json::Value::Array(values) => values.iter_mut().for_each(redact),
            _ => {}
        }
    }
    redact(&mut value);
    let rendered = value.to_string();
    let mut end = rendered.len().min(MAX_PROVIDER_ERROR_BYTES);
    while !rendered.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    rendered[..end].to_string()
}

fn request_id(headers: &reqwest::header::HeaderMap) -> Option<String> {
    ["x-request-id", "request-id", "x-ms-request-id"]
        .into_iter()
        .find_map(|name| headers.get(name))
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(MAX_PROVIDER_REQUEST_ID_BYTES).collect())
}

fn retry_after_ms(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(seconds.saturating_mul(1_000));
    }
    let retry_at = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let millis = retry_at
        .signed_duration_since(chrono::Utc::now())
        .num_milliseconds();
    Some(u64::try_from(millis.max(0)).unwrap_or(u64::MAX))
}

async fn bounded_response_body(response: reqwest::Response) -> String {
    use tokio_stream::StreamExt;

    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            break;
        };
        let remaining = MAX_PROVIDER_ERROR_BYTES.saturating_sub(bytes.len());
        if remaining == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Consume a failed provider response through a bounded, redacted diagnostic
/// path and preserve retry classification plus correlation metadata.
pub(crate) async fn provider_http_error(
    provider: &str,
    response: reqwest::Response,
) -> kernel::ConnectorError {
    let status = response.status();
    let id = request_id(response.headers());
    let retry_after = retry_after_ms(response.headers());
    let detail = bounded_response_body(response).await;
    http_status_error(provider, status, Some(&detail), id, retry_after)
}

pub(crate) fn http_status_error(
    provider: &str,
    status: reqwest::StatusCode,
    detail: Option<&str>,
    request_id: Option<String>,
    retry_after_ms: Option<u64>,
) -> kernel::ConnectorError {
    let message = format!("HTTP {status} - {}", redacted_detail(detail));
    match status {
        reqwest::StatusCode::UNAUTHORIZED => {
            kernel::ConnectorError::authentication(provider.into(), message, request_id)
        }
        reqwest::StatusCode::FORBIDDEN => {
            let filtered = detail.is_some_and(|detail| {
                let detail = detail.to_ascii_lowercase();
                detail.contains("content_filter")
                    || detail.contains("content policy")
                    || detail.contains("safety")
            });
            if filtered {
                kernel::ConnectorError::content_filtered(provider.into(), message, request_id)
            } else {
                kernel::ConnectorError::authorization(provider.into(), message, request_id)
            }
        }
        reqwest::StatusCode::TOO_MANY_REQUESTS => kernel::ConnectorError::rate_limited(
            provider.into(),
            message,
            request_id,
            retry_after_ms,
        ),
        reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::GATEWAY_TIMEOUT => {
            kernel::ConnectorError::timeout(provider.into(), message, request_id)
        }
        status if status.is_server_error() => {
            kernel::ConnectorError::service_unavailable(provider.into(), message, request_id)
        }
        _ => kernel::ConnectorError::invalid_request(provider.into(), message, request_id),
    }
}

/// Some providers report a content-policy stop inside an otherwise successful
/// HTTP response. Convert that into the same permanent typed error.
pub(crate) fn content_filter_error(
    provider: &str,
    finish_reason: Option<&str>,
) -> Option<kernel::ConnectorError> {
    let reason = finish_reason?.to_ascii_lowercase();
    let filtered = reason.contains("content_filter")
        || reason.contains("safety")
        || reason.contains("blocklist")
        || reason.contains("prohibited_content")
        || reason.contains("spii")
        || reason.contains("refusal");
    filtered.then(|| {
        kernel::ConnectorError::content_filtered(
            provider.into(),
            format!("provider stopped generation: {reason}"),
            None,
        )
    })
}

pub(crate) fn transport_error(provider: &str, error: reqwest::Error) -> kernel::ConnectorError {
    if error.is_timeout() {
        kernel::ConnectorError::timeout(provider.into(), "provider transport timed out", None)
    } else {
        // `reqwest::Error` renders the request URL into its `Display`. Adapters
        // must keep credentials out of URLs, but this strips the URL regardless
        // so a future query-string credential cannot leak through an error that
        // reaches logs, the CLI, or a wire client.
        kernel::ConnectorError::ConnectionFailed(error.without_url().to_string())
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
        let throttled = super::http_status_error(
            "test",
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            None,
            Some("req-1".into()),
            Some(1000),
        );
        let server_failure = super::http_status_error(
            "test",
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            None,
            None,
            None,
        );
        let invalid_request =
            super::http_status_error("test", reqwest::StatusCode::BAD_REQUEST, None, None, None);

        assert!(kernel::connector::is_transient(&throttled));
        assert!(kernel::connector::is_transient(&server_failure));
        assert!(!kernel::connector::is_transient(&invalid_request));
        assert_eq!(throttled.request_id(), Some("req-1"));
    }

    #[test]
    fn provider_diagnostics_are_redacted_and_content_filters_are_typed() {
        let error = super::http_status_error(
            "test",
            reqwest::StatusCode::FORBIDDEN,
            Some(
                r#"{"error":{"code":"content_filter","message":"blocked"},"api_key":"sk-secret"}"#,
            ),
            None,
            None,
        );
        let rendered = error.to_string();
        assert!(matches!(error, kernel::ConnectorError::ContentFiltered(_)));
        assert!(!rendered.contains("sk-secret"));
        assert!(super::content_filter_error("test", Some("SAFETY")).is_some());
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
