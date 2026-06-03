//! Structured-logging initialization for the CLI binaries.
//!
//! Installs a `tracing_subscriber` fmt subscriber so the kernel's existing
//! `tracing::info!/warn!` lines (persistence, auth, …) actually emit. Driven by
//! `RUST_LOG` (env-filter), defaulting to `info`. Set `LOG_FORMAT=json` (or
//! `AGENT_LOG_FORMAT=json`) to emit machine-readable JSON for log ingestion;
//! any other value (or unset) keeps the human-readable format.
//!
//! Shared by both `main.rs` (the `agent` CLI) and `bin/agent-server.rs` via a
//! `#[path]` include, so the two entry points initialize logging identically.

use tracing_subscriber::EnvFilter;

/// Install the global tracing subscriber. Idempotent-safe to call once at
/// startup; a second call is ignored (so it never panics if something already
/// set a global subscriber).
pub fn init_logging() {
    // Default to `info` when RUST_LOG is unset or unparseable.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let json = matches!(log_format().as_deref(), Some("json") | Some("JSON"));

    if json {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_current_span(false)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init();
    }
}

/// Read the requested log format from `LOG_FORMAT`, falling back to
/// `AGENT_LOG_FORMAT`. Returns the lowercased value, or `None` if unset/empty.
fn log_format() -> Option<String> {
    let raw = std::env::var("LOG_FORMAT")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("AGENT_LOG_FORMAT")
                .ok()
                .filter(|s| !s.is_empty())
        });
    raw.map(|s| s.to_ascii_lowercase())
}
