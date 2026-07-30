//! `agent-server` — run the kernel as a long-lived syscall server.
//!
//! Boots the kernel from config, registers the configured LLM provider, and
//! serves the JSON syscall API (see `kernel::syscall_server`): agent lifecycle,
//! the `SendMessage` LLM turn, memory store/query, tool calls, and enforcement
//! introspection. Once a provider is registered, `SendMessage` reaches a real
//! backend; with none, the non-LLM syscalls still work (keyless boot).
//!
//! Usage:
//!   agent-server \[ADDR\]               # TCP, default 127.0.0.1:7777
//!   AGENT_SERVER_UNIX=/path.sock agent-server   # Unix-domain socket instead
//!   AGENT_SERVER_TOKEN=secret agent-server      # require auth before any syscall
//!   AGENT_SERVER_TLS_CERT=cert.pem AGENT_SERVER_TLS_KEY=key.pem agent-server
//!                                       # terminate TLS (rustls) on the TCP bind
//!   AGENT_SERVER_TLS_CLIENT_CA=cluster-ca.pem
//!                                       # require trusted client certificates
//!   AGENT_SERVER_TLS_CLIENT_CRL=clients.crl.pem
//!                                       # reject individually revoked clients
//!   AGENT_SERVER_TLS_RELOAD_TRIGGER=/run/agentos/tls.reload
//!                                       # atomically trigger live TLS reload
//!   AGENT_SERVER_ALLOW_INSECURE_REMOTE=1 # explicit development-only override
//!   AGENT_SERVER_CONFIG=/etc/agentos/config.toml
//!                                       # explicit absolute operator config

#[path = "../logging.rs"]
mod logging;
use std::sync::Arc;
use std::time::Duration;

use agent_cli::providers::register_providers;
use kernel::cluster_runtime::start_configured_cluster_runtime;
use kernel::config::Config;
use kernel::syscall_server::{SyscallServer, TlsReloadHandle};
use kernel::AgentKernelImpl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DEFAULT_TLS_RELOAD_INTERVAL_SECONDS: u64 = 5;
const MAX_TLS_RELOAD_INTERVAL_SECONDS: u64 = 3_600;
const MAX_TLS_RELOAD_TRIGGER_BYTES: usize = 4_096;

#[derive(Clone)]
struct TlsMaterialPaths {
    cert: String,
    key: String,
    client_ca: Option<String>,
    client_crl: Option<String>,
}

struct TlsMaterial {
    cert: Vec<u8>,
    key: Vec<u8>,
    client_ca: Option<Vec<u8>>,
    client_crl: Option<Vec<u8>>,
}

impl TlsMaterial {
    fn server_config(&self) -> std::io::Result<rustls::ServerConfig> {
        match (self.client_ca.as_deref(), self.client_crl.as_deref()) {
            (Some(client_ca), Some(client_crl)) => {
                kernel::syscall_server::server_config_from_pem_with_client_ca_and_crls(
                    &self.cert, &self.key, client_ca, client_crl,
                )
            }
            (Some(client_ca), None) => {
                kernel::syscall_server::server_config_from_pem_with_client_ca(
                    &self.cert, &self.key, client_ca,
                )
            }
            (None, None) => kernel::syscall_server::server_config_from_pem(&self.cert, &self.key),
            (None, Some(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a client CRL requires a client CA",
            )),
        }
    }
}

#[tokio::main]
async fn main() {
    // Structured logging first, so kernel init + every later log line emits.
    logging::init_logging();
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7777".to_string());
    let unix_path = std::env::var("AGENT_SERVER_UNIX").ok();
    let token = std::env::var("AGENT_SERVER_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    // TLS is enabled only when both cert and key paths are provided. A partial
    // configuration is an error; silently falling back to plaintext is unsafe.
    let tls = match (
        std::env::var("AGENT_SERVER_TLS_CERT")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("AGENT_SERVER_TLS_KEY")
            .ok()
            .filter(|s| !s.is_empty()),
    ) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => {
            eprintln!(
                "agent-server: AGENT_SERVER_TLS_CERT and AGENT_SERVER_TLS_KEY must be set together"
            );
            std::process::exit(1);
        }
    };
    let allow_insecure_remote = std::env::var("AGENT_SERVER_ALLOW_INSECURE_REMOTE")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
    let tls_client_ca = std::env::var("AGENT_SERVER_TLS_CLIENT_CA")
        .ok()
        .filter(|value| !value.is_empty());
    let tls_client_crl = std::env::var("AGENT_SERVER_TLS_CLIENT_CRL")
        .ok()
        .filter(|value| !value.is_empty());
    let tls_reload_trigger = std::env::var("AGENT_SERVER_TLS_RELOAD_TRIGGER")
        .ok()
        .filter(|value| !value.is_empty());
    let tls_reload_interval = match parse_tls_reload_interval(
        std::env::var("AGENT_SERVER_TLS_RELOAD_INTERVAL_SECONDS")
            .ok()
            .as_deref(),
        tls_reload_trigger.is_some(),
    ) {
        Ok(interval) => interval,
        Err(error) => {
            eprintln!("agent-server: {error}");
            std::process::exit(1);
        }
    };
    if tls_client_ca.is_some() && tls.is_none() {
        eprintln!(
            "agent-server: AGENT_SERVER_TLS_CLIENT_CA requires AGENT_SERVER_TLS_CERT and AGENT_SERVER_TLS_KEY"
        );
        std::process::exit(1);
    }
    if tls_client_ca.is_some() && unix_path.is_some() {
        eprintln!(
            "agent-server: AGENT_SERVER_TLS_CLIENT_CA applies only to TCP TLS and cannot be combined with AGENT_SERVER_UNIX"
        );
        std::process::exit(1);
    }
    if tls_client_crl.is_some() && tls_client_ca.is_none() {
        eprintln!("agent-server: AGENT_SERVER_TLS_CLIENT_CRL requires AGENT_SERVER_TLS_CLIENT_CA");
        std::process::exit(1);
    }
    if tls_client_crl.is_some() && unix_path.is_some() {
        eprintln!(
            "agent-server: AGENT_SERVER_TLS_CLIENT_CRL applies only to TCP TLS and cannot be combined with AGENT_SERVER_UNIX"
        );
        std::process::exit(1);
    }
    if tls_reload_trigger.is_some() && tls.is_none() {
        eprintln!(
            "agent-server: AGENT_SERVER_TLS_RELOAD_TRIGGER requires AGENT_SERVER_TLS_CERT and AGENT_SERVER_TLS_KEY"
        );
        std::process::exit(1);
    }
    if tls_reload_trigger.is_some() && unix_path.is_some() {
        eprintln!(
            "agent-server: AGENT_SERVER_TLS_RELOAD_TRIGGER applies only to TCP TLS and cannot be combined with AGENT_SERVER_UNIX"
        );
        std::process::exit(1);
    }
    if unix_path.is_none() {
        if let Err(error) =
            validate_tcp_security(&addr, token.is_some(), tls.is_some(), allow_insecure_remote)
        {
            eprintln!("agent-server: {error}");
            std::process::exit(1);
        }
    }

    let explicit_config = std::env::var_os("AGENT_SERVER_CONFIG")
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from);
    if explicit_config
        .as_deref()
        .is_some_and(|path| !path.is_absolute())
    {
        eprintln!("agent-server: AGENT_SERVER_CONFIG must be an absolute path");
        std::process::exit(1);
    }
    let loaded_config = match explicit_config.as_deref() {
        Some(path) => Config::try_load_from(path),
        None => Config::try_load(),
    };
    let config = match loaded_config {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(error = %error, "failed to load configuration");
            eprintln!("agent-server: failed to load configuration: {error}");
            std::process::exit(1);
        }
    };
    // Kernel init can fail on a non-writable/locked data dir or a corrupt DB.
    // Degrade to a clear, actionable message and a non-zero exit instead of an
    // un-actionable panic backtrace.
    let kernel = match AgentKernelImpl::from_config(&config) {
        Ok(k) => Arc::new(k),
        Err(e) => {
            tracing::error!(error = %e, data_dir = %config.data_dir.display(), "failed to initialize kernel");
            eprintln!("agent-server: failed to initialize kernel: {e}");
            eprintln!(
                "  (is the data dir writable? {})",
                config.data_dir.display()
            );
            std::process::exit(1);
        }
    };
    if config.cluster_raft.enabled {
        let identity = kernel.cluster_control.identity();
        let local_member = config
            .cluster_raft
            .members
            .iter()
            .find(|member| member.node_id == config.cluster_raft.node_id);
        let Some(local_member) = local_member else {
            eprintln!("agent-server: local Raft member configuration disappeared after validation");
            std::process::exit(1);
        };
        if local_member.application_node_id != identity.node_id
            || local_member.identity_public_key != identity.public_key
        {
            eprintln!(
                "agent-server: local cluster_raft application identity does not match the durable node identity"
            );
            eprintln!(
                "  configured application_node_id: {}",
                local_member.application_node_id
            );
            eprintln!("  durable application_node_id: {}", identity.node_id);
            std::process::exit(1);
        }
    }
    let cluster_runtime = match start_configured_cluster_runtime(
        kernel.context_manager.clone(),
        &config.cluster_raft,
    )
    .await
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(error = %error, "cluster Raft startup failed");
            eprintln!("agent-server: cluster Raft startup failed: {error}");
            std::process::exit(1);
        }
    };
    if let Some(runtime) = cluster_runtime.as_ref() {
        if let Err(error) = kernel.install_cluster_authority(runtime.authority_handle()) {
            eprintln!("agent-server: failed to install cluster authority: {error}");
            std::process::exit(1);
        }
        eprintln!(
            "agent-server: cluster Raft node {} listening on {}; voter generation {}; voters {:?}; transport trust generation {}; overlap expiration {:?}; transport catalog {}",
            runtime.node_id(),
            runtime.local_addr(),
            runtime.voter_set_generation(),
            runtime.voter_ids(),
            runtime.transport_trust_generation(),
            runtime.transport_trust_overlap_not_after(),
            runtime.transport_catalog_sha256(),
        );
    }
    // Make SendMessage syscalls functional against the configured backend.
    register_providers(&kernel, &config);
    if config.service_dir.is_some() {
        if let Err(error) = kernel.boot_services().await {
            tracing::error!(error = %error, "service boot failed; rolling back started services");
            eprintln!("agent-server: service boot failed: {error}");
            std::process::exit(1);
        }
    }
    // Background scheduler observer. Durable fixed-epoch quota needs no timer.
    let _runtime = kernel.start_runtime();

    // Optional Prometheus scrape endpoint. Only started when explicitly
    // configured, so the default deployment opens no extra port. Shares the
    // same kernel Arc, so the exposition is always live.
    if let Some(metrics_addr) = std::env::var("AGENT_SERVER_METRICS_ADDR")
        .ok()
        .filter(|s| !s.is_empty())
    {
        if !is_loopback_bind(&metrics_addr) && !allow_insecure_remote {
            eprintln!(
                "agent-server: refusing non-loopback metrics bind {metrics_addr}; set \
                 AGENT_SERVER_ALLOW_INSECURE_REMOTE=1 only behind a trusted network boundary"
            );
            std::process::exit(1);
        }
        match TcpListener::bind(&metrics_addr).await {
            Ok(listener) => {
                let bound = listener
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| metrics_addr.clone());
                tracing::info!(addr = %bound, "metrics endpoint listening at http://{bound}/metrics");
                eprintln!("agent-server: metrics at http://{bound}/metrics");
                let metrics_kernel = kernel.clone();
                tokio::spawn(serve_metrics_http(listener, metrics_kernel));
            }
            Err(e) => {
                tracing::warn!(addr = %metrics_addr, error = %e, "failed to bind metrics endpoint");
                eprintln!("agent-server: failed to bind metrics {metrics_addr}: {e}");
            }
        }
    }

    let tls_paths = tls.as_ref().map(|(cert, key)| TlsMaterialPaths {
        cert: cert.clone(),
        key: key.clone(),
        client_ca: tls_client_ca.clone(),
        client_crl: tls_client_crl.clone(),
    });
    let initial_tls_reload_trigger = tls_reload_trigger.as_deref().map(|path| {
        read_tls_reload_trigger(path).unwrap_or_else(|error| {
            eprintln!("agent-server: failed to read TLS reload trigger {path}: {error}");
            std::process::exit(1);
        })
    });
    // Unix socket if requested, else TCP.
    let mut server = match &unix_path {
        #[cfg(unix)]
        Some(path) => {
            let _ = std::fs::remove_file(path);
            SyscallServer::bind_unix(kernel, path)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("agent-server: failed to bind unix socket {path}: {e}");
                    std::process::exit(1);
                })
        }
        #[cfg(not(unix))]
        Some(_) => {
            eprintln!("agent-server: AGENT_SERVER_UNIX is only supported on Unix platforms");
            std::process::exit(1);
        }
        None => match &tls {
            Some(_) => {
                let paths = tls_paths
                    .as_ref()
                    .expect("TLS paths exist when TLS is configured");
                let material = read_tls_material(paths).unwrap_or_else(|error| {
                    eprintln!("agent-server: failed to read TLS material: {error}");
                    std::process::exit(1);
                });
                let config = material.server_config().unwrap_or_else(|e| {
                    eprintln!("agent-server: invalid TLS configuration: {e}");
                    std::process::exit(1);
                });
                SyscallServer::bind_tls(kernel, addr.as_str(), config)
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("agent-server: failed to bind TLS {addr}: {e}");
                        std::process::exit(1);
                    })
            }
            None => SyscallServer::bind(kernel, addr.as_str())
                .await
                .unwrap_or_else(|e| {
                    eprintln!("agent-server: failed to bind {addr}: {e}");
                    std::process::exit(1);
                }),
        },
    };

    if let Some(token) = token {
        server = server.with_auth_token(token);
        eprintln!("agent-server: authentication required (AGENT_SERVER_TOKEN set)");
    }

    if let Some(trigger_path) = tls_reload_trigger {
        let handle = server
            .tls_reload_handle()
            .expect("TLS reload trigger is validated to require a TLS listener");
        let paths = tls_paths.expect("TLS reload trigger is validated to require TLS paths");
        let trigger = initial_tls_reload_trigger
            .expect("a configured TLS reload trigger was read during startup");
        let interval =
            tls_reload_interval.expect("a configured TLS reload trigger has a polling interval");
        tokio::spawn(run_tls_reload_loop(
            handle,
            paths,
            trigger_path,
            trigger,
            interval,
        ));
        eprintln!(
            "agent-server: live TLS reload enabled (poll interval {}s)",
            interval.as_secs()
        );
    }

    match &unix_path {
        Some(path) => eprintln!("agent-server listening on unix:{path}"),
        None => {
            let scheme = if tls.is_some() { "tls" } else { "tcp" };
            match server.local_addr() {
                Ok(bound) => eprintln!("agent-server listening on {scheme}:{bound}"),
                // The socket is bound and serving; only the readback failed.
                // Report the configured addr rather than aborting a live server.
                Err(e) => {
                    tracing::warn!(error = %e, "could not read bound local addr");
                    eprintln!("agent-server listening on {scheme}:{addr}");
                }
            }
        }
    }

    let serve_result = tokio::select! {
        result = server.serve() => result,
        result = shutdown_signal() => result,
    };
    if let Some(runtime) = cluster_runtime {
        if let Err(error) = runtime.shutdown().await {
            tracing::error!(error = %error, "cluster Raft shutdown failed");
            eprintln!("agent-server: cluster Raft shutdown failed: {error}");
            std::process::exit(1);
        }
    }
    if let Err(e) = serve_result {
        eprintln!("agent-server: serve error: {e}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

fn parse_tls_reload_interval(
    value: Option<&str>,
    trigger_configured: bool,
) -> Result<Option<Duration>, String> {
    if !trigger_configured {
        return match value {
            Some(_) => Err(
                "AGENT_SERVER_TLS_RELOAD_INTERVAL_SECONDS requires AGENT_SERVER_TLS_RELOAD_TRIGGER"
                    .into(),
            ),
            None => Ok(None),
        };
    }
    let seconds = match value {
        Some(value) => value.parse::<u64>().map_err(|_| {
            "AGENT_SERVER_TLS_RELOAD_INTERVAL_SECONDS must be an integer between 1 and 3600"
                .to_string()
        })?,
        None => DEFAULT_TLS_RELOAD_INTERVAL_SECONDS,
    };
    if !(1..=MAX_TLS_RELOAD_INTERVAL_SECONDS).contains(&seconds) {
        return Err("AGENT_SERVER_TLS_RELOAD_INTERVAL_SECONDS must be between 1 and 3600".into());
    }
    Ok(Some(Duration::from_secs(seconds)))
}

fn read_tls_material(paths: &TlsMaterialPaths) -> std::io::Result<TlsMaterial> {
    let cert = std::fs::read(&paths.cert).map_err(|error| {
        std::io::Error::new(error.kind(), format!("certificate {}: {error}", paths.cert))
    })?;
    let key = std::fs::read(&paths.key).map_err(|error| {
        std::io::Error::new(error.kind(), format!("private key {}: {error}", paths.key))
    })?;
    let client_ca = paths
        .client_ca
        .as_deref()
        .map(|path| {
            std::fs::read(path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("client CA certificate {path}: {error}"),
                )
            })
        })
        .transpose()?;
    let client_crl = paths
        .client_crl
        .as_deref()
        .map(|path| {
            std::fs::read(path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("client certificate revocation list {path}: {error}"),
                )
            })
        })
        .transpose()?;
    Ok(TlsMaterial {
        cert,
        key,
        client_ca,
        client_crl,
    })
}

fn read_tls_reload_trigger(path: &str) -> std::io::Result<Vec<u8>> {
    let trigger = std::fs::read(path)?;
    if trigger.len() > MAX_TLS_RELOAD_TRIGGER_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("reload trigger exceeds {MAX_TLS_RELOAD_TRIGGER_BYTES} bytes"),
        ));
    }
    Ok(trigger)
}

enum TlsReloadPoll {
    Unchanged,
    Candidate {
        trigger: Vec<u8>,
        config: Box<rustls::ServerConfig>,
    },
}

fn poll_tls_reload(
    paths: &TlsMaterialPaths,
    trigger_path: &str,
    accepted_trigger: &[u8],
) -> std::io::Result<TlsReloadPoll> {
    let trigger = read_tls_reload_trigger(trigger_path)?;
    if trigger == accepted_trigger {
        return Ok(TlsReloadPoll::Unchanged);
    }
    let material = read_tls_material(paths)?;
    let config = material.server_config()?;
    if read_tls_reload_trigger(trigger_path)? != trigger {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "TLS reload trigger changed while material was being validated",
        ));
    }
    Ok(TlsReloadPoll::Candidate {
        trigger,
        config: Box::new(config),
    })
}

async fn run_tls_reload_loop(
    handle: TlsReloadHandle,
    paths: TlsMaterialPaths,
    trigger_path: String,
    mut accepted_trigger: Vec<u8>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    let mut last_error = None;
    loop {
        ticker.tick().await;
        let paths = paths.clone();
        let trigger_path = trigger_path.clone();
        let current_trigger = accepted_trigger.clone();
        let poll = tokio::task::spawn_blocking(move || {
            poll_tls_reload(&paths, &trigger_path, &current_trigger)
        })
        .await;
        let poll = match poll {
            Ok(result) => result,
            Err(error) => Err(std::io::Error::other(format!(
                "TLS reload worker failed: {error}"
            ))),
        };
        match poll {
            Ok(TlsReloadPoll::Unchanged) => {}
            Ok(TlsReloadPoll::Candidate { trigger, config }) => match handle.reload(*config) {
                Ok(generation) => {
                    accepted_trigger = trigger;
                    last_error = None;
                    tracing::info!(
                        generation,
                        "TLS certificate and trust configuration reloaded"
                    );
                }
                Err(error) => {
                    let message = error.to_string();
                    if last_error.as_deref() != Some(message.as_str()) {
                        tracing::warn!(
                            error = %error,
                            "TLS reload rejected; previous configuration remains active"
                        );
                    }
                    last_error = Some(message);
                }
            },
            Err(error) => {
                let message = error.to_string();
                if last_error.as_deref() != Some(message.as_str()) {
                    tracing::warn!(
                        error = %error,
                        "TLS reload candidate is incomplete or invalid; previous configuration remains active"
                    );
                }
                last_error = Some(message);
            }
        }
    }
}

fn is_loopback_bind(addr: &str) -> bool {
    if let Ok(socket) = addr.parse::<std::net::SocketAddr>() {
        return socket.ip().is_loopback();
    }
    addr.rsplit_once(':')
        .is_some_and(|(host, _)| host.eq_ignore_ascii_case("localhost"))
}

fn validate_tcp_security(
    addr: &str,
    has_token: bool,
    has_tls: bool,
    allow_insecure_remote: bool,
) -> Result<(), String> {
    if is_loopback_bind(addr) || allow_insecure_remote {
        return Ok(());
    }
    if !has_token {
        return Err(format!(
            "refusing unauthenticated non-loopback bind {addr}; configure AGENT_SERVER_TOKEN and TLS"
        ));
    }
    if !has_tls {
        return Err(format!(
            "refusing plaintext non-loopback bind {addr}; configure AGENT_SERVER_TLS_CERT and AGENT_SERVER_TLS_KEY"
        ));
    }
    Ok(())
}

/// A tiny, dependency-free HTTP `/metrics` endpoint for Prometheus scraping.
///
/// Deliberately minimal: it accepts a connection, reads the request line,
/// answers `GET /metrics` with the live Prometheus exposition and `404` for
/// anything else, then closes the connection (no keep-alive). This is enough
/// for a scraper, avoids pulling in an HTTP framework, and shares the same
/// kernel `Arc` so the numbers are always current.
async fn serve_metrics_http(listener: TcpListener, kernel: Arc<AgentKernelImpl>) {
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            // A transient accept error shouldn't take the endpoint down.
            Err(e) => {
                tracing::warn!(error = %e, "metrics endpoint accept error");
                continue;
            }
        };
        let kernel = kernel.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_metrics_conn(&mut stream, &kernel).await {
                tracing::debug!(error = %e, "metrics connection error");
            }
        });
    }
}

/// Handle one metrics HTTP request on `stream`. Reads up to the end of the
/// request line, routes on method + path, and writes a complete HTTP/1.1
/// response with `Connection: close`.
async fn handle_metrics_conn(
    stream: &mut tokio::net::TcpStream,
    kernel: &AgentKernelImpl,
) -> std::io::Result<()> {
    // Read enough to capture the request line. We never need the body, and
    // bounding the read guards against a slow/oversized client.
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    // Strip any query string from the path (`/metrics?foo=bar` → `/metrics`).
    let path_only = match path.split_once('?') {
        Some((p, _)) => p,
        None => path,
    };

    let response = if method == "GET" && path_only == "/metrics" {
        let body = kernel::metrics::render_prometheus(kernel);
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            kernel::metrics::PROMETHEUS_CONTENT_TYPE,
            body.len(),
            body
        )
    } else {
        let body = "not found\n";
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    };

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[test]
    fn remote_tcp_requires_authentication_and_encryption() {
        assert!(validate_tcp_security("127.0.0.1:7777", false, false, false).is_ok());
        assert!(validate_tcp_security("[::1]:7777", false, false, false).is_ok());
        assert!(validate_tcp_security("localhost:7777", false, false, false).is_ok());

        let open = validate_tcp_security("0.0.0.0:7777", false, false, false).unwrap_err();
        assert!(open.contains("unauthenticated"));
        let plaintext = validate_tcp_security("0.0.0.0:7777", true, false, false).unwrap_err();
        assert!(plaintext.contains("plaintext"));
        assert!(validate_tcp_security("0.0.0.0:7777", true, true, false).is_ok());
        assert!(validate_tcp_security("0.0.0.0:7777", false, false, true).is_ok());
    }

    #[test]
    fn tls_reload_interval_requires_trigger_and_is_bounded() {
        assert_eq!(parse_tls_reload_interval(None, false).unwrap(), None);
        assert!(parse_tls_reload_interval(Some("5"), false)
            .unwrap_err()
            .contains("requires AGENT_SERVER_TLS_RELOAD_TRIGGER"));
        assert_eq!(
            parse_tls_reload_interval(None, true).unwrap(),
            Some(Duration::from_secs(DEFAULT_TLS_RELOAD_INTERVAL_SECONDS))
        );
        assert_eq!(
            parse_tls_reload_interval(Some("1"), true).unwrap(),
            Some(Duration::from_secs(1))
        );
        assert!(parse_tls_reload_interval(Some("0"), true).is_err());
        assert!(parse_tls_reload_interval(Some("3601"), true).is_err());
        assert!(parse_tls_reload_interval(Some("not-a-number"), true).is_err());
    }

    #[test]
    fn tls_reload_poll_publishes_only_after_trigger_change_and_validates_material() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate TLS material");
        let directory =
            std::env::temp_dir().join(format!("agentos-tls-reload-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create TLS test directory");
        let cert_path = directory.join("server.pem");
        let key_path = directory.join("server.key");
        let trigger_path = directory.join("reload");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write certificate");
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write key");
        std::fs::write(&trigger_path, b"generation-one").expect("write initial trigger");
        let paths = TlsMaterialPaths {
            cert: cert_path.to_string_lossy().into_owned(),
            key: key_path.to_string_lossy().into_owned(),
            client_ca: None,
            client_crl: None,
        };
        let trigger_path = trigger_path.to_string_lossy().into_owned();
        let initial = read_tls_reload_trigger(&trigger_path).expect("read initial trigger");
        assert!(matches!(
            poll_tls_reload(&paths, &trigger_path, &initial).expect("poll unchanged trigger"),
            TlsReloadPoll::Unchanged
        ));

        std::fs::write(&key_path, b"incomplete-key-update").expect("write invalid key");
        std::fs::write(&trigger_path, b"generation-two").expect("change trigger");
        assert!(
            poll_tls_reload(&paths, &trigger_path, &initial).is_err(),
            "invalid material must not produce a publishable candidate"
        );

        std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("restore key");
        match poll_tls_reload(&paths, &trigger_path, &initial).expect("valid reload candidate") {
            TlsReloadPoll::Candidate { trigger, .. } => {
                assert_eq!(trigger, b"generation-two");
            }
            TlsReloadPoll::Unchanged => panic!("changed trigger must produce a candidate"),
        }

        std::fs::write(&trigger_path, vec![b'x'; MAX_TLS_RELOAD_TRIGGER_BYTES + 1])
            .expect("write oversized trigger");
        assert_eq!(
            read_tls_reload_trigger(&trigger_path)
                .expect_err("oversized trigger must fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        std::fs::remove_dir_all(directory).expect("remove TLS test directory");
    }

    /// Send a raw HTTP request line to `addr` and return (status_line, body).
    async fn http_get(addr: std::net::SocketAddr, path: &str) -> (String, String) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head.lines().next().unwrap_or("").to_string();
        (status, body.to_string())
    }

    #[tokio::test]
    async fn metrics_http_endpoint_serves_exposition_and_404s() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_metrics_http(listener, kernel));

        // GET /metrics → 200 + a Prometheus exposition body.
        let (status, body) = http_get(addr, "/metrics").await;
        assert!(status.contains("200 OK"), "status: {status}");
        assert!(
            body.contains("# TYPE agentos_syscall_gate_total counter"),
            "body:\n{body}"
        );
        assert!(body.contains("agentos_agents"));

        // A query string is tolerated and still routes to /metrics.
        let (status, _) = http_get(addr, "/metrics?foo=bar").await;
        assert!(status.contains("200 OK"), "status: {status}");

        // Any other path → 404.
        let (status, _) = http_get(addr, "/nope").await;
        assert!(status.contains("404"), "status: {status}");
    }
}
