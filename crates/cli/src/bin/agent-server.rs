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
//!   AGENT_SERVER_ALLOW_INSECURE_REMOTE=1 # explicit development-only override

#[path = "../logging.rs"]
mod logging;
#[path = "../providers.rs"]
mod providers;

use std::sync::Arc;

use kernel::config::Config;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;
use providers::register_providers;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
    if unix_path.is_none() {
        if let Err(error) =
            validate_tcp_security(&addr, token.is_some(), tls.is_some(), allow_insecure_remote)
        {
            eprintln!("agent-server: {error}");
            std::process::exit(1);
        }
    }

    let config = match Config::try_load() {
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
            Some((cert_path, key_path)) => {
                let cert_pem = std::fs::read(cert_path).unwrap_or_else(|e| {
                    eprintln!("agent-server: failed to read TLS cert {cert_path}: {e}");
                    std::process::exit(1);
                });
                let key_pem = std::fs::read(key_path).unwrap_or_else(|e| {
                    eprintln!("agent-server: failed to read TLS key {key_path}: {e}");
                    std::process::exit(1);
                });
                let config = match tls_client_ca.as_deref() {
                    Some(client_ca_path) => {
                        let client_ca_pem =
                            std::fs::read(client_ca_path).unwrap_or_else(|error| {
                                eprintln!(
                                    "agent-server: failed to read TLS client CA {client_ca_path}: {error}"
                                );
                                std::process::exit(1);
                            });
                        kernel::syscall_server::server_config_from_pem_with_client_ca(
                            &cert_pem,
                            &key_pem,
                            &client_ca_pem,
                        )
                    }
                    None => {
                        kernel::syscall_server::server_config_from_pem(&cert_pem, &key_pem)
                    }
                }
                .unwrap_or_else(|e| {
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

    if let Err(e) = server.serve().await {
        eprintln!("agent-server: serve error: {e}");
        std::process::exit(1);
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
