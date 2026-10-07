# syntax=docker/dockerfile:1
#
# AI Agent OS — minimal runtime image.
#
# Builds ONLY the two packages that matter for a headless container:
#   * agent-cli   -> binaries `agent` (the interactive/one-shot CLI) and
#                    `agent-server` (the long-lived JSON syscall wire service)
#   * os-benchmark -> binaries `os-demo`, `os-benchmark`, `stress-test`
#
# `agent-server` lives at crates/cli/src/bin/agent-server.rs, so `-p agent-cli`
# already compiles it — the runtime stage just has to COPY it in.
#
# crates/tauri-app is deliberately NOT built — it needs GTK/WebKit/libsoup
# system libraries that have no place in a slim runtime image. Targeting
# `-p agent-cli -p os-benchmark` means Cargo never compiles tauri-app even
# though it is a workspace member.
#
# Linkage facts that drive the apt deps:
#   * reqwest 0.12 uses default (native-tls) features -> openssl-sys, so the
#     BUILD stage needs libssl-dev + pkg-config + a C toolchain, and the
#     RUNTIME stage needs libssl3 + ca-certificates (for HTTPS to LLM APIs).
#   * rusqlite bundles SQLCipher plus vendored OpenSSL -> encrypted SQLite is
#     statically linked, so NO system libsqlite3/sqlcipher is required at runtime.

############################
# Stage 1 — builder
############################
# The builder supplies Rust; rust-toolchain.toml selects the workspace's pinned
# compiler. Bookworm supplies OpenSSL 3, matching the runtime image.
FROM rust:1.99.0-slim-bookworm@sha256:452176c0cefca88c0b3184ce85a4eb03e3d4fa05d2afb5366abcba853221019e AS builder

# Build-time system deps:
#   build-essential -> C toolchain (cc) for openssl-sys / wasmtime / ring etc.
#   pkg-config + libssl-dev -> for reqwest's native-tls (openssl-sys)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the whole workspace. The .dockerignore keeps target/, .git/,
# node_modules, *.db and friends out of the build context so this stays small.
COPY . .

# Build exactly the binaries we ship — never `--workspace` (that would drag in
# tauri-app and its GTK/WebKit deps). Cargo.lock is committed, so --locked is
# safe and reproducible.
RUN cargo build --release --locked \
        -p agent-cli \
        -p os-benchmark

############################
# Stage 2 — runtime
############################
FROM debian:bookworm-20260918-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime

# Runtime system deps:
#   libssl3         -> libssl.so.3 / libcrypto.so.3 (reqwest native-tls)
#   ca-certificates -> trust store for HTTPS calls to LLM providers
#   netcat-openbsd  -> tiny `nc` used by the agent-server container's
#                      healthcheck to send a real newline-JSON syscall and read
#                      the reply (a port-open probe is not enough).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. HOME=/data so the `dirs` crate resolves XDG paths under the
# mounted volume; we also pin XDG_* explicitly so config + db live in /data.
RUN useradd --create-home --home-dir /data --uid 10001 --shell /usr/sbin/nologin agentos \
    && mkdir -p /data/config/ai-agent-os /data/share/ai-agent-os /backups /keys \
    && chown -R agentos:agentos /data /backups /keys

# Copy the produced binaries from the builder. `agent-server` is the primary
# wire-service entry surface (long-lived JSON syscall protocol over TCP).
COPY --from=builder /build/target/release/agent         /usr/local/bin/agent
COPY --from=builder /build/target/release/agent-server  /usr/local/bin/agent-server
COPY --from=builder /build/target/release/agentctl       /usr/local/bin/agentctl
COPY --from=builder /build/target/release/os-demo       /usr/local/bin/os-demo
COPY --from=builder /build/target/release/os-benchmark  /usr/local/bin/os-benchmark
COPY --from=builder /build/target/release/stress-test   /usr/local/bin/stress-test

# Entrypoint generates the config.toml that the CLI needs. The provider URL and
# model can ONLY come from config.toml (no env var selects them), so the
# entrypoint translates env vars -> config.toml before exec'ing the command.
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER agentos
ENV HOME=/data \
    XDG_CONFIG_HOME=/data/config \
    XDG_DATA_HOME=/data/share \
    # Defaults the entrypoint uses to render config.toml. Override in compose.
    AGENTOS_LLM_PROVIDER=local \
    AGENTOS_MODEL=llama3.2 \
    OLLAMA_BASE_URL=http://localhost:11434

# /data holds config.toml + encrypted agent_os.db. Backups and the operator-
# custodied storage key use separate mount/lifecycle boundaries.
VOLUME ["/data", "/backups", "/keys"]
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command proves the OS layer with ZERO LLM / ZERO keys: the
# syscall-gate enforcement demo (capability / cgroup / namespace / scheduler).
CMD ["os-demo"]
