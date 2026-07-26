# Getting Started

## Prerequisites

- **Rust 1.97+**; the repository pins Rust 1.97.1 for reproducible CI.
- **Node.js 22.12+** when building the Svelte desktop frontend.
- An **LLM API key** if you want real model turns. Supported providers: Azure
  OpenAI (default), OpenAI, Anthropic, local Ollama, plus Groq, Deepseek, Gemini,
  vLLM, and HuggingFace. Many non-LLM paths work keyless.

## Clone and build

```bash
git clone https://github.com/surya-koritala/AIagentOS.git
cd AIagentOS
cargo build --release
```

## Run the tests

The main deterministic Rust suite is:

```bash
cargo test --workspace --exclude tauri-app --locked
```

It does not call live providers, but mock HTTP/TCP tests bind ephemeral
loopback ports. Run `./scripts/ci-local.sh` for the full host-compatible
preflight. GitHub Actions separately proves every supported runner, the
desktop, dependency policy, critical coverage floors, and the container.

Useful filters:

```bash
cargo test --package kernel                 # one crate
cargo test --package kernel execution       # filter by name substring
cargo test --package integration-tests      # property + e2e tests
```

## Configure a provider

Provider selection is via config plus environment variables. The CLI reads
`config.llm_provider` to decide which adapter to register. For Azure OpenAI
(the default):

```bash
export AZURE_OPENAI_API_KEY="your-key"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o"
export AZURE_OPENAI_API_VERSION="2024-08-01-preview"
```

Other providers (`openai`, `anthropic`, `local`, and the OpenAI-compatible
adapters) are selected the same way — set `llm_provider` and the matching env
vars. See `.env.example` in the repo for the full set.

## Run the CLI

The binary is `agent`, shipped by the `agent-cli` package:

```bash
# Interactive REPL
cargo run --package agent-cli

# One-shot
cargo run --package agent-cli -- -c "do something"

# Resume a conversation
cargo run --package agent-cli -- --conversation <ID>

# Pipe mode
echo "input" | cargo run --package agent-cli -- "prompt"
```

## Run the kernel as a syscall server

`agent-server` boots the kernel from config, registers the configured provider,
and serves the JSON syscall API (agent lifecycle, the `SendMessage` LLM turn,
memory store/query, tool calls, and enforcement introspection). With a provider
registered, `SendMessage` reaches a real backend; with none, the non-LLM
syscalls still work (keyless boot).

```bash
# TCP, default 127.0.0.1:7777
cargo run --package agent-cli --bin agent-server

# Remote TCP requires both authentication and TLS
AGENT_SERVER_TOKEN="replace-with-a-secret" \
AGENT_SERVER_TLS_CERT=/etc/agentos/server.crt \
AGENT_SERVER_TLS_KEY=/etc/agentos/server.key \
cargo run --package agent-cli --bin agent-server -- 0.0.0.0:7777

# Unix-domain socket instead of TCP
AGENT_SERVER_UNIX=/tmp/agent.sock cargo run --package agent-cli --bin agent-server

# Require a shared-secret token before any syscall
AGENT_SERVER_TOKEN=secret cargo run --package agent-cli --bin agent-server
```

Drive a protected service through the SDK-backed operator CLI or TUI. Prefer
the environment variable so a token is not retained in shell history:

```bash
AGENT_SERVER_TOKEN=secret cargo run --package agent-cli --bin agentctl -- list
AGENT_SERVER_TOKEN=secret cargo run --package agent-tui -- --addr 127.0.0.1:7777
```

The packaged desktop starts an ephemeral loopback syscall service protected by
a random per-process secret. Its Tauri commands use the same typed SDK path;
they do not call lifecycle or tool methods directly on the kernel.

The server has three explicit caller modes:

- The default loopback listener and a Unix-domain socket are trusted local
  system/operator interfaces. Without a configured token they have full system
  authority, so do not expose or proxy them to untrusted clients.
- `AGENT_SERVER_TOKEN` is a trusted system/operator shared secret and also has
  full system authority. On a non-loopback bind, TLS is mandatory so that secret
  and all requests are encrypted in transit.
- An issued tenant API key or session resolves to its complete user, tenant,
  role, and credential identity. Every request is re-authorized; tenant callers
  cannot use system operations or address another tenant's agents.

`agent-server` refuses open or plaintext non-loopback listeners and non-loopback
metrics listeners. `AGENT_SERVER_ALLOW_INSECURE_REMOTE=1` exists only for an
explicit development environment or a separately secured network boundary; it
turns off that startup guard and is not a production configuration.

## Drive the kernel from the Rust SDK

`agent-sdk` is the ergonomic, Rust-only face of the syscall server. It reuses the
kernel's wire types and adds `KernelClient` (a typed client) and an `Agent`
builder. Connect to a running `agent-server` and drive it through typed async
methods:

```rust
use agent_sdk::Agent;

# async fn run() -> Result<(), agent_sdk::SdkError> {
let mut agent = Agent::builder()
    .name("alpha")
    .task("summarize the docs")
    .profile("standard")
    .connect("127.0.0.1:7777")
    .await?;

let reply = agent.send("hello").await?;
println!("{}", reply.content);
# Ok(())
# }
```

The SDK also exposes enforcement (MAC / capabilities / cgroups / namespaces /
audit / USD budget) as first-class calls, plus memory store/query, storage, and
`load_package`.

## Load an agent package

An agent package is a declarative TOML manifest the kernel can validate and bring
up as a live agent — see [Agent Package Format](./agent-package.md). A sample
lives at `examples/packages/researcher/agent.toml`. Load it in-process or over
the wire through `load_package`.

## Run the benchmarks

```bash
cargo run --package os-benchmark --bin os-benchmark
cargo run --package os-benchmark --bin stress-test
```

## Next steps

- [Concepts](./concepts.md) — how the pieces fit together.
- [Service Files](./tutorials/service-files.md) — declare agents like systemd units.
- [Custom Tools](./tutorials/custom-tools.md) — add tools without writing kernel code.
