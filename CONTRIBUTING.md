# Contributing to AI Agent OS

Thank you for your interest in contributing! This project is open source and we welcome contributions of all kinds.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/AIagentOS.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run the relevant tests, then `./scripts/ci-local.sh` before requesting review
6. Commit: `git commit -m "feat: your feature description"`
7. Push: `git push origin feature/your-feature`
8. Open a Pull Request

## Development Environment

### Prerequisites

- Rust 1.97+ (the repository pins 1.97.1 in `rust-toolchain.toml`)
- Node.js 22.12+ (required by the current Vite/Svelte frontend)
- `mdbook`, `cargo-deny`, and `cargo-llvm-cov` for the complete local preflight
- Linux: `sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`

### Building

```bash
cargo build                    # Build all crates
cargo test                     # Run all tests
cargo test --package kernel    # Test specific crate
./scripts/ci-local.sh          # Reproduce host-compatible release gates
```

### Build footprint

`target/` grows fast here and **Cargo never garbage-collects it**. Every distinct
flag combination writes its own complete artifact set — `cargo test`,
`cargo clippy --all-targets`, `--all-features`, and each feature selection are
all separate — and bumping a large dependency strands the entire previous set
rather than replacing it. About 200 crates are statically linked into each of
~47 separately linked units, so one set is multiple GB and they accumulate
silently. A long session that never prunes can reach hundreds of GB.

The root `Cargo.toml` already drops debug info for dependencies, which cuts each
set by roughly 40%. Retention is the other half, and it is on you:

```bash
cargo clean                    # after switching feature sets or bumping a big dep
rm -rf fuzz/target             # a separate tree; `cargo clean` never reaches it
rm -rf target/llvm-cov-target  # only exists if you ran coverage locally
cargo install cargo-sweep && cargo sweep -t 7   # prune generations older than 7 days
```

Prefer `cargo test -p <crate>` over `cargo test --workspace` while iterating, and
avoid `--all-features` locally — it resolves a much larger graph (candle,
chromiumoxide) that no default build needs.

### Project Structure

```
crates/
├── kernel/          # Core kernel (start here for backend changes)
│   └── src/
│       ├── lib.rs          # Types, errors, kernel orchestrator
│       ├── agent.rs        # Agent lifecycle state machine
│       ├── execution.rs    # Agent execution loop (think→act→observe)
│       ├── connector.rs    # LLM session/provider traits
│       ├── tools.rs        # Tool registry
│       ├── context.rs      # SQLite context manager
│       ├── permissions.rs  # Permission system
│       ├── scheduler.rs    # Priority scheduler
│       ├── sandbox.rs      # Sandbox isolation
│       ├── ipc.rs          # Inter-agent communication
│       ├── observability.rs # Logging, metrics, deviation detection
│       ├── modules.rs      # WASM module system
│       ├── config.rs       # Configuration management
│       └── prerequisites.rs # System checks
├── adapters/        # LLM provider adapters
│   └── src/
│       ├── azure_openai.rs # Azure OpenAI adapter
│       ├── openai.rs       # OpenAI adapter
│       ├── anthropic.rs    # Anthropic Claude adapter
│       └── local.rs        # Ollama/local LLM adapter
├── resources/       # Resource providers
│   └── src/
│       ├── filesystem.rs   # File operations
│       ├── network.rs      # HTTP requests
│       └── application.rs  # Command execution
└── tauri-app/       # Desktop application
    ├── src/         # Rust backend (Tauri commands)
    └── ui/          # Svelte frontend
```

## Code Style

- Follow standard Rust conventions (`cargo fmt`, `cargo clippy`)
- Write tests for new functionality
- Use property-based tests (`proptest`) for correctness properties
- Keep functions focused and small
- Document public APIs with doc comments

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation
- `test:` — Adding tests
- `refactor:` — Code refactoring
- `chore:` — Maintenance

## Areas to Contribute

### Good First Issues

- Add more built-in tools (e.g., `search_files`, `git_status`)
- Improve error messages
- Add more unit tests
- Documentation improvements

### Medium

- LLM streaming (SSE parsing for real-time token display)
- Anthropic streaming support
- Better context window management (tiktoken-rs for accurate token counting)
- UI improvements (keyboard shortcuts, themes)

### Advanced

- WASM module host functions (expose kernel services to plugins)
- Browser automation provider (real implementation)
- Cross-platform sandbox (Windows Job Objects, macOS sandbox-exec)
- Auto-update system

## Testing

- **Unit tests**: Co-located with source (`#[cfg(test)]`)
- **Property tests**: In `tests/src/` using `proptest` — validate correctness properties
- **Integration tests**: In `tests/src/e2e_pipeline.rs` — full pipeline with wiremock
- **Adapter tests**: In `crates/adapters/src/*_tests.rs` — wiremock API mocking

Run specific test suites:

```bash
cargo test --package kernel execution    # Execution loop tests
cargo test --package adapters            # Adapter tests
cargo test --package integration-tests   # Property + E2E tests
```

The deterministic suite never calls a live LLM provider and may bind an
ephemeral loopback port for mock HTTP/TCP servers. Secret-backed provider
qualification is deliberately separate from pull-request CI. GitHub Actions
adds the Linux/macOS/Windows matrices, protected-branch issue-state check,
container persistence proof, scheduled Miri/ASan/fuzz jobs, and signed release
qualification. The manual live-provider workflow uses a protected environment
and is never triggered by an untrusted pull request.

## Questions?

Open an issue or start a discussion on GitHub. We're happy to help!
