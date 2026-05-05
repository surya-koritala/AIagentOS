# Contributing to AI Agent OS

Thank you for your interest in contributing! This project is open source and we welcome contributions of all kinds.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/AIagentOS.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Commit: `git commit -m "feat: your feature description"`
7. Push: `git push origin feature/your-feature`
8. Open a Pull Request

## Development Environment

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- Node.js 18+ (for the Svelte frontend)
- Linux: `sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`

### Building

```bash
cargo build                    # Build all crates
cargo test                     # Run all tests
cargo test --package kernel    # Test specific crate
```

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

## Questions?

Open an issue or start a discussion on GitHub. We're happy to help!
