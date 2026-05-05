# AI Agent OS

[![Build Status](https://github.com/surya-koritala/AIagentOS/actions/workflows/ci.yml/badge.svg)](https://github.com/surya-koritala/AIagentOS/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

**An operating system kernel for AI agents** — manage multiple autonomous AI agents the way a traditional OS manages processes, with scheduling, isolation, permissions, and inter-process communication.

<p align="center">
  <img src="docs/screenshot.png" alt="AI Agent OS Dashboard" width="700">
</p>

## What is AI Agent OS?

AI Agent OS is a desktop application that lets you create, manage, and monitor autonomous AI agents. Each agent connects to an LLM (Azure OpenAI, OpenAI, Anthropic, or local Ollama), gets a sandboxed environment, and can use tools to interact with your system — reading files, running commands, making HTTP requests, and more.

Think of it as a **process manager for AI** — with the same guarantees you'd expect from an OS: isolation between agents, permission controls, resource scheduling, and full observability.

## Features

- **🤖 Multi-Agent Management** — Run up to 10 concurrent agents with priority-based scheduling
- **🔧 Tool Use** — Agents can read/write files, run commands, make HTTP requests
- **🔒 Permission System** — 4 built-in profiles (read-only, standard, elevated, full-access) with audit logging
- **📦 Sandbox Isolation** — Each agent gets an isolated workspace with path traversal prevention
- **🧠 Long-Term Memory** — Agents remember facts across conversations (SQLite-backed)
- **🔄 Auto-Recovery** — LLM retry with exponential backoff, graceful tool failure handling
- **📡 Inter-Agent Communication** — Direct messaging, pub/sub, task delegation
- **🧩 WASM Plugin System** — Extend agent capabilities with WebAssembly modules
- **🖥️ Desktop App** — Tauri 2 + Svelte frontend with dark theme
- **☁️ Multi-Provider** — Azure OpenAI, OpenAI, Anthropic, Local (Ollama)

## Quick Start

### Prerequisites

- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Node.js 18+ (for the frontend)
- System libraries: `libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev` (Linux)

### Build & Run

```bash
# Clone
git clone https://github.com/surya-koritala/AIagentOS.git
cd AIagentOS

# Install frontend dependencies
cd crates/tauri-app/ui && npm install && cd ../../..

# Build frontend
cd crates/tauri-app/ui && npx vite build && cd ../../..

# Run the desktop app
cargo run --package tauri-app
```

On first launch, the setup wizard will ask for your LLM provider credentials.

### Run Tests

```bash
cargo test
```

Currently **160 tests** covering all subsystems with property-based testing.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Tauri Desktop App (Svelte UI)                  │
├─────────────────────────────────────────────────┤
│  Kernel Orchestrator (AgentKernelImpl)          │
├────────┬────────┬────────┬────────┬─────────────┤
│ Agent  │Scheduler│Context │Permis- │  Sandbox    │
│Lifecycle│Priority│ SQLite │ sions  │  Manager    │
├────────┼────────┼────────┼────────┼─────────────┤
│Resource│  LLM   │  WASM  │  IPC   │Observability│
│ Broker │Connector│Modules │Pub/Sub │  Engine     │
├────────┴────────┴────────┴────────┴─────────────┤
│  Adapters (Azure OpenAI, OpenAI, Anthropic,     │
│            Ollama)                               │
│  Resources (Filesystem, Network, Application)   │
└─────────────────────────────────────────────────┘
```

### Crate Structure

| Crate | Purpose |
|-------|---------|
| `crates/kernel` | Core kernel — agent lifecycle, scheduler, context, permissions, sandbox, IPC, observability, execution loop |
| `crates/adapters` | LLM provider adapters (Azure OpenAI, OpenAI, Anthropic, Local) |
| `crates/resources` | Built-in resource providers (filesystem, network, application, browser, peripheral) |
| `crates/tauri-app` | Desktop application (Tauri 2 + Svelte) |
| `tests/` | Integration and property-based tests |
| `modules/example-tool` | Example WASM plugin module |

## How It Works

1. **You send a message** → "Read my config file and summarize it"
2. **Kernel routes to agent** → Finds the agent's executor, loads context
3. **Agent thinks (LLM)** → Sends message + tool definitions to Azure OpenAI/etc
4. **LLM returns tool calls** → `read_file({path: "~/.config/app.toml"})`
5. **Kernel executes tools** → Permission check → Sandbox check → Actually reads the file
6. **Result goes back to LLM** → File contents sent as tool result
7. **LLM responds** → "Your config file contains..."
8. **Memory updated** → Substantial responses stored for future reference

## Configuration

Config is stored at `~/.config/ai-agent-os/config.toml`:

```toml
llm_provider = "azure-openai"
default_model = "gpt-4o"
setup_complete = true

[api_keys]
azure-openai = "your-api-key"

# Azure-specific
azure_endpoint = "https://your-resource.openai.azure.com"
azure_deployment = "gpt-4o"
azure_api_version = "2024-08-01-preview"
```

## Built-in Tools

| Tool | Description |
|------|-------------|
| `read_file` | Read file contents |
| `write_file` | Write/create files |
| `list_directory` | List directory contents |
| `http_get` | Make HTTP GET requests |
| `run_command` | Execute shell commands |

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Run tests
cargo test

# Run with hot-reload (frontend)
cd crates/tauri-app/ui && npm run dev

# Build release
cargo build --release --package tauri-app
```

### Project Status

- [x] Core kernel (agent lifecycle, scheduler, context, permissions, sandbox)
- [x] LLM adapters (Azure OpenAI, OpenAI, Anthropic, Local)
- [x] Tool calling with function execution
- [x] Agent execution loop (think→act→observe)
- [x] Error recovery (LLM retry, tool failure handling)
- [x] Long-term memory
- [x] Desktop app shell (Tauri + Svelte)
- [ ] LLM streaming (token-by-token)
- [ ] WASM module host functions
- [ ] Enhanced UI (activity feed, plan visualization)
- [ ] Packaging & auto-update

## License

MIT — see [LICENSE](LICENSE) for details.

## Acknowledgments

Built with [Rust](https://www.rust-lang.org/), [Tauri](https://tauri.app/), [Svelte](https://svelte.dev/), [Wasmtime](https://wasmtime.dev/), and [SQLite](https://sqlite.org/).
