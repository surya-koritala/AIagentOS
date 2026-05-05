# Example WASM Tool Module

A simple example module demonstrating the AI Agent OS module system.

## Capabilities

- `tool.file_search` — Search for files matching a pattern
- `tool.word_count` — Count words in a given text

## Building

```bash
cd modules/example-tool
cargo build --target wasm32-wasi --release
cp target/wasm32-wasi/release/example_tool.wasm ./module.wasm
```

## Installation

The kernel's module system will:
1. Read `manifest.toml` to validate permissions and resource requirements
2. Load `module.wasm` into a Wasmtime sandbox
3. Expose host functions for kernel service access
