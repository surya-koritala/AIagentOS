# Getting Started with AI Agent OS

## Prerequisites
- Rust 1.75+
- An LLM API key (Azure OpenAI, OpenAI, or Anthropic)

## Installation

```bash
git clone https://github.com/surya-koritala/AIagentOS.git
cd AIagentOS
cargo build --release
```

## Configuration

Create `~/.config/ai-agent-os/config.toml`:
```toml
llm_provider = "azure-openai"
default_model = "gpt-4o"
setup_complete = true

[api_keys]
```

Set environment variables:
```bash
export AZURE_OPENAI_API_KEY="your-key"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o"
export AZURE_OPENAI_API_VERSION="2024-08-01-preview"
```

## Running the CLI

```bash
# Interactive mode
cargo run --package agent-cli

# One-shot
cargo run --package agent-cli -- -c "What files are in /tmp?"

# Pipe mode
cat src/main.rs | cargo run --package agent-cli -- "Explain this code"
```

## Running the OS Kernel

```rust
use kernel::os_kernel::OsKernel;

let kernel = OsKernel::new();
kernel.boot(Some(Path::new("/etc/agents/"))).await?;
let id = kernel.start_agent("my-agent").await?;
kernel.tool_call(id, "/tools/fs", "read", &json!({"path": "/tmp/test"})).await?;
kernel.shutdown().await;
```

## Next Steps
- [Writing a service file](service-files.md)
- [Creating custom tools](custom-tools.md)
