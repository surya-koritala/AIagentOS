# Creating Custom Tools

## TOML-based Tools (No Code)

Create `~/.config/ai-agent-os/tools.toml`:

```toml
[[tool]]
name = "word_count"
description = "Count words in a file"
command = "wc"
args_template = ["-w", "{file_path}"]

[tool.parameters]
file_path = { type = "string", description = "Path to file", required = true }

[[tool]]
name = "grep_code"
description = "Search for pattern in source files"
command = "grep"
args_template = ["-rn", "{pattern}", "{directory}"]

[tool.parameters]
pattern = { type = "string", description = "Search pattern", required = true }
directory = { type = "string", description = "Directory to search", required = true }
```

The agent will automatically discover and use these tools.

## MCP Server Tools

Connect to any MCP-compatible tool server:

Create `~/.config/ai-agent-os/mcp_servers.json`:
```json
[
  {
    "name": "github",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-github"],
    "env": {"GITHUB_TOKEN": "your-token"}
  }
]
```

## WASM Module Tools

For complex tools, create a WASM module:

1. Create `modules/my-tool/manifest.toml`
2. Implement in Rust targeting `wasm32-wasi`
3. Install: the kernel loads it automatically

See `modules/example-tool/` for a complete example.
