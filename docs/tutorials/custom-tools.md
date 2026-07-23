# Creating Custom Tools

## TOML-based Tools (No Code)

Create `~/.config/ai-agent-os/tools.toml`:

```toml
[[tool]]
name = "word_count"
description = "Count words in a file"
command = "wc"
args_template = ["-w", "{file_path}"]

# Security is mandatory. Command templates execute a process, so they require
# CAP_EXEC (0x40) and a sandbox. The resource extractor must be the exact,
# immutable executable from `command`; arguments such as file paths remain
# untrusted parameters and cannot stand in for the process target.
[tool.security]
action = "execute"
required_capabilities = [64]
namespace_visibility = "global"
approval_policy = "user"
sandbox_requirement = "required"
[tool.security.resource_extractor]
kind = "constant"
value = "wc"

[tool.parameters]
file_path = { type = "string", description = "Path to file", required = true }

[[tool]]
name = "grep_code"
description = "Search for pattern in source files"
command = "grep"
args_template = ["-rn", "{pattern}", "{directory}"]

[tool.security]
action = "execute"
required_capabilities = [64]
namespace_visibility = "global"
approval_policy = "user"
sandbox_requirement = "required"
[tool.security.resource_extractor]
kind = "constant"
value = "grep"

[tool.parameters]
pattern = { type = "string", description = "Search pattern", required = true }
directory = { type = "string", description = "Directory to search", required = true }
```

The loader validates the schema and security contract before registering a
tool. A declaration whose constant extractor differs from `command` is rejected,
as are invalid, incomplete, or contradictory declarations.

## MCP Server Tools

Connect to an MCP-compatible tool server only after assigning a local security
contract to each discovered tool. MCP metadata is untrusted: tools without the
`agentosSecurity`, `agentosResourceType`, and `agentosOperation` extensions are
discoverable but registration fails closed. The declared resource type/action
pair must also agree. These extensions describe policy; they do not let the MCP
server grant capabilities, approvals, namespaces, or an unconfined gate.

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
