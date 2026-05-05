# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT** open a public issue
2. Email: surya.koritala@gmail.com (or use GitHub's private vulnerability reporting)
3. Include: description, steps to reproduce, potential impact

We will respond within 48 hours and work with you on a fix.

## Security Considerations

### API Keys
- API keys are stored in `~/.config/ai-agent-os/config.toml`
- The config file is NOT committed to git (in `.gitignore`)
- Keys are never logged or exposed in error messages

### Agent Sandbox
- Agents are sandboxed by default (filesystem isolation)
- Path traversal attacks are prevented via canonicalization
- Network access is restricted to allowlisted hosts
- High-risk operations (delete, execute) require explicit approval

### Permissions
- Default profile is "standard" (read/write, no destructive ops)
- All actions are audit-logged with timestamps
- Permission elevation requires user approval

### WASM Modules
- Modules run in Wasmtime sandbox with resource limits
- Module crashes are isolated (don't affect other agents)
- Manifest validation before installation
