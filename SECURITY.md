# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT** open a public issue
2. Email: surya.koritala@gmail.com (or use GitHub's private vulnerability reporting)
3. Include: description, steps to reproduce, potential impact

We will respond within 48 hours and work with you on a fix.

## Security Considerations

### API Keys
- Provider credentials may come from process environment variables or local
  configuration, depending on the entry point.
- `config.toml` and `.env` files are git-ignored, but local configuration is not
  an encrypted credential vault. Production credential brokering, at-rest
  encryption, and rotation remain open roadmap work.
- Code must not deliberately log credentials. Redaction and leakage resistance
  are CI/review requirements, not an independently audited guarantee yet.

### Agent Sandbox
- Every live agent receives a mandatory sandbox policy. Filesystem paths are
  canonicalized against a per-agent workspace and network hosts are allowlisted.
- This is a load-bearing policy boundary, not complete OS-level process or
  container isolation on every platform. Host process/peripheral operations
  fail closed for untrusted sandbox levels.
- High-risk operations require the capabilities/approval declared by the tool
  contract; an explicitly trusted operator profile can carry broader authority.

### Permissions
- Default profile is "standard" (read/write, no destructive ops)
- Governed tool decisions are audit-logged with timestamps
- Permission elevation requires user approval

### WASM Modules
- The standalone Wasmtime module prototype is explicitly deferred from the v1
  runtime. It is not registered by `AgentKernelImpl` or exposed by the public
  wire API.
- Fuel/trap handling and basic manifest validation exist, but modules are
  unsigned and experimental host imports do not pass through the kernel gate or
  sandbox. Do not load untrusted Wasm modules.
# Threat model

The tool-execution trust boundaries, attacker classes, and required controls are
documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
