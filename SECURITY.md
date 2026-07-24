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
- Every live agent receives a mandatory sandbox identity. Non-trusted
  filesystem operations execute relative to a kernel-owned workspace directory
  capability with private ownership and byte quotas; providers do not reopen
  authorized host path strings.
- HTTP egress is allowlisted, DNS answers are rejected if any address is
  non-public, validated addresses are pinned for the connection, ambient
  proxies and redirects are disabled, and only default HTTP(S) ports are used.
- Native process mode, direct host MCP launch, and unisolated browser execution
  fail closed. Linux container mode requires a rootless daemon and a locally
  verified digest-pinned image with hardened run flags. The protected extended
  security workflow exercises capability removal, read-only root, network
  denial, cancellation cleanup, and crash-orphan reconciliation against a live
  rootless daemon.
- macOS and Windows process/container isolation, untrusted browser/peripheral
  execution, and outbound MCP children are explicitly unsupported and fail
  closed. The project claims the narrower support contract documented in
  [docs/SANDBOX_QUALIFICATION.md](docs/SANDBOX_QUALIFICATION.md), not universal
  host isolation. Independent penetration testing remains a v1 gate in #127.
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
