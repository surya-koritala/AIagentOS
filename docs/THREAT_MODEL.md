# AI Agent OS threat model

This document defines the security boundary for tool execution. The model or
provider is never an authorization authority: every tool call is treated as
untrusted input and must pass tenant ownership, a validated tool declaration,
capabilities, namespace visibility, MAC policy, cgroup limits, approval policy,
the resource broker, and (where declared) a sandbox.

## Assets and trust boundaries

- Host files, credentials, processes, browsers, network access, persisted agent
  state, tenant data, package contents, and resource budgets are protected assets.
- Local operators and code-reviewed kernel policy are trusted administrative
  inputs. Prompts, model output, remote providers, agent packages, MCP servers,
  custom-tool files, wire clients, resource strings, and tool arguments are not.
- Authenticated users are still restricted to their tenant and role. Knowledge
  of an agent UUID is not authority to read or mutate it.

## Wire caller modes

- A loopback-only open TCP listener or a Unix-domain socket is a trusted local
  system/operator boundary. Calls have system authority; socket access and any
  local proxy therefore become part of the trusted computing base.
- `AGENT_SERVER_TOKEN` authenticates a trusted system/operator caller. It is not
  a tenant credential and intentionally retains system authority.
- Tenant API keys and sessions resolve to a user, tenant, role, and hashed
  credential identity. The server re-resolves them for every call, holds the
  authorization boundary through dispatch, and makes revocation durable.

Non-loopback TCP startup fails closed unless both the system shared secret and
TLS certificate/key are configured. The development-only
`AGENT_SERVER_ALLOW_INSECURE_REMOTE=1` override must be protected by an external
trusted network boundary. Tenant credentials do not turn an open server into an
unscoped caller: once presented, that connection remains tenant-scoped and a
revoked credential cannot fall back to system authority.

## Required controls by threat

| Threat | Required control |
|---|---|
| Malicious or injected prompt asks for a dangerous tool | The LLM can request but cannot grant capabilities. The binding's typed action/capabilities, MAC policy, approval requirement, and sandbox are enforced outside the model. |
| Malicious package or custom/MCP tool understates its risk | Registration requires a complete security contract and rejects missing capabilities, extractors, high-risk approval, or sandbox declarations. Remote MCP metadata has no implicit trust. |
| Compromised provider fabricates a tool name or arguments | Unknown names fail closed. The registered declaration, not the name supplied by the provider, drives authorization. |
| Path/URL tricks, alternate keys, non-string values, traversal, encoded separators | Each declaration names one typed resource extractor. Missing/wrong-type fields are denied; the exact extracted string is sent to MAC and the downstream sandbox/provider also validates canonical boundaries. |
| Confused deputy calls another agent's ID or tenant resource | The authenticated principal is retained for every wire request; tenant ownership is checked before dispatch and namespace/IPC checks apply again at the tool boundary. |
| Revoked or inconsistent identity retains authority | Credentials are re-resolved on every request against existing tenant/user records; unknown roles fail closed, revocation is durable, and the auth read lock is held through dispatch so completed revocation has no execution window. |
| Remote listener exposes system authority or secrets in plaintext | Non-loopback TCP requires the system token plus TLS; the metrics listener is loopback-only unless an explicit insecure-development override is set. |
| Capability or quota race | Capability checks precede MAC and atomically reserved hierarchical cgroup tool-call slots are held through provider execution. |
| Policy/config downgrade | Production config defaults to enforcing/default-deny. Permissive mode is a local operator setting that produces a security warning; no agent syscall can enable it. Unconfined execution constructors are test-only. |

## Residual risks and qualification work

The declaration contract does not by itself prove host isolation. Mandatory
host-enforced sandboxes, approval lifecycle UX, canonical path/URL validation,
credential brokering, package signatures, audit retention, and penetration
testing remain tracked by the canonical [capability registry](capabilities.toml)
and issues #108, #111, #115, #121, #124, and #127. A capability must not be
promoted beyond its evidence while any of those limitations apply.
