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
| Malicious package or custom/MCP tool understates its risk | Registration requires resource type, operation, action, individual known capabilities, a required string/constant extractor, namespace visibility, approval, and sandbox policy. Provider/action contradictions are rejected; remote MCP metadata has no implicit trust, and one invalid or conflicting discovery entry prevents the entire MCP batch from being published. |
| Compromised provider fabricates a tool name or arguments | Unknown names fail closed. The registered declaration, not the name supplied by the provider, drives authorization. |
| Path/URL tricks, alternate keys, non-string values, traversal, encoded separators | Each declaration names one typed resource extractor. Missing/wrong-type fields are denied; filesystem `.`/separator aliases are normalized and parent traversal is rejected before MAC, approval, and proof creation. Non-trusted filesystem operations are then executed relative to a kernel-owned directory capability, rather than reopening the authorized host pathname in a provider. |
| Symlink or rename changes a filesystem target after authorization | Non-trusted read/write/create/edit/delete/list operations use the retained workspace directory capability. Capability-relative resolution rejects escapes even when an ancestor is replaced after the broker's policy decision. |
| Allowlisted hostname resolves to local infrastructure or changes between policy and connect | The sandbox resolves all A/AAAA answers, rejects the request if any address is non-public, pins the validated addresses into a no-proxy HTTP client, permits only the scheme's default port, and disables redirects. |
| Untrusted command escapes into the server process | Filesystem sandboxes deny commands. Native `Process` mode is rejected as unsupported. Linux `Container` mode requires a rootless daemon and locally verified digest-pinned image, and applies network-none, read-only root, capability drop, `no-new-privileges`, PID/memory/CPU/output limits, and label-scoped cleanup. macOS and Windows reject container mode. |
| Outbound MCP configuration launches an ambient-authority host child | Direct host MCP launch is disabled. MCP tool declarations may still be published only through the validated registry; an outbound child must wait for an agent-bound isolated backend. |
| Confused deputy calls another agent's ID or tenant resource | The authenticated principal is retained for every wire request; tenant ownership is checked before dispatch and namespace/IPC checks apply again at the tool boundary. |
| Revoked or inconsistent identity retains authority | Credentials are re-resolved on every request against existing tenant/user records; unknown roles fail closed, and an owner-bound per-credential admission lease is held through dispatch. Session/key and overlapping user/tenant revocations share the same pending drain boundary. Revocation durably removes and closes the identity, then reports success only after every relevant admitted lease drains; a bounded timeout returns an explicit incomplete result without reopening the credential. |
| Remote listener exposes system authority or secrets in plaintext | Non-loopback TCP requires the system token plus TLS; the metrics listener is loopback-only unless an explicit insecure-development override is set. |
| Capability, policy, namespace, lifecycle, or quota race | Capability checks precede MAC. Final admission revalidates generation-bound agent registration, capabilities, cgroup membership, lifecycle admission, namespaces, tool tags, and MAC policy/labels/enforcing state before atomically reserving a hierarchical tool-call slot. Change-and-restore ABA mutations fail closed. The slot is held through the individual tool binding execution. LLM admission separately uses one durable provider/root/tenant/profile/agent receipt plus a membership-revision handshake through provider invocation. |
| Approval replay or scope confusion | Approval grants are local-operator only, exact to agent + tool + extracted resource + validated declaration, atomically consumed once after capability/MAC success, and purged when the agent is removed. Remote wire, SDK data, packages, prompts, and MCP metadata cannot mint them. |
| Policy/config downgrade | Production and in-memory constructors default to enforcing/default-deny. Permissive mode is an explicit local constructor/config setting that produces a security warning; no agent syscall can enable it. Fully unconfined construction is test-only. |

## Model-visible security metadata

The registry derives each LLM tool definition and its security-constraint
summary from the same validated `ToolBinding` used at authorization time. The
summary exposes only security classes needed for planning—resource type,
operation, action, capability IDs, approval class, sandbox requirement, and
namespace visibility. It never includes a constant resource value, credential,
approval token, host sandbox path, or policy contents. Operator-authored tool
descriptions and JSON schemas are model-visible and therefore must not contain
secrets.

This disclosure is advisory. A malicious prompt or compromised provider may
ignore it, invent a different tool name, alter arguments, or claim that approval
was granted. None of those statements changes the declaration resolved by the
registry or bypasses the kernel gate.

Policy action labels are the canonical values emitted by the typed
`SecurityAction` declaration (`exec`, `net`, `browser`, and so on), not
provider-operation names. Unknown labels fail policy loading, preventing a typo
such as `execute` from creating an apparently documented but unreachable rule.

## Canonicalization and delegation boundaries

MAC evaluates the declaration's typed extractor; filesystem targets first
receive platform lexical normalization and reject parent traversal so the gate,
approval contract, and immutable agent-request proof share one identity. It does
not treat model-supplied alternate keys, non-string values, or an MCP server's
claimed classification as equivalent. For non-trusted agents, the broker does
not delegate filesystem or HTTP authority to a provider: filesystem operations
use a retained directory capability, and HTTP uses validated, pinned DNS answers
with proxies and redirects disabled. Browser subresources, WebSockets, outbound
MCP children, untrusted peripherals, native process execution, and
macOS/Windows process/container isolation are outside the supported untrusted
runtime and fail closed.

Package code, MCP servers, and resource providers are potential deputies, not
authorization authorities. They receive only a call that already passed tenant
ownership, namespace, capability, MAC, approval, cgroup, and sandbox admission;
they must not accept a caller-supplied agent or tenant identity as a substitute
for the kernel-owned context.

## Residual risks and qualification work

The declaration contract does not by itself prove universal host isolation.
Capability-mediated filesystem/HTTP I/O and the hardened Linux rootless
container contract are implemented and public-API E2E qualified, including a
protected live rootless-container breakout/cancellation/crash-cleanup job.
Native process mode, direct host MCP launch, unisolated browser/peripheral
execution, and macOS/Windows process/container backends fail closed instead of
silently weakening the boundary. Approval lifecycle UX, credential brokering,
package signatures, broader provider isolation, side-effect cancellation/drain
guarantees, audit retention, and independent penetration testing remain tracked
by the canonical [capability registry](capabilities.toml) and issues #115, #119,
#121, #124, and #127. A capability must not be promoted beyond its evidence
while any of those limitations apply.
