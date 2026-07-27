# Sandbox qualification

This is the supported isolation contract for untrusted agents. It deliberately
does not claim that every host integration is sandboxed.

## Supported boundary

| Surface | Untrusted-agent behavior | Evidence |
|---|---|---|
| Filesystem | A private, kernel-owned workspace directory capability; handle-relative I/O, byte quota, traversal/symlink/rename-race denial, cross-agent isolation, teardown, and restart orphan reconciliation | `sandbox.rs`, `resources.rs`, `sandbox_props.rs`, `lifecycle_coordinator.rs` |
| HTTP(S) | Explicit hostname allowlist; credentials and non-default ports denied; every A/AAAA answer must be public; checked addresses are pinned into a no-proxy, no-redirect client | `sandbox.rs`, `resources.rs` |
| Linux process | One fresh digest-pinned container per call on a verified rootless Docker daemon; read-only root, no network, no capabilities, no-new-privileges, PID/CPU/memory/swap/open-file/output limits, bounded `tmpfs`, and only the agent workspace mounted writable | `docker_sandbox.rs`, protected `rootless-container-sandbox` workflow job |
| Raw wire, Rust SDK, package tools, custom tools, MCP server, and model executor | One immutable tool declaration and gate proof reaches the same `ResourceBroker`; the broker derives the sandbox from the kernel-owned agent identity before any provider runs | `sandbox_surfaces.rs` plus in-module executor/MCP/tool tests |

Every live agent receives a managed filesystem sandbox when an in-process
operator does not provide a narrower explicit configuration. Packages, prompts,
MCP metadata, SDK requests, and wire requests cannot select trusted mode or
supply a valid gate proof/sandbox identity.

## Explicitly unsupported for untrusted agents

- Native host-process execution.
- macOS or Windows process/container execution.
- Direct outbound host MCP child processes.
- Browser automation without an isolated browser backend.
- Peripheral/computer-use operations without an explicit trusted operator
  profile.

These paths fail before provider invocation. They do not fall back to ambient
host execution. `IsolationLevel::Trusted` is an in-process operator boundary,
not a package or remote-agent option.

## Live Linux qualification

The protected extended-security workflow starts an exact Docker Engine version
in rootless mode with the `cgroupfs` driver and pulls an immutable Alpine index
digest. Its ignored-by-default live test then:

1. verifies rootless daemon and local image digest checks;
2. checks zero effective capabilities, `NoNewPrivs`, read-only root, network
   denial, and private workspace write access;
3. cancels a long-running container and proves the labeled process/container is
   gone before the call returns; and
4. creates a simulated crash orphan and proves startup reconciliation removes
   its process, mount, and network namespace.

The test writes `target/qualification/rootless-sandbox-crash.json` only after
all live assertions pass. The workflow rejects an artifact unless it names the
exact clean checkout commit, the immutable image, the live-rootless
qualification class, all nine checks, and `production_claim_allowed: false`.
The artifact is retained for 90 days. A workflow definition is evidence
infrastructure, not a passing result: the relevant issue criterion can be
credited only to a successful exact-commit run whose artifact is available.

Ordinary CI retains deterministic contract tests on Linux, macOS, and Windows;
the live job is isolated because those platforms do not all provide a rootless
Linux daemon.

## Residual qualification

The capability registry records this boundary as `public-api-e2e`, not
`production-qualified`. Independent penetration testing and the v1
production-qualification decision are intentionally owned by roadmap issue
#127. A future backend must add its own live escape and cleanup evidence before
any unsupported surface above can be advertised for untrusted agents.
