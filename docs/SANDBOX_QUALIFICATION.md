# Sandbox qualification

This is the supported isolation contract for untrusted agents. It deliberately
does not claim that every host integration is sandboxed.

## Supported boundary

| Surface | Untrusted-agent behavior | Evidence |
|---|---|---|
| Filesystem | A private, kernel-owned workspace directory capability; handle-relative I/O; synced atomic create/replace; strict UTF-8, path/content/list bounds; regular-file and final-symlink checks; byte quota; traversal/ancestor-rename denial; cross-agent isolation; teardown; and restart orphan reconciliation | `sandbox.rs`, `resources.rs`, `sandbox_props.rs`, `lifecycle_coordinator.rs` |
| HTTP(S) | Explicit hostname allowlist; credentials, fragments, and non-default ports denied; every A/AAAA answer must be public; checked addresses are pinned into a no-proxy, no-redirect client; URL, JSON body, response, nesting, and node counts are bounded | `sandbox.rs`, `resources.rs` |
| Linux process | One fresh digest-pinned container per call on a verified rootless Docker daemon; read-only root, no network, no capabilities, no-new-privileges, PID/CPU/memory/swap/open-file/output limits, bounded `tmpfs`, and only the agent workspace mounted writable | `docker_sandbox.rs`, protected `rootless-container-sandbox` workflow job |
| Raw wire, Rust SDK, package tools, custom tools, MCP server, and model executor | One immutable tool declaration and gate proof reaches the same `ResourceBroker`; the broker derives the sandbox from the kernel-owned agent identity before any provider runs | `sandbox_surfaces.rs` plus in-module executor/MCP/tool tests |

Every live agent receives a managed filesystem sandbox when an in-process
operator does not provide an explicit workspace. Even an explicitly trusted
agent performs filesystem tool calls through the retained directory capability
rooted at that workspace; trusted mode does not grant ambient host-file access.
Packages, prompts, MCP metadata, SDK requests, and wire requests cannot select
trusted mode or supply a valid gate proof/sandbox identity. The standalone
`resources::FilesystemProvider` advertises no operations and returns typed
unsupported errors because it cannot carry kernel-owned sandbox authority. The
standalone `resources::NetworkProvider` does the same because it cannot carry
the kernel's DNS, egress, lifecycle, or size-bound authority.

Filesystem text operations accept at most 4 MiB, paths at most 4,096 UTF-8
bytes, and directory listings at most 4,096 entries. Reads, edits, writes, and
deletes reject final symlinks and non-regular files. `create` never replaces an
existing entry; `write` and `edit` publish a synced same-directory staging file
with an atomic rename, preserve existing permissions, and sync the containing
directory on Unix. New files are private (`0600`) and new directories are
private (`0700`) on Unix. Listings are sorted, reject non-UTF-8 names, and
report each entry's file, directory, symlink, or other type. These limits are
part of the provider contract, not evidence that every host filesystem or
non-Unix directory-entry durability behavior has completed live production
qualification. Blocking filesystem workers own their admission permits until
the worker actually exits. Broker cancellation signals the worker, waits for a
bounded foreground drain, and leaves a reaper owning any still-running worker;
capability operations check cancellation before publication, deletion,
directory creation, and throughout quota/list scans. Rust cannot forcibly kill
a thread blocked inside a host filesystem syscall, so a stalled syscall may
retain one permit until the host call returns. It cannot cause the broker to
advertise that capacity as free, and sandbox teardown still waits on the same
operation lock.

HTTP URLs accept at most 4 KiB. JSON request bodies accept at most 1 MiB, 64
levels, and 65,536 values; responses accept at most 4 MiB and must be valid
UTF-8. Only `url` and, for `post`, `body` are accepted by the default agent
provider. Caller-supplied headers, credentials, cookies, filesystem
upload/download paths, WebSocket mode, and redirects are not supported and
fail before transport. These controls are deterministic contract evidence, not
the still-missing live target-egress and rebinding qualification in #124.

## Explicitly unsupported for untrusted agents

- Native host-process execution.
- macOS or Windows process/container execution.
- Direct outbound host MCP child processes.
- Browser automation without an isolated browser backend.
- Peripheral/computer-use operations without an explicit trusted operator
  profile.

These paths fail before provider invocation. They do not fall back to ambient
host execution. `IsolationLevel::Trusted` is an in-process operator boundary
for the explicitly supported non-filesystem surfaces, not a package or
remote-agent option and not an ambient filesystem bypass.

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
