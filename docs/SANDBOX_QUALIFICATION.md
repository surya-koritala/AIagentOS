# Sandbox qualification

This is the supported isolation contract for untrusted agents. It deliberately
does not claim that every host integration is sandboxed.

## Supported boundary

| Surface | Untrusted-agent behavior | Evidence |
|---|---|---|
| Filesystem | A private, kernel-owned workspace directory capability; handle-relative I/O; synced atomic create/replace; strict UTF-8, path/content/list bounds; regular-file and final-symlink checks; byte quota; traversal/ancestor-rename denial; cross-agent isolation; teardown; and restart orphan reconciliation | `sandbox.rs`, `resources.rs`, `sandbox_props.rs`, `lifecycle_coordinator.rs` |
| HTTP(S) | Explicit hostname allowlist; credentials, fragments, and non-default ports denied; every A/AAAA answer must be public; checked addresses are pinned into a no-proxy, no-redirect client; URL, JSON body, response, nesting, and node counts are bounded | `sandbox.rs`, `resources.rs` |
| Linux process | One fresh digest-pinned container per call on a verified rootless Docker daemon; strict bounded literal argv; fixed `/workspace` cwd; no caller environment/stdin; 30-second timeout; strict-UTF-8 output bounds; read-only root, no network, no capabilities, no-new-privileges, PID/CPU/memory/swap/open-file limits, bounded `tmpfs`, and only the agent workspace mounted writable | `docker_sandbox.rs`, protected `rootless-container-sandbox` workflow job |
| Raw wire, Rust SDK, package tools, custom tools, MCP server, and model executor | One immutable tool declaration and gate proof reaches the same `ResourceBroker`; the broker derives the sandbox from the kernel-owned agent identity before any provider runs | `sandbox_surfaces.rs`, including a wiremock-backed LLM tool-call and recovery round, plus in-module executor/MCP/tool tests |

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
The standalone `resources::ApplicationProvider` and the kernel metadata
provider also cannot launch a host process; application execution is dispatched
only to the container backend for a container-isolated sandbox.

Before any provider runs, the resource broker bounds the operation name and
the JSON request envelope. It applies the same depth, node, individual-string,
and aggregate-string bounds to successful provider output before returning it,
and replaces oversized provider error diagnostics with a fixed non-sensitive
error. These provider-independent controls sit outside the stricter
filesystem, HTTP, and application contracts below. Admission queues,
per-resource concurrency, admission wait, and execution time are also bounded.

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
fail before transport. The controlled live Linux qualification below proves
that target pinning, no-proxy transport, redirect refusal, SSRF rejection, and
DNS-rebinding rejection hold during real socket I/O.

Application launch accepts only `command` and `args`. Commands are limited to 4
KiB; there may be at most 1,024 arguments, each at most 64 KiB and at most 1 MiB
combined. Caller environment, cwd, stdin, shell mode, timeout overrides, and
output-limit overrides fail before container execution. The backend passes argv
directly without an implicit shell, fixes cwd to `/workspace`, forwards no
caller or host environment, applies a 30-second timeout, and limits stdout and
stderr independently to 1 MiB of valid UTF-8. Cancellation and timeout remove
the exact container, which includes its process tree.

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

## Live network qualification

The protected extended-security workflow creates a controlled Linux egress
topology with a public-looking loopback address, a private sentinel, an ambient
HTTP proxy pointed at that sentinel, and a hostname whose answer changes from
public to private during the request. Its ignored-by-default live test proves:

1. the permitted request reaches the pinned public address without using the
   ambient proxy;
2. an HTTP redirect is returned to the caller but is not followed;
3. the DNS change cannot redirect the in-flight connection to the private
   sentinel;
4. a subsequent private DNS answer is rejected before a connection; and
5. metadata SSRF, URL credentials, fragments, and non-default ports fail before
   transport.

The test writes `target/qualification/network-egress.json` only after all live
assertions pass. The workflow rejects evidence unless it names the exact clean
checkout commit, the `live_linux_network_egress` qualification class, the
configured ambient proxy, all ten checks, and
`production_claim_allowed: false`. The retained
`network-egress-<commit>` artifact expires after 90 days.

## Live Linux qualification

The protected extended-security workflow starts an exact Docker Engine version
in rootless mode with the `cgroupfs` driver and pulls an immutable Alpine index
digest. Its ignored-by-default live test then:

1. verifies rootless daemon and local image digest checks;
2. checks zero effective capabilities, `NoNewPrivs`, read-only root, network
   denial, and private workspace write access;
3. passes shell metacharacters as a literal argv value and proves no implicit
   shell evaluates them;
4. exceeds the stdout ceiling and proves the call fails closed while removing
   its container;
5. cancels a long-running container and proves the labeled process/container is
   gone before the call returns; and
6. creates a simulated crash orphan and proves startup reconciliation removes
   its process, mount, and network namespace.

The test writes `target/qualification/rootless-sandbox-crash.json` only after
all live assertions pass. The workflow rejects an artifact unless it names the
exact clean checkout commit, the immutable image, the live-rootless
qualification class, all twelve checks, and
`production_claim_allowed: false`.
The artifact is retained for 90 days. A workflow definition is evidence
infrastructure, not a passing result: the relevant issue criterion can be
credited only to a successful exact-commit run whose artifact is available.

Ordinary CI retains deterministic contract tests on Linux, macOS, and Windows;
the live job is isolated because those platforms do not all provide a rootless
Linux daemon.

## Combined provider security evidence

The same protected workflow executes exact kernel tests for atomic/private
filesystem behavior, symlink-swap races, cross-agent denial, provider panic
isolation, generic request/response bounds, cross-surface sandbox parity, and
the explicitly unavailable kernel browser surface. It also installs the
lockfile-pinned Chromium revision and runs the trusted helper against a
disposable local fixture, proving unique profiles, cross-profile cookie
isolation, URL and typed-input secret redaction, download denial, bounded
screenshot output, process reaping, and removal of both profiles. A fail-closed collector
accepts each check only when its log contains the named Rust test's passing
event and an exact one-test successful harness result. It hashes every retained
log and refuses dirty source trees, missing tests, duplicate checks, malformed
commits, non-UTF-8 evidence, and oversized logs.

The final job downloads the exact-commit rootless, network, and core artifacts,
rejects a missing, failed, dirty, or mismatched component, hashes each component
report, and derives a combined artifact. The combined checks cover literal-argv
injection, traversal/symlink races, metadata SSRF, redirects, DNS rebinding,
large output, hung-process cleanup, live browser-profile isolation and cleanup,
kernel-browser de-scope, cross-agent
access, provider panic, generic envelopes, and cross-surface policy. The
artifact remains `production_claim_allowed: false`; it is proof of the
restricted live-provider suite, not a substitute for independent review.

## Residual qualification

The capability registry records this boundary as `public-api-e2e`, not
`production-qualified`. Independent penetration testing and the v1
production-qualification decision are intentionally owned by roadmap issue
#127. A future backend must add its own live escape and cleanup evidence before
any unsupported surface above can be advertised for untrusted agents.
