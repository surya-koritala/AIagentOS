# macOS native process isolation status

Native untrusted process execution remains unavailable. The supported macOS
filesystem, network, model, and operator-client surfaces do not imply that
arbitrary host processes have a qualified isolation boundary.

Issue #335 asks for the Linux container contract using a maintained native
mechanism. Apple marks `sandbox_init` unsupported and describes custom Seatbelt
profiles as unsupported for third-party products. The maintained App Sandbox
uses signed app bundles and entitlements; an inherited helper shares the
parent's static rights. A code signature by itself does not prove per-agent
isolation or distribution qualification. See [Apple's sandbox guidance](https://developer.apple.com/forums/thread/661939),
[supported helper packaging](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app),
and [App Sandbox file access](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox).

## Actual hosted observations

The [native ARM64 and Intel CI probe](https://github.com/surya-koritala/AIagentOS/actions/runs/37806264875)
ran clean source `bc9a7840f28350f63f944c0309978f0635fa1b77` on macOS 26.6.2
ARM64 and macOS 26.6.1 Intel. It compiled a disposable fixture, checked positive
unsandboxed controls, packaged an app bundle, applied only documented App
Sandbox entitlements, verified its ad-hoc fixture signature, and made actual
syscalls. The outside fixtures lived below globally traversable `/private/tmp`;
private and public files used modes `0600` and `0644`. The signed fixture used
an explicit workspace grant and an empty caller environment.

Both architectures produced the same control results:

| Tested control | Observation |
|---|---|
| Private workspace read/write | Allowed |
| Controlled outside public/private file reads and outside writes | Denied with `EPERM` |
| Symlink and `..` reads of those outside fixtures | Denied with `EPERM` |
| Controlled loopback connection | Denied with `EPERM`; listener accepted no connection |
| Raw socket descriptor creation | Allowed; connection denial is not socket-creation denial |
| Runtime temporary-file write outside the workspace | Allowed |
| Fork followed by `setsid` | Allowed; the child can leave the original process group |
| Undeclared `/usr/bin/true` execution | Allowed |
| Requested `RLIMIT_AS` of 64 MiB | Rejected with `EINVAL`; no memory-limit credit |
| File-descriptor limit of 16 | Enforced with `EMFILE` after 13 additional opens |
| `RLIMIT_NPROC` zero | Fork denied; this is a real-UID count, not an aggregate agent boundary |

The retained reports contain exact source and binary hashes, architecture and
OS version, actual operation outcomes, and explicit false values for
`backend_enabled`, `native_process_contract_qualified`, and
`production_claim_allowed`. A green probe job means the observations were
collected correctly. It does not mean a native execution backend is qualified.
The initial standalone signed fixture could not start on Intel; correct app
packaging was necessary before any isolation behavior could be measured.

Apple's [current resource-limit implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_resource.c)
validates address-space limits against current mapping usage and counts
processes by real user identity. The observed failed memory setting cannot be
silently ignored, and a user-wide count cannot be relabeled as per-agent limits.

## Remaining design decision

App Sandbox alone does not satisfy the requested workspace-only writes,
declared executable boundary, process-family ownership/cleanup, or the tested
memory setting. Killing one process group cannot establish complete cleanup
when a child can leave that group. This probe has not qualified aggregate
agent CPU/memory/PID limits, cancellation, 30-second overrun cleanup, crash
reconciliation, workspace identity races, IPC restrictions, or output/UTF-8
limits through the kernel, gate, and broker.

A supported per-agent VM or a separately designed helper boundary needs an
explicit design decision and complete target proof. App Sandbox inheritance
cannot attenuate an already broad parent sandbox into a private agent boundary.
No temporary directory grant, process-group wrapper, approximate resource
monitor, private Seatbelt profile, or trusted-host fallback is enabled here.
Issue #335 and the production qualification owner #127 remain open.

The probe is CI-only, uses disposable ad-hoc signing without protected keys,
and does not call a model, alter the desktop signing configuration, publish a
release, or change the runtime's fail-closed behavior.
