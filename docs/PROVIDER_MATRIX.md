# Resource provider matrix

This is the explicit v1 status of every resource-provider implementation and
operation in the workspace. The status is provider-specific; “E2E verified”
does not mean production-qualified.

| Provider / authority | Operations | Status | Platform contract | Supported boundary and remaining gap |
|---|---|---|---|---|
| Kernel `BuiltinFilesystemProvider` metadata + capability backend | `read`, `write`, `create`, `create_dir`, `edit`, `delete`, `list` | **E2E verified** | **Linux; macOS; Windows** | Agent calls execute only through the retained workspace directory capability. Atomicity, permissions, symlink/special-file rejection, UTF-8/path/content/list bounds, quota, cancellation ownership, cross-agent isolation, teardown, and public call-path parity are tested. Live deployment-filesystem and independent security evidence remain open in #124/#127. |
| Kernel `BuiltinNetworkProvider` + pinned HTTP backend | `get`, `post`, `browse` | **E2E verified** | **Linux; macOS; Windows** | Non-trusted agents require an allowlisted host, public-only complete DNS answer set, pinned no-proxy/no-redirect client, default HTTP(S) port, strict parameter shape, bounded URL/JSON request/UTF-8 response, and broker timeout. Headers, credentials, cookies, upload/download paths, WebSocket, redirects, and fragments are unavailable. Exact-commit Linux qualification exercises a controlled public route, ambient proxy, redirect, private sentinel, and mid-request DNS rebinding; independent review remains open in #127. |
| Kernel `BuiltinAppProvider` metadata + process backend | `launch` | **E2E verified** | **Linux host; digest-pinned Alpine container** | Agent launch is supported only through the qualified Linux rootless digest-pinned container contract. The schema accepts bounded literal `command`/`args` only; cwd is fixed to `/workspace`, no caller/host environment or stdin is forwarded, execution is limited to 30 seconds, and each strict-UTF-8 output stream is limited to 1 MiB. The metadata provider cannot launch an ambient host process. Native/trusted host process mode, host-application control, arbitrary container images, and macOS/Windows container execution are unavailable. |
| Kernel `IpcResourceProvider` | `send`, `receive`, `delegate`, `delegation_status`, `complete_delegation`, `discover` | **E2E verified** | **Linux; macOS; Windows** | Namespace, tenant, lifecycle, capability, quota, and public client parity are tested. This is in-process agent IPC, not host IPC or a device provider. |
| Kernel browser provider | `navigate`, `click`, `type`, `read` | **Experimental — unavailable** | **None — unavailable** | No default browser provider is registered on any platform. Untrusted calls fail before provider invocation because no isolated profile/download/secret/cleanup backend is qualified. |
| Kernel peripheral provider | capture, audio, print, and other device operations | **Experimental — unavailable** | **None — unavailable** | No default peripheral provider is registered on any platform. Untrusted calls fail closed; trusted operator grants, indicators, revocation, and platform implementations remain open. |
| Standalone `FilesystemProvider` (`resources` crate) | all former filesystem operations | **Experimental — unavailable** | **None — unavailable** | Advertises no operations and returns typed `UnsupportedOperation`; it has no kernel sandbox identity. |
| Standalone `NetworkProvider` (`resources` crate) | `get`, `post`, `put`, `delete`, `browse` | **Experimental — unavailable** | **None — unavailable** | Advertises no operations and returns typed `UnsupportedOperation`; it cannot enforce kernel DNS, egress, lifecycle, or bounds. |
| Standalone `ApplicationProvider` (`resources` crate) | all former application operations | **Experimental — unavailable** | **None — unavailable** | Advertises no operations and returns typed `UnsupportedOperation`; it has no kernel sandbox identity or container lifecycle authority. |
| Standalone `PeripheralProvider` (`resources` crate) | capture, audio, print, and other device operations | **Experimental — unavailable** | **None — unavailable** | Advertises no operations and returns typed `UnsupportedOperation`; it has no human/operator grant authority. |
| Feature-gated HTML/playwright helpers | browse/search/navigation helper functions | **Experimental** | **Trusted operator process; feature-dependent** | These are direct trusted-application helpers, not `ResourceProvider` implementations and not runtime discovery entries. They are excluded from the v1 runtime support promise and do not substitute for the kernel network or browser boundary. |

No provider is currently **Production-qualified**. Promotion requires the
provider’s remaining #124 criteria, target-platform/live-path evidence, and
the independent #127 security and release review. Runtime discovery remains
authoritative for what an agent can call; empty or absent providers are not
advertised.
