# Supported platforms and installation evidence

AI Agent OS installs as a user-space runtime on an existing host OS. Architecture
support does not qualify every machine, GPU, model, peripheral, or sandbox backend.
Remote providers require network access; on-device models have separate memory and
model qualification requirements.

## Published artifacts

As of 2026-10-08, the latest stable tag is `v0.3.0` and its GitHub release has
**no binary or desktop assets**. There is no published installer support promise.
The `v0.4.0-rc.1` source candidate remains unpublished. Its restricted Ubuntu 22.04
x86_64 profile is eligible only after the signed final-archive and Phase 1 evidence
described in [the Linux CLI RC guide](LINUX_CLI_RC.md) has passed.

## Candidate artifact matrix

These rows describe the two native matrices in `release.yml`, not published
products. `CI candidate` means native builds and deterministic fixture verification
are required; it does not mean a downloaded production installer has passed
clean-host installation, upgrade, failed update, rollback, or native signing.
The minimum versions below are candidate compatibility floors, not tested promises
for older host versions. CI records the exact runner OS in each retained report.

| Kind | Rust target | Candidate OS floor | Architecture | Formats | Support tier | Runtime dependencies |
| --- | --- | --- | --- | --- | --- | --- |
| CLI | `x86_64-unknown-linux-gnu` | Ubuntu 22.04; glibc 2.35+ | x86_64 | .zip | CI candidate | glibc; no GTK or WebKitGTK |
| CLI | `aarch64-unknown-linux-gnu` | Ubuntu 22.04; glibc 2.35+ | aarch64 (arm64) | .zip | CI candidate | glibc; no GTK or WebKitGTK |
| CLI | `x86_64-apple-darwin` | macOS 13.0+ | x86_64 (Intel) | .zip | CI candidate | macOS system libraries |
| CLI | `aarch64-apple-darwin` | macOS 13.0+ | aarch64 (Apple Silicon) | .zip | CI candidate | macOS system libraries; native arm64, no Rosetta |
| CLI | `x86_64-pc-windows-msvc` | Windows 11 build 22000+ | x86_64 | .zip | CI candidate | Windows system libraries |
| Desktop | `x86_64-unknown-linux-gnu` | Ubuntu 22.04; glibc 2.35+ | x86_64 | .deb, .AppImage | CI candidate; native signing and clean-host qualification pending | GTK 3 (`libgtk-3-0`), WebKitGTK 4.1 (`libwebkit2gtk-4.1-0`); Secret Service for credentials; FUSE 2 for normal AppImage launch |
| Desktop | `aarch64-unknown-linux-gnu` | Ubuntu 22.04; glibc 2.35+ | aarch64 (arm64) | .deb, .AppImage | CI candidate; native signing and clean-host qualification pending | GTK 3 (`libgtk-3-0`), WebKitGTK 4.1 (`libwebkit2gtk-4.1-0`); Secret Service for credentials; FUSE 2 for normal AppImage launch |
| Desktop | `x86_64-apple-darwin` | macOS 13.0+ | x86_64 (Intel) | .dmg, .app.tar.gz | CI candidate; Developer ID, notarization, and clean-host qualification pending | system WKWebView and Keychain |
| Desktop | `aarch64-apple-darwin` | macOS 13.0+ | aarch64 (Apple Silicon) | .dmg, .app.tar.gz | CI candidate; Developer ID, notarization, and clean-host qualification pending | system WKWebView and Keychain; native arm64, no Rosetta |
| Desktop | `x86_64-pc-windows-msvc` | Windows 11 build 22000+ | x86_64 | .msi, -setup.exe | CI candidate; Authenticode and clean-host qualification pending | WebView2 Evergreen runtime; Windows Credential Manager |

Linux archives and desktop bundles are built on Ubuntu 22.04 on their native CPU,
so the build does not raise the glibc floor by silently using `ubuntu-latest`.
macOS CLI builds and app bundles explicitly select the same 13.0 deployment floor.
Windows ARM64, Linux musl, 32-bit hosts, Android, iOS, and bare-metal boot images
are outside these matrices. Hardware resource sizing and real-provider task quality
remain separate from installability.

`scripts/verify_supported_platforms.py` rejects missing or extra documented rows,
duplicate targets, architecture/runner mismatches, format drift, and macOS floor
drift. Its negative regressions run in CI with the existing Python contract suite.

## Exact candidate names

For an exact tag `vX.Y.Z`, CLI archives are
`agentos-vX.Y.Z-TARGET.zip`, with `TARGET` taken verbatim from the table.
Each contains `agent`, `agent-server`, `agentctl`, and `agent-tui` (`.exe` on Windows).

Desktop names bind OS and architecture before any release assets are combined:

- `agentos-vX.Y.Z-desktop-linux-x86_64.deb` and `.AppImage`
- `agentos-vX.Y.Z-desktop-linux-aarch64.deb` and `.AppImage`
- `agentos-vX.Y.Z-desktop-macos-x86_64.dmg` and `.app.tar.gz`
- `agentos-vX.Y.Z-desktop-macos-aarch64.dmg` and `.app.tar.gz`
- `agentos-vX.Y.Z-desktop-windows-x86_64.msi` and `-setup.exe`

The same basename has `.cdx.json` for each CLI archive; desktop SBOMs use
`agentos-vX.Y.Z-desktop-PLATFORM.cdx.json`. Every candidate asset must be in
`SHA256SUMS`, have an adjacent `.sigstore.json`, and have GitHub provenance.
AppImage, Debian, app updater archive, MSI, and NSIS also require the adjacent
Tauri `.sig`. This updater signature is distinct from native platform signing.

## Verify a future published artifact

These commands deliberately require an exact published tag. They are not a way to
install today's source-only stable release. Restricted RCs must use the different
publication identity and additional reports in [LINUX_CLI_RC.md](LINUX_CLI_RC.md).
For a future stable release, install `gh`, `cosign`, and SHA-256 tools, then:

```bash
export AGENTOS_TAG=vX.Y.Z
mkdir "agentos-${AGENTOS_TAG}"
cd "agentos-${AGENTOS_TAG}"
gh release download "$AGENTOS_TAG" --repo surya-koritala/AIagentOS
sha256sum --check SHA256SUMS
# macOS without GNU coreutils: shasum -a 256 --check SHA256SUMS
```

Select the exact asset appropriate to the architecture; for example, Apple Silicon:

```bash
asset="agentos-${AGENTOS_TAG}-aarch64-apple-darwin.zip"
identity="https://github.com/surya-koritala/AIagentOS/.github/workflows/release.yml@refs/tags/${AGENTOS_TAG}"
for candidate in "$asset" SHA256SUMS; do
  cosign verify-blob --bundle "${candidate}.sigstore.json" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$candidate"
  gh attestation verify "$candidate" --repo surya-koritala/AIagentOS \
    --signer-workflow surya-koritala/AIagentOS/.github/workflows/release.yml \
    --source-ref "refs/tags/${AGENTOS_TAG}" --cert-identity "$identity" \
    --deny-self-hosted-runners
done
```

On Windows, use PowerShell for the checksum manifest and exact installer identity:

```powershell
$AgentOsTag = 'vX.Y.Z'
gh release download $AgentOsTag --repo surya-koritala/AIagentOS
Get-Content SHA256SUMS | ForEach-Object {
  if ($_ -notmatch '^([0-9a-f]{64})\s+\*?(?:\./)?([^/\\]+)$') { throw 'Invalid checksum row' }
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Matches[2]).Hash.ToLowerInvariant() -ne $Matches[1]) { throw 'Checksum mismatch' }
}
$Asset = "agentos-$AgentOsTag-desktop-windows-x86_64-setup.exe"
$Identity = "https://github.com/surya-koritala/AIagentOS/.github/workflows/release.yml@refs/tags/$AgentOsTag"
cosign verify-blob --bundle "$Asset.sigstore.json" --certificate-identity $Identity --certificate-oidc-issuer https://token.actions.githubusercontent.com $Asset
if ($LASTEXITCODE -ne 0) { throw 'Sigstore verification failed' }
gh attestation verify $Asset --repo surya-koritala/AIagentOS --signer-workflow surya-koritala/AIagentOS/.github/workflows/release.yml --source-ref "refs/tags/$AgentOsTag" --cert-identity $Identity --deny-self-hosted-runners
if ($LASTEXITCODE -ne 0) { throw 'GitHub provenance verification failed' }
if ((Get-AuthenticodeSignature -LiteralPath $Asset).Status -ne 'Valid') { throw 'Native Authenticode verification failed' }
```

Native signatures must pass separately before installing desktop bundles:

```bash
# macOS, after opening the matching DMG and copying AI Agent OS.app:
codesign --verify --deep --strict --verbose=2 '/Applications/AI Agent OS.app'
spctl --assess --type execute --verbose=2 '/Applications/AI Agent OS.app'
xcrun stapler validate '/Applications/AI Agent OS.app'
file '/Applications/AI Agent OS.app/Contents/MacOS/tauri-app'
# Apple Silicon must report arm64 only:
test "$(lipo -archs '/Applications/AI Agent OS.app/Contents/MacOS/tauri-app')" = arm64
```

Linux native detached GPG signing is still an open release prerequisite. No `.asc`
asset or trusted native key is currently published. When that prerequisite lands,
verify its published trusted fingerprint before running, for example:

```bash
asset="agentos-${AGENTOS_TAG}-desktop-linux-aarch64.AppImage"
test -f "${asset}.asc"
gpg --verify "${asset}.asc" "$asset"
```

A missing GPG signature, a rejected Gatekeeper assessment, or invalid Authenticode
signature is a stop condition, even if Sigstore and checksums pass. The current
stable publication gate remains closed until native identities and clean-host
install/upgrade/failure/rollback evidence exist for every promised platform.

## CI installation evidence

The native ARM workflow builds each CLI binary twice, compares every byte, checks
the Mach-O/ELF architecture, and archives a deterministic ZIP and CycloneDX SBOM.
A distinct fresh runner downloads those artifacts, checks their SHA-256 files,
extracts the final archive without Cargo, executes all five version entry points,
boots the installed server, rejects unauthenticated access, creates multiple
agents, and proves private storage survives server restart without leaking between
agents. Reports bind source SHA, archive digest, actual OS/CPU, and results.
This is keyless CI install evidence, not native signing or a published release
qualification. Paid providers and local models are not invoked.
