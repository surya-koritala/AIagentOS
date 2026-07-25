# Releasing

How we tag what we ship, and how we keep building the right thing and testing it
often. The goal: every feature that lands is traceable to a versioned release,
and every release re-proves the product actually does its one job.

## Versioning

[Semantic Versioning](https://semver.org/). While pre-1.0:

- **`0.x.0` (minor)** — a shipped *feature batch* (the unit we cut releases at).
- **`0.x.y` (patch)** — fixes / hardening with no new surface.
- **`1.0.0`** — when the wire API (`syscall_server` protocol + SDK) carries a
  stability promise (see "Toward a stable API" below).

All workspace crates share one version number; bump them together.

## The discipline (per PR)

1. **Every PR adds a `CHANGELOG.md` entry under `## [Unreleased]`**, in the right
   group (Kernel/SDK/Providers/Scheduling/Memory/Security/Persistence/IPC/…),
   ending with its PR number. If a PR ships no user-visible change, say so in the
   PR body instead — don't pad the changelog.
2. **The `Required release gates` status must be green** before merge. It
   aggregates formatting, warning-free Rust/docs/desktop/frontend builds,
   deterministic tests on Linux/macOS/Windows, dependency policy, global and
   subsystem coverage floors, capability claims, and container startup,
   non-root, health, and persistence checks. Run `./scripts/ci-local.sh` for
   the host-compatible subset before pushing.
3. Keep the change mapped to a **roadmap item / the product wedge**. If a change
   doesn't serve *governed multi-agent execution* (or the product-shell that
   makes it adoptable), question whether it belongs now.

## Cutting a release

1. Pick the version per the rules above.
2. In `CHANGELOG.md`, move the `## [Unreleased]` content into a new
   `## [X.Y.Z] - YYYY-MM-DD` section (leave a fresh empty `Unreleased`).
3. Bump the version in every workspace crate and the exact `version =
   "=X.Y.Z"` constraint on each internal path dependency (including
   `fuzz/Cargo.toml`); run `cargo build` so `Cargo.lock` updates.
4. Open a `chore/release-vX.Y.Z` PR; merge once green.
5. Create a signed, annotated tag for the merged commit, verify it locally, and
   push it. Project policy treats published tags as immutable: never move or
   recreate one:
   ```bash
   git checkout main && git pull
   git tag -s vX.Y.Z -m "AI Agent OS vX.Y.Z"
   git tag -v vX.Y.Z
   git push origin vX.Y.Z
   ```
6. The [`release` workflow](.github/workflows/release.yml) takes over — see below.

## What a release must prove (the gate)

Before tagging, manually dispatch `.github/workflows/release.yml` on the release
branch. This qualification mode creates the complete signed evidence bundle but
cannot publish a GitHub Release. A `v*` tag runs the same workflow and
**publishes only if all of these pass** against the exact tagged commit:

1. **Full required CI** — the same release-blocking workflow used by protected
   pull requests, including all three operating systems and the desktop,
   frontend, supply-chain, coverage, and container gates.
2. **Wedge acceptance** — the keyless `governance-demo` runs: violators are
   contained and audited, compliant agents keep working. If the product's one
   job regresses, the release is blocked.
3. **Reproducible platform binaries** — Linux, macOS, and Windows CLI, server,
   and TUI binaries are built twice in isolated target directories and must be
   byte-for-byte identical before deterministic archives are accepted.
4. **Container qualification** — the pinned-base, non-root `agent-server` image
   builds, boots, answers a real `{"op":"node_info"}` syscall round-trip, and
   retains kernel agent storage across restart.
5. **Supply-chain evidence** — each platform archive has a CycloneDX SBOM, the
   container has an SPDX SBOM, every asset appears in `SHA256SUMS`, and assets
   are keyless-signed with Sigstore and covered by GitHub build provenance.

Only then does the workflow publish a GitHub Release whose notes are the matching
`CHANGELOG.md` section. Verify a downloaded release with:

```bash
sha256sum --check SHA256SUMS
cosign verify-blob \
  --bundle agentos-vX.Y.Z-x86_64-unknown-linux-gnu.zip.sigstore.json \
  --certificate-identity-regexp 'github.com/surya-koritala/AIagentOS' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  agentos-vX.Y.Z-x86_64-unknown-linux-gnu.zip
gh attestation verify agentos-vX.Y.Z-x86_64-unknown-linux-gnu.zip \
  --repo surya-koritala/AIagentOS
```

This is how "are we building the right product?" gets enforced mechanically: a
release that can't contain a rogue agent or boot a server doesn't ship.

## Repository merge policy

`main` must require pull requests, at least one approving review, conversation
resolution, and the `Required release gates` status. Force-pushes and branch
deletion are blocked. Repository administrators retain an emergency bypass;
using it for an ordinary merge violates release policy and must be documented
as an incident. Secret-backed provider qualification is not part of
deterministic PR CI. The manual `Live provider qualification` workflow runs one
governed OpenAI turn using the protected `provider-qualification` environment;
the broader provider/tool/streaming matrix remains tracked separately.

## Toward a stable API (the 1.0 bar)

`1.0.0` is gated on a **versioned, stable wire protocol**. The negotiation
mechanism shipped in v0.3.0 with protocol version 1. The current unreleased tree
adds version 2 while continuing to serve versions 1 through 2:

- The protocol carries an explicit version, `kernel::syscall_server::PROTOCOL_VERSION`
  (currently **2** in the unreleased tree, serving **1..=2**), versioned
  independently of the crate release. Bump it on any
  wire-breaking change (a removed/renamed variant or field); additive changes (a
  new optional syscall) don't.
- A client negotiates with the optional `Syscall::Hello { protocol_version }`
  handshake and learns the server's `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]`
  window plus fine-grained feature identifiers. An out-of-range client — or one talking to a server too old to
  understand `Hello` — gets a clear `SdkError::IncompatibleProtocol` up front
  rather than a confusing failure on a later syscall.
- The SDK pins the version it was built against (re-exported `PROTOCOL_VERSION`)
  and negotiates automatically on connect; `KernelClient::hello()` remains
  available for explicit inspection.
- `Syscall::DescribeProtocol` publishes draft-2020-12 request/reply/MCP schemas,
  compatibility behavior, and framing/deadline/connection bounds before auth.
- Golden fixtures under `protocol/` retain the released v1 shape and current v2
  contract; exhaustive authorization tests also prove all request operations
  appear exactly once in the published schema.

Version 1 keeps the released prose-only error reply. Version 2 adds stable typed
error categories and a retry hint; a connection that omits `Hello` stays on v1.
The compatibility/deprecation rules and current non-streaming limitation are
documented in `docs/PROTOCOL.md`. Until 1.0, any wire-breaking minor must bump
`PROTOCOL_VERSION`, retain the immediately previous window and fixtures unless
retirement is explicit, and call out the migration in the changelog.
