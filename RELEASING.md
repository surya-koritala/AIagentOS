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
2. **CI must be green** before merge: `cargo fmt --all -- --check`,
   `cargo clippy --workspace --exclude tauri-app -- -D warnings`,
   `cargo test --workspace --exclude tauri-app`. This is the "test frequently"
   floor — it runs on every PR, not just releases.
3. Keep the change mapped to a **roadmap item / the product wedge**. If a change
   doesn't serve *governed multi-agent execution* (or the product-shell that
   makes it adoptable), question whether it belongs now.

## Cutting a release

1. Pick the version per the rules above.
2. In `CHANGELOG.md`, move the `## [Unreleased]` content into a new
   `## [X.Y.Z] - YYYY-MM-DD` section (leave a fresh empty `Unreleased`).
3. Bump the version in every crate's `Cargo.toml` (`crates/*/Cargo.toml`); run
   `cargo build` so `Cargo.lock` updates.
4. Open a `chore/release-vX.Y.Z` PR; merge once green.
5. Tag the merged commit and push:
   ```bash
   git checkout main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
6. The [`release` workflow](.github/workflows/release.yml) takes over — see below.

## What a release must prove (the gate)

The tag triggers `.github/workflows/release.yml`, which **publishes only if all
of these pass** against the exact tagged commit:

1. **Quality gate** — fmt + clippy (`-D warnings`) + the full workspace test
   suite.
2. **Wedge acceptance** — the keyless `governance-demo` runs: violators are
   contained and audited, compliant agents keep working. If the product's one
   job regresses, the release is blocked.
3. **Container artifact** — the `agent-server` image builds, boots, and answers a
   real `{"op":"node_info"}` syscall round-trip.

Then it publishes a GitHub Release whose notes are the matching `CHANGELOG.md`
section.

This is how "are we building the right product?" gets enforced mechanically: a
release that can't contain a rogue agent or boot a server doesn't ship.

## Toward a stable API (the 1.0 bar)

`1.0.0` is gated on a **versioned, stable wire protocol**, and the mechanism for
it is now in place (as of v0.3.0):

- The protocol carries an explicit version, `kernel::syscall_server::PROTOCOL_VERSION`
  (currently **1**), versioned independently of the crate release. Bump it on any
  wire-breaking change (a removed/renamed variant or field); additive changes (a
  new optional syscall) don't.
- A client negotiates with the optional `Syscall::Hello { protocol_version }`
  handshake and learns the server's `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]`
  window. An out-of-range client — or one talking to a server too old to
  understand `Hello` — gets a clear `SdkError::IncompatibleProtocol` up front
  rather than a confusing failure on a later syscall.
- The SDK pins the version it was built against (re-exported `PROTOCOL_VERSION`)
  and exposes `KernelClient::hello()` to verify compatibility right after connect.

What remains for the 1.0 promise: a commitment to *hold* `PROTOCOL_VERSION`
stable across minors and to serve a real backward-compatibility window
(`MIN_PROTOCOL_VERSION < PROTOCOL_VERSION`) once we ship a second protocol
revision. Until 1.0, the protocol may still change between minors — bump
`PROTOCOL_VERSION` and note any wire-breaking change prominently in the
changelog entry.
