# Signed Agent Packages

AI Agent OS distributes agents as signed `.agent` data archives. Packages never
load native code: they describe an agent, its prompts/assets, declared tools,
policy requirements, dependencies, and SBOM, then enter the same capability,
namespace, cgroup, sandbox, quota, and audit paths as any other agent.

The earlier standalone `agent.toml` loader remains available for trusted local
development. Production distribution uses the signed archive and tenant
registry described here.

## Archive format and verification

Format version 1 is a deterministic binary envelope around canonical JSON:

```text
magic | format | key-id length | publisher length | payload length
SHA-256 payload digest | Ed25519 signature | key id | publisher | payload
```

The payload contains:

- package name, semantic version, description, publisher, license, dependency
  requirements, required capabilities, and required tools;
- the validated `AgentManifest`;
- typed prompt, asset, and policy files with canonical relative paths and
  per-file SHA-256 checksums;
- an SPDX 2.3 component inventory.

Archives are not compressed. The parser rejects unknown format/schema versions,
truncated or trailing bytes, absolute/traversal/Windows-drive paths, duplicate
paths, duplicate dependencies, mismatched tool declarations, and size/count
overflow. Limits are 16 MiB per archive, 12 MiB for the payload, 1,024 files,
2 MiB per file, and 8 MiB across file contents.

Only the fixed-size envelope and bounded publisher/key identifiers are read
first. The kernel then:

1. looks up the key in the caller tenant's durable trust store;
2. checks its publisher, validity window, and revocation state;
3. verifies the SHA-256 payload digest;
4. verifies the Ed25519 signature over a domain-separated message;
5. parses and validates the payload.

Untrusted package content is never deserialized before steps 1–4 succeed.

## Publisher and registry lifecycle

Authenticated tenant administrators manage trust roots with
`trust_package_key` and `revoke_package_key`. Rotation links the old key to its
replacement; revocation immediately blocks fetch, install, and run
re-verification for artifacts signed by that key.

An authenticated publisher can publish only an archive whose signed publisher
matches its user identity. Registry records, archive bytes, trust roots,
installed state, lockfiles, rate-limit windows, mutation audit, and the
hash-chained publish/yank transparency log share the kernel SQLite durability
boundary. Normal database backup and restore therefore includes the complete
package state.

Published versions are immutable. A publisher or trusted system operator may
yank a version; yanked versions are excluded from fetch, dependency resolution,
rollback targets, and verified run, but remain in installed records and the
transparency/audit history for incident response.

All registry queries are tenant-scoped. Resolution never falls back to another
tenant or a similarly named global package.

## Resolution and transactions

Dependencies use semantic-version requirements. Resolution is deterministic:
the highest non-yanked matching version in the same tenant is selected,
dependency names are traversed in sorted order, and the resulting lockfile is
sorted by package name. Every locked entry includes its exact version and
SHA-256 archive digest.

Cycles, missing required dependencies, and incompatible requirements fail
without changing installed state. Optional dependencies are included only when
a matching tenant version exists.

Install and upgrade:

- re-verify every locked archive and current key status;
- enforce the operator's maximum profile, capability set, and optional tool
  allow-list;
- record the prior state;
- update dependencies and the root package in one `BEGIN IMMEDIATE` SQLite
  transaction.

Rollback restores the previous committed package snapshot. Remove refuses to
delete a required dependency. A crash or error before commit leaves no partial
installation.

## SDK flow

The public Rust SDK exposes the complete authenticated lifecycle:

```rust,no_run
use agent_sdk::{KernelClient, PackageArchive, PackageSigningKey};

# async fn example(
#     client: &mut KernelClient,
#     payload: agent_sdk::PackagePayload,
# ) -> Result<(), Box<dyn std::error::Error>> {
let (signer, _pkcs8_secret) =
    PackageSigningKey::generate("publisher-user-id", "release-2026")?;

client.trust_package_key(
    signer.publisher(),
    signer.key_id(),
    &signer.public_key(),
    "2026-01-01T00:00:00Z",
    None,
    None,
).await?;

let archive = PackageArchive::sign(payload, &signer)?;
client.publish_package(&archive).await?;
let fetched = client.fetch_package("researcher", "1.0.0").await?;
assert_eq!(fetched, archive);

client.install_package("researcher", "^1").await?;
let agent_id = client.run_installed_package("researcher").await?;
client.install_package("researcher", "^2").await?; // atomic upgrade
client.rollback_package("researcher").await?;
client.remove_package("researcher").await?;
# let _ = agent_id;
# Ok(())
# }
```

Secret PKCS#8 key material is returned only to the key-generation caller and is
never stored in the registry. Production publishers should place it in their
normal hardware-backed or managed signing service.

## Legacy manifest loading

`AgentManifest::from_toml_str`, `load_package`, and the wire/SDK `LoadPackage`
operation still accept a bounded unsigned manifest for trusted local workflows.
This path validates fields and tools, constrains tenant privilege, and rolls
back partial agent creation, but it does not establish provenance. Do not use it
as a software-distribution boundary.

## Qualification

Regression coverage includes deterministic hashing, invalid signatures,
tampering, traversal and oversize inputs, expired/revoked/rotated keys,
dependency cycles/conflicts/confusion, cross-tenant visibility, privilege
ceilings, concurrent installs, injected pre-commit crashes, restart durability,
and the full authenticated SDK publish-to-remove lifecycle.

Marketplace ratings and download counters are explicitly outside the v1 public
surface; the old in-memory `marketplace` experiment is not used for package
trust or ranking. Independent penetration testing and the final release
go/no-go remain tracked by issue #127.
