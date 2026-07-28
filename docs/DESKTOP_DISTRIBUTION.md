# Desktop distribution

The desktop client has a reproducible release foundation, but it is not yet a
publicly supported installer. The release workflow produces **qualification
artifacts only**:

| Platform | Qualification bundles | Production requirement still open |
| --- | --- | --- |
| Linux x86-64 | Debian package and AppImage, built on Ubuntu 22.04 | AppImage signing and supported-distribution install/upgrade evidence |
| macOS x86-64 | App bundle and DMG | Developer ID signing, notarization, stapling, and Gatekeeper install/upgrade evidence |
| Windows x86-64 | MSI and NSIS installer | Authenticode signing and clean-host install/upgrade evidence |

Every bundle is built from the production frontend, receives a CycloneDX SBOM,
is included in the release SHA-256 manifest, and is covered by the workflow's
keyless Sigstore signature and GitHub build provenance. Those supply-chain
proofs do not replace native platform signing.

## Version and asset contract

`scripts/verify_desktop_release.py` blocks drift between every workspace crate,
the Tauri configuration, the UI package and lockfile, and an optional `vX.Y.Z`
release tag. It also validates the checked-in multi-resolution PNG, ICO, and
ICNS assets generated from `crates/tauri-app/icons/app-icon.svg`.

Run it before packaging:

```bash
python3 scripts/verify_desktop_release.py
python3 scripts/verify_desktop_release.py --tag v0.3.0
```

The source SVG is the editable asset. Regenerate platform files with the pinned
Tauri CLI version used by `.github/workflows/release.yml`; do not hand-edit the
generated binaries.

## Fail-closed publication

A manual dispatch of `release.yml` qualifies unsigned native installers. A
public `v*` tag is deliberately rejected by `desktop-release-contract` until
all of the following are implemented and exercised against the exact release
candidate:

1. protected native signing identities for Linux, macOS, and Windows;
2. macOS notarization and stapling;
3. mandatory signed updater metadata and artifacts;
4. clean-host install, upgrade, failed-update, and rollback tests on every
   supported platform;
5. an explicit supported OS/architecture matrix and user-facing verification
   instructions.

Skipping or weakening that gate is not a release procedure. The remaining work
is tracked by issue #126.
