# Desktop distribution

The desktop client has a reproducible release and signed-updater foundation,
but it is not yet a publicly supported installer. The release workflow produces
**qualification artifacts only** and now fails closed unless the protected
Tauri updater signing identity is available:

| Platform | Qualification bundles | Production requirement still open |
| --- | --- | --- |
| Linux x86-64 | Debian package and AppImage, built on Ubuntu 22.04 | Native package/AppImage signing and supported-distribution install/upgrade evidence |
| macOS x86-64 | App bundle and DMG | Developer ID signing, notarization, stapling, and Gatekeeper install/upgrade evidence |
| Windows x86-64 | MSI and NSIS installer | Authenticode signing and clean-host install/upgrade evidence |

Every bundle is built from the production frontend, receives a CycloneDX SBOM,
is included in the release SHA-256 manifest, and is covered by the workflow's
keyless Sigstore signature and GitHub build provenance. Those supply-chain
proofs do not replace native platform signing.

## Signed updater contract

The desktop embeds a Tauri minisign public key and checks one HTTPS endpoint:
`https://github.com/surya-koritala/AIagentOS/releases/latest/download/latest.json`.
The private key and its password are never stored in the repository. Release
jobs require `TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` from protected GitHub Actions secrets;
missing values stop the build before packaging.

Tauri creates updater artifacts and `.sig` files for the Debian, AppImage,
macOS app, MSI, and NSIS formats. `scripts/build_desktop_update_manifest.py`
then creates a strict static manifest for tagged builds. It requires exactly one
artifact/signature pair for every supported installer type, embeds signature
contents rather than paths, binds download URLs to the exact `vX.Y.Z` tag, and
rejects malformed signatures, ambiguous assets, non-SemVer versions, and tag
drift. A real Tauri-signed fixture proves the checked-in public key accepts the
expected bytes and rejects tampering.

The Settings screen checks update metadata without exposing the updater plugin
directly, bounds all data crossing IPC, and requires a second confirmation
naming the exact version. Installation rechecks that version, prevents
concurrent installs, downloads only over the configured HTTPS endpoint, and
lets Tauri verify the mandatory signature before native installation. A version
change between review and installation is rejected.

This is not rollback qualification. Operators must retain the prior signed
installer; automatic downgrade is not enabled. Clean-host install, upgrade,
failed-update, and operator-led rollback evidence remains required for every
supported platform.

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

A manual dispatch of `release.yml` qualifies updater-signed but native-unsigned
installers only when the protected updater identity is provisioned. A public
`v*` tag is deliberately rejected by `desktop-release-contract` until all of
the following are implemented and exercised against the exact release candidate:

1. protected native signing identities for Linux, macOS, and Windows;
2. macOS notarization and stapling;
3. clean-host install, upgrade, failed-update, and rollback tests on every
   supported platform;
4. an explicit supported OS/architecture matrix and user-facing verification
   instructions.

Skipping or weakening that gate is not a release procedure. The remaining work
is tracked by issue #126.
