import base64
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from build_desktop_update_manifest import ManifestError, build_manifest
from collect_desktop_assets import FORMATS, asset_name


SIGNATURE = base64.b64encode(
    b"untrusted comment: signature from tauri secret key\nfixture-signature\n"
).decode("ascii")


class DesktopUpdateManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.dist = Path(self.temporary.name)
        for name in [
            asset_name("v1.2.3", platform, suffix)
            for platform, suffixes in FORMATS.items()
            for suffix in suffixes
            if suffix != ".dmg"
        ]:
            asset = self.dist / name
            asset.write_bytes(f"fixture:{name}".encode())
            Path(f"{asset}.sig").write_text(SIGNATURE, encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def build(self):
        return build_manifest(
            self.dist,
            "1.2.3",
            "v1.2.3",
            "surya-koritala/AIagentOS",
            "Release notes",
            "2026-07-28T00:00:00Z",
        )

    def test_builds_installer_specific_and_fallback_targets(self):
        manifest = self.build()
        platforms = manifest["platforms"]

        self.assertEqual(manifest["version"], "1.2.3")
        self.assertEqual(
            platforms["linux-x86_64-deb"]["url"],
            "https://github.com/surya-koritala/AIagentOS/releases/download/"
            "v1.2.3/agentos-v1.2.3-desktop-linux-x86_64.deb",
        )
        self.assertEqual(
            platforms["linux-x86_64"],
            platforms["linux-x86_64-appimage"],
        )
        self.assertEqual(
            platforms["windows-x86_64"],
            platforms["windows-x86_64-nsis"],
        )
        self.assertEqual(
            platforms["darwin-x86_64"],
            platforms["darwin-x86_64-app"],
        )
        self.assertNotIn(str(self.dist), str(manifest))
        self.assertEqual(len(platforms), 13)
        for architecture in ("x86_64", "aarch64"):
            for family, suffix in (("darwin", ".app.tar.gz"), ("linux", ".AppImage")):
                platform = "macos" if family == "darwin" else family
                self.assertTrue(platforms[f"{family}-{architecture}"]["url"].endswith(
                    f"desktop-{platform}-{architecture}{suffix}"
                ))

    def test_rejects_missing_signature_and_ambiguous_asset(self):
        deb = self.dist / asset_name("v1.2.3", "linux-aarch64", ".deb")
        Path(f"{deb}.sig").unlink()
        with self.assertRaisesRegex(ManifestError, "signature for.*linux-aarch64.deb"):
            self.build()

        Path(f"{deb}.sig").write_text(
            SIGNATURE, encoding="utf-8"
        )
        duplicate = self.dist / "agentos-v1.2.3-desktop-linux-aarch64-copy.deb"
        duplicate.write_bytes(b"duplicate")
        Path(f"{duplicate}.sig").write_text(SIGNATURE, encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "exactly one"):
            self.build()

    def test_rejects_invalid_signature_version_tag_and_date(self):
        msi = self.dist / asset_name("v1.2.3", "windows-x86_64", ".msi")
        Path(f"{msi}.sig").write_text(
            "not-base64", encoding="utf-8"
        )
        with self.assertRaisesRegex(ManifestError, "not Tauri minisign base64"):
            self.build()

        with self.assertRaisesRegex(ManifestError, "strict SemVer"):
            build_manifest(
                self.dist,
                "latest",
                "vlatest",
                "owner/repo",
                "notes",
                "2026-07-28T00:00:00Z",
            )

    def test_rejects_mismatched_tag_and_invalid_date(self):
        with self.assertRaisesRegex(ManifestError, "must exactly equal"):
            build_manifest(self.dist, "1.2.3", "v1.2.4", "owner/repo", "notes", "2026-07-28T00:00:00Z")
        with self.assertRaisesRegex(ManifestError, "RFC 3339"):
            build_manifest(self.dist, "1.2.3", "v1.2.3", "owner/repo", "notes", "not-a-date")

    def test_rejects_legacy_unlabelled_and_missing_architecture_assets(self):
        unexpected = self.dist / "legacy.AppImage"
        unexpected.write_bytes(b"unexpected")
        with self.assertRaisesRegex(ManifestError, "unrecognized updater asset"):
            self.build()
        unexpected.unlink()
        (self.dist / asset_name("v1.2.3", "macos-aarch64", ".app.tar.gz")).unlink()
        with self.assertRaisesRegex(ManifestError, "macos-aarch64 requires exactly one"):
            self.build()

    def test_rejects_symlink_in_place_of_architecture_asset(self):
        asset = self.dist / asset_name("v1.2.3", "linux-aarch64", ".AppImage")
        asset.unlink()
        asset.symlink_to(self.dist / asset_name("v1.2.3", "linux-x86_64", ".AppImage"))
        with self.assertRaisesRegex(ManifestError, "requires exactly one"):
            self.build()


if __name__ == "__main__":
    unittest.main()
