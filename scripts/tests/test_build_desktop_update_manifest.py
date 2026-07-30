import base64
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from build_desktop_update_manifest import ManifestError, build_manifest


SIGNATURE = base64.b64encode(
    b"untrusted comment: signature from tauri secret key\nfixture-signature\n"
).decode("ascii")


class DesktopUpdateManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.dist = Path(self.temporary.name)
        for name in [
            "agentos.AppImage",
            "agentos.deb",
            "agentos.app.tar.gz",
            "agentos.msi",
            "agentos-setup.exe",
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
            "v1.2.3/agentos.deb",
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

    def test_rejects_missing_signature_and_ambiguous_asset(self):
        Path(f"{self.dist / 'agentos.deb'}.sig").unlink()
        with self.assertRaisesRegex(ManifestError, "signature for agentos.deb"):
            self.build()

        Path(f"{self.dist / 'agentos.deb'}.sig").write_text(
            SIGNATURE, encoding="utf-8"
        )
        duplicate = self.dist / "second.deb"
        duplicate.write_bytes(b"duplicate")
        Path(f"{duplicate}.sig").write_text(SIGNATURE, encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "exactly one"):
            self.build()

    def test_rejects_invalid_signature_version_tag_and_date(self):
        Path(f"{self.dist / 'agentos.msi'}.sig").write_text(
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
        with self.assertRaisesRegex(ManifestError, "must exactly equal"):
            build_manifest(
                self.dist,
                "1.2.3",
                "v1.2.4",
                "owner/repo",
                "notes",
                "2026-07-28T00:00:00Z",
            )
        with self.assertRaisesRegex(ManifestError, "RFC 3339"):
            build_manifest(
                self.dist,
                "1.2.3",
                "v1.2.3",
                "owner/repo",
                "notes",
                "not-a-date",
            )


if __name__ == "__main__":
    unittest.main()
