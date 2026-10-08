import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collect_desktop_assets import CollectionError, FORMATS, UNSIGNED_FORMATS, asset_name, collect_assets


class DesktopCollectionTests(unittest.TestCase):
    def fixture(self, root, platform):
        bundle = root / platform / "bundle"
        bundle.mkdir(parents=True)
        for suffix in FORMATS[platform]:
            asset = bundle / f"AI Agent OS_1.2.3{suffix}"
            asset.write_bytes(f"{platform}:{suffix}".encode())
            if suffix not in UNSIGNED_FORMATS:
                Path(f"{asset}.sig").write_bytes(b"signature fixture")
        return bundle

    def test_collects_both_architectures_without_mac_archive_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            for platform in FORMATS:
                bundle = self.fixture(root, platform)
                collect_assets(bundle, dist, "v1.2.3", platform)
                for suffix in FORMATS[platform]:
                    output = dist / asset_name("v1.2.3", platform, suffix)
                    self.assertEqual(output.read_bytes(), f"{platform}:{suffix}".encode())
            self.assertEqual(len(list(dist.glob("*.app.tar.gz"))), 2)

    def test_rejects_missing_signature_duplicate_overwrite_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root, "linux-aarch64")
            signature = next(bundle.glob("*.deb.sig"))
            signature.unlink()
            with self.assertRaisesRegex(CollectionError, "missing updater signature"):
                collect_assets(bundle, root / "dist", "v1.2.3", "linux-aarch64")
            self.assertFalse((root / "dist").exists())
            signature.write_bytes(b"fixture")
            duplicate = bundle / "duplicate.deb"
            duplicate.write_bytes(b"duplicate")
            with self.assertRaisesRegex(CollectionError, "exactly one"):
                collect_assets(bundle, root / "dist", "v1.2.3", "linux-aarch64")
            duplicate.unlink()
            collect_assets(bundle, root / "dist", "v1.2.3", "linux-aarch64")
            with self.assertRaisesRegex(CollectionError, "overwrite"):
                collect_assets(bundle, root / "dist", "v1.2.3", "linux-aarch64")
            deb = next(bundle.glob("*.deb"))
            deb.unlink()
            deb.symlink_to(next(bundle.glob("*.AppImage")))
            with self.assertRaisesRegex(CollectionError, "symlinks"):
                collect_assets(bundle, root / "other", "v1.2.3", "linux-aarch64")


if __name__ == "__main__":
    unittest.main()
