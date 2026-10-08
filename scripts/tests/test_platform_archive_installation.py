import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from platform_archive_installation import InstallationError, check_manifest


class NativeInstallationInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.dist = Path(self.temporary.name)
        self.archive = self.dist / "agentos-ci-0123-aarch64-apple-darwin.zip"
        self.archive.write_bytes(b"archive fixture")
        self.sbom = self.archive.with_suffix(".cdx.json")
        self.sbom.write_bytes(b"sbom fixture")
        self.rows = [
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
            for path in (self.archive, self.sbom)
        ]
        (self.dist / "SHA256SUMS").write_text("\n".join(self.rows) + "\n", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def test_requires_complete_checksum_binding_to_archive_and_sbom(self):
        check_manifest(self.dist, self.archive)
        self.sbom.write_bytes(b"tampered")
        with self.assertRaisesRegex(InstallationError, "checksum failed"):
            check_manifest(self.dist, self.archive)

    def test_rejects_missing_duplicate_extra_and_traversal_checksum_rows(self):
        for content in (
            self.rows[0],
            "\n".join(self.rows + [self.rows[0]]),
            "\n".join(self.rows + ["a" * 64 + "  other.zip"]),
            "a" * 64 + "  ../outside.zip",
        ):
            (self.dist / "SHA256SUMS").write_text(content, encoding="utf-8")
            with self.assertRaises(InstallationError):
                check_manifest(self.dist, self.archive)

    def test_rejects_symlinked_candidate(self):
        archive = self.dist / "linked.zip"
        archive.symlink_to(self.archive)
        with self.assertRaisesRegex(InstallationError, "regular file"):
            check_manifest(self.dist, archive)


if __name__ == "__main__":
    unittest.main()
