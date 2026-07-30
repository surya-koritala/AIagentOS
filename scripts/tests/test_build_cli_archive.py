import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from build_cli_archive import ArchiveBuildError, BINARIES, build_archive


class CliArchiveBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        for index, name in enumerate(BINARIES):
            path = self.source / name
            path.write_bytes(f"binary-{index}\n".encode())
            path.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def test_archive_is_byte_stable_canonical_and_exact(self):
        first = self.root / "first.zip"
        second = self.root / "second.zip"
        build_archive(self.source, first)
        build_archive(self.source, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(archive.namelist(), sorted(BINARIES))
            for info in archive.infolist():
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(stat.S_IFMT(info.external_attr >> 16), stat.S_IFREG)
                self.assertEqual(stat.S_IMODE(info.external_attr >> 16), 0o755)

    def test_missing_non_executable_and_existing_output_fail_closed(self):
        (self.source / "agent").unlink()
        with self.assertRaisesRegex(ArchiveBuildError, "cannot inspect"):
            build_archive(self.source, self.root / "missing.zip")
        agent = self.source / "agent"
        agent.write_bytes(b"agent")
        agent.chmod(0o644)
        with self.assertRaisesRegex(ArchiveBuildError, "must be executable"):
            build_archive(self.source, self.root / "non-executable.zip")
        agent.chmod(0o755)
        output = self.root / "existing.zip"
        output.write_bytes(b"do not replace")
        with self.assertRaisesRegex(ArchiveBuildError, "already exists"):
            build_archive(self.source, output)
        self.assertEqual(output.read_bytes(), b"do not replace")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlinked_source_or_binary_is_rejected(self):
        real_source = self.source
        source_link = self.root / "source-link"
        source_link.symlink_to(real_source, target_is_directory=True)
        with self.assertRaisesRegex(ArchiveBuildError, "real directory"):
            build_archive(source_link, self.root / "source-link.zip")
        agent = self.source / "agent"
        agent.unlink()
        agent.symlink_to(self.source / "agentctl")
        with self.assertRaisesRegex(ArchiveBuildError, "regular non-symlink"):
            build_archive(self.source, self.root / "binary-link.zip")


if __name__ == "__main__":
    unittest.main()
