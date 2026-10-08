import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verify_supported_platforms import validate


ROOT = Path(__file__).resolve().parents[2]


class SupportedPlatformTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in (
            ".github/workflows/release.yml", "docs/SUPPORTED_PLATFORMS.md",
            "crates/tauri-app/tauri.conf.json", "README.md", "RELEASING.md",
            "docs/DESKTOP_DISTRIBUTION.md",
        ):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)

    def tearDown(self):
        self.temporary.cleanup()

    def change(self, name, before, after):
        path = self.root / name
        text = path.read_text(encoding="utf-8")
        self.assertIn(before, text)
        path.write_text(text.replace(before, after), encoding="utf-8")

    def test_current_native_matrices_and_document_agree(self):
        self.assertEqual(validate(self.root), [])

    def test_rejects_added_workflow_row_without_document_and_unsupported_runner(self):
        self.change(
            ".github/workflows/release.yml", "            target: aarch64-unknown-linux-gnu",
            "            target: armv7-unknown-linux-gnueabihf",
        )
        failures = validate(self.root)
        self.assertTrue(any("undocumented artifact" in item for item in failures))
        self.assertTrue(any("absent from release matrix" in item for item in failures))
        self.assertTrue(any("unsupported native target" in item for item in failures))

    def test_rejects_document_row_without_workflow_and_missing_documented_row(self):
        document = self.root / "docs/SUPPORTED_PLATFORMS.md"
        text = document.read_text(encoding="utf-8")
        row = next(line for line in text.splitlines() if line.startswith("| CLI |"))
        document.write_text(text.replace(row, ""), encoding="utf-8")
        self.assertTrue(any("undocumented artifact" in item for item in validate(self.root)))
        document.write_text(text + "\n" + row.replace("x86_64-unknown-linux-gnu", "other-target"), encoding="utf-8")
        self.assertTrue(any("absent from release matrix" in item for item in validate(self.root)))

    def test_rejects_format_floor_and_architecture_drift(self):
        self.change("docs/SUPPORTED_PLATFORMS.md", "| .deb, .AppImage |", "| .deb |")
        self.change(".github/workflows/release.yml", "runner: ubuntu-22.04-arm", "runner: ubuntu-latest")
        self.change("crates/tauri-app/tauri.conf.json", '"minimumSystemVersion": "13.0"', '"minimumSystemVersion": "12.0"')
        failures = validate(self.root)
        self.assertTrue(any("formats do not match" in item for item in failures))
        self.assertTrue(any("requires native runner" in item for item in failures))
        self.assertTrue(any("minimumSystemVersion" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
