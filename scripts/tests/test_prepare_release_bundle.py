import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from build_desktop_update_manifest import ManifestError, build_manifest
from prepare_release_bundle import (
    BundleError, desktop_assets, prepare_bundle, release_notes, required_assets,
)


ROOT = Path(__file__).resolve().parents[2]
SIGNATURE = base64.b64encode(
    b"untrusted comment: signature from tauri secret key\nfixture-signature\n"
).decode("ascii")


class OptionalReleaseBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        for name in required_assets("v1.2.3"):
            (self.dist / name).write_bytes(b"required fixture")

    def tearDown(self):
        self.temporary.cleanup()

    def add_desktop(self):
        for name in desktop_assets("v1.2.3"):
            (self.dist / name).write_text(
                SIGNATURE if name.endswith(".sig") else "desktop fixture",
                encoding="utf-8",
            )

    def prepare(self, requested=True, contract="success", desktop="success"):
        return prepare_bundle(self.dist, "v1.2.3", requested, contract, desktop)

    def test_disabled_desktop_preserves_all_five_archives_and_mandatory_evidence(self):
        report = self.prepare(False, "skipped", "skipped")
        self.assertEqual(set(report["included_assets"]), required_assets("v1.2.3"))
        self.assertEqual(len(report["included_assets"]), 11)
        self.assertFalse(report["updater_ready"])
        notes = release_notes(report)
        self.assertIn("disabled", notes)
        self.assertIn("latest.json", notes)
        self.assertIn("agent-code", notes)
        self.assertIn("container image is not published", notes)

    def test_every_missing_or_empty_mandatory_asset_rejects_assembly(self):
        for name in sorted(required_assets("v1.2.3")):
            with self.subTest(name=name):
                path = self.dist / name
                contents = path.read_bytes()
                path.unlink()
                with self.assertRaises(ManifestError):
                    self.prepare(False, "skipped", "skipped")
                path.write_bytes(b"")
                with self.assertRaises(BundleError):
                    self.prepare(False, "skipped", "skipped")
                path.write_bytes(contents)

    def test_failed_skipped_or_cancelled_desktop_cannot_leak_partial_assets(self):
        for result in ("failure", "skipped", "cancelled"):
            with self.subTest(result=result):
                self.add_desktop()
                report = self.prepare(desktop=result)
                self.assertFalse(report["updater_ready"])
                self.assertEqual(set(report["included_assets"]), required_assets("v1.2.3"))
                self.assertIn(result, release_notes(report))

    def test_failed_contract_excludes_even_complete_matrix_output(self):
        self.add_desktop()
        report = self.prepare(contract="failure")
        self.assertFalse(report["updater_ready"])
        self.assertEqual(set(report["included_assets"]), required_assets("v1.2.3"))
        self.assertIn("native signing and clean-host qualification", release_notes(report))

    def test_complete_signed_matrix_produces_all_thirteen_updater_targets(self):
        self.add_desktop()
        report = self.prepare()
        self.assertTrue(report["updater_ready"])
        self.assertEqual(report["omitted_asset_classes"], [])
        manifest = build_manifest(
            self.dist, "1.2.3", "v1.2.3", "surya-koritala/AIagentOS",
            "fixture notes", "2026-10-08T00:00:00Z",
        )
        self.assertEqual(len(manifest["platforms"]), 13)

    def test_each_missing_updater_asset_or_signature_omits_manifest_without_failing(self):
        self.add_desktop()
        inputs = sorted(
            name for name in desktop_assets("v1.2.3")
            if not name.endswith((".dmg", ".cdx.json"))
        )
        self.assertEqual(len(inputs), 16)
        for name in inputs:
            with self.subTest(name=name):
                path = self.dist / name
                contents = path.read_bytes()
                path.unlink()
                report = self.prepare()
                self.assertFalse(report["updater_ready"])
                self.assertIn(name, report["missing_updater_inputs"])
                self.assertIn("latest.json", release_notes(report))
                path.write_bytes(contents)

    def test_present_malformed_signature_still_fails_closed(self):
        self.add_desktop()
        signature = next(self.dist.glob("*.sig"))
        signature.write_text("invalid", encoding="utf-8")
        with self.assertRaises(ManifestError):
            self.prepare()

    def test_unexpected_or_stale_manifest_is_rejected(self):
        for name in ("latest.json", "unrecognized-installer.exe"):
            with self.subTest(name=name):
                path = self.dist / name
                path.write_bytes(b"stale")
                with self.assertRaises(BundleError):
                    self.prepare(False, "skipped", "skipped")
                path.unlink()

    def test_cli_writes_consistent_inventory_notes_and_output(self):
        report = self.root / "inventory.json"
        notes = self.root / "notes.md"
        output = self.root / "github-output"
        result = subprocess.run([
            sys.executable, str(ROOT / "scripts/prepare_release_bundle.py"),
            "--dist", str(self.dist), "--version", "v1.2.3",
            "--desktop-requested", "false", "--desktop-contract-result", "skipped",
            "--desktop-result", "skipped", "--report", str(report),
            "--notes-output", str(notes), "--github-output", str(output),
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(report.read_text())["updater_ready"])
        self.assertEqual(output.read_text(), "updater_ready=false\n")
        self.assertIn("Omitted asset classes", notes.read_text())


if __name__ == "__main__":
    unittest.main()
