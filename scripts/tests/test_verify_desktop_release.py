import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verify_desktop_release import validate


ROOT = Path(__file__).resolve().parents[2]
VERSION = json.loads(
    (ROOT / "crates/tauri-app/tauri.conf.json").read_text(encoding="utf-8")
)["version"]


class DesktopReleaseValidationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        for path in [
            "Cargo.toml",
            "crates/tauri-app/Cargo.toml",
            "crates/tauri-app/tauri.conf.json",
            "crates/tauri-app/ui/package.json",
            "crates/tauri-app/ui/package-lock.json",
        ]:
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / path, destination)
        shutil.copytree(
            ROOT / "crates/tauri-app/icons",
            self.root / "crates/tauri-app/icons",
        )
        workspace = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        start = workspace.index("members = [")
        end = workspace.index("]", start) + 1
        workspace = (
            workspace[:start]
            + 'members = ["crates/tauri-app"]'
            + workspace[end:]
        )
        (self.root / "Cargo.toml").write_text(workspace, encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_accepts_consistent_desktop_release(self):
        self.assertEqual(validate(self.root, f"v{VERSION}"), [])

    def test_rejects_version_and_tag_drift(self):
        package_path = self.root / "crates/tauri-app/ui/package.json"
        package = json.loads(package_path.read_text(encoding="utf-8"))
        package["version"] = "9.9.9"
        package_path.write_text(json.dumps(package), encoding="utf-8")
        failures = validate(self.root, "v0.3.1")
        self.assertTrue(any("ui/package.json version" in item for item in failures))
        self.assertTrue(any("release tag" in item for item in failures))

    def test_rejects_wrong_icon_dimensions(self):
        icon = self.root / "crates/tauri-app/icons/32x32.png"
        data = bytearray(icon.read_bytes())
        data[16:24] = struct.pack(">II", 31, 32)
        icon.write_bytes(data)
        failures = validate(self.root)
        self.assertTrue(any("is 31x32" in item for item in failures))

    def test_rejects_missing_platform_icon(self):
        (self.root / "crates/tauri-app/icons/icon.icns").unlink()
        failures = validate(self.root)
        self.assertIn("icons/icon.icns is missing or invalid", failures)

    def test_rejects_missing_or_dangerous_updater_contract(self):
        config_path = self.root / "crates/tauri-app/tauri.conf.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["bundle"]["createUpdaterArtifacts"] = False
        config["plugins"]["updater"]["pubkey"] = "not-base64"
        config["plugins"]["updater"]["endpoints"] = ["http://example.invalid/latest.json"]
        config["plugins"]["updater"]["dangerousInsecureTransportProtocol"] = True
        config["plugins"]["updater"]["windows"]["installMode"] = "quiet"
        config_path.write_text(json.dumps(config), encoding="utf-8")

        failures = validate(self.root)
        self.assertTrue(any("must create Tauri v2 updater artifacts" in item for item in failures))
        self.assertTrue(any("public key is not valid Tauri base64" in item for item in failures))
        self.assertTrue(any("canonical HTTPS latest.json" in item for item in failures))
        self.assertTrue(any("dangerousInsecureTransportProtocol" in item for item in failures))
        self.assertTrue(any("passive Windows install mode" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
