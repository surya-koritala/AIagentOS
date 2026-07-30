import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verify_linux_cli_rc import validate_contract, validate_release


ROOT = Path(__file__).resolve().parents[2]
VERSION = "1.2.3-rc.4"
TAG = f"v{VERSION}"
COMMIT = "a" * 40


class LinuxCliRcReleaseContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        workflows = self.root / ".github/workflows"
        workflows.mkdir(parents=True)
        shutil.copy2(ROOT / ".github/workflows/release.yml", workflows)
        shutil.copy2(ROOT / ".github/workflows/linux-cli-rc.yml", workflows)
        shutil.copy2(
            ROOT / ".github/workflows/phase1-promotion-qualification.yml",
            workflows,
        )
        shutil.copy2(
            ROOT / ".github/workflows/phase1-independent-review.yml",
            workflows,
        )
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/a", "crates/tauri-app"]\n',
            encoding="utf-8",
        )
        for member in ("crates/a", "crates/tauri-app"):
            manifest = self.root / member / "Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                f'[package]\nname = "{member.replace("/", "-")}"\n'
                f'version = "{VERSION}"\n\n[dependencies]\n'
                f'other = {{ path = "../other", version = "={VERSION}" }}\n',
                encoding="utf-8",
            )
        fuzz = self.root / "fuzz/Cargo.toml"
        fuzz.parent.mkdir()
        fuzz.write_text(
            f'[package]\nname = "fuzz"\nversion = "0.0.0"\n\n[dependencies]\n'
            f'kernel = {{ path = "../crates/a", version = "={VERSION}" }}\n',
            encoding="utf-8",
        )
        tauri_config = self.root / "crates/tauri-app/tauri.conf.json"
        tauri_config.write_text(json.dumps({"version": VERSION}), encoding="utf-8")
        ui = self.root / "crates/tauri-app/ui"
        ui.mkdir()
        (ui / "package.json").write_text(
            json.dumps({"version": VERSION}), encoding="utf-8"
        )
        (ui / "package-lock.json").write_text(
            json.dumps({"version": VERSION, "packages": {"": {"version": VERSION}}}),
            encoding="utf-8",
        )
        (self.root / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## [Unreleased]\n\n## [{VERSION}] - 2026-07-30\n\n- RC.\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_repository_workflow_contract_is_complete_and_release_metadata_matches(self):
        self.assertEqual(validate_contract(ROOT), [])
        self.assertEqual(validate_release(self.root, TAG, COMMIT), [])

    def test_stable_overlap_and_missing_fresh_host_gate_are_rejected(self):
        stable = self.root / ".github/workflows/release.yml"
        stable.write_text(
            stable.read_text(encoding="utf-8").replace('      - "!v*-rc.*"\n', ""),
            encoding="utf-8",
        )
        rc = self.root / ".github/workflows/linux-cli-rc.yml"
        rc.write_text(
            rc.read_text(encoding="utf-8").replace("fresh-host:", "fresh_host_removed:"),
            encoding="utf-8",
        )
        failures = validate_contract(self.root)
        self.assertTrue(any("must exclude" in item for item in failures))
        self.assertTrue(any("'fresh-host:'" in item for item in failures))

    def test_version_dependency_changelog_tag_and_commit_drift_fail_closed(self):
        manifest = self.root / "crates/a/Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                f'version = "={VERSION}"', 'version = "=9.9.9"'
            ),
            encoding="utf-8",
        )
        failures = validate_release(self.root, "v1.2.3", "A" * 40)
        self.assertTrue(any("exact vX.Y.Z-rc.N" in item for item in failures))

        failures = validate_release(self.root, TAG, "A" * 40)
        self.assertTrue(any("40 lowercase" in item for item in failures))
        self.assertTrue(any("dependency version" in item for item in failures))

        (self.root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [Unreleased]\n", encoding="utf-8"
        )
        failures = validate_release(self.root, TAG, COMMIT)
        self.assertTrue(any("CHANGELOG.md" in item for item in failures))

        (self.root / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## [Unreleased]\n\n## [{VERSION}] - 2026-07-30\n\n",
            encoding="utf-8",
        )
        failures = validate_release(self.root, TAG, COMMIT)
        self.assertTrue(any("at least one release note" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
