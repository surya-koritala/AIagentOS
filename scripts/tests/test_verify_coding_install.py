import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_cli_archive import BINARIES, build_archive
from linux_cli_rc_qualification import QualificationError, sha256_file
from verify_coding_install import verify


class CodingInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        source = self.root / "source"
        source.mkdir()
        for name in BINARIES:
            path = source / name
            path.write_text(f"fixture-{name}")
            path.chmod(0o755)
        self.archive = self.root / "candidate.zip"
        build_archive(source, self.archive)
        self.digest = sha256_file(self.archive)
        self.completed = {
            "status": "completed", "original_repository_written": False,
            "provider_tokens": 123,
            "branches": [
                {"phase": "discarded", "test": {"exit_code": 101, "kind": "isolated_process"}},
                {"phase": "selected", "test": {"exit_code": 0, "kind": "isolated_process"}},
            ],
        }

    def tearDown(self):
        self.temp.cleanup()

    def execute(self, command, environment):
        name = Path(command[0]).name
        if command[1] == "--version":
            text = f"{name} 0.4.0-rc.1\n"
        elif command[1] == "--help":
            text = "agent-code fixture --image IMAGE --data-dir DIR"
        elif command[1] == "fixture":
            value = copy.deepcopy(self.completed)
            value["status"] = "paused"
            value["branches"] = value["branches"][:1]
            text = json.dumps(value)
        else:
            text = json.dumps(self.completed)
        return subprocess.CompletedProcess(command, 0, text, "")

    def run_install(self):
        with mock.patch("verify_coding_install.platform.system", return_value="Linux"), mock.patch("verify_coding_install.execute", side_effect=self.execute):
            return verify(self.archive, self.digest, "0.4.0-rc.1", "fixture-image", self.root / "install")

    def test_changed_download_is_rejected_before_extraction_or_execution(self):
        with mock.patch("verify_coding_install.platform.system", return_value="Linux"), mock.patch("verify_coding_install.execute") as execute:
            with self.assertRaisesRegex(QualificationError, "checksum mismatch"):
                verify(self.archive, "0" * 64, "0.4.0-rc.1", "fixture", self.root / "install")
            execute.assert_not_called()
        self.assertFalse((self.root / "install").exists())

    def test_scripted_tests_cannot_be_promoted_to_process_install_evidence(self):
        self.completed["branches"][1]["test"]["kind"] = "contract_fixture"
        with self.assertRaisesRegex(QualificationError, "receipt contract failed"):
            self.run_install()

    def test_valid_receipts_remain_nonproduction_and_preserve_binary_hashes(self):
        report = self.run_install()
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(set(report["binary_sha256"]), set(BINARIES))
        self.assertTrue(report["fresh_process_resume"])
        self.assertFalse(report["completed_effects_replayed"])
        self.assertEqual(report["provider_api_calls"], 0)


if __name__ == "__main__":
    unittest.main()
