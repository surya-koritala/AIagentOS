import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from incident_drill_qualification import (
    EXPECTED_SCENARIOS,
    SCENARIOS,
    ProcessResult,
    QualificationError,
    run_qualification,
    source_metadata,
    validate_catalog,
    write_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
COMMIT = "a" * 40
SOURCE = {"commit": COMMIT, "dirty": False}
ENVIRONMENT = {
    "os": "linux",
    "architecture": "x86_64",
    "python": "3.test",
    "rustc": "rustc test",
}


def successful_runner(command, argv, _repo_root):
    if command.evidence_kind == "cargo_test":
        return ProcessResult(
            0,
            "running 1 test\n"
            f"test {command.expected_test} ... ok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored\n",
        )
    child = Path(argv[argv.index("--output") + 1])
    child.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "qualification_class": "deterministic_resilience_fixture",
                "production_claim_allowed": False,
                "build_profile": "release",
                "smoke_scaled": False,
                "source": {"commit": COMMIT, "dirty": False},
                "scenarios": [
                    {
                        "name": "provider-outage",
                        "passed": True,
                        "checks": {
                            "typed_failures": True,
                            "control_plane_responsive": True,
                        },
                    }
                ],
                "passed": True,
            }
        ),
        encoding="utf-8",
    )
    return ProcessResult(0, "sensitive child output must not be retained")


class IncidentDrillQualificationTests(unittest.TestCase):
    def test_catalog_has_exactly_six_unique_playbooks_and_commands(self):
        validate_catalog(REPO_ROOT)
        self.assertEqual(
            tuple(scenario.scenario_id for scenario in SCENARIOS),
            EXPECTED_SCENARIOS,
        )
        command_ids = [
            command.command_id
            for scenario in SCENARIOS
            for command in scenario.commands
        ]
        self.assertEqual(len(command_ids), len(set(command_ids)))

    def test_complete_fixture_passes_without_retaining_command_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "incident.json"
            report = run_qualification(
                REPO_ROOT,
                output,
                successful_runner,
                source=SOURCE,
                environment=ENVIRONMENT,
            )
            write_report(output, report)
            rendered = output.read_text(encoding="utf-8")
        self.assertTrue(report["passed"])
        self.assertTrue(report["automated_drill_passed"])
        self.assertFalse(report["human_game_day_completed"])
        self.assertFalse(report["game_day_proof_eligible"])
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(len(report["scenarios"]), 6)
        self.assertNotIn("sensitive child output", rendered)
        self.assertNotIn("test result:", rendered)

    def test_failed_or_empty_exact_test_fails_closed(self):
        first_id = SCENARIOS[0].commands[0].command_id

        def runner(command, argv, repo_root):
            if command.command_id == first_id:
                return ProcessResult(0, "running 0 tests\ntest result: ok")
            return successful_runner(command, argv, repo_root)

        with tempfile.TemporaryDirectory() as directory:
            report = run_qualification(
                REPO_ROOT,
                Path(directory) / "incident.json",
                runner,
                source=SOURCE,
                environment=ENVIRONMENT,
            )
        self.assertFalse(report["passed"])
        command = report["scenarios"][0]["commands"][0]
        self.assertEqual(command["return_code"], 0)
        self.assertFalse(command["evidence_valid"])
        self.assertFalse(command["passed"])

    def test_provider_child_report_is_validated_fail_closed(self):
        def runner(command, argv, repo_root):
            if command.evidence_kind == "resilience_report":
                child = Path(argv[argv.index("--output") + 1])
                child.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "qualification_class": "deterministic_resilience_fixture",
                            "production_claim_allowed": False,
                            "build_profile": "release",
                            "smoke_scaled": False,
                            "source": {"commit": "b" * 40, "dirty": False},
                            "scenarios": [
                                {
                                    "name": "provider-outage",
                                    "passed": True,
                                    "checks": {"typed_failures": True},
                                }
                            ],
                            "passed": True,
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, "")
            return successful_runner(command, argv, repo_root)

        with tempfile.TemporaryDirectory() as directory:
            report = run_qualification(
                REPO_ROOT,
                Path(directory) / "incident.json",
                runner,
                source=SOURCE,
                environment=ENVIRONMENT,
            )
        provider = report["scenarios"][-1]["commands"][0]
        self.assertFalse(provider["evidence_valid"])
        self.assertFalse(report["passed"])

    def test_stale_provider_child_cannot_be_reused(self):
        def runner(command, argv, repo_root):
            if command.evidence_kind == "resilience_report":
                return ProcessResult(0, "command returned without publishing evidence")
            return successful_runner(command, argv, repo_root)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "incident.json"
            stale = output.parent / ".incident-provider-outage.json"
            stale.write_text("{}", encoding="utf-8")
            report = run_qualification(
                REPO_ROOT,
                output,
                runner,
                source=SOURCE,
                environment=ENVIRONMENT,
            )
        provider = report["scenarios"][-1]["commands"][0]
        self.assertFalse(provider["evidence_valid"])
        self.assertFalse(report["passed"])

    def test_source_metadata_distinguishes_clean_and_dirty_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "qualification@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Qualification Test"],
                cwd=root,
                check=True,
            )
            tracked = root / "tracked.txt"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            self.assertFalse(source_metadata(root)["dirty"])
            tracked.write_text("dirty\n", encoding="utf-8")
            self.assertTrue(source_metadata(root)["dirty"])

    def test_catalog_validation_rejects_missing_runbook(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(QualificationError, "runbook anchor"):
                validate_catalog(Path(directory))


if __name__ == "__main__":
    unittest.main()
