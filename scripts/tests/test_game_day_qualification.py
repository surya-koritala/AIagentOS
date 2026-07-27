import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from game_day_qualification import (  # noqa: E402
    QualificationError,
    REVIEW_CHECK_IDS,
    SCENARIO_IDS,
    evaluate,
    validate_contract,
)


COMMIT = "a" * 40
ENVIRONMENT = "staging-x64-8cpu-32g"
RELEASE_CANDIDATE = "v1.0.0-rc.1"
EXERCISE_START = datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)
EXERCISE_END = datetime(2026, 1, 15, 15, 0, tzinfo=timezone.utc)


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def valid_observation():
    scenarios = []
    for index, scenario_id in enumerate(SCENARIO_IDS):
        started = EXERCISE_START + timedelta(hours=index)
        detected = started + timedelta(minutes=5)
        mitigated = started + timedelta(minutes=15)
        recovered = started + timedelta(minutes=40)
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "started_at": timestamp(started),
                "detected_at": timestamp(detected),
                "mitigated_at": timestamp(mitigated),
                "recovered_at": timestamp(recovered),
                "target_rto_seconds": 3_600,
                "target_rpo_seconds": 300,
                "observed_data_loss_seconds": 0,
                "runbook_steps_total": 8,
                "runbook_steps_completed": 8,
                "unexpected_tenant_accesses": 0,
                "unresolved_findings": 0,
                "evidence_sha256": format(index + 1, "064x"),
            }
        )
    return {
        "schema_version": 1,
        "qualification_class": "human_incident_game_day_observation",
        "release_candidate": RELEASE_CANDIDATE,
        "source": {"commit": COMMIT, "dirty": False},
        "environment": {
            "environment_id": ENVIRONMENT,
            "deployment_mode": "single-node",
            "os": "linux",
            "arch": "x86_64",
            "configuration_sha256": "b" * 64,
        },
        "exercise": {
            "exercise_id": "game-day-2026-01",
            "started_at": timestamp(EXERCISE_START),
            "ended_at": timestamp(EXERCISE_END),
            "facilitator_id": "facilitator-1",
            "participants": [
                {
                    "participant_id": "incident-commander-1",
                    "role": "incident_commander",
                },
                {"participant_id": "operator-1", "role": "operator"},
                {"participant_id": "observer-1", "role": "observer"},
            ],
        },
        "scenarios": scenarios,
    }


def valid_review(observation_sha256):
    return {
        "schema_version": 1,
        "qualification_class": "independent_human_game_day_review",
        "release_candidate": RELEASE_CANDIDATE,
        "source": {"commit": COMMIT, "dirty": False},
        "environment_id": ENVIRONMENT,
        "observation_sha256": observation_sha256,
        "reviewer_id": "independent-reviewer-1",
        "reviewed_at": "2026-01-16T12:00:00Z",
        "decision": "approved",
        "review_attestation_sha256": "c" * 64,
        "scenario_ids": list(SCENARIO_IDS),
        "checks": {check_id: True for check_id in REVIEW_CHECK_IDS},
        "open_findings": [],
    }


class EvidenceWorkspace:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.observation = self.root / "game-day-observation.json"
        self.review = self.root / "game-day-review.json"
        self.write(valid_observation())

    def write(self, observation, review_mutator=None):
        observation_bytes = json.dumps(
            observation, sort_keys=True, separators=(",", ":")
        ).encode()
        self.observation.write_bytes(observation_bytes)
        review = valid_review(hashlib.sha256(observation_bytes).hexdigest())
        if review_mutator is not None:
            review_mutator(review)
        self.review.write_text(
            json.dumps(review, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    def evaluate(self):
        return evaluate(
            self.observation,
            self.review,
            expected_commit=COMMIT,
            expected_environment=ENVIRONMENT,
            release_candidate=RELEASE_CANDIDATE,
        )

    def close(self):
        self.temporary.cleanup()


class GameDayQualificationTests(unittest.TestCase):
    def setUp(self):
        self.workspace = EvidenceWorkspace()

    def tearDown(self):
        self.workspace.close()

    def test_contract_has_exact_incident_and_review_inventory(self):
        validate_contract()
        self.assertEqual(
            SCENARIO_IDS,
            (
                "credential-compromise",
                "tenant-leak",
                "malicious-package",
                "node-loss",
                "corrupt-database",
                "provider-outage",
            ),
        )
        self.assertEqual(len(REVIEW_CHECK_IDS), 6)

    def test_complete_exact_rc_game_day_is_eligible_and_bounded(self):
        report = self.workspace.evaluate()
        self.assertTrue(report["passed"])
        self.assertTrue(report["human_game_day_completed"])
        self.assertTrue(report["game_day_proof_eligible"])
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(report["failed_scenarios"], [])
        self.assertEqual(report["eligibility_blockers"], [])
        self.assertEqual(
            [scenario["scenario_id"] for scenario in report["scenarios"]],
            list(SCENARIO_IDS),
        )
        self.assertTrue(report["review"]["reviewer_independent"])
        encoded = json.dumps(report)
        self.assertNotIn("independent-reviewer-1", encoded)
        self.assertNotIn("incident-commander-1", encoded)
        self.assertRegex(
            report["evidence"]["observation_sha256"], r"^[0-9a-f]{64}$"
        )

    def test_scenario_outcomes_are_recalculated_not_trusted(self):
        observation = valid_observation()
        observation["scenarios"][0]["target_rto_seconds"] = 60
        observation["scenarios"][1]["observed_data_loss_seconds"] = 301
        observation["scenarios"][2]["runbook_steps_completed"] = 7
        observation["scenarios"][3]["unexpected_tenant_accesses"] = 1
        observation["scenarios"][4]["unresolved_findings"] = 1
        self.workspace.write(observation)
        report = self.workspace.evaluate()
        self.assertFalse(report["game_day_proof_eligible"])
        self.assertEqual(
            report["failed_scenarios"],
            list(SCENARIO_IDS[:5]),
        )
        self.assertIn("rto_met", report["scenarios"][0]["failed_checks"])
        self.assertIn("rpo_met", report["scenarios"][1]["failed_checks"])

    def test_timeline_must_be_ordered_inside_exercise(self):
        observation = valid_observation()
        observation["scenarios"][0]["recovered_at"] = "2026-01-15T09:10:00Z"
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "timeline must be ordered"):
            self.workspace.evaluate()

        observation = valid_observation()
        observation["scenarios"][-1]["recovered_at"] = "2026-01-15T16:00:00Z"
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "exercise window"):
            self.workspace.evaluate()

    def test_scenario_inventory_is_exact_and_ordered(self):
        observation = valid_observation()
        observation["scenarios"][0], observation["scenarios"][1] = (
            observation["scenarios"][1],
            observation["scenarios"][0],
        )
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "exactly"):
            self.workspace.evaluate()

    def test_exercise_duration_and_required_roles_fail_closed(self):
        observation = valid_observation()
        observation["exercise"]["ended_at"] = "2026-01-15T09:30:00Z"
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "at least"):
            self.workspace.evaluate()

        observation = valid_observation()
        observation["exercise"]["participants"][2]["role"] = "operator"
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "requires"):
            self.workspace.evaluate()

    def test_review_binds_exact_observation_bytes(self):
        self.workspace.write(
            valid_observation(),
            lambda review: review.__setitem__("observation_sha256", "d" * 64),
        )
        with self.assertRaisesRegex(QualificationError, "does not bind"):
            self.workspace.evaluate()

    def test_reviewer_must_be_independent_and_approve_every_check(self):
        self.workspace.write(
            valid_observation(),
            lambda review: review.__setitem__("reviewer_id", "operator-1"),
        )
        report = self.workspace.evaluate()
        self.assertFalse(report["game_day_proof_eligible"])
        self.assertIn(
            "review.reviewer_independent", report["eligibility_blockers"]
        )

        def reject_check(review):
            review["checks"]["rpo_rto_results_reviewed"] = False
            review["open_findings"] = ["Recovery point objective needs remediation"]

        self.workspace.write(valid_observation(), reject_check)
        report = self.workspace.evaluate()
        self.assertIn(
            "review.every_review_check_passed", report["eligibility_blockers"]
        )
        self.assertIn("review.zero_open_findings", report["eligibility_blockers"])

    def test_review_must_follow_exercise_and_cover_every_scenario(self):
        self.workspace.write(
            valid_observation(),
            lambda review: review.__setitem__(
                "reviewed_at", "2026-01-15T14:00:00Z"
            ),
        )
        with self.assertRaisesRegex(QualificationError, "must follow"):
            self.workspace.evaluate()

        self.workspace.write(
            valid_observation(),
            lambda review: review["scenario_ids"].reverse(),
        )
        with self.assertRaisesRegex(QualificationError, "cover every scenario"):
            self.workspace.evaluate()

    def test_exact_source_environment_profile_and_release_are_required(self):
        mutations = (
            ("source", {"commit": "d" * 40, "dirty": False}),
            (
                "environment",
                {
                    **valid_observation()["environment"],
                    "environment_id": "other-target",
                },
            ),
            ("release_candidate", "v1.0.0-rc.2"),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                observation = valid_observation()
                observation[key] = value
                self.workspace.write(observation)
                with self.assertRaises(QualificationError):
                    self.workspace.evaluate()

        observation = valid_observation()
        observation["environment"]["deployment_mode"] = "distributed"
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "single-node Linux"):
            self.workspace.evaluate()

    def test_numbers_reject_booleans_and_nonfinite_values(self):
        for bad_value in (True, float("nan"), float("inf")):
            with self.subTest(value=bad_value):
                observation = valid_observation()
                observation["scenarios"][0]["target_rto_seconds"] = bad_value
                self.workspace.write(observation)
                with self.assertRaisesRegex(QualificationError, "finite number"):
                    self.workspace.evaluate()

    def test_duplicate_and_unknown_json_keys_are_rejected(self):
        self.workspace.observation.write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )
        with self.assertRaisesRegex(QualificationError, "duplicate JSON key"):
            self.workspace.evaluate()

        observation = valid_observation()
        observation["invented"] = True
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "keys differ"):
            self.workspace.evaluate()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlink_evidence_is_rejected(self):
        real = self.workspace.root / "real-observation.json"
        self.workspace.observation.rename(real)
        os.symlink(real, self.workspace.observation)
        with self.assertRaisesRegex(QualificationError, "unavailable"):
            self.workspace.evaluate()

    def test_cli_validate_and_require_eligible(self):
        script = Path(__file__).resolve().parents[1] / "game_day_qualification.py"
        validated = subprocess.run(
            [sys.executable, str(script), "--validate"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        output = self.workspace.root / "game-day.json"
        command = [
            sys.executable,
            str(script),
            "--observation",
            str(self.workspace.observation),
            "--review",
            str(self.workspace.review),
            "--expected-commit",
            COMMIT,
            "--expected-environment",
            ENVIRONMENT,
            "--release-candidate",
            RELEASE_CANDIDATE,
            "--output",
            str(output),
            "--require-eligible",
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(output.read_text())["game_day_proof_eligible"])

        observation = copy.deepcopy(valid_observation())
        observation["scenarios"][0]["unresolved_findings"] = 1
        self.workspace.write(observation)
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(output.read_text())["game_day_proof_eligible"])

    def test_workflow_is_exact_tag_protected_and_retains_only_bounded_report(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (
            root / ".github/workflows/game-day-qualification.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, agentos-capacity]", workflow
        )
        self.assertIn('refs/tags/${AGENTOS_RELEASE_CANDIDATE}^{commit}', workflow)
        self.assertIn("game-day-observation.json", workflow)
        self.assertIn("game-day-review.json", workflow)
        self.assertIn("--require-eligible", workflow)
        self.assertIn('test ! -L "$path"', workflow)
        self.assertIn("path: target/qualification/game-day.json", workflow)
        self.assertNotIn(
            "path: ${AGENTOS_GAME_DAY_EVIDENCE_DIR}",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
