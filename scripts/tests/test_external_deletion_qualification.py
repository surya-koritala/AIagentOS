import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from external_deletion_qualification import (  # noqa: E402
    CONTRACT_PATH,
    MAX_EVIDENCE_BYTES,
    OBSERVATION_CLASS,
    QualificationError,
    REPORT_CLASS,
    REVIEW_CHECK_IDS,
    REVIEW_CLASS,
    SUITE,
    evaluate,
    main,
    validate_contract,
)


COMMIT = "a" * 40
ENVIRONMENT = "prod-ca-east-1"
RELEASE_CANDIDATE = "v1.0.0-rc.1"
EXERCISE_START = datetime(2026, 7, 1, 0, 0, tzinfo=timezone.utc)
EXERCISE_END = datetime(2026, 7, 3, 12, 0, tzinfo=timezone.utc)
CONTRACT_SHA256 = hashlib.sha256(CONTRACT_PATH.read_bytes()).hexdigest()
BOUNDARIES = (
    "external/workspace-copies-and-mounts",
    "external/provider-request-and-retention",
    "external/remote-backup-copies",
    "external/log-metric-and-trace-sinks",
    "external/container-model-and-package-registries",
    "external/browser-peripheral-and-tool-services",
)


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def configured_system(
    boundary_id,
    system_id,
    mode,
    *,
    offset_minutes,
    retention_seconds=None,
):
    started = EXERCISE_START + timedelta(minutes=offset_minutes)
    created = started + timedelta(minutes=1)
    if retention_seconds is None:
        action = created + timedelta(minutes=1)
        absent = action + timedelta(minutes=2)
        retention_expires = None
    else:
        retention_expires_at = created + timedelta(seconds=retention_seconds)
        action = retention_expires_at + timedelta(minutes=1)
        absent = action + timedelta(minutes=3)
        retention_expires = timestamp(retention_expires_at)
    return {
        "boundary_id": boundary_id,
        "system_id": system_id,
        "status": "configured",
        "lifecycle_mode": mode,
        "configuration_sha256": "1" * 64,
        "configuration_absence_verified": False,
        "policy_sha256": "2" * 64,
        "evidence_sha256": "3" * 64,
        "exercise": {
            "started_at": timestamp(started),
            "canary_created_at": timestamp(created),
            "lifecycle_action_at": timestamp(action),
            "retention_expires_at": retention_expires,
            "data_absent_at": timestamp(absent),
            "verified_at": timestamp(absent + timedelta(minutes=1)),
            "target_completion_seconds": 600,
            "canary_created": True,
            "canary_discoverable_before_action": mode != "zero-data-retention",
            "early_deletion_denied": mode == "immutable-retention-then-delete",
            "lifecycle_action_accepted": True,
            "retention_expiry_observed": mode
            in {"bounded-retention", "immutable-retention-then-delete"},
            "canary_absent_after_action": True,
            "fresh_principal_absence_verified": True,
            "residual_objects": 0,
            "unexpected_tenant_accesses": 0,
        },
    }


def not_configured_system(boundary_id):
    return {
        "boundary_id": boundary_id,
        "system_id": "none",
        "status": "not-configured",
        "lifecycle_mode": "not-configured",
        "configuration_sha256": "4" * 64,
        "configuration_absence_verified": True,
        "policy_sha256": None,
        "evidence_sha256": "5" * 64,
        "exercise": None,
    }


def valid_observation():
    return {
        "schema_version": 1,
        "qualification_class": OBSERVATION_CLASS,
        "release_candidate": RELEASE_CANDIDATE,
        "source": {"commit": COMMIT, "dirty": False},
        "environment": {
            "environment_id": ENVIRONMENT,
            "deployment_mode": "single-node",
            "os": "linux",
            "arch": "x86_64",
            "configuration_sha256": "6" * 64,
        },
        "profile": {
            "profile_id": "single-node-linux-rootless-container-cli",
            "boundary_contract_sha256": CONTRACT_SHA256,
            "maximum_completion_seconds": 2_592_000,
        },
        "exercise": {
            "exercise_id": "external-data-drill-2026-07",
            "started_at": timestamp(EXERCISE_START),
            "ended_at": timestamp(EXERCISE_END),
            "operator_id": "operator-1",
            "harness_id": "external-data-rig-1",
        },
        "systems": [
            not_configured_system(BOUNDARIES[0]),
            configured_system(
                BOUNDARIES[1],
                "provider-prod-ca-1",
                "delete-api",
                offset_minutes=5,
            ),
            configured_system(
                BOUNDARIES[2],
                "object-store-prod-ca-1",
                "immutable-retention-then-delete",
                offset_minutes=15,
                retention_seconds=86_400,
            ),
            configured_system(
                BOUNDARIES[3],
                "telemetry-prod-ca-1",
                "zero-data-retention",
                offset_minutes=25,
            ),
            configured_system(
                BOUNDARIES[4],
                "registry-prod-ca-1",
                "bounded-retention",
                offset_minutes=35,
                retention_seconds=3_600,
            ),
            not_configured_system(BOUNDARIES[5]),
        ],
    }


def record_keys(observation):
    return [
        f"{system['boundary_id']}::{system['system_id']}"
        for system in observation["systems"]
    ]


def valid_review(observation_sha256, observation):
    return {
        "schema_version": 1,
        "qualification_class": REVIEW_CLASS,
        "release_candidate": RELEASE_CANDIDATE,
        "source": {"commit": COMMIT, "dirty": False},
        "environment_id": ENVIRONMENT,
        "profile_id": "single-node-linux-rootless-container-cli",
        "observation_sha256": observation_sha256,
        "reviewer_id": "independent-reviewer-1",
        "reviewed_at": "2026-07-04T09:00:00Z",
        "decision": "approved",
        "review_attestation_sha256": "7" * 64,
        "record_keys": record_keys(observation),
        "checks": {check_id: True for check_id in REVIEW_CHECK_IDS},
        "open_findings": [],
    }


class EvidenceWorkspace:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.observation = self.root / "external-observation.json"
        self.review = self.root / "external-review.json"
        self.write(valid_observation())

    def write(self, observation, review_mutator=None):
        observation_bytes = json.dumps(
            observation, sort_keys=True, separators=(",", ":")
        ).encode()
        self.observation.write_bytes(observation_bytes)
        review = valid_review(hashlib.sha256(observation_bytes).hexdigest(), observation)
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


class ExternalDeletionQualificationTests(unittest.TestCase):
    def setUp(self):
        self.workspace = EvidenceWorkspace()

    def tearDown(self):
        self.workspace.close()

    def test_contract_is_fixed_to_complete_external_inventory(self):
        validate_contract()
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            tuple(boundary["boundary_id"] for boundary in contract["boundaries"]),
            BOUNDARIES,
        )
        self.assertEqual(contract["maximum_completion_seconds"], 2_592_000)
        self.assertEqual(
            contract["required_configured_boundaries"],
            ["external/remote-backup-copies"],
        )
        self.assertEqual(len(REVIEW_CHECK_IDS), 8)

    def test_complete_exact_rc_evidence_is_eligible_bounded_and_private(self):
        report = self.workspace.evaluate()
        self.assertTrue(report["passed"])
        self.assertEqual(report["suite"], SUITE)
        self.assertEqual(report["qualification_class"], REPORT_CLASS)
        self.assertTrue(report["external_boundary_inventory_complete"])
        self.assertTrue(report["external_deletion_retention_proof_eligible"])
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(report["failed_systems"], [])
        self.assertEqual(report["eligibility_blockers"], [])
        configured = {
            system["lifecycle_mode"]: system
            for system in report["systems"]
            if system["status"] == "configured"
        }
        self.assertEqual(configured["delete-api"]["completion_seconds"], 120)
        self.assertEqual(configured["zero-data-retention"]["completion_seconds"], 180)
        self.assertEqual(
            configured["immutable-retention-then-delete"]["completion_seconds"], 240
        )
        self.assertEqual(configured["bounded-retention"]["completion_seconds"], 240)
        encoded = json.dumps(report)
        self.assertNotIn("operator-1", encoded)
        self.assertNotIn("independent-reviewer-1", encoded)

    def test_required_remote_boundary_cannot_be_not_configured(self):
        observation = valid_observation()
        observation["systems"][2] = not_configured_system(BOUNDARIES[2])
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "ineligible lifecycle mode"):
            self.workspace.evaluate()

    def test_multiple_configured_systems_in_one_boundary_are_supported_and_ordered(self):
        observation = valid_observation()
        second = copy.deepcopy(observation["systems"][2])
        second["system_id"] = "object-store-prod-ca-2"
        observation["systems"].insert(3, second)
        self.workspace.write(observation)
        report = self.workspace.evaluate()
        self.assertTrue(report["external_deletion_retention_proof_eligible"])
        self.assertEqual(
            sum(
                system["boundary_id"] == BOUNDARIES[2]
                for system in report["systems"]
            ),
            2,
        )

    def test_boundary_inventory_is_complete_unique_and_ordered(self):
        cases = []
        missing = valid_observation()
        missing["systems"].pop()
        cases.append((missing, "array with 6"))
        reordered = valid_observation()
        reordered["systems"][0], reordered["systems"][1] = (
            reordered["systems"][1],
            reordered["systems"][0],
        )
        cases.append((reordered, "fixed boundary/system order"))
        duplicate = valid_observation()
        duplicate["systems"].insert(1, copy.deepcopy(duplicate["systems"][0]))
        cases.append((duplicate, "duplicate external system record"))
        mixed = valid_observation()
        mixed["systems"].insert(
            1,
            configured_system(
                BOUNDARIES[0],
                "workspace-prod-ca-1",
                "delete-api",
                offset_minutes=2,
            ),
        )
        cases.append((mixed, "cannot mix configured and not-configured"))
        for observation, message in cases:
            with self.subTest(message=message):
                self.workspace.write(observation)
                with self.assertRaisesRegex(QualificationError, message):
                    self.workspace.evaluate()

    def test_unknown_boundary_mode_and_ambiguous_system_id_fail_closed(self):
        cases = []
        unknown = valid_observation()
        unknown["systems"][0]["boundary_id"] = "external/unknown-system"
        cases.append((unknown, "unknown external boundary"))
        mode = valid_observation()
        mode["systems"][1]["lifecycle_mode"] = "immutable-retention-then-delete"
        cases.append((mode, "ineligible lifecycle mode"))
        ambiguous = valid_observation()
        ambiguous["systems"][1]["system_id"] = "provider::prod"
        cases.append((ambiguous, "must not contain"))
        for observation, message in cases:
            with self.subTest(message=message):
                self.workspace.write(observation)
                with self.assertRaisesRegex(QualificationError, message):
                    self.workspace.evaluate()

    def test_configured_and_not_configured_shapes_are_exact(self):
        configured_mutations = (
            ("configuration_absence_verified", True),
            ("policy_sha256", None),
            ("exercise", None),
            ("system_id", "none"),
        )
        for field, value in configured_mutations:
            with self.subTest(configured=field):
                observation = valid_observation()
                observation["systems"][1][field] = value
                self.workspace.write(observation)
                with self.assertRaisesRegex(QualificationError, "configured disposition"):
                    self.workspace.evaluate()
        not_configured_mutations = (
            ("configuration_absence_verified", False),
            ("policy_sha256", "8" * 64),
            ("exercise", {}),
            ("system_id", "workspace-prod"),
        )
        for field, value in not_configured_mutations:
            with self.subTest(not_configured=field):
                observation = valid_observation()
                observation["systems"][0][field] = value
                self.workspace.write(observation)
                with self.assertRaisesRegex(
                    QualificationError, "not-configured disposition"
                ):
                    self.workspace.evaluate()

    def test_lifecycle_results_are_recalculated_and_fail_eligibility(self):
        fields = (
            ("canary_created", False),
            ("canary_absent_after_action", False),
            ("fresh_principal_absence_verified", False),
            ("lifecycle_action_accepted", False),
            ("residual_objects", 1),
            ("unexpected_tenant_accesses", 1),
        )
        for field, value in fields:
            with self.subTest(field=field):
                observation = valid_observation()
                observation["systems"][1]["exercise"][field] = value
                self.workspace.write(observation)
                report = self.workspace.evaluate()
                self.assertFalse(report["external_deletion_retention_proof_eligible"])
                self.assertEqual(
                    report["failed_systems"],
                    [f"{BOUNDARIES[1]}::provider-prod-ca-1"],
                )

    def test_each_mode_enforces_its_pre_action_and_retention_semantics(self):
        cases = (
            (1, "canary_discoverable_before_action", False),
            (2, "early_deletion_denied", False),
            (2, "retention_expiry_observed", False),
            (3, "canary_discoverable_before_action", True),
            (4, "retention_expiry_observed", False),
        )
        for index, field, value in cases:
            with self.subTest(index=index, field=field):
                observation = valid_observation()
                observation["systems"][index]["exercise"][field] = value
                self.workspace.write(observation)
                self.assertFalse(
                    self.workspace.evaluate()[
                        "external_deletion_retention_proof_eligible"
                    ]
                )

    def test_expiry_presence_and_timeline_are_structurally_validated(self):
        no_expiry = valid_observation()
        no_expiry["systems"][2]["exercise"]["retention_expires_at"] = None
        self.workspace.write(no_expiry)
        with self.assertRaisesRegex(QualificationError, "must bind expiry"):
            self.workspace.evaluate()

        invented_expiry = valid_observation()
        invented_expiry["systems"][1]["exercise"]["retention_expires_at"] = timestamp(
            EXERCISE_START + timedelta(minutes=6)
        )
        self.workspace.write(invented_expiry)
        with self.assertRaisesRegex(QualificationError, "must not invent"):
            self.workspace.evaluate()

        outside = valid_observation()
        outside["systems"][1]["exercise"]["verified_at"] = timestamp(
            EXERCISE_END + timedelta(seconds=1)
        )
        self.workspace.write(outside)
        with self.assertRaisesRegex(QualificationError, "timeline is not monotonic"):
            self.workspace.evaluate()

    def test_completion_target_is_bounded_and_recalculated(self):
        observation = valid_observation()
        exercise = observation["systems"][1]["exercise"]
        exercise["target_completion_seconds"] = 60
        self.workspace.write(observation)
        report = self.workspace.evaluate()
        self.assertFalse(report["external_deletion_retention_proof_eligible"])
        self.assertFalse(report["systems"][1]["checks"]["completion_within_target"])

        observation = valid_observation()
        observation["systems"][1]["exercise"][
            "target_completion_seconds"
        ] = 2_592_001
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "integer <= 2592000"):
            self.workspace.evaluate()

    def test_exact_source_release_environment_and_contract_are_required(self):
        cases = (
            (("source", "commit"), "b" * 40),
            (("source", "dirty"), True),
            (("environment", "environment_id"), "other-prod"),
            (("environment", "os"), "macos"),
            (("profile", "profile_id"), "other-profile"),
            (("profile", "boundary_contract_sha256"), "c" * 64),
            (("profile", "maximum_completion_seconds"), 1),
        )
        for path, value in cases:
            with self.subTest(path=path):
                observation = valid_observation()
                observation[path[0]][path[1]] = value
                self.workspace.write(observation)
                with self.assertRaises(QualificationError):
                    self.workspace.evaluate()

    def test_fixture_like_target_system_operator_harness_and_reviewer_are_rejected(self):
        for path in (
            ("systems", 1, "system_id"),
            ("exercise", "operator_id"),
            ("exercise", "harness_id"),
        ):
            with self.subTest(path=path):
                observation = valid_observation()
                if path[0] == "systems":
                    observation["systems"][path[1]][path[2]] = "test-provider"
                else:
                    observation["exercise"][path[1]] = "test-identity"
                self.workspace.write(observation)
                with self.assertRaisesRegex(QualificationError, "non-fixture target"):
                    self.workspace.evaluate()

        self.workspace.write(
            valid_observation(),
            lambda review: review.update(reviewer_id="fixture-reviewer"),
        )
        with self.assertRaisesRegex(QualificationError, "non-fixture target"):
            self.workspace.evaluate()

    def test_review_is_hash_bound_complete_timely_and_independent(self):
        mutations = (
            (
                lambda review: review.update(observation_sha256="8" * 64),
                "exact observation bytes",
            ),
            (
                lambda review: review["record_keys"].pop(),
                "array with",
            ),
            (
                lambda review: review.update(reviewed_at="2026-08-10T09:00:00Z"),
                "too long",
            ),
        )
        for mutator, message in mutations:
            with self.subTest(message=message):
                self.workspace.write(valid_observation(), mutator)
                with self.assertRaisesRegex(QualificationError, message):
                    self.workspace.evaluate()

        for mutator, blocker in (
            (
                lambda review: review.update(reviewer_id="operator-1"),
                "reviewer is not independent",
            ),
            (
                lambda review: review.update(decision="rejected"),
                "decision is not approved",
            ),
            (
                lambda review: review["checks"].update(
                    raw_service_evidence_retained=False
                ),
                "review checks failed",
            ),
            (
                lambda review: review["open_findings"].append("delete still pending"),
                "open findings",
            ),
        ):
            with self.subTest(blocker=blocker):
                self.workspace.write(valid_observation(), mutator)
                report = self.workspace.evaluate()
                self.assertFalse(report["external_deletion_retention_proof_eligible"])
                self.assertTrue(
                    any(blocker in item for item in report["eligibility_blockers"])
                )

    def test_unknown_duplicate_oversized_and_symlink_evidence_is_rejected(self):
        observation = valid_observation()
        observation["unknown"] = True
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "keys differ"):
            self.workspace.evaluate()

        self.workspace.observation.write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )
        with self.assertRaisesRegex(QualificationError, "duplicate JSON key"):
            self.workspace.evaluate()

        self.workspace.observation.write_bytes(b"x" * (MAX_EVIDENCE_BYTES + 1))
        with self.assertRaisesRegex(QualificationError, "invalid size"):
            self.workspace.evaluate()

        self.workspace.write(valid_observation())
        link = self.workspace.root / "linked-observation.json"
        link.symlink_to(self.workspace.observation)
        with self.assertRaisesRegex(QualificationError, "unavailable"):
            evaluate(
                link,
                self.workspace.review,
                expected_commit=COMMIT,
                expected_environment=ENVIRONMENT,
                release_candidate=RELEASE_CANDIDATE,
            )

    def test_validate_mode_is_isolated(self):
        self.assertEqual(main(["--validate"]), 0)
        with self.assertRaises(SystemExit):
            main(["--validate", "--require-eligible"])

    @mock.patch(
        "external_deletion_qualification._local_source",
        return_value=(COMMIT, False),
    )
    def test_cli_writes_owner_only_new_report_and_refuses_overwrite(self, _source):
        output = self.workspace.root / "report.json"
        arguments = [
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
        self.assertEqual(main(arguments), 0)
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(QualificationError, "new regular file"):
            main(arguments)

    @mock.patch(
        "external_deletion_qualification._local_source",
        return_value=("b" * 40, False),
    )
    def test_cli_requires_the_exact_clean_local_commit(self, _source):
        with self.assertRaisesRegex(QualificationError, "exact clean"):
            main(
                [
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
                    str(self.workspace.root / "report.json"),
                ]
            )


if __name__ == "__main__":
    unittest.main()
