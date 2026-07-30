import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "tests"))

from phase1_independent_review import (  # noqa: E402
    OBSERVATION_CLASS,
    REVIEW_SCHEMA_VERSION,
    WORKFLOW_PATH,
    build_review,
    main,
)
from phase1_promotion_qualification import QualificationError  # noqa: E402
from test_phase1_promotion_qualification import (  # noqa: E402
    COMMIT,
    RELEASE_CANDIDATE,
    REVIEWED_AT,
    TARGET_ENVIRONMENT,
    PromotionWorkspace,
    digest,
    encoded,
)


class Phase1IndependentReviewTests(unittest.TestCase):
    def workspace(self):
        workspace = PromotionWorkspace()
        self.addCleanup(workspace.close)
        return workspace

    def observation(self, workspace):
        review = workspace.make_review(digest(workspace.campaign_path))
        review.pop("review_workflow")
        review.pop("review_attestation_sha256")
        review["schema_version"] = 1
        review["qualification_class"] = OBSERVATION_CLASS
        return review

    def write_observation(self, workspace, mutation=None):
        observation = self.observation(workspace)
        if mutation is not None:
            mutation(observation)
        path = workspace.root / "phase1-review-observation.json"
        path.write_bytes(encoded(observation))
        return path

    def build(self, workspace, observation_path, **overrides):
        arguments = {
            "actor": "independent-reviewer-1",
            "repository": "surya-koritala/AIagentOS",
            "run_id": 700,
            "run_attempt": 1,
            "release_candidate": RELEASE_CANDIDATE,
            "expected_commit": COMMIT,
            "expected_environment": TARGET_ENVIRONMENT,
            "expected_campaign_run_id": 650,
        }
        arguments.update(overrides)
        return build_review(
            workspace.campaign_path,
            workspace.campaign_provenance_path,
            observation_path,
            **arguments,
        )

    def test_authenticated_actor_is_bound_to_normalized_review(self):
        workspace = self.workspace()
        observation_path = self.write_observation(workspace)
        review = self.build(workspace, observation_path)

        self.assertEqual(review["schema_version"], REVIEW_SCHEMA_VERSION)
        self.assertEqual(review["reviewer_id"], "independent-reviewer-1")
        self.assertEqual(review["review_workflow"]["workflow_path"], WORKFLOW_PATH)
        self.assertEqual(review["review_workflow"]["run_id"], 700)
        self.assertEqual(review["review_workflow"]["run_attempt"], 1)
        self.assertEqual(
            review["review_attestation_sha256"], digest(observation_path)
        )
        self.assertNotIn("production_claim_allowed", review)

    def test_actor_operator_reserved_identity_and_rerun_fail_closed(self):
        cases = [
            (
                "authenticated GitHub actor",
                {"actor": "different-reviewer"},
                None,
            ),
            (
                "not independent",
                {"actor": "operator-1"},
                lambda value: value.__setitem__("reviewer_id", "operator-1"),
            ),
            (
                "not independent",
                {"actor": "github-actions"},
                lambda value: value.__setitem__(
                    "reviewer_id", "github-actions"
                ),
            ),
            (
                "fresh workflow dispatch",
                {"run_attempt": 2},
                None,
            ),
        ]
        for message, overrides, mutation in cases:
            with self.subTest(message=message):
                workspace = self.workspace()
                observation_path = self.write_observation(workspace, mutation)
                with self.assertRaisesRegex(QualificationError, message):
                    self.build(workspace, observation_path, **overrides)

    def test_review_must_follow_exact_campaign_and_all_artifacts(self):
        mutations = [
            (
                "exact campaign",
                lambda value: value.__setitem__("campaign_sha256", "f" * 64),
            ),
            (
                "predates",
                lambda value: value.__setitem__(
                    "reviewed_at", "2026-05-01T12:30:00Z"
                ),
            ),
            (
                "future",
                lambda value: value.__setitem__(
                    "reviewed_at", "2099-01-01T00:00:00Z"
                ),
            ),
            (
                "operator inventory",
                lambda value: value.__setitem__(
                    "operator_ids", ["different-operator"]
                ),
            ),
        ]
        for message, mutation in mutations:
            with self.subTest(message=message):
                workspace = self.workspace()
                observation_path = self.write_observation(
                    workspace, mutation
                )
                with self.assertRaisesRegex(QualificationError, message):
                    self.build(workspace, observation_path)

    def test_require_approved_does_not_publish_rejected_review(self):
        workspace = self.workspace()
        observation_path = self.write_observation(
            workspace,
            lambda value: value.__setitem__("decision", "rejected"),
        )
        output = workspace.root / "phase1-review.json"
        result = main(
            [
                "--campaign",
                str(workspace.campaign_path),
                "--campaign-provenance",
                str(workspace.campaign_provenance_path),
                "--observation",
                str(observation_path),
                "--actor",
                "independent-reviewer-1",
                "--repository",
                "surya-koritala/AIagentOS",
                "--run-id",
                "700",
                "--run-attempt",
                "1",
                "--release-candidate",
                RELEASE_CANDIDATE,
                "--expected-commit",
                COMMIT,
                "--expected-environment",
                TARGET_ENVIRONMENT,
                "--expected-campaign-run-id",
                "650",
                "--output",
                str(output),
                "--require-approved",
            ]
        )
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())

    def test_workflow_is_tag_bound_protected_signed_and_retained(self):
        workflow = (
            ROOT / ".github/workflows/phase1-independent-review.yml"
        ).read_text()
        protected_plan = (
            ROOT / "scripts/protected_qualification_plan.py"
        ).read_text()

        for contract in (
            "profile: phase1-independent-review",
            "environment: phase1-review",
            "agentos-review",
            'test "$GITHUB_RUN_ATTEMPT" = "1"',
            "--actor \"$GITHUB_ACTOR\"",
            "phase1-review-observation.json",
            "cosign sign-blob --yes",
            "actions/attest-build-provenance@",
            "phase1-independent-review-${{ inputs.release_candidate }}-${{ github.sha }}",
        ):
            self.assertIn(contract, workflow)
        for contract in (
            '"profile": "phase1-independent-review"',
            '"enable_variable": "AGENTOS_PHASE1_REVIEW_ENABLED"',
            '"environment": "phase1-review"',
            '"AGENTOS_PHASE1_REVIEW_DIR"',
        ):
            self.assertIn(contract, protected_plan)


if __name__ == "__main__":
    unittest.main()
