import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "tests"))

from phase1_promotion_qualification import QualificationError  # noqa: E402
from phase1_review_provenance import (  # noqa: E402
    PLAN_CLASS,
    REPORT_CLASS,
    build_plan,
    verify_provenance,
)
from test_phase1_promotion_qualification import (  # noqa: E402
    COMMIT,
    RELEASE_CANDIDATE,
    TARGET_ENVIRONMENT,
    PromotionWorkspace,
    encoded,
)


REPOSITORY = "surya-koritala/AIagentOS"


class Phase1ReviewProvenanceTests(unittest.TestCase):
    def workspace(self):
        workspace = PromotionWorkspace()
        self.addCleanup(workspace.close)
        return workspace

    def inputs(self, workspace):
        plan = build_plan(
            workspace.campaign_path,
            workspace.review_path,
            release_candidate=RELEASE_CANDIDATE,
            expected_commit=COMMIT,
            expected_environment=TARGET_ENVIRONMENT,
            expected_review_run_id=700,
        )
        plan_path = workspace.root / "review-provenance-plan.json"
        plan_path.write_bytes(encoded(plan))
        metadata_path = workspace.root / plan["run"]["metadata_file"]
        metadata = {
            "id": 700,
            "run_attempt": 1,
            "path": (
                ".github/workflows/phase1-independent-review.yml"
                f"@refs/tags/{RELEASE_CANDIDATE}"
            ),
            "head_sha": COMMIT,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "updated_at": "2026-05-02T12:01:00Z",
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
            "actor": {"login": "independent-reviewer-1"},
            "triggering_actor": {"login": "independent-reviewer-1"},
        }
        metadata_path.write_bytes(encoded(metadata))
        artifact_dir = workspace.root / "review-artifact"
        artifact_dir.mkdir()
        (artifact_dir / "phase1-review.json").write_bytes(
            workspace.review_path.read_bytes()
        )
        (artifact_dir / "phase1-review.json.sigstore.json").write_bytes(
            b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'
        )
        return plan, plan_path, metadata_path, artifact_dir

    def verify(self, workspace, plan_path, metadata_path, artifact_dir):
        with mock.patch(
            "phase1_review_provenance.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0),
        ) as verifier:
            report = verify_provenance(
                workspace.campaign_path,
                workspace.review_path,
                plan_path,
                metadata_path,
                artifact_dir,
                repository=REPOSITORY,
                release_candidate=RELEASE_CANDIDATE,
                expected_commit=COMMIT,
                expected_environment=TARGET_ENVIRONMENT,
                expected_review_run_id=700,
            )
        return report, verifier

    def test_exact_actor_run_artifact_and_keyless_signature_are_required(self):
        workspace = self.workspace()
        plan, plan_path, metadata_path, artifact_dir = self.inputs(workspace)
        report, verifier = self.verify(
            workspace, plan_path, metadata_path, artifact_dir
        )

        self.assertEqual(plan["qualification_class"], PLAN_CLASS)
        self.assertEqual(report["qualification_class"], REPORT_CLASS)
        self.assertTrue(report["reviewer_identity_authenticated"])
        self.assertTrue(
            report["github_review_workflow_provenance_verified"]
        )
        self.assertTrue(report["github_review_artifact_bytes_verified"])
        self.assertTrue(report["keyless_review_signature_verified"])
        self.assertFalse(report["production_claim_allowed"])
        command = verifier.call_args.args[0]
        self.assertEqual(command[0:2], ["cosign", "verify-blob"])
        self.assertIn(
            (
                "https://github.com/surya-koritala/AIagentOS/"
                ".github/workflows/phase1-independent-review.yml"
                f"@refs/tags/{RELEASE_CANDIDATE}"
            ),
            command,
        )
        self.assertNotIn("independent-reviewer-1", json.dumps(report))

    def test_forged_github_metadata_is_rejected(self):
        mutations = [
            lambda value: value.__setitem__("id", 701),
            lambda value: value.__setitem__("run_attempt", 2),
            lambda value: value.__setitem__(
                "path", ".github/workflows/ci.yml@main"
            ),
            lambda value: value.__setitem__("head_sha", "b" * 40),
            lambda value: value.__setitem__("event", "push"),
            lambda value: value.__setitem__("status", "in_progress"),
            lambda value: value.__setitem__("conclusion", "failure"),
            lambda value: value.__setitem__(
                "repository", {"full_name": "attacker/fork"}
            ),
            lambda value: value.__setitem__(
                "head_repository", {"full_name": "attacker/fork"}
            ),
            lambda value: value.__setitem__(
                "actor", {"login": "operator-1"}
            ),
            lambda value: value.__setitem__(
                "triggering_actor", {"login": "operator-1"}
            ),
            lambda value: value.__setitem__(
                "updated_at", "2026-05-02T11:59:59Z"
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                workspace = self.workspace()
                _, plan_path, metadata_path, artifact_dir = self.inputs(
                    workspace
                )
                metadata = json.loads(metadata_path.read_text())
                mutation(metadata)
                metadata_path.write_bytes(encoded(metadata))
                with self.assertRaises(QualificationError):
                    self.verify(
                        workspace, plan_path, metadata_path, artifact_dir
                    )

    def test_tampered_review_extra_artifact_and_bad_signature_fail_closed(self):
        workspace = self.workspace()
        _, plan_path, metadata_path, artifact_dir = self.inputs(workspace)
        review_path = artifact_dir / "phase1-review.json"
        review = json.loads(review_path.read_text())
        review["decision"] = "rejected"
        review_path.write_bytes(encoded(review))
        with self.assertRaisesRegex(QualificationError, "bytes differ"):
            self.verify(workspace, plan_path, metadata_path, artifact_dir)

        workspace = self.workspace()
        _, plan_path, metadata_path, artifact_dir = self.inputs(workspace)
        (artifact_dir / "unexpected.txt").write_text("unexpected")
        with self.assertRaisesRegex(QualificationError, "inventory"):
            self.verify(workspace, plan_path, metadata_path, artifact_dir)

        workspace = self.workspace()
        _, plan_path, metadata_path, artifact_dir = self.inputs(workspace)
        with mock.patch(
            "phase1_review_provenance.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1),
        ):
            with self.assertRaisesRegex(QualificationError, "signature"):
                verify_provenance(
                    workspace.campaign_path,
                    workspace.review_path,
                    plan_path,
                    metadata_path,
                    artifact_dir,
                    repository=REPOSITORY,
                    release_candidate=RELEASE_CANDIDATE,
                    expected_commit=COMMIT,
                    expected_environment=TARGET_ENVIRONMENT,
                    expected_review_run_id=700,
                )

    def test_plan_rejects_wrong_dispatch_run_and_signed_repository(self):
        workspace = self.workspace()
        with self.assertRaisesRegex(QualificationError, "promotion dispatch"):
            build_plan(
                workspace.campaign_path,
                workspace.review_path,
                release_candidate=RELEASE_CANDIDATE,
                expected_commit=COMMIT,
                expected_environment=TARGET_ENVIRONMENT,
                expected_review_run_id=701,
            )

        review = json.loads(workspace.review_path.read_text())
        review["review_workflow"]["repository"] = "attacker/fork"
        workspace.review_path.write_bytes(encoded(review))
        plan = build_plan(
            workspace.campaign_path,
            workspace.review_path,
            release_candidate=RELEASE_CANDIDATE,
            expected_commit=COMMIT,
            expected_environment=TARGET_ENVIRONMENT,
            expected_review_run_id=700,
        )
        plan_path = workspace.root / "wrong-repository-plan.json"
        plan_path.write_bytes(encoded(plan))
        metadata_path = workspace.root / plan["run"]["metadata_file"]
        metadata_path.write_bytes(
            encoded(
                {
                    "id": 700,
                    "run_attempt": 1,
                    "path": ".github/workflows/phase1-independent-review.yml",
                    "head_sha": COMMIT,
                    "event": "workflow_dispatch",
                    "status": "completed",
                    "conclusion": "success",
                    "updated_at": "2026-05-02T12:01:00Z",
                    "repository": {"full_name": REPOSITORY},
                    "head_repository": {"full_name": REPOSITORY},
                    "actor": {"login": "independent-reviewer-1"},
                    "triggering_actor": {
                        "login": "independent-reviewer-1"
                    },
                }
            )
        )
        artifact_dir = workspace.root / "wrong-repository-artifact"
        artifact_dir.mkdir()
        (artifact_dir / "phase1-review.json").write_bytes(
            workspace.review_path.read_bytes()
        )
        (artifact_dir / "phase1-review.json.sigstore.json").write_text("{}")
        with self.assertRaisesRegex(QualificationError, "trusted repository"):
            self.verify(workspace, plan_path, metadata_path, artifact_dir)


if __name__ == "__main__":
    unittest.main()
