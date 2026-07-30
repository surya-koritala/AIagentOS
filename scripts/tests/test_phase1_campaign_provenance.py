import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "tests"))

from phase1_campaign_provenance import (  # noqa: E402
    PLAN_CLASS,
    REPORT_CLASS,
    build_plan,
    verify_provenance,
)
from phase1_promotion_qualification import QualificationError  # noqa: E402
from test_phase1_promotion_qualification import (  # noqa: E402
    COMMIT,
    RELEASE_CANDIDATE,
    TARGET_ENVIRONMENT,
    PromotionWorkspace,
    encoded,
)


REPOSITORY = "surya-koritala/AIagentOS"
CAMPAIGN_RUN_ID = 650


class Phase1CampaignProvenanceTests(unittest.TestCase):
    def workspace(self):
        workspace = PromotionWorkspace()
        self.addCleanup(workspace.close)
        return workspace

    def inputs(self, workspace):
        plan = build_plan(
            workspace.campaign_path,
            release_candidate=RELEASE_CANDIDATE,
            expected_commit=COMMIT,
            expected_environment=TARGET_ENVIRONMENT,
            expected_campaign_run_id=CAMPAIGN_RUN_ID,
        )
        plan_path = workspace.root / "campaign-provenance-plan.json"
        plan_path.write_bytes(encoded(plan))
        metadata_path = workspace.root / plan["run"]["metadata_file"]
        metadata_path.write_bytes(
            encoded(
                {
                    "id": CAMPAIGN_RUN_ID,
                    "run_attempt": 1,
                    "path": (
                        ".github/workflows/phase1-campaign-assembly.yml"
                        f"@refs/tags/{RELEASE_CANDIDATE}"
                    ),
                    "head_sha": COMMIT,
                    "event": "workflow_dispatch",
                    "status": "completed",
                    "conclusion": "success",
                    "updated_at": "2026-05-01T13:00:00Z",
                    "repository": {"full_name": REPOSITORY},
                    "head_repository": {"full_name": REPOSITORY},
                    "actor": {"login": "operator-1"},
                    "triggering_actor": {"login": "operator-1"},
                }
            )
        )
        artifact_dir = workspace.root / "campaign-artifact"
        artifact_dir.mkdir()
        (artifact_dir / "campaign.json").write_bytes(
            workspace.campaign_path.read_bytes()
        )
        (
            artifact_dir / "campaign.json.sigstore.json"
        ).write_bytes(
            b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'
        )
        for artifact in workspace.campaign["artifacts"]:
            (artifact_dir / artifact["path"]).write_bytes(
                workspace.evidence_path(artifact["evidence_id"]).read_bytes()
            )
        return plan, plan_path, metadata_path, artifact_dir

    def verify(self, workspace, plan_path, metadata_path, artifact_dir):
        with mock.patch(
            "phase1_campaign_provenance.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0),
        ) as verifier:
            report = verify_provenance(
                workspace.campaign_path,
                plan_path,
                metadata_path,
                artifact_dir,
                repository=REPOSITORY,
                release_candidate=RELEASE_CANDIDATE,
                expected_commit=COMMIT,
                expected_environment=TARGET_ENVIRONMENT,
                expected_campaign_run_id=CAMPAIGN_RUN_ID,
            )
        return report, verifier

    def test_exact_run_bundle_and_keyless_signature_are_required(self):
        workspace = self.workspace()
        plan, plan_path, metadata_path, artifact_dir = self.inputs(workspace)
        report, verifier = self.verify(
            workspace, plan_path, metadata_path, artifact_dir
        )
        self.assertEqual(plan["qualification_class"], PLAN_CLASS)
        self.assertEqual(report["qualification_class"], REPORT_CLASS)
        self.assertTrue(
            report["github_campaign_workflow_provenance_verified"]
        )
        self.assertTrue(report["github_campaign_artifact_bytes_verified"])
        self.assertTrue(report["keyless_campaign_signature_verified"])
        self.assertFalse(report["production_claim_allowed"])
        command = verifier.call_args.args[0]
        self.assertEqual(command[:2], ["cosign", "verify-blob"])
        self.assertIn(
            (
                "https://github.com/surya-koritala/AIagentOS/"
                ".github/workflows/phase1-campaign-assembly.yml"
                f"@refs/tags/{RELEASE_CANDIDATE}"
            ),
            command,
        )
        self.assertNotIn("operator-1", json.dumps(report))

    def test_forged_campaign_workflow_metadata_is_rejected(self):
        mutations = [
            lambda value: value.__setitem__("id", CAMPAIGN_RUN_ID + 1),
            lambda value: value.__setitem__("run_attempt", 2),
            lambda value: value.__setitem__(
                "path", ".github/workflows/ci.yml@main"
            ),
            lambda value: value.__setitem__("head_sha", "b" * 40),
            lambda value: value.__setitem__("event", "push"),
            lambda value: value.__setitem__("status", "in_progress"),
            lambda value: value.__setitem__("conclusion", "failure"),
            lambda value: value["repository"].__setitem__(
                "full_name", "attacker/fork"
            ),
            lambda value: value["head_repository"].__setitem__(
                "full_name", "attacker/fork"
            ),
            lambda value: value["actor"].__setitem__(
                "login", "not-an-operator"
            ),
            lambda value: value["triggering_actor"].__setitem__(
                "login", "not-an-operator"
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

    def test_tampered_campaign_report_inventory_and_signature_fail_closed(self):
        workspace = self.workspace()
        _, plan_path, metadata_path, artifact_dir = self.inputs(workspace)
        campaign = json.loads((artifact_dir / "campaign.json").read_text())
        campaign["operator_ids"] = ["other-operator"]
        (artifact_dir / "campaign.json").write_bytes(encoded(campaign))
        with self.assertRaisesRegex(QualificationError, "bytes differ"):
            self.verify(workspace, plan_path, metadata_path, artifact_dir)

        workspace = self.workspace()
        _, plan_path, metadata_path, artifact_dir = self.inputs(workspace)
        report = artifact_dir / workspace.campaign["artifacts"][0]["path"]
        report.write_bytes(report.read_bytes() + b" ")
        with self.assertRaises(QualificationError):
            self.verify(workspace, plan_path, metadata_path, artifact_dir)

        workspace = self.workspace()
        _, plan_path, metadata_path, artifact_dir = self.inputs(workspace)
        (artifact_dir / "unexpected.txt").write_text("unexpected")
        with self.assertRaisesRegex(QualificationError, "inventory"):
            self.verify(workspace, plan_path, metadata_path, artifact_dir)

        workspace = self.workspace()
        _, plan_path, metadata_path, artifact_dir = self.inputs(workspace)
        with mock.patch(
            "phase1_campaign_provenance.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1),
        ):
            with self.assertRaisesRegex(QualificationError, "signature"):
                verify_provenance(
                    workspace.campaign_path,
                    plan_path,
                    metadata_path,
                    artifact_dir,
                    repository=REPOSITORY,
                    release_candidate=RELEASE_CANDIDATE,
                    expected_commit=COMMIT,
                    expected_environment=TARGET_ENVIRONMENT,
                    expected_campaign_run_id=CAMPAIGN_RUN_ID,
                )


if __name__ == "__main__":
    unittest.main()
