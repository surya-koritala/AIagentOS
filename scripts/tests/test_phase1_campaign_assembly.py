import copy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "tests"))

from phase1_campaign_assembly import (  # noqa: E402
    PLAN_CLASS,
    REQUEST_CLASS,
    RUN_GROUPS,
    assemble_campaign,
    build_plan,
    write_bundle,
)
from phase1_promotion_qualification import (  # noqa: E402
    CAMPAIGN_CLASS,
    QualificationError,
    _parse_campaign,
)
from test_phase1_promotion_qualification import (  # noqa: E402
    COMMIT,
    COMPLETED_AT,
    ON_DEVICE_ENVIRONMENT,
    PROMOTED_PROVIDERS,
    RELEASE_CANDIDATE,
    TARGET_ENVIRONMENT,
    PromotionWorkspace,
    encoded,
)


REPOSITORY = "surya-koritala/AIagentOS"


class CampaignAssemblyWorkspace:
    def __init__(self):
        self.promotion = PromotionWorkspace()
        self.root = self.promotion.root
        self.request_path = self.root / "campaign-request.json"
        self.plan_path = self.root / "campaign-plan.json"
        self.run_dir = self.root / "campaign-runs"
        self.artifact_dir = self.root / "campaign-artifacts"
        self.run_dir.mkdir()
        self.artifact_dir.mkdir()
        self.run_ids = {
            group: 2000 + index
            for index, group in enumerate(sorted(RUN_GROUPS), start=1)
        }
        self.request = {
            "schema_version": 1,
            "qualification_class": REQUEST_CLASS,
            "release_candidate": RELEASE_CANDIDATE,
            "source": {"commit": COMMIT, "dirty": False},
            "profile_id": "single-node-linux-rootless-container-cli",
            "target_environment_id": TARGET_ENVIRONMENT,
            "on_device_environment_id": ON_DEVICE_ENVIRONMENT,
            "promoted_providers": list(PROMOTED_PROVIDERS),
            "run_ids": self.run_ids,
        }
        self.write_inputs()

    def close(self):
        self.promotion.close()

    def write_inputs(self):
        self.request_path.write_bytes(encoded(self.request))
        plan = build_plan(self.request_path)
        self.plan_path.write_bytes(encoded(plan))
        for run in plan["runs"]:
            metadata = {
                "id": run["run_id"],
                "run_attempt": 1,
                "path": (
                    f"{run['workflow_path']}@refs/tags/{RELEASE_CANDIDATE}"
                ),
                "head_sha": COMMIT,
                "event": run["event"],
                "status": "completed",
                "conclusion": "success",
                "updated_at": COMPLETED_AT,
                "repository": {"full_name": REPOSITORY},
                "head_repository": {"full_name": REPOSITORY},
                "actor": {"login": "operator-1"},
                "triggering_actor": {"login": "operator-1"},
            }
            (self.run_dir / run["metadata_file"]).write_bytes(
                encoded(metadata)
            )
        for artifact in plan["artifacts"]:
            destination = self.artifact_dir / artifact["download_subdir"]
            destination.mkdir()
            source = self.promotion.evidence_path(artifact["evidence_id"])
            (destination / artifact["report_file"]).write_bytes(
                source.read_bytes()
            )
        return plan

    def assemble(self):
        return assemble_campaign(
            self.request_path,
            self.plan_path,
            self.run_dir,
            self.artifact_dir,
            repository=REPOSITORY,
            assembly_actor="operator-1",
            assembly_triggering_actor="operator-1",
        )


class Phase1CampaignAssemblyTests(unittest.TestCase):
    def workspace(self):
        workspace = CampaignAssemblyWorkspace()
        self.addCleanup(workspace.close)
        return workspace

    def test_exact_runs_build_deterministic_bounded_campaign_bundle(self):
        workspace = self.workspace()
        plan = json.loads(workspace.plan_path.read_text())
        campaign, reports = workspace.assemble()
        self.assertEqual(plan["qualification_class"], PLAN_CLASS)
        self.assertEqual(campaign["qualification_class"], CAMPAIGN_CLASS)
        self.assertEqual(
            campaign["promoted_providers"], PROMOTED_PROVIDERS
        )
        self.assertEqual(campaign["operator_ids"], ["operator-1"])
        self.assertEqual(
            [item["evidence_id"] for item in campaign["artifacts"]],
            sorted(workspace.promotion.reports),
        )
        output = workspace.root / "bundle"
        write_bundle(output, campaign, reports)
        parsed, _, records, _ = _parse_campaign(
            output / "campaign.json",
            release_candidate=RELEASE_CANDIDATE,
            expected_commit=COMMIT,
            expected_environment=TARGET_ENVIRONMENT,
        )
        self.assertEqual(parsed["operator_ids"], ["operator-1"])
        self.assertEqual(
            set(entry.name for entry in output.iterdir()),
            {"campaign.json", *reports},
        )
        self.assertEqual(set(records), set(workspace.promotion.reports))

    def test_request_rejects_mixed_identity_provider_and_run_inventory(self):
        mutations = [
            lambda request: request["source"].__setitem__(
                "commit", "not-a-commit"
            ),
            lambda request: request.__setitem__(
                "release_candidate", "v0.4.0"
            ),
            lambda request: request.__setitem__(
                "promoted_providers", ["ollama", "vllm"]
            ),
            lambda request: request["run_ids"].__setitem__(
                "game-day", request["run_ids"]["resource-soak"]
            ),
            lambda request: request["run_ids"].__setitem__("unexpected", 9),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                workspace = self.workspace()
                request = copy.deepcopy(workspace.request)
                mutation(request)
                workspace.request_path.write_bytes(encoded(request))
                with self.assertRaises(QualificationError):
                    build_plan(workspace.request_path)

    def test_forged_run_metadata_fails_closed(self):
        mutations = [
            lambda value: value.__setitem__("run_attempt", 0),
            lambda value: value.__setitem__(
                "path", ".github/workflows/ci.yml@main"
            ),
            lambda value: value.__setitem__("head_sha", "b" * 40),
            lambda value: value.__setitem__("event", "schedule"),
            lambda value: value.__setitem__("status", "in_progress"),
            lambda value: value.__setitem__("conclusion", "failure"),
            lambda value: value["repository"].__setitem__(
                "full_name", "attacker/fork"
            ),
            lambda value: value["actor"].__setitem__(
                "login", "github-actions"
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                workspace = self.workspace()
                metadata_path = sorted(workspace.run_dir.iterdir())[0]
                metadata = json.loads(metadata_path.read_text())
                mutation(metadata)
                metadata_path.write_bytes(encoded(metadata))
                with self.assertRaises(QualificationError):
                    workspace.assemble()

    def test_tampered_missing_and_extra_artifact_inputs_fail_closed(self):
        workspace = self.workspace()
        report = next(workspace.artifact_dir.rglob("*.json"))
        report.write_bytes(report.read_bytes() + b"{")
        with self.assertRaises(QualificationError):
            workspace.assemble()

        workspace = self.workspace()
        next(workspace.artifact_dir.iterdir()).rename(
            workspace.artifact_dir / "renamed"
        )
        with self.assertRaisesRegex(QualificationError, "inventory"):
            workspace.assemble()

        workspace = self.workspace()
        (workspace.run_dir / "unexpected.json").write_text("{}")
        with self.assertRaisesRegex(QualificationError, "inventory"):
            workspace.assemble()

    def test_workflow_uses_exact_tag_attempts_and_keyless_campaign_signature(self):
        workflow = (
            ROOT / ".github/workflows/phase1-campaign-assembly.yml"
        ).read_text()
        self.assertIn('test "$GITHUB_RUN_ATTEMPT" = "1"', workflow)
        self.assertIn("scripts/phase1_campaign_assembly.py", workflow)
        self.assertIn("actions/runs/${run_id}/attempts/${run_attempt}", workflow)
        self.assertIn('gh run download "$run_id"', workflow)
        self.assertIn("cosign sign-blob --yes", workflow)
        self.assertIn(
            "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
            workflow,
        )
        self.assertIn(
            "phase1-campaign-${{ inputs.release_candidate }}-${{ github.sha }}",
            workflow,
        )
        self.assertNotIn("AGENTOS_PHASE1_EVIDENCE_DIR", workflow)


if __name__ == "__main__":
    unittest.main()
