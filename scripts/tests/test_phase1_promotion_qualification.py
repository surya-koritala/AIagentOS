import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from phase1_promotion_qualification import (  # noqa: E402
    BASE_EVIDENCE,
    CAMPAIGN_CLASS,
    MAX_CAMPAIGN_BYTES,
    PROFILE_ID,
    PROVIDERS,
    QualificationError,
    REVIEW_CHECK_IDS,
    REVIEW_CLASS,
    evaluate,
    main,
)


COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40
RELEASE_CANDIDATE = "v0.4.0-rc.1"
TARGET_ENVIRONMENT = "target-linux-rootless-1"
ON_DEVICE_ENVIRONMENT = "gguf-cpu-runner-1"
PROMOTED_PROVIDERS = ["openai", "ollama", "vllm"]
COMPLETED_AT = "2026-05-01T12:00:00Z"
REVIEWED_AT = "2026-05-02T12:00:00Z"


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_identity(qualification_class, environment=None):
    report = {
        "schema_version": 1,
        "qualification_class": qualification_class,
        "release_candidate": RELEASE_CANDIDATE,
        "source": {"commit": COMMIT, "dirty": False},
        "production_claim_allowed": False,
    }
    if environment is not None:
        report["environment"] = {"environment_id": environment}
    return report


def linux_cli_report():
    return {
        **exact_identity("restricted_linux_cli_release_candidate"),
        "supply_chain": {
            "github_provenance_verified": True,
            "keyless_sigstore_verified": True,
        },
        "runtime": {
            "authentication_required": True,
            "clean_restart_persisted_state": True,
            "exact_version_served": True,
            "gate_counters_observable": True,
            "governed_agent_created": True,
            "tls_verified": True,
            "wrong_authentication_rejected": True,
        },
        "durability": {
            "backup_encrypted": True,
            "backup_signed": True,
            "enforcement_rearmed": True,
            "fresh_host_restore_completed": True,
            "fresh_host_runtime_verified": True,
            "missing_key_failed_closed": True,
            "recovery_anchor_verified": True,
            "storage_encrypted": True,
            "tampered_backup_rejected": True,
        },
        "upgrade": {
            "released_agent_survived": True,
            "released_schema_encrypted": True,
            "released_schema_fixture_verified": True,
        },
    }


def live_plan_report():
    return {
        "schema_version": 1,
        "qualification_class": "live_provider_dispatch_plan",
        "status": "ready",
        "production_claim_allowed": False,
        "source": {"commit": COMMIT},
        "selected_providers": list(PROMOTED_PROVIDERS),
        "available_providers": list(PROVIDERS),
    }


def provider_report(provider):
    return {
        "schema_version": 1,
        "provider": provider,
        "model": f"{provider}-qualification-model",
        "status": "passed",
        "capabilities": {"streaming": True},
        "response": {"content_nonempty": True, "tool_call_count": 0},
    }


def on_device_report():
    return {
        **exact_identity(
            "exact_release_candidate_on_device_gguf", ON_DEVICE_ENVIRONMENT
        ),
        "passed": True,
        "on_device_proof_eligible": True,
        "checks": {
            "bounded_generation": True,
            "cancellation_worker_drained": True,
            "load_within_target": True,
            "peak_rss_within_target": True,
            "provisioned_inputs_stable": True,
            "supported_cpu_profile": True,
        },
    }


def target_remote_backup_report():
    return {
        **exact_identity(
            "target_remote_object_store_recovery", TARGET_ENVIRONMENT
        ),
        "passed": True,
        "target_remote_recovery_proof_eligible": True,
    }


def storage_profile_report():
    return {
        **exact_identity(
            "exact_release_candidate_destructive_storage_profile",
            TARGET_ENVIRONMENT,
        ),
        "passed": True,
        "destructive_storage_profile_completed": True,
        "storage_profile_proof_eligible": True,
        "review": {
            "reviewer_independent": True,
            "all_checks_passed": True,
            "decision": "approved",
        },
    }


def external_deletion_report():
    return {
        **exact_identity(
            "exact_release_candidate_external_deletion_retention",
            TARGET_ENVIRONMENT,
        ),
        "passed": True,
        "external_boundary_inventory_complete": True,
        "external_deletion_retention_proof_eligible": True,
        "review": {
            "reviewer_independent": True,
            "all_checks_passed": True,
            "decision": "approved",
        },
    }


def resource_soak_report():
    return {
        "schema_version": 1,
        "qualification_class": "target_resource_soak",
        "source": {"commit": COMMIT, "dirty": False},
        "environment": {"environment_id": TARGET_ENVIRONMENT},
        "production_claim_allowed": False,
        "build_profile": "release",
        "smoke_scaled": False,
        "configuration": {"duration_seconds": 86400},
        "result": {"passed": True, "elapsed_seconds": 86400},
        "resource_soak_proof_eligible": True,
    }


def game_day_report():
    return {
        **exact_identity(
            "exact_release_candidate_human_game_day", TARGET_ENVIRONMENT
        ),
        "passed": True,
        "human_game_day_completed": True,
        "game_day_proof_eligible": True,
        "review": {
            "reviewer_independent": True,
            "passed": True,
            "decision": "approved",
        },
        "failed_scenarios": [],
        "eligibility_blockers": [],
    }


def release_slo_report(resource_soak_sha, game_day_sha):
    return {
        **exact_identity("exact_release_candidate_slo_report", TARGET_ENVIRONMENT),
        "report_generated": True,
        "release_slo_proof_eligible": True,
        "targets": [{"target_id": f"target-{index}", "passed": True} for index in range(9)],
        "failed_targets": [],
        "eligibility_blockers": [],
        "evidence": {
            "resource_soak_sha256": resource_soak_sha,
            "human_game_day_sha256": game_day_sha,
        },
    }


class PromotionWorkspace:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir()
        self.campaign_path = self.root / "campaign.json"
        self.review_path = self.root / "review.json"
        self.output_path = self.root / "decision.json"
        self.reports = {
            "linux-cli-rc": linux_cli_report(),
            "live-provider-plan": live_plan_report(),
            "on-device": on_device_report(),
            "target-remote-backup": target_remote_backup_report(),
            "storage-profile": storage_profile_report(),
            "external-deletion": external_deletion_report(),
            "resource-soak": resource_soak_report(),
            "game-day": game_day_report(),
        }
        for provider in PROMOTED_PROVIDERS:
            self.reports[f"provider:{provider}"] = provider_report(provider)
        self.write_reports(include_slo=False)
        self.reports["release-slo"] = release_slo_report(
            digest(self.evidence_dir / BASE_EVIDENCE["resource-soak"][0]),
            digest(self.evidence_dir / BASE_EVIDENCE["game-day"][0]),
        )
        self.write_reports()
        self.campaign = self.make_campaign()
        self.write_campaign_and_review()

    def close(self):
        self.temporary.cleanup()

    def evidence_path(self, evidence_id):
        if evidence_id.startswith("provider:"):
            provider = evidence_id.removeprefix("provider:")
            return self.evidence_dir / f"provider-{provider}.json"
        return self.evidence_dir / BASE_EVIDENCE[evidence_id][0]

    def write_reports(self, include_slo=True):
        for evidence_id, report in self.reports.items():
            if evidence_id == "release-slo" and not include_slo:
                continue
            self.evidence_path(evidence_id).write_bytes(encoded(report))

    def make_campaign(self):
        artifacts = []
        live_run_id = 500
        for index, evidence_id in enumerate(sorted(self.reports)):
            if evidence_id.startswith("provider:") or evidence_id == "live-provider-plan":
                run_id = live_run_id
            else:
                run_id = 1000 + index
            if evidence_id.startswith("provider:"):
                provider = evidence_id.removeprefix("provider:")
                filename = f"provider-{provider}.json"
                workflow = ".github/workflows/live-provider-qualification.yml"
            else:
                filename, workflow = BASE_EVIDENCE[evidence_id]
            artifacts.append(
                {
                    "evidence_id": evidence_id,
                    "path": filename,
                    "sha256": digest(self.evidence_path(evidence_id)),
                    "workflow_path": workflow,
                    "workflow_run_id": run_id,
                    "workflow_run_attempt": 1,
                    "workflow_head_sha": COMMIT,
                    "workflow_conclusion": "success",
                    "workflow_completed_at": COMPLETED_AT,
                }
            )
        return {
            "schema_version": 1,
            "qualification_class": CAMPAIGN_CLASS,
            "release_candidate": RELEASE_CANDIDATE,
            "source": {"commit": COMMIT, "dirty": False},
            "profile_id": PROFILE_ID,
            "target_environment_id": TARGET_ENVIRONMENT,
            "on_device_environment_id": ON_DEVICE_ENVIRONMENT,
            "promoted_providers": list(PROMOTED_PROVIDERS),
            "operator_ids": ["operator-1"],
            "artifacts": artifacts,
        }

    def make_review(self, campaign_sha):
        return {
            "schema_version": 1,
            "qualification_class": REVIEW_CLASS,
            "release_candidate": RELEASE_CANDIDATE,
            "source": {"commit": COMMIT, "dirty": False},
            "profile_id": PROFILE_ID,
            "target_environment_id": TARGET_ENVIRONMENT,
            "on_device_environment_id": ON_DEVICE_ENVIRONMENT,
            "campaign_sha256": campaign_sha,
            "operator_ids": ["operator-1"],
            "reviewer_id": "independent-reviewer-1",
            "reviewed_at": REVIEWED_AT,
            "decision": "approved",
            "checks": {check_id: True for check_id in REVIEW_CHECK_IDS},
            "open_findings": [],
            "review_attestation_sha256": "c" * 64,
        }

    def write_campaign_and_review(self, mutate_review=None):
        self.campaign_path.write_bytes(encoded(self.campaign))
        review = self.make_review(digest(self.campaign_path))
        if mutate_review is not None:
            mutate_review(review)
        self.review_path.write_bytes(encoded(review))

    def refresh(self, mutate_review=None):
        self.write_reports()
        by_id = {
            artifact["evidence_id"]: artifact
            for artifact in self.campaign["artifacts"]
        }
        for evidence_id in self.reports:
            by_id[evidence_id]["sha256"] = digest(self.evidence_path(evidence_id))
        self.write_campaign_and_review(mutate_review)

    def evaluate(self):
        return evaluate(
            self.campaign_path,
            self.review_path,
            self.evidence_dir,
            release_candidate=RELEASE_CANDIDATE,
            expected_commit=COMMIT,
            expected_environment=TARGET_ENVIRONMENT,
        )


class Phase1PromotionQualificationTests(unittest.TestCase):
    def workspace(self):
        workspace = PromotionWorkspace()
        self.addCleanup(workspace.close)
        return workspace

    def test_complete_campaign_is_ready_bounded_and_identity_private(self):
        workspace = self.workspace()
        report = workspace.evaluate()
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["phase1_release_candidate_ready"])
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(report["promoted_providers"], PROMOTED_PROVIDERS)
        self.assertEqual(
            report["evidence"]["artifact_count"],
            len(BASE_EVIDENCE) + len(PROMOTED_PROVIDERS),
        )
        encoded_report = json.dumps(report)
        self.assertNotIn("operator-1", encoded_report)
        self.assertNotIn("independent-reviewer-1", encoded_report)

    def test_missing_extra_reordered_and_duplicate_artifacts_fail_closed(self):
        mutations = []

        def missing(campaign):
            campaign["artifacts"].pop()

        mutations.append(missing)

        def extra(campaign):
            artifact = copy.deepcopy(campaign["artifacts"][0])
            artifact["evidence_id"] = "unexpected"
            campaign["artifacts"].append(artifact)

        mutations.append(extra)

        def reordered(campaign):
            campaign["artifacts"][0], campaign["artifacts"][1] = (
                campaign["artifacts"][1],
                campaign["artifacts"][0],
            )

        mutations.append(reordered)

        def duplicate(campaign):
            campaign["artifacts"][-1] = copy.deepcopy(campaign["artifacts"][0])

        mutations.append(duplicate)
        for mutation in mutations:
            with self.subTest(mutation=mutation.__name__):
                workspace = self.workspace()
                mutation(workspace.campaign)
                workspace.write_campaign_and_review()
                with self.assertRaises(QualificationError):
                    workspace.evaluate()

    def test_mixed_source_release_and_environment_are_rejected(self):
        mutations = [
            lambda report: report["source"].__setitem__("commit", OTHER_COMMIT),
            lambda report: report.__setitem__("release_candidate", "v0.4.0-rc.2"),
            lambda report: report["environment"].__setitem__(
                "environment_id", "other-environment"
            ),
        ]
        evidence_ids = ["on-device", "storage-profile", "release-slo"]
        for evidence_id, mutation in zip(evidence_ids, mutations):
            with self.subTest(evidence_id=evidence_id):
                workspace = self.workspace()
                mutation(workspace.reports[evidence_id])
                workspace.refresh()
                with self.assertRaises(QualificationError):
                    workspace.evaluate()

    def test_digest_symlink_duplicate_json_and_oversize_are_rejected(self):
        workspace = self.workspace()
        provider_path = workspace.evidence_path("provider:openai")
        provider_path.write_bytes(provider_path.read_bytes() + b" ")
        with self.assertRaisesRegex(QualificationError, "digest"):
            workspace.evaluate()

        workspace = self.workspace()
        provider_path = workspace.evidence_path("provider:openai")
        provider_path.unlink()
        provider_path.symlink_to(workspace.evidence_path("provider:ollama"))
        with self.assertRaisesRegex(QualificationError, "non-symlink"):
            workspace.evaluate()

        workspace = self.workspace()
        workspace.campaign_path.write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )
        with self.assertRaisesRegex(QualificationError, "duplicate JSON key"):
            workspace.evaluate()

        workspace = self.workspace()
        workspace.campaign_path.write_bytes(b" " * (MAX_CAMPAIGN_BYTES + 1))
        with self.assertRaisesRegex(QualificationError, "must contain"):
            workspace.evaluate()

    def test_provider_scope_plan_and_one_run_provenance_are_enforced(self):
        workspace = self.workspace()
        workspace.campaign["promoted_providers"] = ["ollama", "vllm"]
        workspace.write_campaign_and_review()
        with self.assertRaisesRegex(QualificationError, "hosted provider"):
            workspace.evaluate()

        workspace = self.workspace()
        workspace.reports["live-provider-plan"]["selected_providers"] = [
            "openai",
            "ollama",
        ]
        workspace.refresh()
        with self.assertRaisesRegex(QualificationError, "promoted provider"):
            workspace.evaluate()

        workspace = self.workspace()
        artifacts = {
            artifact["evidence_id"]: artifact
            for artifact in workspace.campaign["artifacts"]
        }
        artifacts["provider:openai"]["workflow_run_id"] += 1
        workspace.write_campaign_and_review()
        with self.assertRaisesRegex(QualificationError, "one run"):
            workspace.evaluate()

    def test_failed_provider_and_soak_create_an_ineligible_decision(self):
        workspace = self.workspace()
        workspace.reports["provider:openai"]["status"] = "failed"
        workspace.reports["resource-soak"]["result"]["passed"] = False
        workspace.evidence_path("resource-soak").write_bytes(
            encoded(workspace.reports["resource-soak"])
        )
        workspace.reports["release-slo"]["evidence"]["resource_soak_sha256"] = (
            digest(workspace.evidence_path("resource-soak"))
        )
        workspace.refresh()
        report = workspace.evaluate()
        self.assertFalse(report["phase1_release_candidate_ready"])
        self.assertIn("provider:openai.status", report["eligibility_blockers"])
        self.assertIn(
            "resource-soak.result.passed", report["eligibility_blockers"]
        )

    def test_release_slo_must_bind_retained_soak_and_game_day(self):
        workspace = self.workspace()
        workspace.reports["release-slo"]["evidence"]["resource_soak_sha256"] = (
            "d" * 64
        )
        workspace.refresh()
        with self.assertRaisesRegex(QualificationError, "retained resource soak"):
            workspace.evaluate()

        workspace = self.workspace()
        workspace.reports["release-slo"]["evidence"]["human_game_day_sha256"] = (
            "d" * 64
        )
        workspace.refresh()
        with self.assertRaisesRegex(QualificationError, "retained game day"):
            workspace.evaluate()

    def test_review_independence_decision_findings_checks_and_freshness_gate(self):
        mutations = [
            (
                "review.reviewer_independent",
                lambda review: review.__setitem__("reviewer_id", "operator-1"),
            ),
            ("review.decision", lambda review: review.__setitem__("decision", "rejected")),
            (
                "review.open_findings",
                lambda review: review.__setitem__(
                    "open_findings", ["target backup custody is unresolved"]
                ),
            ),
            (
                "review.workflow_run_provenance_verified",
                lambda review: review["checks"].__setitem__(
                    "workflow_run_provenance_verified", False
                ),
            ),
            (
                "review.review_delay",
                lambda review: review.__setitem__(
                    "reviewed_at", "2026-06-15T12:00:00Z"
                ),
            ),
        ]
        for blocker, mutation in mutations:
            with self.subTest(blocker=blocker):
                workspace = self.workspace()
                workspace.write_campaign_and_review(mutation)
                report = workspace.evaluate()
                self.assertFalse(report["phase1_release_candidate_ready"])
                self.assertIn(blocker, report["eligibility_blockers"])

    def test_review_must_follow_and_hash_bind_every_artifact(self):
        workspace = self.workspace()
        workspace.write_campaign_and_review(
            lambda review: review.__setitem__(
                "reviewed_at", "2026-04-30T12:00:00Z"
            )
        )
        with self.assertRaisesRegex(QualificationError, "predates"):
            workspace.evaluate()

        workspace = self.workspace()
        workspace.write_campaign_and_review(
            lambda review: review.__setitem__("campaign_sha256", "d" * 64)
        )
        with self.assertRaisesRegex(QualificationError, "exact campaign"):
            workspace.evaluate()

    def test_future_workflow_and_review_timestamps_are_rejected(self):
        workspace = self.workspace()
        workspace.campaign["artifacts"][0]["workflow_completed_at"] = (
            "2099-01-01T00:00:00Z"
        )
        workspace.write_campaign_and_review()
        with self.assertRaisesRegex(QualificationError, "in the future"):
            workspace.evaluate()

        workspace = self.workspace()
        workspace.write_campaign_and_review(
            lambda review: review.__setitem__(
                "reviewed_at", "2099-01-01T00:00:00Z"
            )
        )
        with self.assertRaisesRegex(QualificationError, "in the future"):
            workspace.evaluate()

    def test_require_eligible_cli_writes_failed_report_and_returns_one(self):
        workspace = self.workspace()
        workspace.reports["provider:openai"]["status"] = "failed"
        workspace.refresh()
        result = main(
            [
                "--campaign",
                str(workspace.campaign_path),
                "--review",
                str(workspace.review_path),
                "--evidence-dir",
                str(workspace.evidence_dir),
                "--release-candidate",
                RELEASE_CANDIDATE,
                "--expected-commit",
                COMMIT,
                "--expected-environment",
                TARGET_ENVIRONMENT,
                "--output",
                str(workspace.output_path),
                "--require-eligible",
            ]
        )
        self.assertEqual(result, 1)
        self.assertFalse(
            json.loads(workspace.output_path.read_text())[
                "phase1_release_candidate_ready"
            ]
        )

    def test_tag_workflow_retains_bundle_and_only_phase1_gate_publishes(self):
        tag_workflow = (ROOT / ".github/workflows/linux-cli-rc.yml").read_text()
        promotion_workflow = (
            ROOT / ".github/workflows/phase1-promotion-qualification.yml"
        ).read_text()

        self.assertIn("name: qualified-linux-cli-rc-bundle", tag_workflow)
        self.assertNotIn("gh release create", tag_workflow)
        self.assertIn(
            "needs: exact-release-candidate-promotion", promotion_workflow
        )
        self.assertIn(
            "python3 scripts/phase1_promotion_qualification.py",
            promotion_workflow,
        )
        self.assertIn("--require-eligible", promotion_workflow)
        self.assertIn(
            'test "$(jq -r .phase1_release_candidate_ready "$report")" = "true"',
            promotion_workflow,
        )
        self.assertIn(
            'test "$(jq -r .production_claim_allowed "$report")" = "false"',
            promotion_workflow,
        )
        self.assertIn("gh release create", promotion_workflow)


if __name__ == "__main__":
    unittest.main()
