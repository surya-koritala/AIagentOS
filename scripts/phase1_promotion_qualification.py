#!/usr/bin/env python3
"""Build one fail-closed promotion decision from exact Phase 1 evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from live_provider_qualification_plan import PROVIDERS


SCHEMA_VERSION = 1
REVIEW_SCHEMA_VERSION = 2
CAMPAIGN_CLASS = "restricted_phase1_evidence_campaign"
REVIEW_CLASS = "independent_restricted_phase1_promotion_review"
REPORT_CLASS = "restricted_phase1_promotion_decision"
WORKFLOW_PROVENANCE_CLASS = "restricted_phase1_github_provenance"
REVIEW_PROVENANCE_CLASS = "restricted_phase1_independent_review_provenance"
PROFILE_ID = "single-node-linux-rootless-container-cli"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RC_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
MAX_CAMPAIGN_BYTES = 256 * 1024
MAX_REVIEW_BYTES = 256 * 1024
MAX_WORKFLOW_PROVENANCE_BYTES = 512 * 1024
MAX_REVIEW_PROVENANCE_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_ARTIFACTS = 32
MAX_REVIEW_DELAY = dt.timedelta(days=30)
HOSTED_PROVIDERS = frozenset(
    provider for provider in PROVIDERS if provider not in {"ollama", "vllm"}
)

BASE_EVIDENCE = {
    "linux-cli-rc": (
        "linux-cli-rc-qualification.json",
        ".github/workflows/linux-cli-rc.yml",
    ),
    "live-provider-plan": (
        "live-provider-plan.json",
        ".github/workflows/live-provider-qualification.yml",
    ),
    "on-device": (
        "on-device.json",
        ".github/workflows/on-device-qualification.yml",
    ),
    "target-remote-backup": (
        "target-remote-backup.json",
        ".github/workflows/target-remote-backup-qualification.yml",
    ),
    "storage-profile": (
        "storage-profile.json",
        ".github/workflows/storage-profile-qualification.yml",
    ),
    "external-deletion": (
        "external-deletion.json",
        ".github/workflows/external-deletion-qualification.yml",
    ),
    "resource-soak": (
        "resource-soak.json",
        ".github/workflows/resource-soak-qualification.yml",
    ),
    "release-slo": (
        "release-slo-report.json",
        ".github/workflows/release-slo-qualification.yml",
    ),
    "game-day": (
        "game-day.json",
        ".github/workflows/game-day-qualification.yml",
    ),
}
REVIEW_CHECK_IDS = (
    "exact_release_candidate_and_commit",
    "workflow_run_provenance_verified",
    "artifact_digests_verified",
    "linux_cli_signatures_and_fresh_host_reviewed",
    "promoted_provider_contracts_reviewed",
    "on_device_model_and_resource_limits_reviewed",
    "remote_backup_retention_and_recovery_reviewed",
    "destructive_storage_rpo_rto_reviewed",
    "external_deletion_and_retention_reviewed",
    "resource_soak_and_slo_reviewed",
    "human_game_day_reviewed",
    "no_open_findings",
)
RESERVED_REVIEWER_IDS = frozenset(
    {"github-actions", "agentos", "qualification-harness", "unknown"}
)


class QualificationError(ValueError):
    """The campaign is malformed, mixed-source, tampered, or incomplete."""


def _duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _regular_file(path: Path, label: str, maximum: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise QualificationError(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise QualificationError(f"{label} must contain 1..{maximum} bytes")
    return metadata


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], str]:
    metadata = _regular_file(path, label, maximum)
    try:
        encoded = path.read_bytes()
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_duplicate_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                QualificationError(f"{label} contains non-finite JSON: {token}")
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"{label} is invalid JSON: {error}") from error
    if path.stat().st_size != metadata.st_size:
        raise QualificationError(f"{label} changed while it was read")
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be one JSON object")
    return value, hashlib.sha256(encoded).hexdigest()


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise QualificationError(f"{label} keys differ; missing={missing}, extra={extra}")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be an object")
    return value


def _array(
    value: Any, label: str, *, minimum: int = 0, maximum: int = 100
) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise QualificationError(
            f"{label} must contain {minimum}..{maximum} entries"
        )
    return value


def _string(value: Any, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
    ):
        raise QualificationError(f"{label} must be a non-empty bounded string")
    return value


def _identifier(value: Any, label: str) -> str:
    result = _string(value, label, maximum=128)
    if IDENTIFIER_RE.fullmatch(result) is None:
        raise QualificationError(f"{label} contains unsafe characters")
    return result


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{label} must be a boolean")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise QualificationError(f"{label} must be a positive integer")
    return value


def _sha256(value: Any, label: str) -> str:
    result = _string(value, label, maximum=64)
    if SHA256_RE.fullmatch(result) is None:
        raise QualificationError(f"{label} must be a lowercase SHA-256 digest")
    return result


def _timestamp(value: Any, label: str) -> dt.datetime:
    raw = _string(value, label, maximum=40)
    if not raw.endswith("Z"):
        raise QualificationError(f"{label} must be UTC and end in Z")
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise QualificationError(f"{label} is not an ISO-8601 timestamp") from error
    if parsed.tzinfo != dt.timezone.utc:
        raise QualificationError(f"{label} must use UTC")
    return parsed


def _source(value: Any, expected_commit: str, label: str) -> dict[str, Any]:
    source = _object(value, label)
    if source.get("commit") != expected_commit or source.get("dirty") is not False:
        raise QualificationError(f"{label} must bind the exact clean source commit")
    return source


def _canonical_id_list(
    value: Any, label: str, *, minimum: int, maximum: int
) -> list[str]:
    result = [
        _identifier(item, f"{label}[]")
        for item in _array(value, label, minimum=minimum, maximum=maximum)
    ]
    if len(result) != len(set(item.casefold() for item in result)):
        raise QualificationError(f"{label} contains duplicates")
    if result != sorted(result, key=str.casefold):
        raise QualificationError(f"{label} must be in canonical sorted order")
    return result


def _provider_list(value: Any) -> list[str]:
    providers = [
        _identifier(item, "campaign.promoted_providers[]")
        for item in _array(
            value, "campaign.promoted_providers", minimum=2, maximum=len(PROVIDERS)
        )
    ]
    expected_order = [provider for provider in PROVIDERS if provider in providers]
    if providers != expected_order or len(providers) != len(set(providers)):
        raise QualificationError(
            "campaign.promoted_providers must be unique and use provider-catalog order"
        )
    unknown = sorted(set(providers) - set(PROVIDERS))
    if unknown:
        raise QualificationError(f"campaign contains unsupported providers: {unknown}")
    if "ollama" not in providers or "vllm" not in providers:
        raise QualificationError("Phase 1 promotion requires both Ollama and vLLM")
    if not set(providers).intersection(HOSTED_PROVIDERS):
        raise QualificationError("Phase 1 promotion requires at least one hosted provider")
    return providers


def _evidence_spec(evidence_id: str) -> tuple[str, str]:
    if evidence_id in BASE_EVIDENCE:
        return BASE_EVIDENCE[evidence_id]
    if evidence_id.startswith("provider:"):
        provider = evidence_id.removeprefix("provider:")
        if provider in PROVIDERS:
            return (
                f"provider-{provider}.json",
                ".github/workflows/live-provider-qualification.yml",
            )
    raise QualificationError(f"unsupported evidence_id: {evidence_id}")


def _parse_campaign(
    path: Path,
    *,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]], list[dt.datetime]]:
    campaign, campaign_sha = _load_json(
        path, "Phase 1 campaign manifest", MAX_CAMPAIGN_BYTES
    )
    _exact_keys(
        campaign,
        {
            "schema_version",
            "qualification_class",
            "release_candidate",
            "source",
            "profile_id",
            "target_environment_id",
            "on_device_environment_id",
            "promoted_providers",
            "operator_ids",
            "artifacts",
        },
        "campaign",
    )
    if campaign["schema_version"] != SCHEMA_VERSION:
        raise QualificationError("campaign schema_version is unsupported")
    if campaign["qualification_class"] != CAMPAIGN_CLASS:
        raise QualificationError("campaign qualification_class is invalid")
    if campaign["release_candidate"] != release_candidate:
        raise QualificationError("campaign release candidate does not match")
    _source(campaign["source"], expected_commit, "campaign.source")
    if campaign["profile_id"] != PROFILE_ID:
        raise QualificationError("campaign profile_id is unsupported")
    if campaign["target_environment_id"] != expected_environment:
        raise QualificationError("campaign target environment does not match")
    on_device_environment = _identifier(
        campaign["on_device_environment_id"], "campaign.on_device_environment_id"
    )
    if on_device_environment == expected_environment:
        raise QualificationError(
            "on-device and target environments must have distinct stable identities"
        )
    providers = _provider_list(campaign["promoted_providers"])
    operators = _canonical_id_list(
        campaign["operator_ids"], "campaign.operator_ids", minimum=1, maximum=10
    )
    if any(operator.casefold() in RESERVED_REVIEWER_IDS for operator in operators):
        raise QualificationError("campaign operator_ids contain a reserved identity")

    artifacts = _array(
        campaign["artifacts"],
        "campaign.artifacts",
        minimum=len(BASE_EVIDENCE) + len(providers),
        maximum=MAX_ARTIFACTS,
    )
    parsed: dict[str, dict[str, Any]] = {}
    completion_times: list[dt.datetime] = []
    artifact_ids: list[str] = []
    latest_allowed_time = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
    artifact_keys = {
        "evidence_id",
        "path",
        "sha256",
        "workflow_path",
        "workflow_run_id",
        "workflow_run_attempt",
        "workflow_head_sha",
        "workflow_conclusion",
        "workflow_completed_at",
    }
    for index, raw_artifact in enumerate(artifacts):
        artifact = _object(raw_artifact, f"campaign.artifacts[{index}]")
        _exact_keys(artifact, artifact_keys, f"campaign.artifacts[{index}]")
        evidence_id = _identifier(
            artifact["evidence_id"], f"campaign.artifacts[{index}].evidence_id"
        )
        if evidence_id in parsed:
            raise QualificationError(f"duplicate evidence_id: {evidence_id}")
        expected_name, expected_workflow = _evidence_spec(evidence_id)
        artifact_path = _string(
            artifact["path"], f"campaign.artifacts[{index}].path", maximum=128
        )
        if Path(artifact_path).name != artifact_path or artifact_path != expected_name:
            raise QualificationError(f"{evidence_id} has an unsafe or unexpected path")
        if artifact["workflow_path"] != expected_workflow:
            raise QualificationError(f"{evidence_id} names the wrong workflow")
        digest = _sha256(
            artifact["sha256"], f"campaign.artifacts[{index}].sha256"
        )
        run_id = _positive_integer(
            artifact["workflow_run_id"],
            f"campaign.artifacts[{index}].workflow_run_id",
        )
        run_attempt = _positive_integer(
            artifact["workflow_run_attempt"],
            f"campaign.artifacts[{index}].workflow_run_attempt",
        )
        if artifact["workflow_head_sha"] != expected_commit:
            raise QualificationError(f"{evidence_id} workflow used a different commit")
        if artifact["workflow_conclusion"] != "success":
            raise QualificationError(f"{evidence_id} workflow did not conclude successfully")
        completed_at = _timestamp(
            artifact["workflow_completed_at"],
            f"campaign.artifacts[{index}].workflow_completed_at",
        )
        if completed_at > latest_allowed_time:
            raise QualificationError(f"{evidence_id} workflow completion is in the future")
        artifact_ids.append(evidence_id)
        completion_times.append(completed_at)
        parsed[evidence_id] = {
            "evidence_id": evidence_id,
            "path": artifact_path,
            "sha256": digest,
            "workflow_path": expected_workflow,
            "workflow_run_id": run_id,
            "workflow_run_attempt": run_attempt,
            "workflow_head_sha": expected_commit,
            "workflow_conclusion": "success",
            "workflow_completed_at": completed_at,
        }
    if artifact_ids != sorted(artifact_ids):
        raise QualificationError("campaign.artifacts must be sorted by evidence_id")
    required = set(BASE_EVIDENCE) | {f"provider:{provider}" for provider in providers}
    if set(parsed) != required:
        missing = sorted(required - set(parsed))
        extra = sorted(set(parsed) - required)
        raise QualificationError(
            f"campaign evidence inventory differs; missing={missing}, extra={extra}"
        )
    plan_run = parsed["live-provider-plan"]
    for provider in providers:
        provider_run = parsed[f"provider:{provider}"]
        for field in (
            "workflow_run_id",
            "workflow_run_attempt",
            "workflow_head_sha",
            "workflow_completed_at",
        ):
            if provider_run[field] != plan_run[field]:
                raise QualificationError(
                    "live provider plan and provider reports must come from one run"
                )
    campaign["_validated_promoted_providers"] = providers
    campaign["_validated_operator_ids"] = operators
    campaign["_validated_on_device_environment"] = on_device_environment
    return campaign, campaign_sha, parsed, completion_times


def _expect_exact_identity(
    report: dict[str, Any],
    *,
    label: str,
    qualification_class: str,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str | None = None,
) -> None:
    if report.get("schema_version") != 1:
        raise QualificationError(f"{label} schema_version is unsupported")
    if report.get("qualification_class") != qualification_class:
        raise QualificationError(f"{label} qualification_class is invalid")
    if report.get("release_candidate") != release_candidate:
        raise QualificationError(f"{label} release candidate does not match")
    _source(report.get("source"), expected_commit, f"{label}.source")
    if report.get("production_claim_allowed") is not False:
        raise QualificationError(f"{label} must keep production_claim_allowed false")
    if expected_environment is not None:
        environment = _object(report.get("environment"), f"{label}.environment")
        if environment.get("environment_id") != expected_environment:
            raise QualificationError(f"{label} environment does not match")


def _failed_boolean_checks(
    report: dict[str, Any], label: str, checks: tuple[tuple[str, ...], ...]
) -> list[str]:
    blockers: list[str] = []
    for path in checks:
        value: Any = report
        for component in path:
            value = _object(value, f"{label}.{'.'.join(path[:-1])}").get(component)
        if value is not True:
            blockers.append(f"{label}.{'.'.join(path)}")
    return blockers


def _validate_evidence(
    evidence_id: str,
    report: dict[str, Any],
    *,
    release_candidate: str,
    expected_commit: str,
    target_environment: str,
    on_device_environment: str,
    promoted_providers: list[str],
) -> list[str]:
    blockers: list[str] = []
    if evidence_id == "linux-cli-rc":
        _expect_exact_identity(
            report,
            label=evidence_id,
            qualification_class="restricted_linux_cli_release_candidate",
            release_candidate=release_candidate,
            expected_commit=expected_commit,
        )
        blockers.extend(
            _failed_boolean_checks(
                report,
                evidence_id,
                (
                    ("supply_chain", "github_provenance_verified"),
                    ("supply_chain", "keyless_sigstore_verified"),
                    ("runtime", "authentication_required"),
                    ("runtime", "clean_restart_persisted_state"),
                    ("runtime", "exact_version_served"),
                    ("runtime", "gate_counters_observable"),
                    ("runtime", "governed_agent_created"),
                    ("runtime", "tls_verified"),
                    ("runtime", "wrong_authentication_rejected"),
                    ("durability", "backup_encrypted"),
                    ("durability", "backup_signed"),
                    ("durability", "enforcement_rearmed"),
                    ("durability", "fresh_host_restore_completed"),
                    ("durability", "fresh_host_runtime_verified"),
                    ("durability", "missing_key_failed_closed"),
                    ("durability", "recovery_anchor_verified"),
                    ("durability", "storage_encrypted"),
                    ("durability", "tampered_backup_rejected"),
                    ("upgrade", "released_agent_survived"),
                    ("upgrade", "released_schema_encrypted"),
                    ("upgrade", "released_schema_fixture_verified"),
                ),
            )
        )
    elif evidence_id == "live-provider-plan":
        if report.get("schema_version") != 1:
            raise QualificationError("live-provider-plan schema_version is unsupported")
        if report.get("qualification_class") != "live_provider_dispatch_plan":
            raise QualificationError("live-provider-plan qualification_class is invalid")
        source = _object(report.get("source"), "live-provider-plan.source")
        if source.get("commit") != expected_commit:
            raise QualificationError("live-provider-plan used a different commit")
        if report.get("production_claim_allowed") is not False:
            raise QualificationError(
                "live-provider-plan must keep production_claim_allowed false"
            )
        if report.get("selected_providers") != promoted_providers:
            raise QualificationError(
                "live-provider-plan does not match promoted provider inventory"
            )
        if report.get("available_providers") != list(PROVIDERS):
            raise QualificationError("live-provider-plan provider catalog differs")
        if report.get("status") != "ready":
            blockers.append("live-provider-plan.status")
    elif evidence_id.startswith("provider:"):
        provider = evidence_id.removeprefix("provider:")
        if report.get("schema_version") != 1 or report.get("provider") != provider:
            raise QualificationError(f"{evidence_id} identity is invalid")
        model = report.get("model")
        if not isinstance(model, str) or not model or len(model.encode()) > 512:
            raise QualificationError(f"{evidence_id} model identity is invalid")
        if report.get("status") != "passed":
            blockers.append(f"{evidence_id}.status")
        response = _object(report.get("response"), f"{evidence_id}.response")
        content_nonempty = response.get("content_nonempty") is True
        tool_calls = response.get("tool_call_count")
        if isinstance(tool_calls, bool) or not isinstance(tool_calls, int) or tool_calls < 0:
            raise QualificationError(f"{evidence_id} tool_call_count is invalid")
        if not content_nonempty and tool_calls == 0:
            blockers.append(f"{evidence_id}.response")
        if not isinstance(report.get("capabilities"), dict):
            raise QualificationError(f"{evidence_id} capabilities are missing")
    elif evidence_id == "on-device":
        _expect_exact_identity(
            report,
            label=evidence_id,
            qualification_class="exact_release_candidate_on_device_gguf",
            release_candidate=release_candidate,
            expected_commit=expected_commit,
            expected_environment=on_device_environment,
        )
        blockers.extend(
            _failed_boolean_checks(
                report,
                evidence_id,
                (
                    ("passed",),
                    ("on_device_proof_eligible",),
                    ("checks", "bounded_generation"),
                    ("checks", "cancellation_worker_drained"),
                    ("checks", "load_within_target"),
                    ("checks", "peak_rss_within_target"),
                    ("checks", "provisioned_inputs_stable"),
                    ("checks", "supported_cpu_profile"),
                ),
            )
        )
    elif evidence_id == "target-remote-backup":
        _expect_exact_identity(
            report,
            label=evidence_id,
            qualification_class="target_remote_object_store_recovery",
            release_candidate=release_candidate,
            expected_commit=expected_commit,
            expected_environment=target_environment,
        )
        blockers.extend(
            _failed_boolean_checks(
                report,
                evidence_id,
                (("passed",), ("target_remote_recovery_proof_eligible",)),
            )
        )
    elif evidence_id == "storage-profile":
        _expect_exact_identity(
            report,
            label=evidence_id,
            qualification_class="exact_release_candidate_destructive_storage_profile",
            release_candidate=release_candidate,
            expected_commit=expected_commit,
            expected_environment=target_environment,
        )
        blockers.extend(
            _failed_boolean_checks(
                report,
                evidence_id,
                (
                    ("passed",),
                    ("destructive_storage_profile_completed",),
                    ("storage_profile_proof_eligible",),
                    ("review", "reviewer_independent"),
                    ("review", "all_checks_passed"),
                ),
            )
        )
        if _object(report.get("review"), "storage-profile.review").get("decision") != "approved":
            blockers.append("storage-profile.review.decision")
    elif evidence_id == "external-deletion":
        _expect_exact_identity(
            report,
            label=evidence_id,
            qualification_class="exact_release_candidate_external_deletion_retention",
            release_candidate=release_candidate,
            expected_commit=expected_commit,
            expected_environment=target_environment,
        )
        blockers.extend(
            _failed_boolean_checks(
                report,
                evidence_id,
                (
                    ("passed",),
                    ("external_boundary_inventory_complete",),
                    ("external_deletion_retention_proof_eligible",),
                    ("review", "reviewer_independent"),
                    ("review", "all_checks_passed"),
                ),
            )
        )
        if _object(report.get("review"), "external-deletion.review").get("decision") != "approved":
            blockers.append("external-deletion.review.decision")
    elif evidence_id == "resource-soak":
        if report.get("schema_version") != 1:
            raise QualificationError("resource-soak schema_version is unsupported")
        if report.get("qualification_class") != "target_resource_soak":
            raise QualificationError("resource-soak qualification_class is invalid")
        _source(report.get("source"), expected_commit, "resource-soak.source")
        environment = _object(report.get("environment"), "resource-soak.environment")
        if environment.get("environment_id") != target_environment:
            raise QualificationError("resource-soak environment does not match")
        if report.get("production_claim_allowed") is not False:
            raise QualificationError(
                "resource-soak must keep production_claim_allowed false"
            )
        if report.get("build_profile") != "release" or report.get("smoke_scaled") is not False:
            blockers.append("resource-soak.release-profile")
        blockers.extend(
            _failed_boolean_checks(
                report,
                evidence_id,
                (("result", "passed"), ("resource_soak_proof_eligible",)),
            )
        )
        configuration = _object(
            report.get("configuration"), "resource-soak.configuration"
        )
        result = _object(report.get("result"), "resource-soak.result")
        duration_seconds = configuration.get("duration_seconds")
        if (
            isinstance(duration_seconds, bool)
            or not isinstance(duration_seconds, (int, float))
            or duration_seconds < 86400
        ):
            blockers.append("resource-soak.configuration.duration_seconds")
        elapsed_seconds = result.get("elapsed_seconds")
        if (
            isinstance(elapsed_seconds, bool)
            or not isinstance(elapsed_seconds, (int, float))
            or elapsed_seconds < 86400
        ):
            blockers.append("resource-soak.result.elapsed_seconds")
    elif evidence_id == "release-slo":
        _expect_exact_identity(
            report,
            label=evidence_id,
            qualification_class="exact_release_candidate_slo_report",
            release_candidate=release_candidate,
            expected_commit=expected_commit,
            expected_environment=target_environment,
        )
        blockers.extend(
            _failed_boolean_checks(
                report,
                evidence_id,
                (("report_generated",), ("release_slo_proof_eligible",)),
            )
        )
        targets = _array(report.get("targets"), "release-slo.targets", minimum=9, maximum=9)
        if any(not isinstance(target, dict) or target.get("passed") is not True for target in targets):
            blockers.append("release-slo.targets")
        if report.get("failed_targets") != [] or report.get("eligibility_blockers") != []:
            blockers.append("release-slo.eligibility")
    elif evidence_id == "game-day":
        _expect_exact_identity(
            report,
            label=evidence_id,
            qualification_class="exact_release_candidate_human_game_day",
            release_candidate=release_candidate,
            expected_commit=expected_commit,
            expected_environment=target_environment,
        )
        blockers.extend(
            _failed_boolean_checks(
                report,
                evidence_id,
                (
                    ("passed",),
                    ("human_game_day_completed",),
                    ("game_day_proof_eligible",),
                    ("review", "reviewer_independent"),
                    ("review", "passed"),
                ),
            )
        )
        if _object(report.get("review"), "game-day.review").get("decision") != "approved":
            blockers.append("game-day.review.decision")
        if report.get("failed_scenarios") != [] or report.get("eligibility_blockers") != []:
            blockers.append("game-day.eligibility")
    else:
        raise QualificationError(f"unsupported evidence validator: {evidence_id}")
    return blockers


def _parse_review(
    path: Path,
    *,
    campaign_sha: str,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
    on_device_environment: str,
    operator_ids: list[str],
    completion_times: list[dt.datetime],
) -> tuple[dict[str, Any], str, list[str]]:
    review, review_sha = _load_json(path, "Phase 1 independent review", MAX_REVIEW_BYTES)
    _exact_keys(
        review,
        {
            "schema_version",
            "qualification_class",
            "release_candidate",
            "source",
            "profile_id",
            "target_environment_id",
            "on_device_environment_id",
            "campaign_sha256",
            "operator_ids",
            "reviewer_id",
            "reviewed_at",
            "decision",
            "checks",
            "open_findings",
            "review_attestation_sha256",
            "review_workflow",
        },
        "review",
    )
    if review["schema_version"] != REVIEW_SCHEMA_VERSION:
        raise QualificationError("review schema_version is unsupported")
    if review["qualification_class"] != REVIEW_CLASS:
        raise QualificationError("review qualification_class is invalid")
    if review["release_candidate"] != release_candidate:
        raise QualificationError("review release candidate does not match")
    _source(review["source"], expected_commit, "review.source")
    if review["profile_id"] != PROFILE_ID:
        raise QualificationError("review profile_id is unsupported")
    if review["target_environment_id"] != expected_environment:
        raise QualificationError("review target environment does not match")
    if review["on_device_environment_id"] != on_device_environment:
        raise QualificationError("review on-device environment does not match")
    if review["campaign_sha256"] != campaign_sha:
        raise QualificationError("review does not bind the exact campaign bytes")
    reviewed_operators = _canonical_id_list(
        review["operator_ids"], "review.operator_ids", minimum=1, maximum=10
    )
    if reviewed_operators != operator_ids:
        raise QualificationError("review operator inventory does not match campaign")
    reviewer_id = _identifier(review["reviewer_id"], "review.reviewer_id")
    reviewer_independent = reviewer_id.casefold() not in {
        item.casefold() for item in operator_ids
    } | RESERVED_REVIEWER_IDS
    reviewed_at = _timestamp(review["reviewed_at"], "review.reviewed_at")
    if reviewed_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise QualificationError("review timestamp is in the future")
    latest_completion = max(completion_times)
    if reviewed_at < latest_completion:
        raise QualificationError("review predates one or more workflow artifacts")
    review_delay = reviewed_at - latest_completion
    checks = _object(review["checks"], "review.checks")
    _exact_keys(checks, set(REVIEW_CHECK_IDS), "review.checks")
    review_checks = {
        check_id: _boolean(checks[check_id], f"review.checks.{check_id}")
        for check_id in REVIEW_CHECK_IDS
    }
    findings = [
        _string(item, "review.open_findings[]", maximum=300)
        for item in _array(
            review["open_findings"], "review.open_findings", minimum=0, maximum=20
        )
    ]
    _sha256(review["review_attestation_sha256"], "review.review_attestation_sha256")
    review_workflow = _object(review["review_workflow"], "review.review_workflow")
    _exact_keys(
        review_workflow,
        {
            "repository",
            "workflow_path",
            "event",
            "run_id",
            "run_attempt",
            "head_sha",
        },
        "review.review_workflow",
    )
    _identifier(
        review_workflow["repository"], "review.review_workflow.repository"
    )
    if (
        review_workflow["workflow_path"]
        != ".github/workflows/phase1-independent-review.yml"
    ):
        raise QualificationError("review names the wrong authentication workflow")
    if review_workflow["event"] != "workflow_dispatch":
        raise QualificationError("review authentication must use workflow_dispatch")
    _positive_integer(
        review_workflow["run_id"], "review.review_workflow.run_id"
    )
    if (
        _positive_integer(
            review_workflow["run_attempt"],
            "review.review_workflow.run_attempt",
        )
        != 1
    ):
        raise QualificationError(
            "review authentication must use a fresh workflow dispatch"
        )
    if review_workflow["head_sha"] != expected_commit:
        raise QualificationError("review workflow used a different commit")
    blockers: list[str] = []
    if not reviewer_independent:
        blockers.append("review.reviewer_independent")
    if review["decision"] != "approved":
        blockers.append("review.decision")
    blockers.extend(
        f"review.{check_id}"
        for check_id, passed in review_checks.items()
        if not passed
    )
    if findings:
        blockers.append("review.open_findings")
    if review_delay > MAX_REVIEW_DELAY:
        blockers.append("review.review_delay")
    review["_reviewer_independent"] = reviewer_independent
    review["_review_delay_seconds"] = int(review_delay.total_seconds())
    review["_all_checks_passed"] = all(review_checks.values())
    review["_open_findings_count"] = len(findings)
    return review, review_sha, blockers


def _parse_review_provenance(
    path: Path,
    *,
    campaign_sha: str,
    review: dict[str, Any],
    review_sha: str,
    release_candidate: str,
    expected_commit: str,
) -> tuple[dict[str, Any], str]:
    report, report_sha = _load_json(
        path,
        "Phase 1 independent review provenance",
        MAX_REVIEW_PROVENANCE_BYTES,
    )
    _exact_keys(
        report,
        {
            "schema_version",
            "qualification_class",
            "generated_at",
            "repository",
            "release_candidate",
            "source",
            "campaign_sha256",
            "independent_review_sha256",
            "review_workflow",
            "review_signature_bundle_sha256",
            "reviewer_identity_authenticated",
            "github_review_workflow_provenance_verified",
            "github_review_artifact_bytes_verified",
            "keyless_review_signature_verified",
            "production_claim_allowed",
        },
        "review provenance",
    )
    if report["schema_version"] != SCHEMA_VERSION:
        raise QualificationError("review provenance schema_version is unsupported")
    if report["qualification_class"] != REVIEW_PROVENANCE_CLASS:
        raise QualificationError(
            "review provenance qualification_class is invalid"
        )
    if report["release_candidate"] != release_candidate:
        raise QualificationError(
            "review provenance release candidate does not match"
        )
    _source(report["source"], expected_commit, "review provenance.source")
    repository = _identifier(
        report["repository"], "review provenance.repository"
    )
    if repository != review["review_workflow"]["repository"]:
        raise QualificationError(
            "review provenance repository does not match signed review"
        )
    if report["campaign_sha256"] != campaign_sha:
        raise QualificationError(
            "review provenance does not bind the exact campaign bytes"
        )
    if report["independent_review_sha256"] != review_sha:
        raise QualificationError(
            "review provenance does not bind the exact review bytes"
        )
    _sha256(
        report["review_signature_bundle_sha256"],
        "review provenance.review_signature_bundle_sha256",
    )
    for field in (
        "reviewer_identity_authenticated",
        "github_review_workflow_provenance_verified",
        "github_review_artifact_bytes_verified",
        "keyless_review_signature_verified",
    ):
        if report[field] is not True:
            raise QualificationError(
                f"review provenance does not prove {field}"
            )
    if report["production_claim_allowed"] is not False:
        raise QualificationError(
            "review provenance must keep production_claim_allowed false"
        )
    generated_at = _timestamp(
        report["generated_at"], "review provenance.generated_at"
    )
    if generated_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise QualificationError("review provenance timestamp is in the future")
    if generated_at < _timestamp(review["reviewed_at"], "review.reviewed_at"):
        raise QualificationError(
            "review provenance predates the independent review"
        )
    workflow = _object(
        report["review_workflow"], "review provenance.review_workflow"
    )
    _exact_keys(
        workflow,
        {
            "run_id",
            "run_attempt",
            "workflow_path",
            "head_sha",
            "event",
            "workflow_updated_at",
        },
        "review provenance.review_workflow",
    )
    expected_workflow = review["review_workflow"]
    if (
        _positive_integer(
            workflow["run_id"], "review provenance.review_workflow.run_id"
        )
        != expected_workflow["run_id"]
        or _positive_integer(
            workflow["run_attempt"],
            "review provenance.review_workflow.run_attempt",
        )
        != expected_workflow["run_attempt"]
        or workflow["workflow_path"] != expected_workflow["workflow_path"]
        or workflow["head_sha"] != expected_workflow["head_sha"]
        or workflow["event"] != expected_workflow["event"]
    ):
        raise QualificationError(
            "review provenance workflow identity does not match signed review"
        )
    workflow_updated_at = _timestamp(
        workflow["workflow_updated_at"],
        "review provenance.review_workflow.workflow_updated_at",
    )
    if workflow_updated_at < _timestamp(
        review["reviewed_at"], "review.reviewed_at"
    ):
        raise QualificationError(
            "authenticated review workflow completed before the review"
        )
    if generated_at < workflow_updated_at:
        raise QualificationError(
            "review provenance predates the authenticated workflow completion"
        )
    return report, report_sha


def _parse_workflow_provenance(
    path: Path,
    *,
    campaign_sha: str,
    release_candidate: str,
    expected_commit: str,
    artifact_records: dict[str, dict[str, Any]],
    completion_times: list[dt.datetime],
) -> tuple[dict[str, Any], str]:
    report, report_sha = _load_json(
        path,
        "Phase 1 GitHub workflow provenance",
        MAX_WORKFLOW_PROVENANCE_BYTES,
    )
    _exact_keys(
        report,
        {
            "schema_version",
            "qualification_class",
            "generated_at",
            "repository",
            "release_candidate",
            "source",
            "campaign_sha256",
            "run_count",
            "artifact_count",
            "runs",
            "artifacts",
            "github_workflow_provenance_verified",
            "github_artifact_bytes_verified",
            "production_claim_allowed",
        },
        "workflow provenance",
    )
    if report["schema_version"] != SCHEMA_VERSION:
        raise QualificationError(
            "workflow provenance schema_version is unsupported"
        )
    if report["qualification_class"] != WORKFLOW_PROVENANCE_CLASS:
        raise QualificationError(
            "workflow provenance qualification_class is invalid"
        )
    if report["release_candidate"] != release_candidate:
        raise QualificationError(
            "workflow provenance release candidate does not match"
        )
    _source(report["source"], expected_commit, "workflow provenance.source")
    _identifier(report["repository"], "workflow provenance.repository")
    if report["campaign_sha256"] != campaign_sha:
        raise QualificationError(
            "workflow provenance does not bind the exact campaign bytes"
        )
    if (
        report["github_workflow_provenance_verified"] is not True
        or report["github_artifact_bytes_verified"] is not True
        or report["production_claim_allowed"] is not False
    ):
        raise QualificationError(
            "workflow provenance does not contain both required verified results"
        )
    generated_at = _timestamp(
        report["generated_at"], "workflow provenance.generated_at"
    )
    if generated_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise QualificationError("workflow provenance timestamp is in the future")
    if generated_at < max(completion_times):
        raise QualificationError(
            "workflow provenance predates one or more workflow artifacts"
        )

    expected_runs: dict[tuple[int, int], dict[str, Any]] = {}
    expected_artifacts: list[dict[str, Any]] = []
    for evidence_id in sorted(artifact_records):
        record = artifact_records[evidence_id]
        key = (record["workflow_run_id"], record["workflow_run_attempt"])
        run = expected_runs.setdefault(
            key,
            {
                "run_id": key[0],
                "run_attempt": key[1],
                "workflow_path": record["workflow_path"],
                "head_sha": expected_commit,
                "workflow_updated_at": record["workflow_completed_at"],
                "evidence_ids": [],
            },
        )
        if (
            run["workflow_path"] != record["workflow_path"]
            or run["workflow_updated_at"] != record["workflow_completed_at"]
        ):
            raise QualificationError(
                "campaign reuses one workflow attempt for mixed provenance"
            )
        run["evidence_ids"].append(evidence_id)
        expected_artifacts.append(
            {
                "evidence_id": evidence_id,
                "run_id": key[0],
                "run_attempt": key[1],
                "report_sha256": record["sha256"],
            }
        )

    runs = _array(
        report["runs"],
        "workflow provenance.runs",
        minimum=len(expected_runs),
        maximum=len(expected_runs),
    )
    parsed_runs: list[dict[str, Any]] = []
    for index, raw_run in enumerate(runs):
        run = _object(raw_run, f"workflow provenance.runs[{index}]")
        _exact_keys(
            run,
            {
                "run_id",
                "run_attempt",
                "workflow_path",
                "head_sha",
                "workflow_updated_at",
                "evidence_ids",
            },
            f"workflow provenance.runs[{index}]",
        )
        key = (
            _positive_integer(
                run["run_id"], f"workflow provenance.runs[{index}].run_id"
            ),
            _positive_integer(
                run["run_attempt"],
                f"workflow provenance.runs[{index}].run_attempt",
            ),
        )
        expected = expected_runs.get(key)
        if expected is None:
            raise QualificationError(
                "workflow provenance contains an unexpected workflow attempt"
            )
        evidence_ids = [
            _identifier(
                evidence_id,
                f"workflow provenance.runs[{index}].evidence_ids[]",
            )
            for evidence_id in _array(
                run["evidence_ids"],
                f"workflow provenance.runs[{index}].evidence_ids",
                minimum=1,
                maximum=MAX_ARTIFACTS,
            )
        ]
        parsed = {
            "run_id": key[0],
            "run_attempt": key[1],
            "workflow_path": run["workflow_path"],
            "head_sha": run["head_sha"],
            "workflow_updated_at": _timestamp(
                run["workflow_updated_at"],
                f"workflow provenance.runs[{index}].workflow_updated_at",
            ),
            "evidence_ids": evidence_ids,
        }
        if parsed != expected:
            raise QualificationError(
                "workflow provenance run does not match the campaign"
            )
        parsed_runs.append(parsed)
    if [
        (run["run_id"], run["run_attempt"]) for run in parsed_runs
    ] != sorted(expected_runs):
        raise QualificationError(
            "workflow provenance runs must be uniquely and canonically ordered"
        )
    if report["run_count"] != len(expected_runs):
        raise QualificationError("workflow provenance run_count is incorrect")

    artifacts = _array(
        report["artifacts"],
        "workflow provenance.artifacts",
        minimum=len(expected_artifacts),
        maximum=len(expected_artifacts),
    )
    parsed_artifacts: list[dict[str, Any]] = []
    for index, raw_artifact in enumerate(artifacts):
        artifact = _object(
            raw_artifact, f"workflow provenance.artifacts[{index}]"
        )
        _exact_keys(
            artifact,
            {
                "evidence_id",
                "run_id",
                "run_attempt",
                "artifact_name",
                "report_sha256",
            },
            f"workflow provenance.artifacts[{index}]",
        )
        _identifier(
            artifact["artifact_name"],
            f"workflow provenance.artifacts[{index}].artifact_name",
        )
        parsed_artifacts.append(
            {
                "evidence_id": _identifier(
                    artifact["evidence_id"],
                    f"workflow provenance.artifacts[{index}].evidence_id",
                ),
                "run_id": _positive_integer(
                    artifact["run_id"],
                    f"workflow provenance.artifacts[{index}].run_id",
                ),
                "run_attempt": _positive_integer(
                    artifact["run_attempt"],
                    f"workflow provenance.artifacts[{index}].run_attempt",
                ),
                "report_sha256": _sha256(
                    artifact["report_sha256"],
                    f"workflow provenance.artifacts[{index}].report_sha256",
                ),
            }
        )
    if parsed_artifacts != expected_artifacts:
        raise QualificationError(
            "workflow provenance artifact bytes do not match the campaign"
        )
    if report["artifact_count"] != len(expected_artifacts):
        raise QualificationError(
            "workflow provenance artifact_count is incorrect"
        )
    return report, report_sha


def evaluate(
    campaign_path: Path,
    review_path: Path,
    review_provenance_path: Path,
    workflow_provenance_path: Path,
    evidence_dir: Path,
    *,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
) -> dict[str, Any]:
    if RC_RE.fullmatch(release_candidate) is None:
        raise QualificationError("release candidate must be an exact vX.Y.Z-rc.N tag")
    if COMMIT_RE.fullmatch(expected_commit) is None:
        raise QualificationError("expected commit must be 40 lowercase hexadecimal characters")
    _identifier(expected_environment, "expected_environment")
    try:
        directory_metadata = evidence_dir.lstat()
    except OSError as error:
        raise QualificationError(f"cannot inspect evidence directory: {error}") from error
    if not stat.S_ISDIR(directory_metadata.st_mode) or stat.S_ISLNK(
        directory_metadata.st_mode
    ):
        raise QualificationError("evidence directory must be a real directory")

    campaign, campaign_sha, artifact_records, completion_times = _parse_campaign(
        campaign_path,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
    )
    promoted_providers = campaign["_validated_promoted_providers"]
    operator_ids = campaign["_validated_operator_ids"]
    on_device_environment = campaign["_validated_on_device_environment"]
    workflow_provenance, workflow_provenance_sha = _parse_workflow_provenance(
        workflow_provenance_path,
        campaign_sha=campaign_sha,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        artifact_records=artifact_records,
        completion_times=completion_times,
    )
    blockers: list[str] = []
    reports: dict[str, dict[str, Any]] = {}
    retained_artifacts: list[dict[str, Any]] = []
    for evidence_id in sorted(artifact_records):
        record = artifact_records[evidence_id]
        path = evidence_dir / record["path"]
        report, digest = _load_json(
            path, f"{evidence_id} evidence", MAX_EVIDENCE_BYTES
        )
        if digest != record["sha256"]:
            raise QualificationError(f"{evidence_id} digest does not match campaign")
        reports[evidence_id] = report
        blockers.extend(
            _validate_evidence(
                evidence_id,
                report,
                release_candidate=release_candidate,
                expected_commit=expected_commit,
                target_environment=expected_environment,
                on_device_environment=on_device_environment,
                promoted_providers=promoted_providers,
            )
        )
        retained_artifacts.append(
            {
                "evidence_id": evidence_id,
                "sha256": digest,
                "workflow_path": record["workflow_path"],
                "workflow_run_id": record["workflow_run_id"],
                "workflow_run_attempt": record["workflow_run_attempt"],
            }
        )

    slo_evidence = _object(reports["release-slo"].get("evidence"), "release-slo.evidence")
    if slo_evidence.get("resource_soak_sha256") != artifact_records["resource-soak"]["sha256"]:
        raise QualificationError("release SLO does not bind the retained resource soak")
    if slo_evidence.get("human_game_day_sha256") != artifact_records["game-day"]["sha256"]:
        raise QualificationError("release SLO does not bind the retained game day")

    review, review_sha, review_blockers = _parse_review(
        review_path,
        campaign_sha=campaign_sha,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
        on_device_environment=on_device_environment,
        operator_ids=operator_ids,
        completion_times=completion_times,
    )
    review_provenance, review_provenance_sha = _parse_review_provenance(
        review_provenance_path,
        campaign_sha=campaign_sha,
        review=review,
        review_sha=review_sha,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
    )
    blockers.extend(review_blockers)
    ready = not blockers
    return {
        "schema_version": SCHEMA_VERSION,
        "qualification_class": REPORT_CLASS,
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "status": "passed" if ready else "failed",
        "release_candidate": release_candidate,
        "source": {"commit": expected_commit, "dirty": False},
        "profile": {
            "profile_id": PROFILE_ID,
            "target_environment_id": expected_environment,
            "on_device_environment_id": on_device_environment,
        },
        "promoted_providers": promoted_providers,
        "evidence": {
            "campaign_sha256": campaign_sha,
            "independent_review_sha256": review_sha,
            "independent_review_provenance_sha256": review_provenance_sha,
            "workflow_provenance_sha256": workflow_provenance_sha,
            "artifact_count": len(retained_artifacts),
            "artifacts": retained_artifacts,
            "same_clean_source_commit": True,
            "same_release_candidate": True,
            "github_workflow_provenance_verified": workflow_provenance[
                "github_workflow_provenance_verified"
            ],
            "github_artifact_bytes_verified": workflow_provenance[
                "github_artifact_bytes_verified"
            ],
            "github_review_workflow_provenance_verified": review_provenance[
                "github_review_workflow_provenance_verified"
            ],
            "github_review_artifact_bytes_verified": review_provenance[
                "github_review_artifact_bytes_verified"
            ],
            "keyless_review_signature_verified": review_provenance[
                "keyless_review_signature_verified"
            ],
        },
        "review": {
            "reviewed_at": review["reviewed_at"],
            "reviewer_independent": review["_reviewer_independent"],
            "reviewer_identity_authenticated": review_provenance[
                "reviewer_identity_authenticated"
            ],
            "decision": review["decision"],
            "all_checks_passed": review["_all_checks_passed"],
            "open_findings_count": review["_open_findings_count"],
            "review_delay_seconds": review["_review_delay_seconds"],
            "review_attestation_sha256": review["review_attestation_sha256"],
        },
        "phase1_release_candidate_ready": ready,
        "production_claim_allowed": False,
        "eligibility_blockers": blockers,
        "caveats": [
            "This decision is limited to the restricted single-node Linux rootless-container CLI release candidate and promoted provider/model set named above.",
            "The bounded report proves GitHub-authenticated evidence and independent-review workflow attempts, downloaded artifact bytes, and the keyless review signature in addition to cross-artifact schema, digest, exact-source, environment, and reviewer-separation contracts.",
            "Whole-product production approval remains false until provider/client, distributed-control-plane, independent-security, and final v1 release gates pass.",
        ],
    }


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def validate_contract() -> None:
    if len(PROVIDERS) != len(set(PROVIDERS)) or not HOSTED_PROVIDERS:
        raise QualificationError("provider catalog is invalid")
    if set(BASE_EVIDENCE) != {
        "linux-cli-rc",
        "live-provider-plan",
        "on-device",
        "target-remote-backup",
        "storage-profile",
        "external-deletion",
        "resource-soak",
        "release-slo",
        "game-day",
    }:
        raise QualificationError("Phase 1 evidence inventory changed")
    if len(REVIEW_CHECK_IDS) != len(set(REVIEW_CHECK_IDS)):
        raise QualificationError("review check inventory contains duplicates")
    for evidence_id, (filename, workflow) in BASE_EVIDENCE.items():
        if Path(filename).name != filename or not workflow.startswith(
            ".github/workflows/"
        ):
            raise QualificationError(f"unsafe evidence contract for {evidence_id}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--review", type=Path)
    parser.add_argument("--review-provenance", type=Path)
    parser.add_argument("--workflow-provenance", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--release-candidate")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-environment")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-eligible", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_contract()
        execution_values = (
            args.campaign,
            args.review,
            args.review_provenance,
            args.workflow_provenance,
            args.evidence_dir,
            args.release_candidate,
            args.expected_commit,
            args.expected_environment,
            args.output,
        )
        if args.validate:
            if any(value is not None for value in execution_values) or args.require_eligible:
                raise QualificationError(
                    "--validate cannot be combined with execution arguments"
                )
            print(
                f"validated Phase 1 promotion schema v{SCHEMA_VERSION}: "
                f"{len(BASE_EVIDENCE)} base artifacts, {len(PROVIDERS)} providers"
            )
            return 0
        if any(value is None for value in execution_values):
            raise QualificationError(
                "--campaign, --review, --review-provenance, --evidence-dir, "
                "--release-candidate, --workflow-provenance, --expected-commit, "
                "--expected-environment, and --output are required"
            )
        report = evaluate(
            args.campaign,
            args.review,
            args.review_provenance,
            args.workflow_provenance,
            args.evidence_dir,
            release_candidate=args.release_candidate,
            expected_commit=args.expected_commit,
            expected_environment=args.expected_environment,
        )
        _write_report(args.output, report)
        if args.require_eligible and not report["phase1_release_candidate_ready"]:
            return 1
    except (QualificationError, OSError) as error:
        print(f"Phase 1 promotion qualification failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
