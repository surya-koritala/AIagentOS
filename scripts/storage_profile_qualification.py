#!/usr/bin/env python3
"""Validate destructive storage evidence for the supported v1 deployment profile.

Raw fault-controller logs, device identifiers, operator identity, and the
independent attestation remain in an operator-controlled evidence store. This
validator accepts only bounded JSON summaries, recalculates RPO/RTO from UTC
timestamps, binds review to the exact observation bytes, and emits a non-secret
report. It never turns an unexecuted or synthetic fault into production proof.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


class QualificationError(RuntimeError):
    """The evidence is malformed or does not satisfy the qualification contract."""


SCHEMA_VERSION = 1
SUITE = "agentos-v1-destructive-storage-profile"
OBSERVATION_CLASS = "destructive_storage_profile_observation"
REVIEW_CLASS = "independent_destructive_storage_review"
REPORT_CLASS = "exact_release_candidate_destructive_storage_profile"
SUPPORTED_PROFILE_ID = "single-node-linux-rootless-container-cli"
TARGET_RPO_SECONDS = 300
TARGET_RTO_SECONDS = 3_600
MAX_EVIDENCE_BYTES = 512 * 1024
MAX_REVIEW_DELAY_SECONDS = 30 * 24 * 60 * 60
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_CANDIDATE_RE = re.compile(
    r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?$"
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,99}$")
NON_TARGET_IDENTIFIERS = {
    "dev",
    "development",
    "fixture",
    "local",
    "mock",
    "test",
}

SCENARIO_CONTRACT = {
    "host-power-loss": {
        "fault_mechanism": "out_of_band_power_cut",
        "recovery_sources": {"local-journal", "immutable-remote-backup"},
        "requires_boot_change": True,
    },
    "torn-write": {
        "fault_mechanism": "block_level_torn_write",
        "recovery_sources": {"immutable-remote-backup"},
        "requires_boot_change": False,
    },
    "device-loss": {
        "fault_mechanism": "storage_device_detached",
        "recovery_sources": {"immutable-remote-backup"},
        "requires_boot_change": False,
    },
}
SCENARIO_IDS = tuple(SCENARIO_CONTRACT)
REVIEW_CHECK_IDS = (
    "actual_out_of_band_power_cut_reviewed",
    "block_level_torn_write_reviewed",
    "storage_device_detachment_reviewed",
    "recovery_identity_and_integrity_reviewed",
    "rpo_rto_measurements_reviewed",
    "target_profile_matches_release_contract",
    "raw_evidence_retained",
)


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise QualificationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise QualificationError(f"{label} is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise QualificationError(f"{label} must be a regular non-symlink file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_EVIDENCE_BYTES:
            raise QualificationError(f"{label} has an invalid size")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(MAX_EVIDENCE_BYTES + 1)
        if len(raw) != metadata.st_size or len(raw) > MAX_EVIDENCE_BYTES:
            raise QualificationError(f"{label} changed while being read")
        value = json.loads(raw, object_pairs_hook=_duplicates_rejected)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"{label} is not valid JSON") from error
    finally:
        os.close(descriptor)
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must contain one JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def _exact_keys(value: dict[str, Any], expected: set[str], path: str) -> None:
    actual = set(value)
    if actual != expected:
        raise QualificationError(
            f"{path} keys differ: missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QualificationError(f"{path} must be an object")
    return value


def _array(value: Any, path: str, *, minimum: int, maximum: int) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise QualificationError(
            f"{path} must be an array with {minimum}..{maximum} entries"
        )
    return value


def _string(value: Any, path: str, *, max_length: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(ord(character) < 0x20 for character in value)
    ):
        raise QualificationError(f"{path} must be a bounded non-empty string")
    return value


def _identifier(value: Any, path: str, *, target: bool = False) -> str:
    result = _string(value, path, max_length=100)
    if not IDENTIFIER_RE.fullmatch(result):
        raise QualificationError(f"{path} must be a stable non-secret identifier")
    if target:
        components = re.split(r"[._:@-]+", result.lower())
        if any(component in NON_TARGET_IDENTIFIERS for component in components):
            raise QualificationError(f"{path} must identify a non-fixture target")
    return result


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{path} must be a boolean")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise QualificationError(f"{path} must be an integer >= {minimum}")
    return value


def _sha256(value: Any, path: str) -> str:
    result = _string(value, path, max_length=64)
    if not SHA256_RE.fullmatch(result):
        raise QualificationError(f"{path} must be a lowercase SHA-256 digest")
    return result


def _timestamp(value: Any, path: str) -> dt.datetime:
    text = _string(value, path, max_length=40)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise QualificationError(f"{path} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QualificationError(f"{path} must include a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def _seconds(later: dt.datetime, earlier: dt.datetime) -> int:
    value = (later - earlier).total_seconds()
    if not math.isfinite(value) or value < 0 or not value.is_integer():
        raise QualificationError("derived durations must be non-negative whole seconds")
    return int(value)


def _source(value: Any, expected_commit: str, path: str) -> dict[str, Any]:
    source = _object(value, path)
    _exact_keys(source, {"commit", "dirty"}, path)
    commit = _string(source["commit"], f"{path}.commit", max_length=40)
    if not FULL_SHA_RE.fullmatch(commit) or commit != expected_commit:
        raise QualificationError(f"{path}.commit must match the exact requested commit")
    if _boolean(source["dirty"], f"{path}.dirty"):
        raise QualificationError(f"{path}.dirty must be false")
    return {"commit": commit, "dirty": False}


def _validate_scenario(
    value: Any,
    *,
    exercise_start: dt.datetime,
    exercise_end: dt.datetime,
) -> dict[str, Any]:
    scenario = _object(value, "observation.scenarios[]")
    _exact_keys(
        scenario,
        {
            "scenario_id",
            "started_at",
            "last_acknowledged_write_at",
            "fault_injected_at",
            "recovery_started_at",
            "newest_recovered_write_at",
            "service_healthy_at",
            "fault_mechanism",
            "recovery_source",
            "pre_fault_boot_id_sha256",
            "post_recovery_boot_id_sha256",
            "expected_fault_observed",
            "sqlite_quick_check",
            "installation_identity_verified",
            "recovery_artifact_verified",
            "enforcement_rearmed",
            "unexpected_tenant_accesses",
            "evidence_sha256",
        },
        "observation.scenarios[]",
    )
    scenario_id = _identifier(scenario["scenario_id"], "scenario.scenario_id")
    contract = SCENARIO_CONTRACT.get(scenario_id)
    if contract is None:
        raise QualificationError(f"unknown destructive scenario {scenario_id!r}")

    started = _timestamp(scenario["started_at"], f"{scenario_id}.started_at")
    last_ack = _timestamp(
        scenario["last_acknowledged_write_at"],
        f"{scenario_id}.last_acknowledged_write_at",
    )
    fault = _timestamp(scenario["fault_injected_at"], f"{scenario_id}.fault_injected_at")
    recovery = _timestamp(
        scenario["recovery_started_at"], f"{scenario_id}.recovery_started_at"
    )
    newest = _timestamp(
        scenario["newest_recovered_write_at"],
        f"{scenario_id}.newest_recovered_write_at",
    )
    healthy = _timestamp(
        scenario["service_healthy_at"], f"{scenario_id}.service_healthy_at"
    )
    if not (
        exercise_start
        <= started
        <= newest
        <= last_ack
        <= fault
        <= recovery
        <= healthy
        <= exercise_end
    ):
        raise QualificationError(f"{scenario_id} timeline is not monotonic")

    mechanism = _identifier(
        scenario["fault_mechanism"], f"{scenario_id}.fault_mechanism"
    )
    if mechanism != contract["fault_mechanism"]:
        raise QualificationError(f"{scenario_id} uses the wrong real fault mechanism")
    recovery_source = _identifier(
        scenario["recovery_source"], f"{scenario_id}.recovery_source"
    )
    if recovery_source not in contract["recovery_sources"]:
        raise QualificationError(f"{scenario_id} uses an ineligible recovery source")

    pre_boot = _sha256(
        scenario["pre_fault_boot_id_sha256"],
        f"{scenario_id}.pre_fault_boot_id_sha256",
    )
    post_boot = _sha256(
        scenario["post_recovery_boot_id_sha256"],
        f"{scenario_id}.post_recovery_boot_id_sha256",
    )
    boot_changed = pre_boot != post_boot
    if contract["requires_boot_change"] and not boot_changed:
        raise QualificationError(
            "host-power-loss must prove different pre-fault and post-recovery boot IDs"
        )

    rpo_seconds = _seconds(last_ack, newest)
    rto_seconds = _seconds(healthy, fault)
    checks = {
        "real_fault_mechanism_observed": _boolean(
            scenario["expected_fault_observed"],
            f"{scenario_id}.expected_fault_observed",
        ),
        "rpo_within_target": rpo_seconds <= TARGET_RPO_SECONDS,
        "rto_within_target": rto_seconds <= TARGET_RTO_SECONDS,
        "database_integrity_verified": _string(
            scenario["sqlite_quick_check"],
            f"{scenario_id}.sqlite_quick_check",
            max_length=20,
        )
        == "ok",
        "installation_identity_verified": _boolean(
            scenario["installation_identity_verified"],
            f"{scenario_id}.installation_identity_verified",
        ),
        "recovery_artifact_verified": _boolean(
            scenario["recovery_artifact_verified"],
            f"{scenario_id}.recovery_artifact_verified",
        ),
        "enforcement_rearmed": _boolean(
            scenario["enforcement_rearmed"], f"{scenario_id}.enforcement_rearmed"
        ),
        "tenant_boundary_preserved": _integer(
            scenario["unexpected_tenant_accesses"],
            f"{scenario_id}.unexpected_tenant_accesses",
        )
        == 0,
        "boot_transition_verified": not contract["requires_boot_change"]
        or boot_changed,
    }
    return {
        "scenario_id": scenario_id,
        "fault_mechanism": mechanism,
        "recovery_source": recovery_source,
        "rpo_seconds": rpo_seconds,
        "rto_seconds": rto_seconds,
        "target_rpo_seconds": TARGET_RPO_SECONDS,
        "target_rto_seconds": TARGET_RTO_SECONDS,
        "evidence_sha256": _sha256(
            scenario["evidence_sha256"], f"{scenario_id}.evidence_sha256"
        ),
        "checks": checks,
        "passed": all(checks.values()),
    }


def validate_contract() -> None:
    if (
        SCHEMA_VERSION != 1
        or tuple(SCENARIO_CONTRACT) != SCENARIO_IDS
        or len(SCENARIO_IDS) != 3
        or len(REVIEW_CHECK_IDS) != 7
        or TARGET_RPO_SECONDS <= 0
        or TARGET_RTO_SECONDS <= TARGET_RPO_SECONDS
    ):
        raise QualificationError("destructive storage qualification constants are invalid")


def evaluate(
    observation_path: Path,
    review_path: Path,
    *,
    expected_commit: str,
    expected_environment: str,
    release_candidate: str,
) -> dict[str, Any]:
    validate_contract()
    if not FULL_SHA_RE.fullmatch(expected_commit):
        raise QualificationError("expected commit must be a full lowercase Git SHA")
    if not RELEASE_CANDIDATE_RE.fullmatch(release_candidate):
        raise QualificationError("release candidate must be vX.Y.Z or vX.Y.Z-rc.N")
    expected_environment = _identifier(
        expected_environment, "expected_environment", target=True
    )

    observation, observation_sha256 = _load_json(
        observation_path, "storage observation"
    )
    _exact_keys(
        observation,
        {
            "schema_version",
            "qualification_class",
            "release_candidate",
            "source",
            "environment",
            "profile",
            "exercise",
            "scenarios",
        },
        "observation",
    )
    if _integer(observation["schema_version"], "observation.schema_version") != 1:
        raise QualificationError("observation schema version is unsupported")
    if (
        _string(
            observation["qualification_class"],
            "observation.qualification_class",
        )
        != OBSERVATION_CLASS
    ):
        raise QualificationError("observation qualification class is wrong")
    if (
        _string(
            observation["release_candidate"], "observation.release_candidate"
        )
        != release_candidate
    ):
        raise QualificationError("observation release candidate does not match")
    source = _source(observation["source"], expected_commit, "observation.source")

    environment = _object(observation["environment"], "observation.environment")
    _exact_keys(
        environment,
        {
            "environment_id",
            "deployment_mode",
            "os",
            "arch",
            "filesystem_type",
            "filesystem_configuration_sha256",
            "storage_stack_id",
            "object_store_service_id",
            "configuration_sha256",
        },
        "observation.environment",
    )
    environment_id = _identifier(
        environment["environment_id"],
        "observation.environment.environment_id",
        target=True,
    )
    if environment_id != expected_environment:
        raise QualificationError("observation environment does not match")
    deployment_mode = _identifier(
        environment["deployment_mode"], "observation.environment.deployment_mode"
    )
    operating_system = _identifier(
        environment["os"], "observation.environment.os"
    )
    architecture = _identifier(
        environment["arch"], "observation.environment.arch"
    )
    if (
        deployment_mode != "single-node"
        or operating_system != "linux"
        or architecture != "x86_64"
    ):
        raise QualificationError(
            "storage evidence must use the supported single-node Linux x86_64 profile"
        )
    report_environment = {
        "environment_id": environment_id,
        "deployment_mode": deployment_mode,
        "os": operating_system,
        "arch": architecture,
        "filesystem_type": _identifier(
            environment["filesystem_type"],
            "observation.environment.filesystem_type",
            target=True,
        ),
        "filesystem_configuration_sha256": _sha256(
            environment["filesystem_configuration_sha256"],
            "observation.environment.filesystem_configuration_sha256",
        ),
        "storage_stack_id": _identifier(
            environment["storage_stack_id"],
            "observation.environment.storage_stack_id",
            target=True,
        ),
        "object_store_service_id": _identifier(
            environment["object_store_service_id"],
            "observation.environment.object_store_service_id",
            target=True,
        ),
        "configuration_sha256": _sha256(
            environment["configuration_sha256"],
            "observation.environment.configuration_sha256",
        ),
    }

    profile = _object(observation["profile"], "observation.profile")
    _exact_keys(
        profile,
        {"profile_id", "target_rpo_seconds", "target_rto_seconds"},
        "observation.profile",
    )
    profile_id = _identifier(profile["profile_id"], "observation.profile.profile_id")
    if profile_id != SUPPORTED_PROFILE_ID:
        raise QualificationError("observation profile is not the supported v1 profile")
    if (
        _integer(
            profile["target_rpo_seconds"],
            "observation.profile.target_rpo_seconds",
            minimum=1,
        )
        != TARGET_RPO_SECONDS
        or _integer(
            profile["target_rto_seconds"],
            "observation.profile.target_rto_seconds",
            minimum=1,
        )
        != TARGET_RTO_SECONDS
    ):
        raise QualificationError("observation RPO/RTO targets do not match the contract")

    exercise = _object(observation["exercise"], "observation.exercise")
    _exact_keys(
        exercise,
        {"exercise_id", "started_at", "ended_at", "operator_id", "harness_id"},
        "observation.exercise",
    )
    exercise_id = _identifier(
        exercise["exercise_id"], "observation.exercise.exercise_id"
    )
    exercise_start = _timestamp(
        exercise["started_at"], "observation.exercise.started_at"
    )
    exercise_end = _timestamp(exercise["ended_at"], "observation.exercise.ended_at")
    exercise_seconds = _seconds(exercise_end, exercise_start)
    if exercise_seconds <= 0 or exercise_seconds > 48 * 60 * 60:
        raise QualificationError("storage exercise duration must be 1 second..48 hours")
    operator_id = _identifier(
        exercise["operator_id"], "observation.exercise.operator_id"
    )
    harness_id = _identifier(
        exercise["harness_id"], "observation.exercise.harness_id", target=True
    )

    raw_scenarios = _array(
        observation["scenarios"],
        "observation.scenarios",
        minimum=len(SCENARIO_IDS),
        maximum=len(SCENARIO_IDS),
    )
    scenarios = [
        _validate_scenario(
            scenario,
            exercise_start=exercise_start,
            exercise_end=exercise_end,
        )
        for scenario in raw_scenarios
    ]
    scenario_ids = [scenario["scenario_id"] for scenario in scenarios]
    if scenario_ids != list(SCENARIO_IDS):
        raise QualificationError(
            "destructive scenarios must appear once in the fixed contract order"
        )

    review, review_sha256 = _load_json(review_path, "storage review")
    _exact_keys(
        review,
        {
            "schema_version",
            "qualification_class",
            "release_candidate",
            "source",
            "environment_id",
            "profile_id",
            "observation_sha256",
            "reviewer_id",
            "reviewed_at",
            "decision",
            "review_attestation_sha256",
            "scenario_ids",
            "checks",
            "open_findings",
        },
        "review",
    )
    if _integer(review["schema_version"], "review.schema_version") != 1:
        raise QualificationError("review schema version is unsupported")
    if (
        _string(review["qualification_class"], "review.qualification_class")
        != REVIEW_CLASS
    ):
        raise QualificationError("review qualification class is wrong")
    if (
        _string(review["release_candidate"], "review.release_candidate")
        != release_candidate
    ):
        raise QualificationError("review release candidate does not match")
    _source(review["source"], expected_commit, "review.source")
    if (
        _identifier(review["environment_id"], "review.environment_id", target=True)
        != environment_id
        or _identifier(review["profile_id"], "review.profile_id") != profile_id
    ):
        raise QualificationError("review target identity does not match observation")
    if _sha256(review["observation_sha256"], "review.observation_sha256") != observation_sha256:
        raise QualificationError("review is not bound to the exact observation bytes")
    reviewer_id = _identifier(review["reviewer_id"], "review.reviewer_id")
    reviewer_independent = reviewer_id.casefold() not in {
        operator_id.casefold(),
        harness_id.casefold(),
    }
    reviewed_at = _timestamp(review["reviewed_at"], "review.reviewed_at")
    review_delay_seconds = _seconds(reviewed_at, exercise_end)
    if review_delay_seconds > MAX_REVIEW_DELAY_SECONDS:
        raise QualificationError("review occurred too long after the exercise")
    decision = _identifier(review["decision"], "review.decision")
    if decision not in {"approved", "rejected"}:
        raise QualificationError("review decision must be approved or rejected")
    reviewed_scenario_ids = [
        _identifier(value, "review.scenario_ids[]")
        for value in _array(
            review["scenario_ids"],
            "review.scenario_ids",
            minimum=len(SCENARIO_IDS),
            maximum=len(SCENARIO_IDS),
        )
    ]
    if reviewed_scenario_ids != list(SCENARIO_IDS):
        raise QualificationError("review scenario inventory is incomplete or reordered")
    checks = _object(review["checks"], "review.checks")
    _exact_keys(checks, set(REVIEW_CHECK_IDS), "review.checks")
    review_checks = {
        check_id: _boolean(checks[check_id], f"review.checks.{check_id}")
        for check_id in REVIEW_CHECK_IDS
    }
    findings = [
        _string(value, "review.open_findings[]", max_length=300)
        for value in _array(
            review["open_findings"], "review.open_findings", minimum=0, maximum=20
        )
    ]

    failed_scenarios = [
        scenario["scenario_id"] for scenario in scenarios if not scenario["passed"]
    ]
    blockers: list[str] = []
    if failed_scenarios:
        blockers.append("one or more destructive scenarios failed")
    if not reviewer_independent:
        blockers.append("reviewer is not independent of operator and harness")
    if decision != "approved":
        blockers.append("independent review decision is not approved")
    if not all(review_checks.values()):
        blockers.append("one or more independent review checks failed")
    if findings:
        blockers.append("independent review has open findings")
    proof_eligible = not blockers

    return {
        "schema_version": SCHEMA_VERSION,
        "suite": SUITE,
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "qualification_class": REPORT_CLASS,
        "release_candidate": release_candidate,
        "source": source,
        "environment": report_environment,
        "profile": {
            "profile_id": profile_id,
            "target_rpo_seconds": TARGET_RPO_SECONDS,
            "target_rto_seconds": TARGET_RTO_SECONDS,
        },
        "exercise": {
            "exercise_id": exercise_id,
            "duration_seconds": exercise_seconds,
            "harness_id": harness_id,
        },
        "evidence": {
            "observation_sha256": observation_sha256,
            "review_sha256": review_sha256,
        },
        "scenarios": scenarios,
        "failed_scenarios": failed_scenarios,
        "review": {
            "reviewed_at": reviewed_at.isoformat().replace("+00:00", "Z"),
            "review_delay_seconds": review_delay_seconds,
            "reviewer_independent": reviewer_independent,
            "decision": decision,
            "review_attestation_sha256": _sha256(
                review["review_attestation_sha256"],
                "review.review_attestation_sha256",
            ),
            "all_checks_passed": all(review_checks.values()),
            "open_findings_count": len(findings),
        },
        "destructive_storage_profile_completed": all(
            scenario["passed"] for scenario in scenarios
        ),
        "storage_profile_proof_eligible": proof_eligible,
        "production_claim_allowed": False,
        "passed": proof_eligible,
        "eligibility_blockers": blockers,
        "caveats": [
            "Eligibility requires externally retained raw controller/device evidence and independent identity attestation; this bounded report cannot authenticate people or hardware by itself.",
            "This report qualifies only the declared filesystem/storage stack and exact supported single-node Linux profile.",
            "Whole-product production approval remains false until every Phase 1 and independent release gate passes.",
        ],
    }


def _local_source() -> tuple[str, bool]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise QualificationError("local Git source identity is unavailable") from error
    return commit, dirty


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except OSError as error:
        raise QualificationError("report destination must be a new regular file") from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as target:
            target.write(encoded)
            target.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--review", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-environment")
    parser.add_argument("--release-candidate")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-eligible", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    execution_values = (
        args.observation,
        args.review,
        args.expected_commit,
        args.expected_environment,
        args.release_candidate,
        args.output,
    )
    if args.validate:
        if any(value is not None for value in execution_values) or args.require_eligible:
            parser.error("--validate cannot be combined with execution arguments")
        validate_contract()
        print(
            f"validated destructive storage schema v{SCHEMA_VERSION}: "
            f"{REPORT_CLASS}, {SUPPORTED_PROFILE_ID}, "
            f"RPO<={TARGET_RPO_SECONDS}s, RTO<={TARGET_RTO_SECONDS}s"
        )
        return 0
    if any(value is None for value in execution_values):
        parser.error("qualification execution requires every documented argument")
    local_commit, local_dirty = _local_source()
    if local_commit != args.expected_commit or local_dirty:
        raise QualificationError(
            "qualification must run from the exact clean requested commit"
        )
    report = evaluate(
        args.observation,
        args.review,
        expected_commit=args.expected_commit,
        expected_environment=args.expected_environment,
        release_candidate=args.release_candidate,
    )
    _write_report(args.output, report)
    if args.require_eligible and not report["storage_profile_proof_eligible"]:
        raise QualificationError("destructive storage evidence is not eligible")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except QualificationError as error:
        print(f"storage profile qualification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
