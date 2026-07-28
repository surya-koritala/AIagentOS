#!/usr/bin/env python3
"""Validate exact-RC external deletion and retention evidence.

The target harness and independent reviewer retain raw service responses,
controller logs, identities, and credentials outside GitHub. This validator
accepts bounded hash-linked summaries, recalculates lifecycle completion time,
checks every external boundary in the versioned contract, and emits a
non-secret report. It cannot turn a fixture or policy assertion into proof.
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
    """The supplied evidence does not satisfy the qualification contract."""


SCHEMA_VERSION = 1
SUITE = "agentos-v1-external-deletion-retention"
OBSERVATION_CLASS = "external_deletion_retention_observation"
REVIEW_CLASS = "independent_external_deletion_retention_review"
REPORT_CLASS = "exact_release_candidate_external_deletion_retention"
CONTRACT_PATH = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "external-data-boundaries.json"
)
MAX_EVIDENCE_BYTES = 512 * 1024
MAX_SYSTEM_RECORDS = 64
MAX_EXERCISE_SECONDS = 45 * 24 * 60 * 60
MAX_REVIEW_DELAY_SECONDS = 30 * 24 * 60 * 60
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_CANDIDATE_RE = re.compile(
    r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?$"
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,99}$")
NON_TARGET_COMPONENTS = {
    "dev",
    "development",
    "fixture",
    "local",
    "mock",
    "test",
}
REVIEW_CHECK_IDS = (
    "target_configuration_matches_release_candidate",
    "every_configured_external_system_exercised",
    "deletion_and_retention_timelines_recalculated",
    "absence_reproduced_with_fresh_principal",
    "immutable_backup_retention_and_final_deletion_reviewed",
    "cross_tenant_access_results_reviewed",
    "raw_service_evidence_retained",
    "external_policy_owners_approved",
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
        if any(component in NON_TARGET_COMPONENTS for component in components):
            raise QualificationError(f"{path} must identify a non-fixture target")
    return result


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{path} must be a boolean")
    return value


def _integer(
    value: Any,
    path: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise QualificationError(f"{path} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise QualificationError(f"{path} must be an integer <= {maximum}")
    return value


def _sha256(value: Any, path: str) -> str:
    result = _string(value, path, max_length=64)
    if not SHA256_RE.fullmatch(result):
        raise QualificationError(f"{path} must be a lowercase SHA-256 digest")
    return result


def _optional_sha256(value: Any, path: str) -> str | None:
    return None if value is None else _sha256(value, path)


def _timestamp(value: Any, path: str) -> dt.datetime:
    text = _string(value, path, max_length=40)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise QualificationError(f"{path} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QualificationError(f"{path} must include a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def _optional_timestamp(value: Any, path: str) -> dt.datetime | None:
    return None if value is None else _timestamp(value, path)


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


def _load_contract() -> tuple[dict[str, Any], str]:
    contract, digest = _load_json(CONTRACT_PATH, "external boundary contract")
    _exact_keys(
        contract,
        {
            "schema_version",
            "profile_id",
            "maximum_completion_seconds",
            "required_configured_boundaries",
            "boundaries",
        },
        "contract",
    )
    if _integer(contract["schema_version"], "contract.schema_version") != SCHEMA_VERSION:
        raise QualificationError("external boundary contract schema is unsupported")
    profile_id = _identifier(contract["profile_id"], "contract.profile_id")
    maximum = _integer(
        contract["maximum_completion_seconds"],
        "contract.maximum_completion_seconds",
        minimum=1,
        maximum=MAX_EXERCISE_SECONDS,
    )
    raw_boundaries = _array(
        contract["boundaries"], "contract.boundaries", minimum=1, maximum=32
    )
    boundaries: list[dict[str, Any]] = []
    boundary_ids: list[str] = []
    for index, raw_boundary in enumerate(raw_boundaries):
        boundary = _object(raw_boundary, f"contract.boundaries[{index}]")
        _exact_keys(
            boundary,
            {"boundary_id", "eligible_modes"},
            f"contract.boundaries[{index}]",
        )
        boundary_id = _string(
            boundary["boundary_id"],
            f"contract.boundaries[{index}].boundary_id",
            max_length=96,
        )
        if not boundary_id.startswith("external/") or boundary_id in boundary_ids:
            raise QualificationError("contract boundary IDs must be unique external IDs")
        modes = [
            _identifier(value, f"{boundary_id}.eligible_modes[]")
            for value in _array(
                boundary["eligible_modes"],
                f"{boundary_id}.eligible_modes",
                minimum=1,
                maximum=8,
            )
        ]
        if len(set(modes)) != len(modes):
            raise QualificationError(f"{boundary_id} has duplicate lifecycle modes")
        boundary_ids.append(boundary_id)
        boundaries.append({"boundary_id": boundary_id, "eligible_modes": modes})
    required = [
        _string(value, "contract.required_configured_boundaries[]", max_length=96)
        for value in _array(
            contract["required_configured_boundaries"],
            "contract.required_configured_boundaries",
            minimum=1,
            maximum=len(boundary_ids),
        )
    ]
    if len(set(required)) != len(required) or any(
        boundary not in boundary_ids for boundary in required
    ):
        raise QualificationError("required configured boundaries are invalid")
    return (
        {
            "schema_version": SCHEMA_VERSION,
            "profile_id": profile_id,
            "maximum_completion_seconds": maximum,
            "required_configured_boundaries": required,
            "boundaries": boundaries,
        },
        digest,
    )


def _validate_exercise(
    value: Any,
    *,
    boundary_id: str,
    system_id: str,
    mode: str,
    exercise_start: dt.datetime,
    exercise_end: dt.datetime,
    maximum_completion_seconds: int,
) -> dict[str, Any]:
    exercise = _object(value, f"{boundary_id}/{system_id}.exercise")
    _exact_keys(
        exercise,
        {
            "started_at",
            "canary_created_at",
            "lifecycle_action_at",
            "retention_expires_at",
            "data_absent_at",
            "verified_at",
            "target_completion_seconds",
            "canary_created",
            "canary_discoverable_before_action",
            "early_deletion_denied",
            "lifecycle_action_accepted",
            "retention_expiry_observed",
            "canary_absent_after_action",
            "fresh_principal_absence_verified",
            "residual_objects",
            "unexpected_tenant_accesses",
        },
        f"{boundary_id}/{system_id}.exercise",
    )
    started = _timestamp(exercise["started_at"], f"{system_id}.started_at")
    created = _timestamp(
        exercise["canary_created_at"], f"{system_id}.canary_created_at"
    )
    action = _timestamp(
        exercise["lifecycle_action_at"], f"{system_id}.lifecycle_action_at"
    )
    retention_expires = _optional_timestamp(
        exercise["retention_expires_at"], f"{system_id}.retention_expires_at"
    )
    absent = _timestamp(exercise["data_absent_at"], f"{system_id}.data_absent_at")
    verified = _timestamp(exercise["verified_at"], f"{system_id}.verified_at")
    if not (
        exercise_start
        <= started
        <= created
        <= action
        <= absent
        <= verified
        <= exercise_end
    ):
        raise QualificationError(f"{boundary_id}/{system_id} timeline is not monotonic")
    retention_mode = mode in {
        "bounded-retention",
        "immutable-retention-then-delete",
    }
    if retention_mode:
        if retention_expires is None or not created <= retention_expires <= action:
            raise QualificationError(
                f"{boundary_id}/{system_id} must bind expiry before final action"
            )
        completion_seconds = _seconds(absent, retention_expires)
    else:
        if retention_expires is not None:
            raise QualificationError(
                f"{boundary_id}/{system_id} must not invent a retention expiry"
            )
        reference = created if mode == "zero-data-retention" else action
        completion_seconds = _seconds(absent, reference)
    target = _integer(
        exercise["target_completion_seconds"],
        f"{system_id}.target_completion_seconds",
        minimum=1,
        maximum=maximum_completion_seconds,
    )
    discoverable = _boolean(
        exercise["canary_discoverable_before_action"],
        f"{system_id}.canary_discoverable_before_action",
    )
    early_denied = _boolean(
        exercise["early_deletion_denied"], f"{system_id}.early_deletion_denied"
    )
    expiry_observed = _boolean(
        exercise["retention_expiry_observed"],
        f"{system_id}.retention_expiry_observed",
    )
    checks = {
        "canary_created": _boolean(
            exercise["canary_created"], f"{system_id}.canary_created"
        ),
        "pre_action_state_matches_mode": (
            not discoverable if mode == "zero-data-retention" else discoverable
        ),
        "immutable_early_delete_denied": (
            early_denied if mode == "immutable-retention-then-delete" else not early_denied
        ),
        "lifecycle_action_accepted": _boolean(
            exercise["lifecycle_action_accepted"],
            f"{system_id}.lifecycle_action_accepted",
        ),
        "retention_expiry_observed": (
            expiry_observed if retention_mode else not expiry_observed
        ),
        "completion_within_target": completion_seconds <= target,
        "canary_absent_after_action": _boolean(
            exercise["canary_absent_after_action"],
            f"{system_id}.canary_absent_after_action",
        ),
        "fresh_principal_absence_verified": _boolean(
            exercise["fresh_principal_absence_verified"],
            f"{system_id}.fresh_principal_absence_verified",
        ),
        "zero_residual_objects": _integer(
            exercise["residual_objects"], f"{system_id}.residual_objects"
        )
        == 0,
        "tenant_boundary_preserved": _integer(
            exercise["unexpected_tenant_accesses"],
            f"{system_id}.unexpected_tenant_accesses",
        )
        == 0,
    }
    return {
        "target_completion_seconds": target,
        "completion_seconds": completion_seconds,
        "checks": checks,
        "passed": all(checks.values()),
    }


def validate_contract() -> None:
    contract, _ = _load_contract()
    boundary_ids = [
        boundary["boundary_id"] for boundary in contract["boundaries"]
    ]
    if (
        len(boundary_ids) != 6
        or len(REVIEW_CHECK_IDS) != 8
        or "external/remote-backup-copies"
        not in contract["required_configured_boundaries"]
    ):
        raise QualificationError("external deletion qualification constants are invalid")


def evaluate(
    observation_path: Path,
    review_path: Path,
    *,
    expected_commit: str,
    expected_environment: str,
    release_candidate: str,
) -> dict[str, Any]:
    contract, contract_sha256 = _load_contract()
    validate_contract()
    if not FULL_SHA_RE.fullmatch(expected_commit):
        raise QualificationError("expected commit must be a full lowercase Git SHA")
    if not RELEASE_CANDIDATE_RE.fullmatch(release_candidate):
        raise QualificationError("release candidate must be vX.Y.Z or vX.Y.Z-rc.N")
    expected_environment = _identifier(
        expected_environment, "expected_environment", target=True
    )

    observation, observation_sha256 = _load_json(
        observation_path, "external deletion observation"
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
            "systems",
        },
        "observation",
    )
    if _integer(observation["schema_version"], "observation.schema_version") != 1:
        raise QualificationError("observation schema version is unsupported")
    if (
        _string(
            observation["qualification_class"], "observation.qualification_class"
        )
        != OBSERVATION_CLASS
    ):
        raise QualificationError("observation qualification class is wrong")
    if (
        _string(observation["release_candidate"], "observation.release_candidate")
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
            "external evidence must use the supported single-node Linux x86_64 profile"
        )
    report_environment = {
        "environment_id": environment_id,
        "deployment_mode": deployment_mode,
        "os": operating_system,
        "arch": architecture,
        "configuration_sha256": _sha256(
            environment["configuration_sha256"],
            "observation.environment.configuration_sha256",
        ),
    }

    profile = _object(observation["profile"], "observation.profile")
    _exact_keys(
        profile,
        {
            "profile_id",
            "boundary_contract_sha256",
            "maximum_completion_seconds",
        },
        "observation.profile",
    )
    profile_id = _identifier(profile["profile_id"], "observation.profile.profile_id")
    if profile_id != contract["profile_id"]:
        raise QualificationError("observation profile is not the supported v1 profile")
    if (
        _sha256(
            profile["boundary_contract_sha256"],
            "observation.profile.boundary_contract_sha256",
        )
        != contract_sha256
        or _integer(
            profile["maximum_completion_seconds"],
            "observation.profile.maximum_completion_seconds",
            minimum=1,
        )
        != contract["maximum_completion_seconds"]
    ):
        raise QualificationError("observation does not bind the exact boundary contract")

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
    if exercise_seconds <= 0 or exercise_seconds > MAX_EXERCISE_SECONDS:
        raise QualificationError("external deletion exercise duration is invalid")
    operator_id = _identifier(
        exercise["operator_id"], "observation.exercise.operator_id", target=True
    )
    harness_id = _identifier(
        exercise["harness_id"], "observation.exercise.harness_id", target=True
    )

    boundary_contract = {
        boundary["boundary_id"]: set(boundary["eligible_modes"])
        for boundary in contract["boundaries"]
    }
    boundary_order = {
        boundary["boundary_id"]: index
        for index, boundary in enumerate(contract["boundaries"])
    }
    raw_systems = _array(
        observation["systems"],
        "observation.systems",
        minimum=len(boundary_contract),
        maximum=MAX_SYSTEM_RECORDS,
    )
    systems: list[dict[str, Any]] = []
    record_keys: list[str] = []
    boundary_statuses: dict[str, list[str]] = {
        boundary_id: [] for boundary_id in boundary_contract
    }
    for index, raw_system in enumerate(raw_systems):
        path = f"observation.systems[{index}]"
        system = _object(raw_system, path)
        _exact_keys(
            system,
            {
                "boundary_id",
                "system_id",
                "status",
                "lifecycle_mode",
                "configuration_sha256",
                "configuration_absence_verified",
                "policy_sha256",
                "evidence_sha256",
                "exercise",
            },
            path,
        )
        boundary_id = _string(system["boundary_id"], f"{path}.boundary_id", max_length=96)
        if boundary_id not in boundary_contract:
            raise QualificationError(f"unknown external boundary {boundary_id!r}")
        status = _identifier(system["status"], f"{path}.status")
        if status not in {"configured", "not-configured"}:
            raise QualificationError(f"{path}.status is unsupported")
        system_id = _identifier(
            system["system_id"], f"{path}.system_id", target=status == "configured"
        )
        if "::" in system_id:
            raise QualificationError(f"{path}.system_id must not contain '::'")
        mode = _identifier(system["lifecycle_mode"], f"{path}.lifecycle_mode")
        if mode not in boundary_contract[boundary_id]:
            raise QualificationError(f"{boundary_id} uses an ineligible lifecycle mode")
        absence_verified = _boolean(
            system["configuration_absence_verified"],
            f"{path}.configuration_absence_verified",
        )
        configuration_sha256 = _sha256(
            system["configuration_sha256"], f"{path}.configuration_sha256"
        )
        evidence_sha256 = _sha256(
            system["evidence_sha256"], f"{path}.evidence_sha256"
        )
        if status == "not-configured":
            if (
                system_id != "none"
                or mode != "not-configured"
                or not absence_verified
                or system["policy_sha256"] is not None
                or system["exercise"] is not None
            ):
                raise QualificationError(
                    f"{boundary_id} not-configured disposition is inconsistent"
                )
            result = {
                "boundary_id": boundary_id,
                "system_id": system_id,
                "status": status,
                "lifecycle_mode": mode,
                "configuration_sha256": configuration_sha256,
                "configuration_absence_verified": True,
                "policy_sha256": None,
                "evidence_sha256": evidence_sha256,
                "target_completion_seconds": None,
                "completion_seconds": None,
                "checks": {"configuration_absence_verified": True},
                "passed": True,
            }
        else:
            if (
                system_id == "none"
                or mode == "not-configured"
                or absence_verified
                or system["policy_sha256"] is None
                or system["exercise"] is None
            ):
                raise QualificationError(
                    f"{boundary_id}/{system_id} configured disposition is inconsistent"
                )
            exercise_result = _validate_exercise(
                system["exercise"],
                boundary_id=boundary_id,
                system_id=system_id,
                mode=mode,
                exercise_start=exercise_start,
                exercise_end=exercise_end,
                maximum_completion_seconds=contract[
                    "maximum_completion_seconds"
                ],
            )
            result = {
                "boundary_id": boundary_id,
                "system_id": system_id,
                "status": status,
                "lifecycle_mode": mode,
                "configuration_sha256": configuration_sha256,
                "configuration_absence_verified": False,
                "policy_sha256": _sha256(
                    system["policy_sha256"], f"{path}.policy_sha256"
                ),
                "evidence_sha256": evidence_sha256,
                **exercise_result,
            }
        record_key = f"{boundary_id}::{system_id}"
        if record_key in record_keys:
            raise QualificationError(f"duplicate external system record {record_key}")
        record_keys.append(record_key)
        boundary_statuses[boundary_id].append(status)
        systems.append(result)

    expected_order = sorted(
        record_keys,
        key=lambda key: (
            boundary_order[key.split("::", 1)[0]],
            key.split("::", 1)[1],
        ),
    )
    if record_keys != expected_order:
        raise QualificationError("external systems must use fixed boundary/system order")
    for boundary_id, statuses in boundary_statuses.items():
        if not statuses:
            raise QualificationError(f"external boundary {boundary_id} is missing")
        if "not-configured" in statuses and len(statuses) != 1:
            raise QualificationError(
                f"{boundary_id} cannot mix configured and not-configured records"
            )
    for boundary_id in contract["required_configured_boundaries"]:
        if any(status != "configured" for status in boundary_statuses[boundary_id]):
            raise QualificationError(
                f"{boundary_id} must be configured in the supported profile"
            )

    review, review_sha256 = _load_json(
        review_path, "external deletion independent review"
    )
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
            "record_keys",
            "checks",
            "open_findings",
        },
        "review",
    )
    if _integer(review["schema_version"], "review.schema_version") != 1:
        raise QualificationError("review schema version is unsupported")
    if _string(review["qualification_class"], "review.qualification_class") != REVIEW_CLASS:
        raise QualificationError("review qualification class is wrong")
    if _string(review["release_candidate"], "review.release_candidate") != release_candidate:
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
    reviewer_id = _identifier(
        review["reviewer_id"], "review.reviewer_id", target=True
    )
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
    reviewed_record_keys = [
        _string(value, "review.record_keys[]", max_length=200)
        for value in _array(
            review["record_keys"],
            "review.record_keys",
            minimum=len(record_keys),
            maximum=len(record_keys),
        )
    ]
    if reviewed_record_keys != record_keys:
        raise QualificationError("review system inventory is incomplete or reordered")
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

    failed_systems = [
        f"{system['boundary_id']}::{system['system_id']}"
        for system in systems
        if not system["passed"]
    ]
    blockers: list[str] = []
    if failed_systems:
        blockers.append("one or more external system lifecycle exercises failed")
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
            "boundary_contract_sha256": contract_sha256,
            "maximum_completion_seconds": contract[
                "maximum_completion_seconds"
            ],
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
        "systems": systems,
        "failed_systems": failed_systems,
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
        "external_boundary_inventory_complete": True,
        "external_deletion_retention_proof_eligible": proof_eligible,
        "production_claim_allowed": False,
        "passed": proof_eligible,
        "eligibility_blockers": blockers,
        "caveats": [
            "Eligibility requires externally retained raw service evidence and independent identity attestation; this bounded report cannot authenticate people, accounts, or provider behavior by itself.",
            "Not-configured dispositions qualify only the exact hashed target configuration and must be repeated when an external integration is added.",
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
        contract, digest = _load_contract()
        validate_contract()
        print(
            f"validated external deletion schema v{SCHEMA_VERSION}: "
            f"{len(contract['boundaries'])} boundaries, "
            f"profile={contract['profile_id']}, contract={digest}"
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
    if args.require_eligible and not report[
        "external_deletion_retention_proof_eligible"
    ]:
        raise QualificationError("external deletion evidence is not eligible")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except QualificationError as error:
        print(f"external deletion qualification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
