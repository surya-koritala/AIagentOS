#!/usr/bin/env python3
"""Validate exact-release-candidate human incident game-day evidence.

The raw observation and independent review remain in an operator-controlled
evidence store. This program validates their bounded schemas, recalculates
timeline/RPO/RTO outcomes instead of trusting a pass flag, binds the review to
the exact observation bytes, and emits a non-secret report containing hashes.
It cannot prove that a claimed human identity is authentic; that remains a
protected-runner and independently retained attestation responsibility.
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
import sys
from pathlib import Path
from typing import Any, Sequence


class QualificationError(RuntimeError):
    """The evidence could not be parsed or did not satisfy the schema."""


SCHEMA_VERSION = 1
SUITE = "agentos-v1-human-game-day"
OBSERVATION_CLASS = "human_incident_game_day_observation"
REVIEW_CLASS = "independent_human_game_day_review"
REPORT_CLASS = "exact_release_candidate_human_game_day"
MAX_EVIDENCE_BYTES = 512 * 1024
MIN_EXERCISE_SECONDS = 3_600
MAX_REVIEW_DELAY_SECONDS = 30 * 24 * 60 * 60
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_CANDIDATE_RE = re.compile(
    r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?$"
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,99}$")

SCENARIO_IDS = (
    "credential-compromise",
    "tenant-leak",
    "malicious-package",
    "node-loss",
    "corrupt-database",
    "provider-outage",
)
REQUIRED_PARTICIPANT_ROLES = {
    "incident_commander",
    "operator",
    "observer",
}
ALLOWED_PARTICIPANT_ROLES = REQUIRED_PARTICIPANT_ROLES | {
    "facilitator",
    "security",
    "database",
    "provider",
}
REVIEW_CHECK_IDS = (
    "exact_release_candidate_exercised",
    "timeline_and_measurements_reviewed",
    "runbook_steps_reviewed",
    "rpo_rto_results_reviewed",
    "tenant_boundaries_preserved",
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


def _array(value: Any, path: str, *, minimum: int = 0, maximum: int = 100) -> list[Any]:
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


def _identifier(value: Any, path: str) -> str:
    result = _string(value, path, max_length=100)
    if not IDENTIFIER_RE.fullmatch(result):
        raise QualificationError(f"{path} must be a stable non-secret identifier")
    return result


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{path} must be a boolean")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise QualificationError(f"{path} must be an integer >= {minimum}")
    return value


def _number(value: Any, path: str, *, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise QualificationError(f"{path} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise QualificationError(f"{path} must be a finite number >= {minimum}")
    return result


def _sha256(value: Any, path: str) -> str:
    result = _string(value, path, max_length=64)
    if not SHA256_RE.fullmatch(result):
        raise QualificationError(f"{path} must be a lowercase SHA-256 digest")
    return result


def _timestamp(value: Any, path: str) -> dt.datetime:
    text = _string(value, path, max_length=40)
    if not text.endswith("Z"):
        raise QualificationError(f"{path} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise QualificationError(f"{path} must be an RFC3339 UTC timestamp") from error
    if parsed.tzinfo != dt.timezone.utc:
        raise QualificationError(f"{path} must use UTC")
    return parsed


def _validate_source(value: Any, expected_commit: str, path: str) -> dict[str, Any]:
    source = _object(value, path)
    _exact_keys(source, {"commit", "dirty"}, path)
    commit = _string(source["commit"], f"{path}.commit", max_length=40)
    dirty = _boolean(source["dirty"], f"{path}.dirty")
    if commit != expected_commit:
        raise QualificationError(f"{path}.commit does not match the requested commit")
    if dirty:
        raise QualificationError(f"{path} must describe a clean source checkout")
    return {"commit": commit, "dirty": False}


def _validate_environment(value: Any, expected_environment: str) -> dict[str, Any]:
    environment = _object(value, "observation.environment")
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
        environment["environment_id"], "observation.environment.environment_id"
    )
    if environment_id != expected_environment:
        raise QualificationError("observation environment does not match target")
    deployment_mode = _identifier(
        environment["deployment_mode"], "observation.environment.deployment_mode"
    )
    operating_system = _identifier(
        environment["os"], "observation.environment.os"
    )
    architecture = _identifier(
        environment["arch"], "observation.environment.arch"
    )
    if deployment_mode != "single-node" or operating_system != "linux":
        raise QualificationError(
            "game-day evidence must use the supported single-node Linux profile"
        )
    return {
        "environment_id": environment_id,
        "deployment_mode": deployment_mode,
        "os": operating_system,
        "arch": architecture,
        "configuration_sha256": _sha256(
            environment["configuration_sha256"],
            "observation.environment.configuration_sha256",
        ),
    }


def _validate_participants(
    exercise: dict[str, Any],
) -> tuple[str, set[str], set[str]]:
    facilitator = _identifier(
        exercise["facilitator_id"], "observation.exercise.facilitator_id"
    )
    participants = _array(
        exercise["participants"],
        "observation.exercise.participants",
        minimum=3,
        maximum=20,
    )
    participant_ids: set[str] = set()
    roles: set[str] = set()
    for index, item in enumerate(participants):
        participant = _object(item, f"observation.exercise.participants[{index}]")
        _exact_keys(
            participant,
            {"participant_id", "role"},
            f"observation.exercise.participants[{index}]",
        )
        participant_id = _identifier(
            participant["participant_id"],
            f"observation.exercise.participants[{index}].participant_id",
        )
        role = _identifier(
            participant["role"],
            f"observation.exercise.participants[{index}].role",
        )
        if participant_id in participant_ids:
            raise QualificationError("game-day participant identifiers must be unique")
        if role not in ALLOWED_PARTICIPANT_ROLES:
            raise QualificationError(f"unsupported game-day participant role {role}")
        participant_ids.add(participant_id)
        roles.add(role)
    if not REQUIRED_PARTICIPANT_ROLES.issubset(roles):
        raise QualificationError(
            "game day requires incident_commander, operator, and observer roles"
        )
    return facilitator, participant_ids, roles


def _validate_scenarios(
    value: Any,
    exercise_start: dt.datetime,
    exercise_end: dt.datetime,
) -> list[dict[str, Any]]:
    scenarios = _array(
        value,
        "observation.scenarios",
        minimum=len(SCENARIO_IDS),
        maximum=len(SCENARIO_IDS),
    )
    summaries: list[dict[str, Any]] = []
    observed_ids: list[str] = []
    for index, item in enumerate(scenarios):
        path = f"observation.scenarios[{index}]"
        scenario = _object(item, path)
        _exact_keys(
            scenario,
            {
                "scenario_id",
                "started_at",
                "detected_at",
                "mitigated_at",
                "recovered_at",
                "target_rto_seconds",
                "target_rpo_seconds",
                "observed_data_loss_seconds",
                "runbook_steps_total",
                "runbook_steps_completed",
                "unexpected_tenant_accesses",
                "unresolved_findings",
                "evidence_sha256",
            },
            path,
        )
        scenario_id = _identifier(scenario["scenario_id"], f"{path}.scenario_id")
        observed_ids.append(scenario_id)
        started = _timestamp(scenario["started_at"], f"{path}.started_at")
        detected = _timestamp(scenario["detected_at"], f"{path}.detected_at")
        mitigated = _timestamp(scenario["mitigated_at"], f"{path}.mitigated_at")
        recovered = _timestamp(scenario["recovered_at"], f"{path}.recovered_at")
        if not (
            exercise_start <= started <= detected <= mitigated <= recovered <= exercise_end
        ):
            raise QualificationError(
                f"{path} timeline must be ordered inside the exercise window"
            )
        target_rto = _number(
            scenario["target_rto_seconds"], f"{path}.target_rto_seconds", minimum=1
        )
        target_rpo = _number(
            scenario["target_rpo_seconds"], f"{path}.target_rpo_seconds"
        )
        observed_data_loss = _number(
            scenario["observed_data_loss_seconds"],
            f"{path}.observed_data_loss_seconds",
        )
        runbook_total = _integer(
            scenario["runbook_steps_total"], f"{path}.runbook_steps_total", minimum=1
        )
        runbook_completed = _integer(
            scenario["runbook_steps_completed"],
            f"{path}.runbook_steps_completed",
        )
        if runbook_completed > runbook_total:
            raise QualificationError(f"{path} completed runbook steps exceed total")
        unexpected_accesses = _integer(
            scenario["unexpected_tenant_accesses"],
            f"{path}.unexpected_tenant_accesses",
        )
        unresolved_findings = _integer(
            scenario["unresolved_findings"], f"{path}.unresolved_findings"
        )
        rto_seconds = (recovered - detected).total_seconds()
        checks = {
            "positive_recovery_interval": rto_seconds > 0,
            "rto_met": rto_seconds <= target_rto,
            "rpo_met": observed_data_loss <= target_rpo,
            "all_runbook_steps_completed": runbook_completed == runbook_total,
            "zero_unexpected_tenant_accesses": unexpected_accesses == 0,
            "zero_unresolved_findings": unresolved_findings == 0,
        }
        failed_checks = [
            check_id for check_id, passed in checks.items() if passed is not True
        ]
        summaries.append(
            {
                "scenario_id": scenario_id,
                "elapsed_seconds": (recovered - started).total_seconds(),
                "rto_seconds": rto_seconds,
                "target_rto_seconds": target_rto,
                "observed_data_loss_seconds": observed_data_loss,
                "target_rpo_seconds": target_rpo,
                "runbook_steps_total": runbook_total,
                "runbook_steps_completed": runbook_completed,
                "unexpected_tenant_accesses": unexpected_accesses,
                "unresolved_findings": unresolved_findings,
                "evidence_sha256": _sha256(
                    scenario["evidence_sha256"], f"{path}.evidence_sha256"
                ),
                "checks": checks,
                "failed_checks": failed_checks,
                "passed": not failed_checks,
            }
        )
    if tuple(observed_ids) != SCENARIO_IDS:
        raise QualificationError(
            f"game-day scenarios must be exactly {SCENARIO_IDS} in order"
        )
    return summaries


def _validate_observation(
    observation: dict[str, Any],
    expected_commit: str,
    expected_environment: str,
    release_candidate: str,
) -> dict[str, Any]:
    _exact_keys(
        observation,
        {
            "schema_version",
            "qualification_class",
            "release_candidate",
            "source",
            "environment",
            "exercise",
            "scenarios",
        },
        "observation",
    )
    if _integer(observation["schema_version"], "observation.schema_version") != 1:
        raise QualificationError("game-day observation schema version is unsupported")
    if observation["qualification_class"] != OBSERVATION_CLASS:
        raise QualificationError("observation is not human game-day evidence")
    observed_rc = _string(
        observation["release_candidate"],
        "observation.release_candidate",
        max_length=50,
    )
    if observed_rc != release_candidate:
        raise QualificationError("observation release candidate does not match request")
    source = _validate_source(observation["source"], expected_commit, "observation.source")
    environment = _validate_environment(
        observation["environment"], expected_environment
    )
    exercise = _object(observation["exercise"], "observation.exercise")
    _exact_keys(
        exercise,
        {
            "exercise_id",
            "started_at",
            "ended_at",
            "facilitator_id",
            "participants",
        },
        "observation.exercise",
    )
    exercise_id = _identifier(
        exercise["exercise_id"], "observation.exercise.exercise_id"
    )
    started = _timestamp(exercise["started_at"], "observation.exercise.started_at")
    ended = _timestamp(exercise["ended_at"], "observation.exercise.ended_at")
    duration = (ended - started).total_seconds()
    if duration < MIN_EXERCISE_SECONDS:
        raise QualificationError(
            f"game day must run for at least {MIN_EXERCISE_SECONDS} seconds"
        )
    facilitator, participant_ids, roles = _validate_participants(exercise)
    scenarios = _validate_scenarios(observation["scenarios"], started, ended)
    return {
        "source": source,
        "environment": environment,
        "release_candidate": observed_rc,
        "exercise_id": exercise_id,
        "exercise_started_at": exercise["started_at"],
        "exercise_ended_at": exercise["ended_at"],
        "exercise_duration_seconds": duration,
        "facilitator_id": facilitator,
        "participant_ids": participant_ids,
        "participant_count": len(participant_ids),
        "participant_roles": sorted(roles),
        "scenarios": scenarios,
    }


def _validate_review(
    review: dict[str, Any],
    *,
    observation_sha256: str,
    observation: dict[str, Any],
    expected_commit: str,
    expected_environment: str,
    release_candidate: str,
) -> dict[str, Any]:
    _exact_keys(
        review,
        {
            "schema_version",
            "qualification_class",
            "release_candidate",
            "source",
            "environment_id",
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
        raise QualificationError("game-day review schema version is unsupported")
    if review["qualification_class"] != REVIEW_CLASS:
        raise QualificationError("review is not independent human game-day review evidence")
    if (
        _string(review["release_candidate"], "review.release_candidate", max_length=50)
        != release_candidate
    ):
        raise QualificationError("review release candidate does not match request")
    _validate_source(review["source"], expected_commit, "review.source")
    if (
        _identifier(review["environment_id"], "review.environment_id")
        != expected_environment
    ):
        raise QualificationError("review environment does not match target")
    if _sha256(review["observation_sha256"], "review.observation_sha256") != observation_sha256:
        raise QualificationError("independent review does not bind the exact observation")
    reviewer_id = _identifier(review["reviewer_id"], "review.reviewer_id")
    reviewer_independent = reviewer_id not in (
        observation["participant_ids"] | {observation["facilitator_id"]}
    )
    reviewed_at = _timestamp(review["reviewed_at"], "review.reviewed_at")
    exercise_end = _timestamp(
        observation["exercise_ended_at"], "observation.exercise.ended_at"
    )
    review_delay = (reviewed_at - exercise_end).total_seconds()
    if review_delay < 0 or review_delay > MAX_REVIEW_DELAY_SECONDS:
        raise QualificationError(
            "independent review must follow the exercise within 30 days"
        )
    decision = _string(review["decision"], "review.decision", max_length=20)
    if decision not in {"approved", "rejected"}:
        raise QualificationError("review decision must be approved or rejected")
    scenario_ids = _array(
        review["scenario_ids"],
        "review.scenario_ids",
        minimum=len(SCENARIO_IDS),
        maximum=len(SCENARIO_IDS),
    )
    if tuple(scenario_ids) != SCENARIO_IDS:
        raise QualificationError("independent review must cover every scenario in order")
    checks = _object(review["checks"], "review.checks")
    _exact_keys(checks, set(REVIEW_CHECK_IDS), "review.checks")
    reviewed_checks = {
        check_id: _boolean(checks[check_id], f"review.checks.{check_id}")
        for check_id in REVIEW_CHECK_IDS
    }
    findings = _array(
        review["open_findings"], "review.open_findings", maximum=50
    )
    for index, finding in enumerate(findings):
        _string(finding, f"review.open_findings[{index}]", max_length=200)
    review_checks = {
        "reviewer_independent": reviewer_independent,
        "review_approved": decision == "approved",
        "every_review_check_passed": all(reviewed_checks.values()),
        "zero_open_findings": not findings,
    }
    return {
        "reviewed_at": review["reviewed_at"],
        "reviewer_independent": reviewer_independent,
        "decision": decision,
        "review_attestation_sha256": _sha256(
            review["review_attestation_sha256"],
            "review.review_attestation_sha256",
        ),
        "reviewed_checks": reviewed_checks,
        "open_finding_count": len(findings),
        "checks": review_checks,
        "passed": all(review_checks.values()),
    }


def evaluate(
    observation_path: Path,
    review_path: Path,
    *,
    expected_commit: str,
    expected_environment: str,
    release_candidate: str,
) -> dict[str, Any]:
    if not FULL_SHA_RE.fullmatch(expected_commit):
        raise QualificationError("expected commit must be a full lowercase Git SHA")
    expected_environment = _identifier(
        expected_environment, "expected environment"
    )
    if expected_environment.lower() in {
        "local",
        "smoke",
        "fixture",
        "test",
        "development",
        "dev",
    }:
        raise QualificationError("expected environment must identify a target deployment")
    if not RELEASE_CANDIDATE_RE.fullmatch(release_candidate):
        raise QualificationError(
            "release candidate must look like v1.2.3 or v1.2.3-rc.1"
        )
    observation_value, observation_sha = _load_json(
        observation_path, "game-day observation"
    )
    review_value, review_sha = _load_json(review_path, "independent game-day review")
    observation = _validate_observation(
        observation_value,
        expected_commit,
        expected_environment,
        release_candidate,
    )
    review = _validate_review(
        review_value,
        observation_sha256=observation_sha,
        observation=observation,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
        release_candidate=release_candidate,
    )
    failed_scenarios = [
        scenario["scenario_id"]
        for scenario in observation["scenarios"]
        if scenario["passed"] is not True
    ]
    blockers = [f"scenario.{scenario_id}" for scenario_id in failed_scenarios]
    blockers.extend(
        f"review.{check_id}"
        for check_id, passed in review["checks"].items()
        if passed is not True
    )
    eligible = not blockers
    return {
        "schema_version": SCHEMA_VERSION,
        "suite": SUITE,
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "qualification_class": REPORT_CLASS,
        "proof_scope": "human_runbook_execution_and_independent_review",
        "release_candidate": release_candidate,
        "source": observation["source"],
        "environment": observation["environment"],
        "exercise": {
            "exercise_id": observation["exercise_id"],
            "started_at": observation["exercise_started_at"],
            "ended_at": observation["exercise_ended_at"],
            "duration_seconds": observation["exercise_duration_seconds"],
            "participant_count": observation["participant_count"],
            "participant_roles": observation["participant_roles"],
        },
        "evidence": {
            "observation_sha256": observation_sha,
            "independent_review_sha256": review_sha,
            "review_attestation_sha256": review["review_attestation_sha256"],
        },
        "review": {
            "reviewed_at": review["reviewed_at"],
            "reviewer_independent": review["reviewer_independent"],
            "decision": review["decision"],
            "reviewed_checks": review["reviewed_checks"],
            "open_finding_count": review["open_finding_count"],
            "checks": review["checks"],
            "passed": review["passed"],
        },
        "scenarios": observation["scenarios"],
        "failed_scenarios": failed_scenarios,
        "eligibility_blockers": blockers,
        "passed": eligible,
        "human_game_day_completed": eligible,
        "game_day_proof_eligible": eligible,
        "production_claim_allowed": False,
        "caveats": [
            "The bounded report proves schema, source, timeline, measurement, hash-binding, and reviewer-separation checks; the protected evidence process must authenticate human identities.",
            "Raw timelines, actor identifiers, findings, and detached reviewer attestation remain in the operator-controlled evidence store.",
            "production_claim_allowed remains false until the separate SLO, release, security, deployment, and independent-release-review gates pass.",
        ],
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def validate_contract() -> None:
    if len(set(SCENARIO_IDS)) != len(SCENARIO_IDS):
        raise QualificationError("game-day scenario identifiers must be unique")
    if len(set(REVIEW_CHECK_IDS)) != len(REVIEW_CHECK_IDS):
        raise QualificationError("game-day review checks must be unique")
    if not REQUIRED_PARTICIPANT_ROLES.issubset(ALLOWED_PARTICIPANT_ROLES):
        raise QualificationError("required participant roles are not allowed")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--review", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-environment")
    parser.add_argument("--release-candidate")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-eligible", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_contract()
        if args.validate:
            supplied = [
                args.observation,
                args.review,
                args.expected_commit,
                args.expected_environment,
                args.release_candidate,
                args.output,
            ]
            if any(value is not None for value in supplied) or args.require_eligible:
                parser.error("--validate cannot be combined with report arguments")
            print(
                f"validated human game-day schema v{SCHEMA_VERSION}: "
                + ", ".join(SCENARIO_IDS)
            )
            return 0
        required = {
            "--observation": args.observation,
            "--review": args.review,
            "--expected-commit": args.expected_commit,
            "--expected-environment": args.expected_environment,
            "--release-candidate": args.release_candidate,
            "--output": args.output,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            parser.error("required arguments missing: " + ", ".join(missing))
        report = evaluate(
            args.observation,
            args.review,
            expected_commit=args.expected_commit,
            expected_environment=args.expected_environment,
            release_candidate=args.release_candidate,
        )
        write_report(args.output, report)
        print(args.output)
        if args.require_eligible and report["game_day_proof_eligible"] is not True:
            return 1
        return 0
    except QualificationError as error:
        print(f"game-day qualification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
