#!/usr/bin/env python3
"""Create one authenticated Phase 1 review from a protected reviewer record."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from phase1_promotion_qualification import (
    MAX_REVIEW_DELAY,
    PROFILE_ID,
    RESERVED_REVIEWER_IDS,
    REVIEW_CHECK_IDS,
    REVIEW_CLASS,
    QualificationError,
    _array,
    _boolean,
    _canonical_id_list,
    _exact_keys,
    _identifier,
    _load_json,
    _object,
    _parse_campaign,
    _parse_campaign_provenance,
    _positive_integer,
    _sha256,
    _source,
    _string,
    _timestamp,
)


SCHEMA_VERSION = 1
REVIEW_SCHEMA_VERSION = 2
OBSERVATION_CLASS = "independent_restricted_phase1_review_observation"
WORKFLOW_PATH = ".github/workflows/phase1-independent-review.yml"
MAX_OBSERVATION_BYTES = 256 * 1024
GITHUB_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$"
)


def _github_login(value: Any, label: str) -> str:
    login = _string(value, label, maximum=39)
    if GITHUB_LOGIN_RE.fullmatch(login) is None:
        raise QualificationError(f"{label} must be a canonical GitHub login")
    return login


def _parse_observation(
    path: Path,
    *,
    campaign_sha: str,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
    on_device_environment: str,
    operator_ids: list[str],
    actor: str,
    completion_times: list[dt.datetime],
) -> tuple[dict[str, Any], str]:
    observation, observation_sha = _load_json(
        path, "Phase 1 independent review observation", MAX_OBSERVATION_BYTES
    )
    _exact_keys(
        observation,
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
        },
        "review observation",
    )
    if observation["schema_version"] != SCHEMA_VERSION:
        raise QualificationError("review observation schema_version is unsupported")
    if observation["qualification_class"] != OBSERVATION_CLASS:
        raise QualificationError("review observation qualification_class is invalid")
    if observation["release_candidate"] != release_candidate:
        raise QualificationError("review observation release candidate does not match")
    _source(observation["source"], expected_commit, "review observation.source")
    if observation["profile_id"] != PROFILE_ID:
        raise QualificationError("review observation profile_id is unsupported")
    if observation["target_environment_id"] != expected_environment:
        raise QualificationError("review observation target environment does not match")
    if observation["on_device_environment_id"] != on_device_environment:
        raise QualificationError("review observation on-device environment does not match")
    if observation["campaign_sha256"] != campaign_sha:
        raise QualificationError("review observation does not bind the exact campaign")
    reviewed_operators = _canonical_id_list(
        observation["operator_ids"],
        "review observation.operator_ids",
        minimum=1,
        maximum=10,
    )
    if reviewed_operators != operator_ids:
        raise QualificationError(
            "review observation operator inventory does not match campaign"
        )
    reviewer_id = _github_login(
        observation["reviewer_id"], "review observation.reviewer_id"
    )
    if reviewer_id.casefold() != actor.casefold():
        raise QualificationError(
            "review observation reviewer does not match authenticated GitHub actor"
        )
    if reviewer_id.casefold() in {
        item.casefold() for item in operator_ids
    } | RESERVED_REVIEWER_IDS:
        raise QualificationError(
            "authenticated GitHub reviewer is not independent from campaign operators"
        )
    reviewed_at = _timestamp(
        observation["reviewed_at"], "review observation.reviewed_at"
    )
    if reviewed_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise QualificationError("review observation timestamp is in the future")
    latest_completion = max(completion_times)
    if reviewed_at < latest_completion:
        raise QualificationError(
            "review observation predates one or more workflow artifacts"
        )
    if reviewed_at - latest_completion > MAX_REVIEW_DELAY:
        raise QualificationError("review observation is stale")
    checks = _object(observation["checks"], "review observation.checks")
    _exact_keys(checks, set(REVIEW_CHECK_IDS), "review observation.checks")
    normalized_checks = {
        check_id: _boolean(
            checks[check_id], f"review observation.checks.{check_id}"
        )
        for check_id in REVIEW_CHECK_IDS
    }
    findings = [
        _string(item, "review observation.open_findings[]", maximum=300)
        for item in _array(
            observation["open_findings"],
            "review observation.open_findings",
            minimum=0,
            maximum=20,
        )
    ]
    decision = _string(observation["decision"], "review observation.decision")
    if decision not in {"approved", "rejected"}:
        raise QualificationError(
            "review observation decision must be approved or rejected"
        )
    observation["_validated_reviewer_id"] = actor
    observation["_validated_reviewed_at"] = observation["reviewed_at"]
    observation["_validated_decision"] = decision
    observation["_validated_checks"] = normalized_checks
    observation["_validated_findings"] = findings
    return observation, observation_sha


def build_review(
    campaign_path: Path,
    campaign_provenance_path: Path,
    observation_path: Path,
    *,
    actor: str,
    repository: str,
    run_id: int,
    run_attempt: int,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
    expected_campaign_run_id: int,
) -> dict[str, Any]:
    """Normalize one protected reviewer record into a workflow-bound review."""

    authenticated_actor = _github_login(actor, "authenticated GitHub actor")
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise QualificationError("repository must be an exact owner/name identity")
    authenticated_run_id = _positive_integer(run_id, "review workflow run id")
    authenticated_attempt = _positive_integer(
        run_attempt, "review workflow run attempt"
    )
    if authenticated_attempt != 1:
        raise QualificationError(
            "independent review must use a fresh workflow dispatch, not a rerun"
        )
    campaign, campaign_sha, _, completion_times = _parse_campaign(
        campaign_path,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
    )
    campaign_provenance, _ = _parse_campaign_provenance(
        campaign_provenance_path,
        campaign_sha=campaign_sha,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_campaign_run_id=expected_campaign_run_id,
        completion_times=completion_times,
    )
    completion_times.append(
        _timestamp(
            campaign_provenance["campaign_workflow"][
                "workflow_updated_at"
            ],
            "campaign provenance workflow_updated_at",
        )
    )
    operator_ids = campaign["_validated_operator_ids"]
    on_device_environment = campaign["_validated_on_device_environment"]
    observation, observation_sha = _parse_observation(
        observation_path,
        campaign_sha=campaign_sha,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
        on_device_environment=on_device_environment,
        operator_ids=operator_ids,
        actor=authenticated_actor,
        completion_times=completion_times,
    )
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "qualification_class": REVIEW_CLASS,
        "release_candidate": release_candidate,
        "source": {"commit": expected_commit, "dirty": False},
        "profile_id": PROFILE_ID,
        "target_environment_id": expected_environment,
        "on_device_environment_id": on_device_environment,
        "campaign_sha256": campaign_sha,
        "operator_ids": operator_ids,
        "reviewer_id": authenticated_actor,
        "reviewed_at": observation["_validated_reviewed_at"],
        "decision": observation["_validated_decision"],
        "checks": observation["_validated_checks"],
        "open_findings": observation["_validated_findings"],
        "review_attestation_sha256": observation_sha,
        "review_workflow": {
            "repository": repository,
            "workflow_path": WORKFLOW_PATH,
            "event": "workflow_dispatch",
            "run_id": authenticated_run_id,
            "run_attempt": authenticated_attempt,
            "head_sha": expected_commit,
        },
    }


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def validate_contract() -> None:
    if REVIEW_SCHEMA_VERSION <= SCHEMA_VERSION:
        raise QualificationError("authenticated review schema must advance v1")
    if len(REVIEW_CHECK_IDS) != len(set(REVIEW_CHECK_IDS)):
        raise QualificationError("review check catalog contains duplicates")
    _sha256("0" * 64, "contract digest")
    _github_login("independent-reviewer", "contract actor")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--campaign-provenance", type=Path)
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--actor")
    parser.add_argument("--repository")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--run-attempt", type=int)
    parser.add_argument("--release-candidate")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-environment")
    parser.add_argument("--expected-campaign-run-id", type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-approved", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_contract()
        if args.validate:
            if any(
                value not in (None, False)
                for name, value in vars(args).items()
                if name != "validate"
            ):
                raise QualificationError(
                    "--validate cannot be combined with review arguments"
                )
            print(
                "validated authenticated independent Phase 1 review schema "
                f"v{REVIEW_SCHEMA_VERSION}"
            )
            return 0
        required = (
            args.campaign,
            args.campaign_provenance,
            args.observation,
            args.actor,
            args.repository,
            args.run_id,
            args.run_attempt,
            args.release_candidate,
            args.expected_commit,
            args.expected_environment,
            args.expected_campaign_run_id,
            args.output,
        )
        if any(value is None for value in required):
            raise QualificationError(
                "campaign, campaign provenance, observation, actor, repository, "
                "run identities, release identity, environment, and output are "
                "required"
            )
        review = build_review(
            args.campaign,
            args.campaign_provenance,
            args.observation,
            actor=args.actor,
            repository=args.repository,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            release_candidate=args.release_candidate,
            expected_commit=args.expected_commit,
            expected_environment=args.expected_environment,
            expected_campaign_run_id=args.expected_campaign_run_id,
        )
        if args.require_approved and (
            review["decision"] != "approved"
            or not all(review["checks"].values())
            or review["open_findings"]
        ):
            raise QualificationError(
                "review is not approved with every check true and no findings"
            )
        _write_new_json(args.output, review)
    except (QualificationError, OSError) as error:
        print(f"independent Phase 1 review failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
