#!/usr/bin/env python3
"""Authenticate the signed independent Phase 1 review workflow and artifact."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any

from phase1_promotion_qualification import (
    MAX_REVIEW_BYTES,
    QualificationError,
    _load_json,
    _parse_campaign,
    _parse_review,
    _positive_integer,
)


SCHEMA_VERSION = 1
PLAN_CLASS = "restricted_phase1_independent_review_provenance_plan"
REPORT_CLASS = "restricted_phase1_independent_review_provenance"
WORKFLOW_PATH = ".github/workflows/phase1-independent-review.yml"
REVIEW_FILE = "phase1-review.json"
SIGNATURE_FILE = "phase1-review.json.sigstore.json"
MAX_PLAN_BYTES = 256 * 1024
MAX_GITHUB_RUN_BYTES = 2 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4 * 1024 * 1024
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$"
)
GITHUB_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")


def _timestamp_text(value: dt.datetime) -> str:
    normalized = value.astimezone(dt.timezone.utc)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise QualificationError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise QualificationError(f"{label} is not a valid timestamp") from error
    if parsed.utcoffset() != dt.timedelta(0):
        raise QualificationError(f"{label} must use UTC")
    return parsed


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be an object")
    return value


def _string(value: Any, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
    ):
        raise QualificationError(f"{label} must be a non-empty bounded string")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise QualificationError(
            f"{label} keys differ; missing={missing}, extra={extra}"
        )


def _sha256_file(path: Path, label: str, maximum: int) -> str:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise QualificationError(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise QualificationError(f"{label} must contain 1..{maximum} bytes")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    if path.stat().st_size != metadata.st_size:
        raise QualificationError(f"{label} changed while it was read")
    return digest.hexdigest()


def _normalized_workflow_path(value: Any, label: str) -> str:
    raw = _string(value, label, maximum=512)
    path, separator, source_ref = raw.partition("@")
    if separator and not source_ref:
        raise QualificationError(f"{label} contains an empty source ref")
    if (
        path != WORKFLOW_PATH
        or "\n" in raw
        or "\r" in raw
    ):
        raise QualificationError(f"{label} is not the review workflow")
    return path


def _github_login(value: Any, label: str) -> str:
    login = _string(value, label, maximum=39)
    if GITHUB_LOGIN_RE.fullmatch(login) is None:
        raise QualificationError(f"{label} is not a canonical GitHub login")
    return login


def _review_context(
    campaign_path: Path,
    review_path: Path,
    *,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
) -> tuple[dict[str, Any], str, dict[str, Any], str]:
    campaign, campaign_sha, _, completion_times = _parse_campaign(
        campaign_path,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
    )
    review, review_sha, _ = _parse_review(
        review_path,
        campaign_sha=campaign_sha,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
        on_device_environment=campaign["_validated_on_device_environment"],
        operator_ids=campaign["_validated_operator_ids"],
        completion_times=completion_times,
    )
    return campaign, campaign_sha, review, review_sha


def build_plan(
    campaign_path: Path,
    review_path: Path,
    *,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
    expected_review_run_id: int,
) -> dict[str, Any]:
    _, campaign_sha, review, review_sha = _review_context(
        campaign_path,
        review_path,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
    )
    run_id = _positive_integer(
        expected_review_run_id, "expected review workflow run id"
    )
    workflow = review["review_workflow"]
    if workflow["run_id"] != run_id:
        raise QualificationError(
            "signed review run does not match the promotion dispatch"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "qualification_class": PLAN_CLASS,
        "release_candidate": release_candidate,
        "source": {"commit": expected_commit, "dirty": False},
        "campaign_sha256": campaign_sha,
        "independent_review_sha256": review_sha,
        "reviewer_id": review["reviewer_id"],
        "reviewed_at": review["reviewed_at"],
        "run": {
            "run_id": workflow["run_id"],
            "run_attempt": workflow["run_attempt"],
            "repository": workflow["repository"],
            "workflow_path": workflow["workflow_path"],
            "head_sha": workflow["head_sha"],
            "event": workflow["event"],
            "metadata_file": (
                f"{workflow['run_id']}-{workflow['run_attempt']}.json"
            ),
        },
        "artifact": {
            "artifact_name": (
                f"phase1-independent-review-{release_candidate}-{expected_commit}"
            ),
            "review_file": REVIEW_FILE,
            "signature_file": SIGNATURE_FILE,
        },
        "production_claim_allowed": False,
    }


def _validate_plan(plan: dict[str, Any]) -> None:
    _exact_keys(
        plan,
        {
            "schema_version",
            "qualification_class",
            "release_candidate",
            "source",
            "campaign_sha256",
            "independent_review_sha256",
            "reviewer_id",
            "reviewed_at",
            "run",
            "artifact",
            "production_claim_allowed",
        },
        "review provenance plan",
    )
    if plan["schema_version"] != SCHEMA_VERSION:
        raise QualificationError("review provenance plan schema is unsupported")
    if plan["qualification_class"] != PLAN_CLASS:
        raise QualificationError(
            "review provenance plan qualification_class is invalid"
        )
    if plan["production_claim_allowed"] is not False:
        raise QualificationError(
            "review provenance plan must keep production_claim_allowed false"
        )


def _verify_run(
    metadata: dict[str, Any],
    expected: dict[str, Any],
    *,
    reviewer_id: str,
    reviewed_at: str,
    repository: str,
) -> str:
    for field in (
        "id",
        "run_attempt",
        "path",
        "head_sha",
        "event",
        "status",
        "conclusion",
        "updated_at",
        "repository",
        "head_repository",
        "actor",
        "triggering_actor",
    ):
        if field not in metadata:
            raise QualificationError(f"GitHub review run metadata is missing {field}")
    if _positive_integer(metadata["id"], "GitHub review run id") != expected["run_id"]:
        raise QualificationError("GitHub review run id does not match")
    if (
        _positive_integer(
            metadata["run_attempt"], "GitHub review run attempt"
        )
        != expected["run_attempt"]
    ):
        raise QualificationError("GitHub review run attempt does not match")
    if (
        _normalized_workflow_path(
            metadata["path"], "GitHub review workflow path"
        )
        != expected["workflow_path"]
    ):
        raise QualificationError("GitHub review workflow path does not match")
    if metadata["head_sha"] != expected["head_sha"]:
        raise QualificationError("GitHub review workflow head SHA does not match")
    if metadata["event"] != "workflow_dispatch":
        raise QualificationError("GitHub review workflow event is not workflow_dispatch")
    if metadata["status"] != "completed" or metadata["conclusion"] != "success":
        raise QualificationError(
            "GitHub review workflow did not complete successfully"
        )
    for field in ("repository", "head_repository"):
        identity = _object(metadata[field], f"GitHub review {field}")
        if identity.get("full_name") != repository:
            raise QualificationError(
                f"GitHub review {field} does not match trusted repository"
            )
    expected_reviewer = _github_login(reviewer_id, "signed review reviewer_id")
    for field in ("actor", "triggering_actor"):
        identity = _object(metadata[field], f"GitHub review {field}")
        authenticated = _github_login(
            identity.get("login"), f"GitHub review {field}.login"
        )
        if authenticated.casefold() != expected_reviewer.casefold():
            raise QualificationError(
                f"GitHub review {field} does not match signed reviewer"
            )
    workflow_updated_at = _timestamp(
        metadata["updated_at"], "GitHub review workflow updated_at"
    )
    if workflow_updated_at < _timestamp(reviewed_at, "signed review reviewed_at"):
        raise QualificationError(
            "GitHub review workflow completed before the signed review"
        )
    if workflow_updated_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise QualificationError("GitHub review workflow completion is in the future")
    return _timestamp_text(workflow_updated_at)


def _verify_signature(
    review_path: Path,
    bundle_path: Path,
    *,
    repository: str,
    release_candidate: str,
) -> None:
    identity = (
        f"https://github.com/{repository}/{WORKFLOW_PATH}"
        f"@refs/tags/{release_candidate}"
    )
    try:
        result = subprocess.run(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                str(bundle_path),
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                str(review_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationError(
            "cannot execute bounded keyless review signature verification"
        ) from error
    if result.returncode != 0:
        raise QualificationError("keyless review signature verification failed")


def verify_provenance(
    campaign_path: Path,
    review_path: Path,
    plan_path: Path,
    run_metadata_path: Path,
    artifact_dir: Path,
    *,
    repository: str,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
    expected_review_run_id: int,
) -> dict[str, Any]:
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise QualificationError("repository must be an exact owner/name identity")
    expected_plan = build_plan(
        campaign_path,
        review_path,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
        expected_review_run_id=expected_review_run_id,
    )
    plan, _ = _load_json(
        plan_path, "Phase 1 review provenance plan", MAX_PLAN_BYTES
    )
    _validate_plan(plan)
    if plan != expected_plan:
        raise QualificationError(
            "review provenance plan does not match exact campaign, review, and dispatch"
        )
    if plan["run"]["repository"] != repository:
        raise QualificationError(
            "signed review repository does not match trusted repository"
        )
    metadata, _ = _load_json(
        run_metadata_path,
        "GitHub independent review workflow run",
        MAX_GITHUB_RUN_BYTES,
    )
    workflow_updated_at = _verify_run(
        metadata,
        plan["run"],
        reviewer_id=plan["reviewer_id"],
        reviewed_at=plan["reviewed_at"],
        repository=repository,
    )
    try:
        directory_metadata = artifact_dir.lstat()
    except OSError as error:
        raise QualificationError(
            f"cannot inspect downloaded review artifact: {error}"
        ) from error
    if not stat.S_ISDIR(directory_metadata.st_mode) or stat.S_ISLNK(
        directory_metadata.st_mode
    ):
        raise QualificationError(
            "downloaded review artifact must be a real directory"
        )
    expected_files = {
        plan["artifact"]["review_file"],
        plan["artifact"]["signature_file"],
    }
    actual_files = {entry.name for entry in artifact_dir.iterdir()}
    if actual_files != expected_files:
        raise QualificationError(
            "downloaded review artifact inventory differs from contract"
        )
    downloaded_review = artifact_dir / plan["artifact"]["review_file"]
    signature_bundle = artifact_dir / plan["artifact"]["signature_file"]
    _, downloaded_review_sha = _load_json(
        downloaded_review, "downloaded independent review", MAX_REVIEW_BYTES
    )
    if downloaded_review_sha != plan["independent_review_sha256"]:
        raise QualificationError(
            "downloaded independent review bytes differ from signed review"
        )
    signature_sha = _sha256_file(
        signature_bundle,
        "independent review signature bundle",
        MAX_SIGNATURE_BYTES,
    )
    _verify_signature(
        downloaded_review,
        signature_bundle,
        repository=repository,
        release_candidate=release_candidate,
    )
    generated_at = max(
        dt.datetime.now(dt.timezone.utc),
        _timestamp(workflow_updated_at, "GitHub review workflow updated_at"),
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "qualification_class": REPORT_CLASS,
        "generated_at": _timestamp_text(generated_at),
        "repository": repository,
        "release_candidate": release_candidate,
        "source": {"commit": expected_commit, "dirty": False},
        "campaign_sha256": plan["campaign_sha256"],
        "independent_review_sha256": plan["independent_review_sha256"],
        "review_workflow": {
            "run_id": plan["run"]["run_id"],
            "run_attempt": plan["run"]["run_attempt"],
            "workflow_path": plan["run"]["workflow_path"],
            "head_sha": plan["run"]["head_sha"],
            "event": plan["run"]["event"],
            "workflow_updated_at": workflow_updated_at,
        },
        "review_signature_bundle_sha256": signature_sha,
        "reviewer_identity_authenticated": True,
        "github_review_workflow_provenance_verified": True,
        "github_review_artifact_bytes_verified": True,
        "keyless_review_signature_verified": True,
        "production_claim_allowed": False,
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
    _github_login("independent-reviewer", "contract reviewer")
    if Path(REVIEW_FILE).name != REVIEW_FILE:
        raise QualificationError("review artifact filename is unsafe")
    if Path(SIGNATURE_FILE).name != SIGNATURE_FILE:
        raise QualificationError("review signature filename is unsafe")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--review", type=Path)
    parser.add_argument("--release-candidate")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-environment")
    parser.add_argument("--expected-review-run-id", type=int)
    parser.add_argument("--plan-output", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--run-metadata", type=Path)
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        validate_contract()
        if args.validate:
            if any(
                value is not None
                for name, value in vars(args).items()
                if name != "validate"
            ):
                raise QualificationError(
                    "--validate cannot be combined with execution arguments"
                )
            print(
                "validated independent Phase 1 review provenance schema "
                f"v{SCHEMA_VERSION}"
            )
            return 0
        common = (
            args.campaign,
            args.review,
            args.release_candidate,
            args.expected_commit,
            args.expected_environment,
            args.expected_review_run_id,
        )
        if any(value is None for value in common):
            raise QualificationError(
                "campaign, review, release identity, environment, and expected "
                "review run id are required"
            )
        if args.plan_output is not None:
            if any(
                value is not None
                for value in (
                    args.plan,
                    args.repository,
                    args.run_metadata,
                    args.artifact_dir,
                    args.output,
                )
            ):
                raise QualificationError(
                    "--plan-output cannot be combined with verification arguments"
                )
            _write_new_json(
                args.plan_output,
                build_plan(
                    args.campaign,
                    args.review,
                    release_candidate=args.release_candidate,
                    expected_commit=args.expected_commit,
                    expected_environment=args.expected_environment,
                    expected_review_run_id=args.expected_review_run_id,
                ),
            )
            return 0
        verification = (
            args.plan,
            args.repository,
            args.run_metadata,
            args.artifact_dir,
            args.output,
        )
        if any(value is None for value in verification):
            raise QualificationError(
                "verification requires --plan, --repository, --run-metadata, "
                "--artifact-dir, and --output"
            )
        _write_new_json(
            args.output,
            verify_provenance(
                args.campaign,
                args.review,
                args.plan,
                args.run_metadata,
                args.artifact_dir,
                repository=args.repository,
                release_candidate=args.release_candidate,
                expected_commit=args.expected_commit,
                expected_environment=args.expected_environment,
                expected_review_run_id=args.expected_review_run_id,
            ),
        )
    except (QualificationError, OSError) as error:
        print(f"Phase 1 review provenance failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
