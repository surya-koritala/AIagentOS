#!/usr/bin/env python3
"""Authenticate every Phase 1 workflow attempt and retained report artifact."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from phase1_promotion_qualification import (
    BASE_EVIDENCE,
    PROVIDERS,
    QualificationError,
    _load_json,
    _parse_campaign,
    _positive_integer,
)


SCHEMA_VERSION = 1
PLAN_CLASS = "restricted_phase1_github_provenance_plan"
REPORT_CLASS = "restricted_phase1_github_provenance"
MAX_PLAN_BYTES = 256 * 1024
MAX_GITHUB_RUN_BYTES = 2 * 1024 * 1024
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$"
)


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


def _string(value: Any, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
    ):
        raise QualificationError(f"{label} must be a non-empty bounded string")
    return value


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


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise QualificationError(
            f"{label} keys differ; missing={missing}, extra={extra}"
        )


def _real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise QualificationError(f"{label} must be a real directory")


def _artifact_name(
    evidence_id: str, *, release_candidate: str, commit: str
) -> str:
    if evidence_id == "linux-cli-rc":
        return "qualified-linux-cli-rc-bundle"
    if evidence_id == "live-provider-plan":
        return f"live-provider-plan-{commit}"
    if evidence_id.startswith("provider:"):
        provider = evidence_id.removeprefix("provider:")
        if provider not in PROVIDERS:
            raise QualificationError(f"unsupported provider evidence: {provider}")
        return f"provider-{provider}"
    names = {
        "on-device": f"on-device-qualification-{release_candidate}-{commit}",
        "target-remote-backup": (
            f"target-remote-backup-{release_candidate}-{commit}"
        ),
        "storage-profile": f"storage-profile-{release_candidate}-{commit}",
        "external-deletion": (
            f"external-deletion-{release_candidate}-{commit}"
        ),
        "resource-soak": f"resource-soak-{commit}",
        "release-slo": f"release-slo-{release_candidate}-{commit}",
        "game-day": f"game-day-{release_candidate}-{commit}",
    }
    try:
        return names[evidence_id]
    except KeyError as error:
        raise QualificationError(
            f"unsupported Phase 1 evidence artifact: {evidence_id}"
        ) from error


def _download_subdir(evidence_id: str) -> str:
    result = evidence_id.replace(":", "__")
    if (
        not result
        or Path(result).name != result
        or re.fullmatch(r"[A-Za-z0-9._-]+", result) is None
    ):
        raise QualificationError(f"unsafe evidence download directory: {evidence_id}")
    return result


def build_plan(
    campaign_path: Path,
    *,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
    expected_linux_cli_run_id: int,
) -> dict[str, Any]:
    _, campaign_sha, records, _ = _parse_campaign(
        campaign_path,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
    )
    linux_run_id = _positive_integer(
        expected_linux_cli_run_id, "expected_linux_cli_run_id"
    )
    if records["linux-cli-rc"]["workflow_run_id"] != linux_run_id:
        raise QualificationError(
            "campaign Linux CLI run does not match the downloaded signed bundle run"
        )

    grouped_runs: dict[tuple[int, int], dict[str, Any]] = {}
    artifacts: list[dict[str, Any]] = []
    for evidence_id in sorted(records):
        record = records[evidence_id]
        key = (record["workflow_run_id"], record["workflow_run_attempt"])
        completed_at = _timestamp_text(record["workflow_completed_at"])
        run = grouped_runs.setdefault(
            key,
            {
                "run_id": key[0],
                "run_attempt": key[1],
                "workflow_path": record["workflow_path"],
                "head_sha": expected_commit,
                "conclusion": "success",
                "workflow_updated_at": completed_at,
                "metadata_file": f"{key[0]}-{key[1]}.json",
                "evidence_ids": [],
            },
        )
        for field, expected in (
            ("workflow_path", record["workflow_path"]),
            ("head_sha", expected_commit),
            ("conclusion", "success"),
            ("workflow_updated_at", completed_at),
        ):
            if run[field] != expected:
                raise QualificationError(
                    f"workflow run {key[0]} attempt {key[1]} has mixed {field}"
                )
        run["evidence_ids"].append(evidence_id)
        artifacts.append(
            {
                "evidence_id": evidence_id,
                "run_id": key[0],
                "run_attempt": key[1],
                "artifact_name": _artifact_name(
                    evidence_id,
                    release_candidate=release_candidate,
                    commit=expected_commit,
                ),
                "download_subdir": _download_subdir(evidence_id),
                "report_file": record["path"],
                "report_sha256": record["sha256"],
            }
        )
    runs = sorted(
        grouped_runs.values(),
        key=lambda run: (run["run_id"], run["run_attempt"]),
    )
    for run in runs:
        run["evidence_ids"] = sorted(run["evidence_ids"])
    return {
        "schema_version": SCHEMA_VERSION,
        "qualification_class": PLAN_CLASS,
        "release_candidate": release_candidate,
        "source": {"commit": expected_commit, "dirty": False},
        "campaign_sha256": campaign_sha,
        "runs": runs,
        "artifacts": artifacts,
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
            "runs",
            "artifacts",
            "production_claim_allowed",
        },
        "provenance plan",
    )
    if plan["schema_version"] != SCHEMA_VERSION:
        raise QualificationError("provenance plan schema_version is unsupported")
    if plan["qualification_class"] != PLAN_CLASS:
        raise QualificationError("provenance plan qualification_class is invalid")
    if plan["production_claim_allowed"] is not False:
        raise QualificationError(
            "provenance plan must keep production_claim_allowed false"
        )


def _normalized_workflow_path(value: Any, label: str) -> str:
    raw = _string(value, label, maximum=512)
    path, separator, source_ref = raw.partition("@")
    if separator and not source_ref:
        raise QualificationError(f"{label} contains an empty source ref")
    if (
        not path.startswith(".github/workflows/")
        or Path(path).suffix not in {".yml", ".yaml"}
        or "\n" in raw
        or "\r" in raw
    ):
        raise QualificationError(f"{label} is not a safe workflow path")
    return path


def _validate_run_metadata(
    metadata: dict[str, Any],
    expected: dict[str, Any],
    *,
    repository: str,
) -> dict[str, Any]:
    for field in (
        "id",
        "run_attempt",
        "path",
        "head_sha",
        "status",
        "conclusion",
        "updated_at",
        "repository",
        "head_repository",
    ):
        if field not in metadata:
            raise QualificationError(f"GitHub run metadata is missing {field}")
    if _positive_integer(metadata["id"], "GitHub run id") != expected["run_id"]:
        raise QualificationError("GitHub run id does not match the campaign")
    if (
        _positive_integer(metadata["run_attempt"], "GitHub run attempt")
        != expected["run_attempt"]
    ):
        raise QualificationError("GitHub run attempt does not match the campaign")
    if (
        _normalized_workflow_path(metadata["path"], "GitHub workflow path")
        != expected["workflow_path"]
    ):
        raise QualificationError("GitHub workflow path does not match the campaign")
    if metadata["head_sha"] != expected["head_sha"]:
        raise QualificationError("GitHub workflow head SHA does not match the campaign")
    if metadata["status"] != "completed" or metadata["conclusion"] != "success":
        raise QualificationError("GitHub workflow attempt did not complete successfully")
    if _timestamp(metadata["updated_at"], "GitHub workflow updated_at") != _timestamp(
        expected["workflow_updated_at"], "campaign workflow_updated_at"
    ):
        raise QualificationError(
            "GitHub workflow updated_at does not match the campaign"
        )
    for field in ("repository", "head_repository"):
        identity = _object(metadata[field], f"GitHub {field}")
        if identity.get("full_name") != repository:
            raise QualificationError(
                f"GitHub {field} does not match the trusted repository"
            )
    return {
        "run_id": expected["run_id"],
        "run_attempt": expected["run_attempt"],
        "workflow_path": expected["workflow_path"],
        "head_sha": expected["head_sha"],
        "workflow_updated_at": expected["workflow_updated_at"],
        "evidence_ids": expected["evidence_ids"],
    }


def verify_provenance(
    campaign_path: Path,
    plan_path: Path,
    run_metadata_dir: Path,
    artifact_download_dir: Path,
    evidence_dir: Path,
    *,
    repository: str,
    release_candidate: str,
    expected_commit: str,
    expected_environment: str,
    expected_linux_cli_run_id: int,
) -> dict[str, Any]:
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise QualificationError("repository must be an exact owner/name identity")
    expected_plan = build_plan(
        campaign_path,
        release_candidate=release_candidate,
        expected_commit=expected_commit,
        expected_environment=expected_environment,
        expected_linux_cli_run_id=expected_linux_cli_run_id,
    )
    plan, _ = _load_json(
        plan_path, "Phase 1 GitHub provenance plan", MAX_PLAN_BYTES
    )
    _validate_plan(plan)
    if plan != expected_plan:
        raise QualificationError(
            "provenance plan does not match the exact campaign and dispatch"
        )
    _real_directory(run_metadata_dir, "GitHub run metadata directory")
    _real_directory(artifact_download_dir, "GitHub artifact download directory")
    _real_directory(evidence_dir, "protected evidence directory")

    expected_metadata_files = {run["metadata_file"] for run in plan["runs"]}
    actual_metadata_files = {entry.name for entry in run_metadata_dir.iterdir()}
    if actual_metadata_files != expected_metadata_files:
        raise QualificationError(
            "GitHub run metadata inventory differs from the provenance plan"
        )
    verified_runs: list[dict[str, Any]] = []
    for run in plan["runs"]:
        metadata, _ = _load_json(
            run_metadata_dir / run["metadata_file"],
            f"GitHub run {run['run_id']} attempt {run['run_attempt']}",
            MAX_GITHUB_RUN_BYTES,
        )
        verified_runs.append(
            _validate_run_metadata(metadata, run, repository=repository)
        )

    expected_download_dirs = {
        artifact["download_subdir"] for artifact in plan["artifacts"]
    }
    actual_download_dirs = {entry.name for entry in artifact_download_dir.iterdir()}
    if actual_download_dirs != expected_download_dirs:
        raise QualificationError(
            "downloaded GitHub artifact inventory differs from the provenance plan"
        )
    verified_artifacts: list[dict[str, Any]] = []
    for artifact in plan["artifacts"]:
        download_root = artifact_download_dir / artifact["download_subdir"]
        _real_directory(
            download_root, f"{artifact['evidence_id']} downloaded artifact"
        )
        downloaded_report = download_root / artifact["report_file"]
        protected_report = evidence_dir / artifact["report_file"]
        _, downloaded_digest = _load_json(
            downloaded_report,
            f"{artifact['evidence_id']} downloaded report",
            8 * 1024 * 1024,
        )
        _, protected_digest = _load_json(
            protected_report,
            f"{artifact['evidence_id']} protected report",
            8 * 1024 * 1024,
        )
        if (
            downloaded_digest != artifact["report_sha256"]
            or protected_digest != artifact["report_sha256"]
        ):
            raise QualificationError(
                f"{artifact['evidence_id']} downloaded and protected bytes differ"
            )
        verified_artifacts.append(
            {
                "evidence_id": artifact["evidence_id"],
                "run_id": artifact["run_id"],
                "run_attempt": artifact["run_attempt"],
                "artifact_name": artifact["artifact_name"],
                "report_sha256": artifact["report_sha256"],
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "qualification_class": REPORT_CLASS,
        "generated_at": _timestamp_text(dt.datetime.now(dt.timezone.utc)),
        "repository": repository,
        "release_candidate": release_candidate,
        "source": {"commit": expected_commit, "dirty": False},
        "campaign_sha256": plan["campaign_sha256"],
        "run_count": len(verified_runs),
        "artifact_count": len(verified_artifacts),
        "runs": verified_runs,
        "artifacts": verified_artifacts,
        "github_workflow_provenance_verified": True,
        "github_artifact_bytes_verified": True,
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
    if len(PROVIDERS) != len(set(PROVIDERS)):
        raise QualificationError("provider catalog contains duplicates")
    for evidence_id in BASE_EVIDENCE:
        _artifact_name(
            evidence_id,
            release_candidate="v0.0.0-rc.1",
            commit="0" * 40,
        )
        _download_subdir(evidence_id)
    for provider in PROVIDERS:
        _artifact_name(
            f"provider:{provider}",
            release_candidate="v0.0.0-rc.1",
            commit="0" * 40,
        )
        _download_subdir(f"provider:{provider}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--release-candidate")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-environment")
    parser.add_argument("--expected-linux-cli-run-id", type=int)
    parser.add_argument("--plan-output", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--run-metadata-dir", type=Path)
    parser.add_argument("--artifact-download-dir", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
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
                "validated Phase 1 GitHub provenance schema "
                f"v{SCHEMA_VERSION}: {len(BASE_EVIDENCE)} base artifacts, "
                f"{len(PROVIDERS)} providers"
            )
            return 0
        common = (
            args.campaign,
            args.release_candidate,
            args.expected_commit,
            args.expected_environment,
            args.expected_linux_cli_run_id,
        )
        if any(value is None for value in common):
            raise QualificationError(
                "--campaign, --release-candidate, --expected-commit, "
                "--expected-environment, and --expected-linux-cli-run-id "
                "are required"
            )
        if args.plan_output is not None:
            if any(
                value is not None
                for value in (
                    args.plan,
                    args.repository,
                    args.run_metadata_dir,
                    args.artifact_download_dir,
                    args.evidence_dir,
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
                    release_candidate=args.release_candidate,
                    expected_commit=args.expected_commit,
                    expected_environment=args.expected_environment,
                    expected_linux_cli_run_id=args.expected_linux_cli_run_id,
                ),
            )
            return 0
        verification = (
            args.plan,
            args.repository,
            args.run_metadata_dir,
            args.artifact_download_dir,
            args.evidence_dir,
            args.output,
        )
        if any(value is None for value in verification):
            raise QualificationError(
                "verification requires --plan, --repository, "
                "--run-metadata-dir, --artifact-download-dir, "
                "--evidence-dir, and --output"
            )
        _write_new_json(
            args.output,
            verify_provenance(
                args.campaign,
                args.plan,
                args.run_metadata_dir,
                args.artifact_download_dir,
                args.evidence_dir,
                repository=args.repository,
                release_candidate=args.release_candidate,
                expected_commit=args.expected_commit,
                expected_environment=args.expected_environment,
                expected_linux_cli_run_id=args.expected_linux_cli_run_id,
            ),
        )
    except (QualificationError, OSError) as error:
        print(f"Phase 1 GitHub provenance failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
