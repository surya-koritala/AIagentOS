#!/usr/bin/env python3
"""Assemble one deterministic Phase 1 campaign from exact GitHub runs."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any

from phase1_promotion_qualification import (
    CAMPAIGN_CLASS,
    COMMIT_RE,
    MAX_CAMPAIGN_BYTES,
    PROFILE_ID,
    RC_RE,
    RESERVED_REVIEWER_IDS,
    QualificationError,
    _canonical_id_list,
    _exact_keys,
    _identifier,
    _load_json,
    _object,
    _positive_integer,
    _provider_list,
    _source,
    _timestamp,
)
from phase1_workflow_provenance import _artifact_name, _download_subdir


SCHEMA_VERSION = 1
REQUEST_CLASS = "restricted_phase1_campaign_assembly_request"
PLAN_CLASS = "restricted_phase1_campaign_assembly_plan"
WORKFLOW_PATH = ".github/workflows/phase1-campaign-assembly.yml"
CAMPAIGN_FILE = "campaign.json"
SIGNATURE_FILE = "campaign.json.sigstore.json"
MAX_REQUEST_BYTES = 256 * 1024
MAX_PLAN_BYTES = 256 * 1024
MAX_GITHUB_RUN_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$"
)
GITHUB_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")

RUN_GROUPS = {
    "external-deletion": (
        ".github/workflows/external-deletion-qualification.yml",
        "workflow_dispatch",
        ("external-deletion",),
    ),
    "game-day": (
        ".github/workflows/game-day-qualification.yml",
        "workflow_dispatch",
        ("game-day",),
    ),
    "linux-cli-rc": (
        ".github/workflows/linux-cli-rc.yml",
        "push",
        ("linux-cli-rc",),
    ),
    "live-provider": (
        ".github/workflows/live-provider-qualification.yml",
        "workflow_dispatch",
        ("live-provider-plan",),
    ),
    "on-device": (
        ".github/workflows/on-device-qualification.yml",
        "workflow_dispatch",
        ("on-device",),
    ),
    "release-slo": (
        ".github/workflows/release-slo-qualification.yml",
        "workflow_dispatch",
        ("release-slo",),
    ),
    "resource-soak": (
        ".github/workflows/resource-soak-qualification.yml",
        "workflow_dispatch",
        ("resource-soak",),
    ),
    "storage-profile": (
        ".github/workflows/storage-profile-qualification.yml",
        "workflow_dispatch",
        ("storage-profile",),
    ),
    "target-remote-backup": (
        ".github/workflows/target-remote-backup-qualification.yml",
        "workflow_dispatch",
        ("target-remote-backup",),
    ),
}


def _encoded(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _timestamp_text(value: dt.datetime) -> str:
    normalized = value.astimezone(dt.timezone.utc)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _string(value: Any, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
    ):
        raise QualificationError(f"{label} must be a non-empty bounded string")
    return value


def _array(
    value: Any, label: str, *, minimum: int = 0, maximum: int = 100
) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise QualificationError(
            f"{label} must contain {minimum}..{maximum} entries"
        )
    return value


def _github_login(value: Any, label: str) -> str:
    login = _string(value, label, maximum=39)
    if GITHUB_LOGIN_RE.fullmatch(login) is None:
        raise QualificationError(f"{label} is not a canonical human GitHub login")
    if login.casefold() in RESERVED_REVIEWER_IDS:
        raise QualificationError(f"{label} is a reserved harness identity")
    return login


def _real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise QualificationError(f"{label} must be a real directory")


def _safe_workflow_path(value: Any, label: str) -> str:
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


def _parse_request(
    path: Path,
) -> tuple[dict[str, Any], str, list[str], dict[str, int]]:
    request, request_sha = _load_json(
        path, "Phase 1 campaign assembly request", MAX_REQUEST_BYTES
    )
    _exact_keys(
        request,
        {
            "schema_version",
            "qualification_class",
            "release_candidate",
            "source",
            "profile_id",
            "target_environment_id",
            "on_device_environment_id",
            "promoted_providers",
            "run_ids",
        },
        "campaign assembly request",
    )
    if request["schema_version"] != SCHEMA_VERSION:
        raise QualificationError("campaign request schema_version is unsupported")
    if request["qualification_class"] != REQUEST_CLASS:
        raise QualificationError("campaign request qualification_class is invalid")
    release_candidate = _string(
        request["release_candidate"], "campaign request.release_candidate"
    )
    if RC_RE.fullmatch(release_candidate) is None:
        raise QualificationError(
            "campaign request release candidate must be vX.Y.Z-rc.N"
        )
    source = _object(request["source"], "campaign request.source")
    _exact_keys(source, {"commit", "dirty"}, "campaign request.source")
    _source(source, source.get("commit"), "campaign request.source")
    if COMMIT_RE.fullmatch(source["commit"]) is None:
        raise QualificationError(
            "campaign request source commit must be 40 lowercase hexadecimal characters"
        )
    if request["profile_id"] != PROFILE_ID:
        raise QualificationError("campaign request profile_id is unsupported")
    target_environment = _identifier(
        request["target_environment_id"],
        "campaign request.target_environment_id",
    )
    on_device_environment = _identifier(
        request["on_device_environment_id"],
        "campaign request.on_device_environment_id",
    )
    if on_device_environment == target_environment:
        raise QualificationError(
            "on-device and target environments must have distinct identities"
        )
    providers = _provider_list(request["promoted_providers"])
    raw_run_ids = _object(request["run_ids"], "campaign request.run_ids")
    _exact_keys(raw_run_ids, set(RUN_GROUPS), "campaign request.run_ids")
    run_ids = {
        group: _positive_integer(
            raw_run_ids[group], f"campaign request.run_ids.{group}"
        )
        for group in RUN_GROUPS
    }
    if len(set(run_ids.values())) != len(run_ids):
        raise QualificationError("campaign request run IDs must be unique")
    return request, request_sha, providers, run_ids


def build_plan(request_path: Path) -> dict[str, Any]:
    request, request_sha, providers, run_ids = _parse_request(request_path)
    commit = request["source"]["commit"]
    release_candidate = request["release_candidate"]
    runs: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for group in sorted(RUN_GROUPS):
        workflow_path, event, base_evidence = RUN_GROUPS[group]
        evidence_ids = list(base_evidence)
        if group == "live-provider":
            evidence_ids.extend(f"provider:{provider}" for provider in providers)
        run_id = run_ids[group]
        runs.append(
            {
                "run_group": group,
                "run_id": run_id,
                "workflow_path": workflow_path,
                "event": event,
                "head_sha": commit,
                "metadata_file": f"{run_id}.json",
                "evidence_ids": sorted(evidence_ids),
            }
        )
        for evidence_id in evidence_ids:
            report_file = (
                f"provider-{evidence_id.removeprefix('provider:')}.json"
                if evidence_id.startswith("provider:")
                else {
                    "linux-cli-rc": "linux-cli-rc-qualification.json",
                    "live-provider-plan": "live-provider-plan.json",
                    "on-device": "on-device.json",
                    "target-remote-backup": "target-remote-backup.json",
                    "storage-profile": "storage-profile.json",
                    "external-deletion": "external-deletion.json",
                    "resource-soak": "resource-soak.json",
                    "release-slo": "release-slo-report.json",
                    "game-day": "game-day.json",
                }[evidence_id]
            )
            artifacts.append(
                {
                    "evidence_id": evidence_id,
                    "run_group": group,
                    "run_id": run_id,
                    "artifact_name": _artifact_name(
                        evidence_id,
                        release_candidate=release_candidate,
                        commit=commit,
                    ),
                    "download_subdir": _download_subdir(evidence_id),
                    "report_file": report_file,
                }
            )
    return {
        "schema_version": SCHEMA_VERSION,
        "qualification_class": PLAN_CLASS,
        "release_candidate": release_candidate,
        "source": {"commit": commit, "dirty": False},
        "profile_id": PROFILE_ID,
        "target_environment_id": request["target_environment_id"],
        "on_device_environment_id": request["on_device_environment_id"],
        "promoted_providers": providers,
        "request_sha256": request_sha,
        "runs": sorted(runs, key=lambda item: item["run_group"]),
        "artifacts": sorted(artifacts, key=lambda item: item["evidence_id"]),
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
            "profile_id",
            "target_environment_id",
            "on_device_environment_id",
            "promoted_providers",
            "request_sha256",
            "runs",
            "artifacts",
            "production_claim_allowed",
        },
        "campaign assembly plan",
    )
    if plan["schema_version"] != SCHEMA_VERSION:
        raise QualificationError("campaign assembly plan schema is unsupported")
    if plan["qualification_class"] != PLAN_CLASS:
        raise QualificationError(
            "campaign assembly plan qualification_class is invalid"
        )
    if plan["production_claim_allowed"] is not False:
        raise QualificationError(
            "campaign assembly plan must keep production_claim_allowed false"
        )


def _verify_run(
    metadata: dict[str, Any],
    expected: dict[str, Any],
    *,
    repository: str,
) -> tuple[dict[str, Any], list[str]]:
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
            raise QualificationError(
                f"GitHub evidence run metadata is missing {field}"
            )
    run_id = _positive_integer(metadata["id"], "GitHub evidence run id")
    if run_id != expected["run_id"]:
        raise QualificationError("GitHub evidence run id does not match plan")
    run_attempt = _positive_integer(
        metadata["run_attempt"], "GitHub evidence run attempt"
    )
    if (
        _safe_workflow_path(metadata["path"], "GitHub evidence workflow path")
        != expected["workflow_path"]
    ):
        raise QualificationError(
            f"{expected['run_group']} used the wrong workflow"
        )
    if metadata["head_sha"] != expected["head_sha"]:
        raise QualificationError(
            f"{expected['run_group']} used a different source commit"
        )
    if metadata["event"] != expected["event"]:
        raise QualificationError(
            f"{expected['run_group']} used an unsupported workflow event"
        )
    if metadata["status"] != "completed" or metadata["conclusion"] != "success":
        raise QualificationError(
            f"{expected['run_group']} workflow did not complete successfully"
        )
    for field in ("repository", "head_repository"):
        identity = _object(metadata[field], f"GitHub evidence {field}")
        if identity.get("full_name") != repository:
            raise QualificationError(
                f"GitHub evidence {field} does not match trusted repository"
            )
    completed_at = _timestamp(
        metadata["updated_at"], "GitHub evidence workflow updated_at"
    )
    if completed_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise QualificationError("GitHub evidence workflow completion is in the future")
    operators: list[str] = []
    for field in ("actor", "triggering_actor"):
        identity = _object(metadata[field], f"GitHub evidence {field}")
        operators.append(
            _github_login(identity.get("login"), f"GitHub evidence {field}.login")
        )
    return (
        {
            "run_attempt": run_attempt,
            "workflow_completed_at": _timestamp_text(completed_at),
        },
        operators,
    )


def assemble_campaign(
    request_path: Path,
    plan_path: Path,
    run_metadata_dir: Path,
    artifact_download_dir: Path,
    *,
    repository: str,
    assembly_actor: str,
    assembly_triggering_actor: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    if REPOSITORY_RE.fullmatch(repository) is None:
        raise QualificationError("repository must be an exact owner/name identity")
    expected_plan = build_plan(request_path)
    plan, _ = _load_json(
        plan_path, "Phase 1 campaign assembly plan", MAX_PLAN_BYTES
    )
    _validate_plan(plan)
    if plan != expected_plan:
        raise QualificationError(
            "campaign assembly plan does not match the exact request"
        )
    _real_directory(run_metadata_dir, "GitHub run metadata directory")
    _real_directory(artifact_download_dir, "downloaded artifact directory")

    expected_metadata = {run["metadata_file"] for run in plan["runs"]}
    actual_metadata = {entry.name for entry in run_metadata_dir.iterdir()}
    if actual_metadata != expected_metadata:
        raise QualificationError(
            "GitHub run metadata inventory differs from assembly plan"
        )
    run_results: dict[str, dict[str, Any]] = {}
    operator_ids = [
        _github_login(assembly_actor, "campaign assembly actor"),
        _github_login(
            assembly_triggering_actor, "campaign assembly triggering actor"
        ),
    ]
    for run in plan["runs"]:
        metadata, _ = _load_json(
            run_metadata_dir / run["metadata_file"],
            f"GitHub evidence run {run['run_id']}",
            MAX_GITHUB_RUN_BYTES,
        )
        result, operators = _verify_run(metadata, run, repository=repository)
        run_results[run["run_group"]] = result
        operator_ids.extend(operators)
    operators = _canonical_id_list(
        sorted(set(operator_ids), key=str.casefold),
        "derived campaign operator_ids",
        minimum=1,
        maximum=10,
    )

    expected_downloads = {
        artifact["download_subdir"] for artifact in plan["artifacts"]
    }
    actual_downloads = {entry.name for entry in artifact_download_dir.iterdir()}
    if actual_downloads != expected_downloads:
        raise QualificationError(
            "downloaded artifact inventory differs from assembly plan"
        )
    artifacts: list[dict[str, Any]] = []
    reports: dict[str, bytes] = {}
    for artifact in plan["artifacts"]:
        root = artifact_download_dir / artifact["download_subdir"]
        _real_directory(root, f"{artifact['evidence_id']} downloaded artifact")
        report_path = root / artifact["report_file"]
        _, report_sha = _load_json(
            report_path,
            f"{artifact['evidence_id']} report",
            MAX_REPORT_BYTES,
        )
        report_bytes = report_path.read_bytes()
        if _sha256_bytes(report_bytes) != report_sha:
            raise QualificationError(
                f"{artifact['evidence_id']} report changed while it was read"
            )
        if artifact["report_file"] in reports:
            raise QualificationError(
                f"duplicate campaign report path: {artifact['report_file']}"
            )
        reports[artifact["report_file"]] = report_bytes
        run = run_results[artifact["run_group"]]
        artifacts.append(
            {
                "evidence_id": artifact["evidence_id"],
                "path": artifact["report_file"],
                "sha256": report_sha,
                "workflow_path": next(
                    item["workflow_path"]
                    for item in plan["runs"]
                    if item["run_group"] == artifact["run_group"]
                ),
                "workflow_run_id": artifact["run_id"],
                "workflow_run_attempt": run["run_attempt"],
                "workflow_head_sha": plan["source"]["commit"],
                "workflow_conclusion": "success",
                "workflow_completed_at": run["workflow_completed_at"],
            }
        )
    campaign = {
        "schema_version": SCHEMA_VERSION,
        "qualification_class": CAMPAIGN_CLASS,
        "release_candidate": plan["release_candidate"],
        "source": plan["source"],
        "profile_id": plan["profile_id"],
        "target_environment_id": plan["target_environment_id"],
        "on_device_environment_id": plan["on_device_environment_id"],
        "promoted_providers": plan["promoted_providers"],
        "operator_ids": operators,
        "artifacts": sorted(artifacts, key=lambda item: item["evidence_id"]),
    }
    if len(_encoded(campaign)) > MAX_CAMPAIGN_BYTES:
        raise QualificationError("assembled campaign exceeds its size bound")
    return campaign, reports


def _write_new_file(path: Path, encoded: bytes) -> None:
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


def write_bundle(
    output_dir: Path,
    campaign: dict[str, Any],
    reports: dict[str, bytes],
) -> None:
    try:
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as error:
        raise QualificationError(
            f"cannot create new campaign bundle directory: {error}"
        ) from error
    try:
        _write_new_file(output_dir / CAMPAIGN_FILE, _encoded(campaign))
        for name in sorted(reports):
            if Path(name).name != name:
                raise QualificationError(f"unsafe campaign report path: {name}")
            _write_new_file(output_dir / name, reports[name])
    except BaseException:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_new_file(path, _encoded(value))


def validate_contract() -> None:
    if set(RUN_GROUPS) != {
        "external-deletion",
        "game-day",
        "linux-cli-rc",
        "live-provider",
        "on-device",
        "release-slo",
        "resource-soak",
        "storage-profile",
        "target-remote-backup",
    }:
        raise QualificationError("campaign assembly run inventory changed")
    _github_login("release-operator", "contract actor")
    if Path(CAMPAIGN_FILE).name != CAMPAIGN_FILE:
        raise QualificationError("campaign filename is unsafe")
    if Path(SIGNATURE_FILE).name != SIGNATURE_FILE:
        raise QualificationError("campaign signature filename is unsafe")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--request", type=Path)
    parser.add_argument("--plan-output", type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--assembly-actor")
    parser.add_argument("--assembly-triggering-actor")
    parser.add_argument("--run-metadata-dir", type=Path)
    parser.add_argument("--artifact-download-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
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
                "validated Phase 1 campaign assembly schema "
                f"v{SCHEMA_VERSION}: {len(RUN_GROUPS)} exact workflow runs"
            )
            return 0
        if args.request is None:
            raise QualificationError("--request is required")
        if args.plan_output is not None:
            if any(
                value is not None
                for value in (
                    args.plan,
                    args.repository,
                    args.assembly_actor,
                    args.assembly_triggering_actor,
                    args.run_metadata_dir,
                    args.artifact_download_dir,
                    args.output_dir,
                )
            ):
                raise QualificationError(
                    "--plan-output cannot be combined with assembly arguments"
                )
            _write_new_json(args.plan_output, build_plan(args.request))
            return 0
        required = (
            args.plan,
            args.repository,
            args.assembly_actor,
            args.assembly_triggering_actor,
            args.run_metadata_dir,
            args.artifact_download_dir,
            args.output_dir,
        )
        if any(value is None for value in required):
            raise QualificationError(
                "assembly requires --plan, --repository, both assembly actors, "
                "--run-metadata-dir, --artifact-download-dir, and --output-dir"
            )
        campaign, reports = assemble_campaign(
            args.request,
            args.plan,
            args.run_metadata_dir,
            args.artifact_download_dir,
            repository=args.repository,
            assembly_actor=args.assembly_actor,
            assembly_triggering_actor=args.assembly_triggering_actor,
        )
        write_bundle(args.output_dir, campaign, reports)
    except (QualificationError, OSError) as error:
        print(f"Phase 1 campaign assembly failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
