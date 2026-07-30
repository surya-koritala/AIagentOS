#!/usr/bin/env python3
"""Build a bounded dispatch preflight for protected external qualifications."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys


SCHEMA_VERSION = 1
QUALIFICATION_CLASS = "protected_external_dispatch_plan"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PROFILE_RE = re.compile(r"^[a-z][a-z0-9-]*$")
PROFILE_CONFIGS = (
    {
        "profile": "capacity-baseline",
        "enable_variable": "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "environment": "capacity-qualification",
        "runner_labels": ["self-hosted", "linux", "x64", "agentos-capacity"],
        "required_variables": [],
        "optional_variables": [],
        "required_secrets": [],
        "optional_secrets": [],
    },
    {
        "profile": "resource-soak",
        "enable_variable": "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "environment": "capacity-qualification",
        "runner_labels": ["self-hosted", "linux", "x64", "agentos-capacity"],
        "required_variables": [],
        "optional_variables": [],
        "required_secrets": [],
        "optional_secrets": [],
    },
    {
        "profile": "target-remote-backup",
        "enable_variable": "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "environment": "capacity-qualification",
        "runner_labels": ["self-hosted", "linux", "x64", "agentos-capacity"],
        "required_variables": [
            "AGENTOS_TARGET_REMOTE_ENDPOINT",
            "AGENTOS_TARGET_REMOTE_BUCKET",
            "AGENTOS_TARGET_REMOTE_REGION",
        ],
        "optional_variables": [],
        "required_secrets": [
            "AGENTOS_TARGET_REMOTE_ACCESS_KEY_ID",
            "AGENTOS_TARGET_REMOTE_SECRET_ACCESS_KEY",
        ],
        "optional_secrets": ["AGENTOS_TARGET_REMOTE_SESSION_TOKEN"],
    },
    {
        "profile": "release-slo",
        "enable_variable": "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "environment": "capacity-qualification",
        "runner_labels": ["self-hosted", "linux", "x64", "agentos-capacity"],
        "required_variables": ["AGENTOS_SLO_EVIDENCE_DIR"],
        "optional_variables": [],
        "required_secrets": [],
        "optional_secrets": [],
    },
    {
        "profile": "game-day",
        "enable_variable": "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "environment": "capacity-qualification",
        "runner_labels": ["self-hosted", "linux", "x64", "agentos-capacity"],
        "required_variables": ["AGENTOS_GAME_DAY_EVIDENCE_DIR"],
        "optional_variables": [],
        "required_secrets": [],
        "optional_secrets": [],
    },
    {
        "profile": "on-device",
        "enable_variable": "AGENTOS_MODEL_QUALIFICATION_ENABLED",
        "environment": "model-qualification",
        "runner_labels": ["self-hosted", "linux", "x64", "agentos-model"],
        "required_variables": [
            "AGENTOS_GGUF_MODEL",
            "AGENTOS_TOKENIZER",
            "AGENTOS_ON_DEVICE_HARDWARE_ID",
        ],
        "optional_variables": ["AGENTOS_ON_DEVICE_RAYON_THREADS"],
        "required_secrets": [],
        "optional_secrets": [],
    },
    {
        "profile": "storage-profile",
        "enable_variable": "AGENTOS_DESTRUCTIVE_STORAGE_QUALIFICATION_ENABLED",
        "environment": "destructive-storage-qualification",
        "runner_labels": [
            "self-hosted",
            "linux",
            "x64",
            "agentos-destructive-storage",
        ],
        "required_variables": ["AGENTOS_STORAGE_PROFILE_EVIDENCE_DIR"],
        "optional_variables": [],
        "required_secrets": [],
        "optional_secrets": [],
    },
    {
        "profile": "external-deletion",
        "enable_variable": "AGENTOS_EXTERNAL_DATA_QUALIFICATION_ENABLED",
        "environment": "external-data-qualification",
        "runner_labels": ["self-hosted", "linux", "x64", "agentos-external-data"],
        "required_variables": ["AGENTOS_EXTERNAL_DELETION_EVIDENCE_DIR"],
        "optional_variables": [],
        "required_secrets": [],
        "optional_secrets": [],
    },
)
PROFILES = tuple(config["profile"] for config in PROFILE_CONFIGS)
PROFILE_BY_ID = {config["profile"]: config for config in PROFILE_CONFIGS}


class QualificationPlanError(ValueError):
    """The requested protected qualification preflight is malformed."""


def validate_catalog() -> None:
    if not PROFILE_CONFIGS:
        raise QualificationPlanError("profile catalog must not be empty")
    if len(PROFILES) != len(set(PROFILES)):
        raise QualificationPlanError("profile catalog contains duplicates")
    required_keys = {
        "profile",
        "enable_variable",
        "environment",
        "runner_labels",
        "required_variables",
        "optional_variables",
        "required_secrets",
        "optional_secrets",
    }
    for config in PROFILE_CONFIGS:
        if set(config) != required_keys:
            raise QualificationPlanError("profile configuration keys are incomplete")
        profile = config["profile"]
        if not isinstance(profile, str) or PROFILE_RE.fullmatch(profile) is None:
            raise QualificationPlanError(
                f"profile catalog contains an invalid ID: {profile}"
            )
        runner_labels = config["runner_labels"]
        if (
            not isinstance(runner_labels, list)
            or len(runner_labels) < 2
            or len(runner_labels) != len(set(runner_labels))
            or "self-hosted" not in runner_labels
        ):
            raise QualificationPlanError(
                f"profile {profile} must declare unique self-hosted runner labels"
            )


def parse_enablement(value: str) -> tuple[bool, bool]:
    """Return (explicitly_enabled, valid) without accepting ambiguous values."""

    normalized = value.strip()
    if normalized in ("", "false"):
        return False, True
    if normalized == "true":
        return True, True
    return False, False


def build_plan(profile: str, enabled: str, commit: str) -> dict[str, object]:
    """Build a source-bound preflight without claiming infrastructure exists."""

    if COMMIT_RE.fullmatch(commit) is None:
        raise QualificationPlanError(
            "source commit must be a lowercase 40-character SHA-1"
        )
    config = PROFILE_BY_ID.get(profile)
    if config is None:
        raise QualificationPlanError(f"unsupported qualification profile: {profile}")

    explicitly_enabled, enable_value_valid = parse_enablement(enabled)
    ready = explicitly_enabled and enable_value_valid
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "qualification_class": QUALIFICATION_CLASS,
        "profile": profile,
        "status": "ready" if ready else "not_run",
        "readiness_scope": "dispatch_configuration_only",
        "infrastructure_verified": False,
        "production_claim_allowed": False,
        "source": {"commit": commit},
        "enable_variable": config["enable_variable"],
        "configuration": {
            "explicitly_enabled": explicitly_enabled,
            "enable_value_valid": enable_value_valid,
        },
        "required_environment": config["environment"],
        "required_runner_labels": list(config["runner_labels"]),
        "required_variables": list(config["required_variables"]),
        "optional_variables": list(config["optional_variables"]),
        "required_secrets": list(config["required_secrets"]),
        "optional_secrets": list(config["optional_secrets"]),
    }
    if not enable_value_valid:
        report["reason"] = (
            f"{config['enable_variable']} must be exactly true or false; "
            "ambiguous enablement is rejected"
        )
    elif not explicitly_enabled:
        report["reason"] = (
            f"protected qualification is disabled; provision the listed environment, "
            f"runner, variables, and secrets, then set {config['enable_variable']}=true"
        )
    else:
        report["reason"] = (
            "dispatch is explicitly enabled; the protected job must still prove "
            "its runner, environment inputs, exact-source checks, and result"
        )
    return report


def write_json(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def write_github_output(path: Path, report: dict[str, object]) -> None:
    ready = report["status"] == "ready"
    with path.open("a", encoding="utf-8") as output:
        output.write(f"ready={'true' if ready else 'false'}\n")
        output.write(f"profile={report['profile']}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--profile")
    parser.add_argument("--enabled", default="")
    parser.add_argument("--commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)

    try:
        validate_catalog()
        if args.validate:
            if any(
                value is not None
                for value in (
                    args.profile,
                    args.commit,
                    args.output,
                    args.github_output,
                )
            ) or args.enabled:
                raise QualificationPlanError(
                    "--validate cannot be combined with plan output arguments"
                )
            print(
                f"validated protected qualification plan schema v{SCHEMA_VERSION} "
                f"with {len(PROFILES)} profiles"
            )
            return 0
        if args.profile is None or args.commit is None or args.output is None:
            raise QualificationPlanError(
                "--profile, --commit, and --output are required"
            )

        report = build_plan(args.profile, args.enabled, args.commit)
        write_json(args.output, report)
        if args.github_output is not None:
            write_github_output(args.github_output, report)
    except (QualificationPlanError, OSError) as error:
        print(f"protected qualification plan failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
