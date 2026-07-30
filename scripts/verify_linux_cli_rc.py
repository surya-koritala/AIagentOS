#!/usr/bin/env python3
"""Fail-closed source and workflow contract for restricted Linux CLI RCs."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path


RC_TAG_PATTERN = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*)$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def _workspace_members(path: Path) -> list[str]:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    workspace = document.get("workspace")
    if not isinstance(workspace, dict):
        raise ValueError("workspace members are missing")
    members = workspace.get("members")
    if (
        not isinstance(members, list)
        or not members
        or any(not isinstance(member, str) or not member for member in members)
    ):
        raise ValueError("workspace members are missing")
    return members


def _package_version(path: Path) -> str | None:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    package = document.get("package")
    if not isinstance(package, dict):
        return None
    version = package.get("version")
    return version if isinstance(version, str) else None


def _path_dependency_versions(value: object) -> list[str]:
    versions: list[str] = []
    if isinstance(value, dict):
        if "path" in value and isinstance(value.get("version"), str):
            versions.append(value["version"])
        for nested in value.values():
            versions.extend(_path_dependency_versions(nested))
    elif isinstance(value, list):
        for nested in value:
            versions.extend(_path_dependency_versions(nested))
    return versions


def validate_contract(root: Path) -> list[str]:
    failures: list[str] = []
    stable = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    rc = (root / ".github/workflows/linux-cli-rc.yml").read_text(encoding="utf-8")
    promotion = (
        root / ".github/workflows/phase1-promotion-qualification.yml"
    ).read_text(encoding="utf-8")
    independent_review = (
        root / ".github/workflows/phase1-independent-review.yml"
    ).read_text(encoding="utf-8")
    campaign = (
        root / ".github/workflows/phase1-campaign-assembly.yml"
    ).read_text(encoding="utf-8")
    if '- "!v*-rc.*"' not in stable:
        failures.append("stable release workflow must exclude release-candidate tags")
    required = [
        '- "v*-rc.*"',
        "required-ci:",
        "governance:",
        "reproducible-linux:",
        "cmp -s",
        "Prove shipped binaries report the exact release version",
        "scripts/build_cli_archive.py",
        "Require GitHub-verified cryptographic tag signature",
        "repos/${GITHUB_REPOSITORY}/git/tags/${tag_object}",
        ".verification.verified == true",
        ".verification.verified_at",
        "sign-runtime:",
        "cosign sign-blob",
        "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
        "fresh-host:",
        "scripts/linux_cli_rc_qualification.py qualify",
        "--released-schema-tag v0.3.0",
        "finalize:",
        "scripts/linux_cli_rc_qualification.py validate-report",
        "Signed candidate bundle awaiting Phase 1 promotion",
        "qualified-linux-cli-rc-bundle",
    ]
    for value in required:
        if value not in rc:
            failures.append(f"Linux CLI RC workflow lost required contract {value!r}")
    forbidden = [
        "pull_request_target",
        "self-hosted",
        "continue-on-error: true",
        "AGENT_SERVER_ALLOW_INSECURE_REMOTE",
        "gh release create",
    ]
    for value in forbidden:
        if value in rc:
            failures.append(f"Linux CLI RC workflow contains forbidden contract {value!r}")
    if "contents: write" in rc:
        failures.append("the tag workflow must not receive publication permission")
    promotion_required = [
        "workflow_dispatch:",
        "release_candidate:",
        "linux_cli_rc_run_id:",
        "phase1_campaign_run_id:",
        "phase1_review_run_id:",
        "environment_id:",
        "profile: phase1-promotion",
        "runs-on: [self-hosted, linux, x64, agentos-capacity]",
        "environment: capacity-qualification",
        "PHASE1_CAMPAIGN_RUN_ID",
        "scripts/phase1_campaign_provenance.py",
        "scripts/phase1_promotion_qualification.py",
        "scripts/phase1_workflow_provenance.py",
        "scripts/phase1_review_provenance.py",
        "actions/runs/${run_id}/attempts/${run_attempt}",
        'gh run download "$run_id"',
        "--campaign-provenance",
        "--workflow-provenance",
        "--review-provenance",
        "phase1-campaign-provenance.json",
        "phase1-workflow-provenance.json",
        "phase1-review-provenance.json",
        "github_campaign_workflow_provenance_verified",
        "keyless_campaign_signature_verified",
        "github_workflow_provenance_verified",
        "github_artifact_bytes_verified",
        "reviewer_identity_authenticated",
        "keyless_review_signature_verified",
        "phase1-independent-review/phase1-review.json",
        "--require-eligible",
        "phase1_release_candidate_ready",
        "production_claim_allowed",
        "needs: exact-release-candidate-promotion",
        "cosign verify-blob",
        "cosign sign-blob",
        "attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
        "gh release create",
        "--prerelease",
        "--verify-tag",
    ]
    for value in promotion_required:
        if value not in promotion:
            failures.append(
                f"Phase 1 promotion workflow lost required contract {value!r}"
            )
    if promotion.count("permissions:\n      actions: read\n      contents: write") != 1:
        failures.append("only the gated Phase 1 publication job may write contents")
    review_required = [
        "workflow_dispatch:",
        "profile: phase1-independent-review",
        "runs-on: [self-hosted, linux, x64, agentos-review]",
        "environment: phase1-review",
        "AGENTOS_PHASE1_REVIEW_DIR",
        "phase1_campaign_run_id:",
        "scripts/phase1_campaign_provenance.py",
        "--campaign-provenance",
        'test "$GITHUB_RUN_ATTEMPT" = "1"',
        "scripts/phase1_independent_review.py",
        "--actor \"$GITHUB_ACTOR\"",
        "cosign sign-blob --yes",
        "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
        "phase1-independent-review-${{ inputs.release_candidate }}-${{ github.sha }}",
    ]
    for value in review_required:
        if value not in independent_review:
            failures.append(
                f"Phase 1 independent-review workflow lost contract {value!r}"
            )
    campaign_required = [
        "workflow_dispatch:",
        "promoted_providers_json:",
        "run_ids_json:",
        'test "$GITHUB_RUN_ATTEMPT" = "1"',
        "scripts/phase1_campaign_assembly.py",
        "scripts/phase1_campaign_provenance.py",
        "actions/runs/${run_id}/attempts/${run_attempt}",
        'gh run download "$run_id"',
        "cosign sign-blob --yes",
        "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
        "phase1-campaign-${{ inputs.release_candidate }}-${{ github.sha }}",
    ]
    for value in campaign_required:
        if value not in campaign:
            failures.append(
                f"Phase 1 campaign workflow lost contract {value!r}"
            )
    if "self-hosted" in campaign or "contents: write" in campaign:
        failures.append(
            "Phase 1 campaign workflow must stay GitHub-hosted and read-only"
        )
    return failures


def validate_release(root: Path, tag: str, commit: str) -> list[str]:
    failures = validate_contract(root)
    match = RC_TAG_PATTERN.fullmatch(tag)
    if match is None:
        failures.append("release tag must be exact vX.Y.Z-rc.N with N >= 1")
        return failures
    if COMMIT_PATTERN.fullmatch(commit) is None:
        failures.append("release commit must be 40 lowercase hexadecimal characters")
    version = match.group(1)
    try:
        members = _workspace_members(root / "Cargo.toml")
    except (OSError, ValueError) as error:
        failures.append(str(error))
        return failures
    for member in members:
        manifest = root / member / "Cargo.toml"
        try:
            member_version = _package_version(manifest)
        except OSError as error:
            failures.append(f"cannot read {manifest.relative_to(root)}: {error}")
            continue
        if member_version is not None:
            if member_version != version:
                failures.append(
                    f"{member}/Cargo.toml version {member_version!r} does not match {version!r}"
                )
        document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        for dependency_version in _path_dependency_versions(document):
            if dependency_version != f"={version}":
                failures.append(
                    f"{member}/Cargo.toml internal dependency version "
                    f"{dependency_version!r} does not match {version!r}"
                )
    fuzz = tomllib.loads((root / "fuzz/Cargo.toml").read_text(encoding="utf-8"))
    for dependency_version in _path_dependency_versions(fuzz):
        if dependency_version != f"={version}":
            failures.append(
                f"fuzz/Cargo.toml internal dependency version "
                f"{dependency_version!r} does not match {version!r}"
            )

    tauri = json.loads(
        (root / "crates/tauri-app/tauri.conf.json").read_text(encoding="utf-8")
    )
    package = json.loads(
        (root / "crates/tauri-app/ui/package.json").read_text(encoding="utf-8")
    )
    lock = json.loads(
        (root / "crates/tauri-app/ui/package-lock.json").read_text(encoding="utf-8")
    )
    for source, declared in {
        "tauri.conf.json": tauri.get("version"),
        "ui/package.json": package.get("version"),
        "ui/package-lock.json": lock.get("version"),
        "ui/package-lock.json root package": lock.get("packages", {}).get("", {}).get("version"),
    }.items():
        if declared != version:
            failures.append(f"{source} version {declared!r} does not match {version!r}")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(
        r"(?m)^## \[([^\]]+)\](?:\s+-\s+\d{4}-\d{2}-\d{2})?\s*$",
        changelog,
    )
    if headings.count("Unreleased") != 1:
        failures.append("CHANGELOG.md must contain exactly one [Unreleased] section")
    else:
        unreleased = re.search(
            r"(?ms)^## \[Unreleased\]\s*$(.*?)(?=^## \[|\Z)",
            changelog,
        )
        if unreleased is None or unreleased.group(1).strip():
            failures.append(
                "CHANGELOG.md [Unreleased] section must be empty before an RC tag"
            )
    if headings.count(version) != 1:
        failures.append(f"CHANGELOG.md must contain exactly one [{version}] release section")
    else:
        section = re.search(
            rf"(?ms)^## \[{re.escape(version)}\](?:\s+-\s+\d{{4}}-\d{{2}}-\d{{2}})?\s*$"
            rf"(.*?)(?=^## \[|\Z)",
            changelog,
        )
        if section is None or re.search(r"(?m)^\s*-\s+\S", section.group(1)) is None:
            failures.append(
                f"CHANGELOG.md [{version}] section must contain at least one release note"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    args = parser.parse_args()
    try:
        if (args.tag is None) != (args.commit is None):
            parser.error("--tag and --commit must be supplied together")
        failures = (
            validate_release(args.root.resolve(), args.tag, args.commit)
            if args.tag is not None
            else validate_contract(args.root.resolve())
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        failures = [str(error)]
    if failures:
        for failure in failures:
            print(f"Linux CLI RC validation failed: {failure}", file=sys.stderr)
        return 1
    print("restricted Linux CLI RC source and workflow contract is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
