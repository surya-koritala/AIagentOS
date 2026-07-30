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
        "sign-runtime:",
        "cosign sign-blob",
        "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
        "fresh-host:",
        "scripts/linux_cli_rc_qualification.py qualify",
        "--released-schema-tag v0.3.0",
        "finalize:",
        "scripts/linux_cli_rc_qualification.py validate-report",
        "publish:",
        "gh release create",
        "--prerelease",
        "--verify-tag",
    ]
    for value in required:
        if value not in rc:
            failures.append(f"Linux CLI RC workflow lost required contract {value!r}")
    forbidden = [
        "pull_request_target",
        "self-hosted",
        "continue-on-error: true",
        "AGENT_SERVER_ALLOW_INSECURE_REMOTE",
    ]
    for value in forbidden:
        if value in rc:
            failures.append(f"Linux CLI RC workflow contains forbidden contract {value!r}")
    if rc.count("permissions:\n      contents: write") != 1:
        failures.append("only the publication job may receive contents: write")
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
    headings = re.findall(r"(?m)^## \[([^\]]+)\](?:\s+-\s+\d{4}-\d{2}-\d{2})?\s*$", changelog)
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
