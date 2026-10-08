#!/usr/bin/env python3
"""Fail when documented candidate artifacts and native release matrices drift."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from collect_desktop_assets import FORMATS


TARGET_ARCHITECTURES = {
    "x86_64-unknown-linux-gnu": ("linux-x86_64", "ubuntu-22.04"),
    "aarch64-unknown-linux-gnu": ("linux-aarch64", "ubuntu-22.04-arm"),
    "x86_64-apple-darwin": ("macos-x86_64", "macos-15-intel"),
    "aarch64-apple-darwin": ("macos-aarch64", "macos-15"),
    "x86_64-pc-windows-msvc": ("windows-x86_64", "windows-latest"),
}


def _matrix(workflow: str, job: str) -> list[dict[str, str]]:
    section = re.search(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [a-z][a-z0-9-]*:|\Z)", workflow)
    if section is None:
        raise ValueError(f"release workflow is missing job {job}")
    include = re.search(r"(?ms)^        include:\n(.*?)(?=^    [^ ]|\Z)", section.group(1))
    if include is None:
        raise ValueError(f"{job} requires an explicit include matrix")
    rows: list[dict[str, str]] = []
    for line in include.group(1).splitlines():
        first = re.fullmatch(r"          - runner: ([A-Za-z0-9.-]+)", line)
        value = re.fullmatch(r"            ([a-z]+): (.+)", line)
        if first:
            rows.append({"runner": first.group(1)})
        elif value and rows:
            if value.group(1) in rows[-1]:
                raise ValueError(f"duplicate {value.group(1)} in {job} matrix")
            rows[-1][value.group(1)] = value.group(2).strip('"')
        elif line.strip() and not line.strip().startswith("#"):
            raise ValueError(f"unrecognized {job} matrix line: {line.strip()}")
    if not rows:
        raise ValueError(f"{job} matrix is empty")
    return rows


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    try:
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        document = (root / "docs/SUPPORTED_PLATFORMS.md").read_text(encoding="utf-8")
        desktop = _matrix(workflow, "desktop-artifacts")
        archives = _matrix(workflow, "release-artifacts")
        documented: dict[tuple[str, str], list[str]] = {}
        for line in document.splitlines():
            if not line.startswith(("| CLI |", "| Desktop |")):
                continue
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if len(cells) != 7 or any(not cell for cell in cells):
                failures.append("platform rows must state kind, target, OS floor, architecture, formats, tier, and dependencies")
                continue
            key = (cells[0], cells[1].strip("`"))
            if key in documented:
                failures.append(f"duplicate documented platform {key}")
            documented[key] = cells
        expected: set[tuple[str, str]] = set()
        for kind, rows in (("CLI", archives), ("Desktop", desktop)):
            seen: set[str] = set()
            for row in rows:
                target = row.get("target", "")
                expected.add((kind, target))
                if target in seen:
                    failures.append(f"duplicate {kind} target {target}")
                seen.add(target)
                if target not in TARGET_ARCHITECTURES:
                    failures.append(f"unsupported native target {target}; document and verify it explicitly")
                    continue
                platform, runner = TARGET_ARCHITECTURES[target]
                if row["runner"] != runner:
                    failures.append(f"{kind} {target} requires native runner {runner}")
                if kind == "Desktop":
                    if row.get("platform") != platform:
                        failures.append(f"desktop platform {row.get('platform')} does not match {target}")
                    required_bundles = {
                        "linux": "deb,appimage", "macos": "app,dmg", "windows": "msi,nsis"
                    }[platform.split("-", 1)[0]]
                    if row.get("bundles") != required_bundles:
                        failures.append(f"desktop bundle formats do not match {platform}")
                if (kind, target) in documented:
                    cells = documented[(kind, target)]
                    suffixes = (".zip",) if kind == "CLI" else FORMATS[platform]
                    if any(suffix not in cells[4] for suffix in suffixes):
                        failures.append(f"documented formats do not match {kind} {target}")
                    if not any(char.isdigit() for char in cells[2]):
                        failures.append(f"missing numeric OS floor for {kind} {target}")
                    if target.split("-", 1)[0] not in cells[3]:
                        failures.append(f"documented architecture does not match {kind} {target}")
        for key in sorted(expected - documented.keys()):
            failures.append(f"release matrix has undocumented artifact {key}")
        for key in sorted(documented.keys() - expected):
            failures.append(f"document lists artifact absent from release matrix {key}")
        if {row.get("target") for row in archives} != {row.get("target") for row in desktop}:
            failures.append("CLI and desktop native target sets must agree")
        config = json.loads((root / "crates/tauri-app/tauri.conf.json").read_text(encoding="utf-8"))
        if config.get("bundle", {}).get("macOS", {}).get("minimumSystemVersion") != "13.0":
            failures.append("desktop macOS minimumSystemVersion must match documented 13.0 floor")
        if 'MACOSX_DEPLOYMENT_TARGET: "13.0"' not in workflow:
            failures.append("CLI macOS deployment target must match documented 13.0 floor")
        for path in ("README.md", "RELEASING.md", "docs/DESKTOP_DISTRIBUTION.md"):
            if "SUPPORTED_PLATFORMS.md" not in (root / path).read_text(encoding="utf-8"):
                failures.append(f"{path} must link to supported platforms")
    except (OSError, ValueError, KeyError) as error:
        failures.append(str(error))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    failures = validate(args.root)
    for failure in failures:
        print(f"supported platform validation failed: {failure}", file=sys.stderr)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
