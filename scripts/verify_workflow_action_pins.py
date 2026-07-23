#!/usr/bin/env python3
"""Validate immutable GitHub Action pins and optionally prove they resolve."""

from __future__ import annotations

import argparse
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


USES_PATTERN = re.compile(r"^\s*-\s*uses:\s*([^\s#]+)")
SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class ActionPin:
    repository: str
    revision: str
    workflow: Path
    line: int


def discover_action_pins(workflow_root: Path) -> tuple[list[ActionPin], list[str]]:
    pins: list[ActionPin] = []
    failures: list[str] = []
    workflow_paths = sorted(
        {
            *workflow_root.rglob("*.yml"),
            *workflow_root.rglob("*.yaml"),
        }
    )
    for workflow in workflow_paths:
        for line_number, raw_line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            match = USES_PATTERN.match(raw_line)
            if match is None:
                continue
            reference = match.group(1).strip("\"'")
            if reference.startswith("./"):
                continue
            if "@" not in reference:
                failures.append(f"{workflow}:{line_number}: action has no revision")
                continue
            action, revision = reference.rsplit("@", maxsplit=1)
            segments = action.split("/")
            if len(segments) < 2:
                failures.append(
                    f"{workflow}:{line_number}: invalid action reference {reference!r}"
                )
                continue
            if SHA_PATTERN.fullmatch(revision) is None:
                failures.append(
                    f"{workflow}:{line_number}: action revision must be a 40-character "
                    f"commit SHA: {reference!r}"
                )
                continue
            pins.append(
                ActionPin(
                    repository="/".join(segments[:2]),
                    revision=revision.lower(),
                    workflow=workflow,
                    line=line_number,
                )
            )
    return pins, failures


def remote_pin_failures(
    pins: list[ActionPin],
    token: str,
    api_url: str = "https://api.github.com",
) -> list[str]:
    failures: list[str] = []
    locations: dict[tuple[str, str], list[str]] = {}
    for pin in pins:
        locations.setdefault((pin.repository, pin.revision), []).append(
            f"{pin.workflow}:{pin.line}"
        )

    for (repository, revision), pin_locations in sorted(locations.items()):
        url = f"{api_url.rstrip('/')}/repos/{repository}/commits/{revision}"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "AIagentOS-action-pin-verifier",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        error: Exception | None = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    if response.status == 200:
                        error = None
                        break
                    error = RuntimeError(f"HTTP {response.status}")
            except urllib.error.HTTPError as current:
                error = current
                if current.code < 500 and current.code != 429:
                    break
            except (urllib.error.URLError, TimeoutError) as current:
                error = current
            if attempt < 2:
                time.sleep(attempt + 1)
        if error is not None:
            location = ", ".join(pin_locations)
            failures.append(
                f"{repository}@{revision} does not resolve ({location}): {error}"
            )
        else:
            print(f"resolved {repository}@{revision}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "workflow_root",
        nargs="?",
        type=Path,
        default=Path(".github/workflows"),
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="prove each pinned commit exists using the GitHub commits API",
    )
    args = parser.parse_args()

    try:
        pins, failures = discover_action_pins(args.workflow_root)
    except OSError as error:
        parser.error(str(error))
    if not pins and not failures:
        failures.append(f"no external actions found under {args.workflow_root}")
    if args.remote and not failures:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            failures.append("GH_TOKEN or GITHUB_TOKEN is required with --remote")
        else:
            failures.extend(
                remote_pin_failures(
                    pins,
                    token,
                    os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                )
            )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1
    print(f"validated {len(pins)} immutable action reference(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
