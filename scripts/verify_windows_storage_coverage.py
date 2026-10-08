#!/usr/bin/env python3
"""Compare executed native Windows storage test inventory with the Unix inventory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

MODULES = ("storage", "storage_encryption", "config", "remote_backup")
REQUIRED = (
    "storage::tests::retention_does_not_follow_symlinked_backup_entries",
    "storage::tests::corrupt_recovery_rejects_symlink_sidecar_without_touching_target",
    "storage::tests::portable_storage_is_owner_only_and_rejects_symlink_payloads",
    "storage::tests::backup_rejects_symlink_roots_and_files",
    "storage_encryption::tests::key_file_is_owner_only_bounded_non_overwriting_and_authenticates_database",
    "config::tests::saved_config_is_owner_only_and_repairs_permissive_existing_files",
)


def inventory(text: str) -> set[str]:
    return {line.removesuffix(": test") for line in text.splitlines() if line.endswith(": test")}


def validate(unix: set[str], windows: set[str]) -> list[str]:
    failures = []
    for module in MODULES:
        prefix = module + "::"
        unix_count = sum(name.startswith(prefix) for name in unix)
        windows_count = sum(name.startswith(prefix) for name in windows)
        if unix_count == 0 or windows_count < unix_count:
            failures.append(f"{module}: Windows {windows_count} must be >= non-zero Unix {unix_count}")
    for name in REQUIRED:
        if name not in unix or name not in windows:
            failures.append(f"required proving regression must exist on both platforms: {name}")
    if sum(name.startswith("windows_private_fs::tests::") for name in windows) < 10:
        failures.append("at least 10 native Windows ACL/reparse/publication regressions must execute")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unix", type=Path, required=True)
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    unix = inventory(args.unix.read_text(encoding="utf-8"))
    windows = inventory(args.windows.read_text(encoding="utf-8"))
    failures = validate(unix, windows)
    report = {"module_counts": {module: {
        "unix": sum(name.startswith(module + "::") for name in unix),
        "windows": sum(name.startswith(module + "::") for name in windows),
    } for module in MODULES}, "native_windows_tests": sorted(name for name in windows if name.startswith("windows_private_fs::tests::")),
        "required_regressions": list(REQUIRED), "failures": failures,
        "coverage_parity_passed": not failures, "production_claim_allowed": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for failure in failures:
        print(failure)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
