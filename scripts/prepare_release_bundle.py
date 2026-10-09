#!/usr/bin/env python3
"""Validate required release assets and account for optional desktop output."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from build_desktop_update_manifest import SEMVER, _regular_file, _signature_for
from collect_desktop_assets import FORMATS, UNSIGNED_FORMATS, asset_name


CLI_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
)
JOB_RESULTS = ("success", "failure", "cancelled", "skipped")


class BundleError(ValueError):
    """A required asset is missing or optional output is unsafe to include."""


def required_assets(version: str) -> set[str]:
    return {
        f"agentos-{version}-{target}{suffix}"
        for target in CLI_TARGETS
        for suffix in (".zip", ".cdx.json")
    } | {f"agentos-{version}-container.spdx.json"}


def desktop_assets(version: str) -> set[str]:
    names = {
        asset_name(version, platform, suffix)
        for platform, suffixes in FORMATS.items()
        for suffix in suffixes
    }
    names |= {
        f"{name}.sig"
        for name in names
        if not any(name.endswith(suffix) for suffix in UNSIGNED_FORMATS)
    }
    names |= {
        asset_name(version, platform, ".cdx.json") for platform in FORMATS
    }
    return names


def inspect_updater_pairs(dist: Path, version: str) -> tuple[bool, list[str]]:
    """Require every installer-specific signed pair across all five platforms."""
    missing = []
    for platform, suffixes in FORMATS.items():
        for suffix in suffixes:
            if suffix in UNSIGNED_FORMATS:
                continue
            asset = dist / asset_name(version, platform, suffix)
            signature = Path(f"{asset}.sig")
            for path in (asset, signature):
                if not path.exists() and not path.is_symlink():
                    missing.append(path.name)
                    continue
                _regular_file(path, "updater input")
                if path.stat().st_size == 0:
                    raise BundleError(f"updater input is empty: {path.name}")
            if asset.exists() and signature.exists():
                _signature_for(asset)
    return not missing, sorted(missing)


def prepare_bundle(
    dist: Path,
    version: str,
    desktop_requested: bool,
    desktop_contract_result: str,
    desktop_result: str,
) -> dict[str, object]:
    if re.fullmatch(r"qualification-[1-9][0-9]*", version) is None and (
        not version.startswith("v") or not SEMVER.fullmatch(version[1:])
    ):
        raise BundleError("artifact version must be vSemVer or a qualification run")
    if any(result not in JOB_RESULTS for result in (desktop_contract_result, desktop_result)):
        raise BundleError("desktop job result is not a completed GitHub job result")
    if dist.is_symlink() or not dist.is_dir():
        raise BundleError("distribution must be a regular non-symlink directory")

    mandatory = required_assets(version)
    optional = desktop_assets(version)
    for name in sorted(mandatory):
        path = dist / name
        _regular_file(path, "required release asset")
        if path.stat().st_size == 0:
            raise BundleError(f"required release asset is empty: {name}")

    # Downloaded output from a failed matrix may be only partially uploaded.
    # Never publish those desktop artifacts as qualified installers.
    found_optional = []
    for path in dist.iterdir():
        if path.name in mandatory:
            continue
        if path.name not in optional:
            raise BundleError(f"unexpected release asset: {path.name}")
        _regular_file(path, "desktop release asset")
        found_optional.append(path)

    reason = None
    if not desktop_requested:
        reason = "Desktop artifacts were disabled for this release."
    elif desktop_contract_result != "success":
        reason = (
            f"Desktop release contract reported {desktop_contract_result}; "
            "native signing and clean-host qualification remain required."
        )
    elif desktop_result != "success":
        reason = f"Desktop installer matrix reported {desktop_result}; partial output was excluded."

    if reason:
        for path in found_optional:
            path.unlink()
        omissions = [
            {"asset_class": "desktop installers, updater signatures, and desktop SBOMs", "reason": reason},
            {"asset_class": "latest.json", "reason": "The complete qualified desktop updater matrix is absent."},
        ]
        updater_ready = False
        missing_pairs = []
    else:
        for path in found_optional:
            if path.stat().st_size == 0:
                raise BundleError(f"desktop release asset is empty: {path.name}")
        missing_desktop = sorted(optional - {path.name for path in found_optional})
        updater_ready, missing_pairs = inspect_updater_pairs(dist, version)
        omissions = []
        if missing_desktop:
            omissions.append({
                "asset_class": "desktop installers, updater signatures, and desktop SBOMs",
                "reason": "Missing assets: " + ", ".join(missing_desktop),
            })
        if not updater_ready:
            omissions.append({
                "asset_class": "latest.json",
                "reason": "Missing updater inputs: " + ", ".join(missing_pairs),
            })

    return {
        "schema_version": 1,
        "artifact_version": version,
        "desktop_requested": desktop_requested,
        "desktop_contract_result": desktop_contract_result,
        "desktop_result": desktop_result,
        "updater_ready": updater_ready,
        "missing_updater_inputs": missing_pairs,
        "included_assets": sorted(path.name for path in dist.iterdir()),
        "omitted_asset_classes": omissions,
    }


def release_notes(report: dict[str, object]) -> str:
    lines = ["", "## Distribution assets", "", (
        "Includes five CLI archives (each containing agent, agent-server, "
        "agent-tui, agentctl, and agent-code), five CycloneDX SBOMs, "
        "the container SPDX SBOM, SHA256SUMS, Sigstore bundles, and build provenance."
    )]
    omissions = report["omitted_asset_classes"]
    if omissions:
        lines += ["", "Omitted asset classes:", ""]
        for item in omissions:
            lines.append(f"- **{item['asset_class']}**: {item['reason']}")
    else:
        lines += ["", "Includes the complete desktop installer and signed updater matrix."]
    lines += ["", "The container image is not published to a registry by this workflow."]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--desktop-requested", choices=("true", "false"), required=True)
    parser.add_argument("--desktop-contract-result", choices=JOB_RESULTS, required=True)
    parser.add_argument("--desktop-result", choices=JOB_RESULTS, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--notes-output", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    report = prepare_bundle(
        args.dist, args.version, args.desktop_requested == "true",
        args.desktop_contract_result, args.desktop_result,
    )
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.notes_output.write_text(release_notes(report), encoding="utf-8")
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"updater_ready={str(report['updater_ready']).lower()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
