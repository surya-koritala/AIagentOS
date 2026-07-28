#!/usr/bin/env python3
"""Build a fail-closed Tauri v2 static update manifest from signed assets."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import quote


SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_NOTES_BYTES = 64 * 1024


class ManifestError(ValueError):
    """A release input cannot produce an unambiguous signed update manifest."""


def _regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ManifestError(f"{label} must be a regular non-symlink file: {path}")


def _one_asset(dist: Path, suffix: str, label: str) -> Path:
    matches = sorted(
        path
        for path in dist.iterdir()
        if path.name.endswith(suffix)
        and not path.name.endswith(f"{suffix}.sig")
        and path.is_file()
        and not path.is_symlink()
    )
    if len(matches) != 1:
        names = ", ".join(path.name for path in matches) or "none"
        raise ManifestError(f"{label} requires exactly one *{suffix} asset; found {names}")
    return matches[0]


def _signature_for(asset: Path) -> str:
    signature_path = Path(f"{asset}.sig")
    _regular_file(signature_path, f"signature for {asset.name}")
    if signature_path.stat().st_size > MAX_SIGNATURE_BYTES:
        raise ManifestError(f"signature for {asset.name} exceeds {MAX_SIGNATURE_BYTES} bytes")
    signature = signature_path.read_text(encoding="utf-8").strip()
    try:
        decoded = base64.b64decode(signature, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as error:
        raise ManifestError(f"signature for {asset.name} is not Tauri minisign base64") from error
    if "untrusted comment: signature from" not in decoded or "\n" not in decoded:
        raise ManifestError(f"signature for {asset.name} lacks the minisign envelope")
    return signature


def _platform(asset: Path, repository: str, tag: str) -> dict[str, str]:
    return {
        "url": (
            f"https://github.com/{repository}/releases/download/"
            f"{quote(tag, safe='')}/{quote(asset.name, safe='')}"
        ),
        "signature": _signature_for(asset),
    }


def build_manifest(
    dist: Path,
    version: str,
    tag: str,
    repository: str,
    notes: str,
    pub_date: str,
) -> dict[str, object]:
    if not SEMVER.fullmatch(version):
        raise ManifestError(f"version is not strict SemVer: {version!r}")
    if tag != f"v{version}":
        raise ManifestError(f"tag {tag!r} must exactly equal 'v{version}'")
    if not REPOSITORY.fullmatch(repository):
        raise ManifestError(f"repository is not owner/name: {repository!r}")
    if dist.is_symlink() or not dist.is_dir():
        raise ManifestError(f"distribution directory must be a non-symlink directory: {dist}")
    if len(notes.encode("utf-8")) > MAX_NOTES_BYTES:
        raise ManifestError(f"release notes exceed {MAX_NOTES_BYTES} bytes")
    try:
        datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
    except ValueError as error:
        raise ManifestError("pub-date must be RFC 3339") from error

    appimage = _platform(
        _one_asset(dist, ".AppImage", "Linux AppImage"), repository, tag
    )
    deb = _platform(_one_asset(dist, ".deb", "Linux Debian"), repository, tag)
    mac_app = _platform(
        _one_asset(dist, ".app.tar.gz", "macOS app"), repository, tag
    )
    msi = _platform(_one_asset(dist, ".msi", "Windows MSI"), repository, tag)
    nsis = _platform(
        _one_asset(dist, "-setup.exe", "Windows NSIS"), repository, tag
    )

    return {
        "version": version,
        "notes": notes,
        "pub_date": pub_date,
        "platforms": {
            "darwin-x86_64": mac_app,
            "darwin-x86_64-app": mac_app,
            "linux-x86_64": appimage,
            "linux-x86_64-appimage": appimage,
            "linux-x86_64-deb": deb,
            "windows-x86_64": nsis,
            "windows-x86_64-msi": msi,
            "windows-x86_64-nsis": nsis,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--notes-file", type=Path, required=True)
    parser.add_argument("--pub-date", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    _regular_file(args.notes_file, "release notes")
    notes = args.notes_file.read_text(encoding="utf-8").strip()
    if not notes:
        raise ManifestError("release notes must not be empty")
    manifest = build_manifest(
        args.dist.resolve(),
        args.version,
        args.tag,
        args.repository,
        notes,
        args.pub_date,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
