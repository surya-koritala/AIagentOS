#!/usr/bin/env python3
"""Fail-closed validation for desktop release metadata and bundle assets."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import struct
import sys
from pathlib import Path
from urllib.parse import urlparse


REQUIRED_PNGS = {
    "32x32.png": (32, 32),
    "64x64.png": (64, 64),
    "128x128.png": (128, 128),
    "128x128@2x.png": (256, 256),
    "icon.png": (512, 512),
}


def workspace_members(path: Path) -> list[str]:
    contents = path.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^members\s*=\s*\[(.*?)\]", contents)
    if not match:
        raise ValueError("workspace members are missing")
    return re.findall(r'"([^"]+)"', match.group(1))


def package_version(path: Path) -> str | None:
    contents = path.read_text(encoding="utf-8")
    package = re.search(r"(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)", contents)
    if not package:
        return None
    version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', package.group(1))
    return version.group(1) if version else None


def png_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    return struct.unpack(">II", data[16:24])


def validate(root: Path, tag: str | None = None) -> list[str]:
    failures: list[str] = []
    member_versions: dict[str, str] = {}
    for member in workspace_members(root / "Cargo.toml"):
        manifest = root / member / "Cargo.toml"
        version = package_version(manifest)
        if version:
            member_versions[member] = version

    desktop_version = member_versions["crates/tauri-app"]
    for member, version in member_versions.items():
        if version != desktop_version:
            failures.append(
                f"{member}/Cargo.toml version {version!r} does not match "
                f"desktop version {desktop_version!r}"
            )

    tauri_config = json.loads(
        (root / "crates/tauri-app/tauri.conf.json").read_text(encoding="utf-8")
    )
    ui_package = json.loads(
        (root / "crates/tauri-app/ui/package.json").read_text(encoding="utf-8")
    )
    ui_lock = json.loads(
        (root / "crates/tauri-app/ui/package-lock.json").read_text(encoding="utf-8")
    )
    declared_versions = {
        "tauri.conf.json": str(tauri_config.get("version")),
        "ui/package.json": str(ui_package.get("version")),
        "ui/package-lock.json": str(ui_lock.get("version")),
        "ui/package-lock.json root package": str(
            ui_lock.get("packages", {}).get("", {}).get("version")
        ),
    }
    for source, version in declared_versions.items():
        if version != desktop_version:
            failures.append(
                f"{source} version {version!r} does not match {desktop_version!r}"
            )

    if tag and tag != f"v{desktop_version}":
        failures.append(
            f"release tag {tag!r} must exactly match desktop version "
            f"'v{desktop_version}'"
        )

    icons = root / "crates/tauri-app/icons"
    for name, expected in REQUIRED_PNGS.items():
        path = icons / name
        if not path.is_file():
            failures.append(f"missing desktop icon {path.relative_to(root)}")
            continue
        try:
            actual = png_dimensions(path)
        except ValueError as error:
            failures.append(f"{path.relative_to(root)}: {error}")
        else:
            if actual != expected:
                failures.append(
                    f"{path.relative_to(root)} is {actual[0]}x{actual[1]}, "
                    f"expected {expected[0]}x{expected[1]}"
                )

    ico = icons / "icon.ico"
    if not ico.is_file() or ico.stat().st_size < 1_000:
        failures.append("icons/icon.ico is missing or not a multi-resolution asset")
    else:
        data = ico.read_bytes()[:6]
        if len(data) != 6 or data[:4] != b"\x00\x00\x01\x00":
            failures.append("icons/icon.ico has an invalid ICO header")
        elif int.from_bytes(data[4:6], "little") < 4:
            failures.append("icons/icon.ico must contain at least four image sizes")

    icns = icons / "icon.icns"
    if (
        not icns.is_file()
        or icns.stat().st_size < 1_000
        or icns.read_bytes()[:4] != b"icns"
    ):
        failures.append("icons/icon.icns is missing or invalid")

    configured_icons = set(tauri_config.get("bundle", {}).get("icon", []))
    required_configured = {
        "icons/32x32.png",
        "icons/128x128.png",
        "icons/128x128@2x.png",
        "icons/icon.icns",
        "icons/icon.ico",
    }
    missing_config = sorted(required_configured - configured_icons)
    if missing_config:
        failures.append(
            "tauri.conf.json does not configure required desktop icons: "
            + ", ".join(missing_config)
        )

    bundle = tauri_config.get("bundle", {})
    if bundle.get("createUpdaterArtifacts") is not True:
        failures.append("tauri.conf.json must create Tauri v2 updater artifacts")

    updater = tauri_config.get("plugins", {}).get("updater", {})
    public_key = updater.get("pubkey")
    if not isinstance(public_key, str) or not public_key:
        failures.append("tauri.conf.json must embed the updater public key")
    else:
        try:
            decoded_key = base64.b64decode(public_key, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            failures.append("tauri.conf.json updater public key is not valid Tauri base64")
        else:
            if not decoded_key.startswith("untrusted comment: minisign public key:"):
                failures.append("tauri.conf.json updater public key is not a minisign key")
            if len(decoded_key.splitlines()) != 2:
                failures.append("tauri.conf.json updater public key has an invalid envelope")

    expected_endpoint = (
        "https://github.com/surya-koritala/AIagentOS/"
        "releases/latest/download/latest.json"
    )
    endpoints = updater.get("endpoints")
    if endpoints != [expected_endpoint]:
        failures.append(
            "tauri.conf.json updater endpoint must be the canonical HTTPS latest.json"
        )
    elif urlparse(endpoints[0]).scheme != "https":
        failures.append("tauri.conf.json updater endpoint must use HTTPS")
    for dangerous in [
        "dangerousInsecureTransportProtocol",
        "dangerousAcceptInvalidCerts",
        "dangerousAcceptInvalidHostnames",
    ]:
        if updater.get(dangerous) is True:
            failures.append(f"tauri.conf.json updater must not enable {dangerous}")
    if updater.get("windows", {}).get("installMode") != "passive":
        failures.append("tauri.conf.json updater must use passive Windows install mode")

    desktop_manifest = (root / "crates/tauri-app/Cargo.toml").read_text(
        encoding="utf-8"
    )
    if 'tauri-plugin-updater = { version = "=2.10.1", optional = true }' not in desktop_manifest:
        failures.append("desktop updater plugin must remain exactly pinned to 2.10.1")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--tag",
        default=os.environ.get("GITHUB_REF_NAME")
        if os.environ.get("GITHUB_REF_TYPE") == "tag"
        else None,
        help="exact vX.Y.Z release tag; defaults from a GitHub tag run",
    )
    args = parser.parse_args()
    failures = validate(args.root.resolve(), args.tag)
    if failures:
        for failure in failures:
            print(f"desktop release validation failed: {failure}", file=sys.stderr)
        return 1
    print("desktop release metadata and bundle assets are consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
