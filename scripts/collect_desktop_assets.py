#!/usr/bin/env python3
"""Collect exactly one native bundle per format under architecture-bound names."""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


FORMATS = {
    "linux-x86_64": (".deb", ".AppImage"),
    "linux-aarch64": (".deb", ".AppImage"),
    "macos-x86_64": (".dmg", ".app.tar.gz"),
    "macos-aarch64": (".dmg", ".app.tar.gz"),
    "windows-x86_64": (".msi", "-setup.exe"),
}
UNSIGNED_FORMATS = frozenset({".dmg"})
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$")


class CollectionError(ValueError):
    """Native bundle output is incomplete, ambiguous, or unsafe to publish."""


def asset_name(version: str, platform: str, suffix: str) -> str:
    return f"agentos-{version}-desktop-{platform}{suffix}"


def collect_assets(bundle_root: Path, dist: Path, version: str, platform: str) -> list[Path]:
    if platform not in FORMATS or SAFE_VERSION.fullmatch(version) is None:
        raise CollectionError("platform or artifact version is invalid")
    if bundle_root.is_symlink() or not bundle_root.is_dir():
        raise CollectionError("bundle root must be a regular directory")
    if dist.is_symlink():
        raise CollectionError("distribution directory must not be a symlink")
    copies: list[tuple[Path, Path]] = []
    for suffix in FORMATS[platform]:
        matches = sorted(path for path in bundle_root.rglob(f"*{suffix}") if path.is_file())
        if len(matches) != 1:
            raise CollectionError(f"{platform} requires exactly one *{suffix}; found {len(matches)}")
        source = matches[0]
        if source.is_symlink() or any(
            (bundle_root / parent).is_symlink()
            for parent in source.relative_to(bundle_root).parents
        ):
            raise CollectionError("bundle assets must not traverse symlinks")
        output = dist / asset_name(version, platform, suffix)
        copies.append((source, output))
        if suffix not in UNSIGNED_FORMATS:
            signature = Path(f"{source}.sig")
            if signature.is_symlink() or not signature.is_file():
                raise CollectionError(f"missing updater signature for {source.name}")
            copies.append((signature, Path(f"{output}.sig")))
    if any(output.exists() or output.is_symlink() for _, output in copies):
        raise CollectionError("refusing to overwrite an existing distribution asset")
    dist.mkdir(parents=True, exist_ok=True)
    for source, output in copies:
        shutil.copyfile(source, output)
    return [output for _, output in copies]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", required=True)
    args = parser.parse_args()
    for output in collect_assets(args.bundle_root, args.dist, args.version, args.platform):
        print(output.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
