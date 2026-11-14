#!/usr/bin/env python3
"""Read-only first-pass inventory of a vendor-supplied GPL tar archive.

This program DOES NOT extract, build, patch, execute or flash firmware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

MAX_COMPRESSED = 2 * 1024**3
MAX_DECLARED = 8 * 1024**3
MAX_MEMBERS = 300_000
MAX_CANDIDATES = 100


class IntakeError(Exception):
    pass


def safe_member_name(name: str) -> str:
    path = PurePosixPath(name)
    if not name or name.startswith("/") or "\x00" in name or ".." in path.parts:
        raise IntakeError("archive contains an unsafe member pathname")
    return str(path)


def interesting(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return (
        name in {"makefile", "kconfig", "defconfig", ".config", "readme", "readme.md"}
        or name.endswith((".dts", ".dtsi", ".dtb", ".config"))
        or name.startswith("busybox")
    )


def digest_archive(path: Path) -> tuple[str, int]:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_COMPRESSED:
        raise IntakeError("input must be a regular archive within the compressed-size bound")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_COMPRESSED:
                raise IntakeError("compressed archive grew beyond its bound")
            digest.update(chunk)
    return digest.hexdigest(), total


def inspect(path: Path) -> dict:
    sha256, compressed_bytes = digest_archive(path)
    members = 0
    declared_bytes = 0
    regular = 0
    links = 0
    other = 0
    candidates = []
    seen = set()
    duplicate_names = 0
    try:
        # Streaming mode: no extraction, materialisation or execution.
        with tarfile.open(path, mode="r|*") as archive:
            for member in archive:
                members += 1
                if members > MAX_MEMBERS:
                    raise IntakeError("archive member count exceeds bound")
                name = safe_member_name(member.name)
                if name in seen:
                    duplicate_names += 1
                else:
                    seen.add(name)
                if member.isfile():
                    if member.size < 0:
                        raise IntakeError("invalid declared member size")
                    regular += 1
                    declared_bytes += member.size
                    if declared_bytes > MAX_DECLARED:
                        raise IntakeError("declared content exceeds size bound")
                    if interesting(name) and len(candidates) < MAX_CANDIDATES:
                        candidates.append(name)
                elif member.issym() or member.islnk():
                    links += 1
                    # No link target is followed, not even for inventory.
                elif not member.isdir():
                    other += 1
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise IntakeError("archive structure cannot be inspected safely") from exc
    return {
        "schema": 1,
        "archive_sha256": sha256,
        "compressed_bytes": compressed_bytes,
        "members": members,
        "regular_files": regular,
        "declared_regular_bytes": declared_bytes,
        "links_not_followed": links,
        "other_member_types": other,
        "duplicate_paths": duplicate_names,
        "sample_source_paths": candidates,
        "note": "metadata-only inspection; not a recovery image or executable firmware proof",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(inspect(args.archive), sort_keys=True))
        return 0
    except (OSError, IntakeError) as exc:
        print(f"firmware intake: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
