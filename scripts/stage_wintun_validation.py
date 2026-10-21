"""Stage only the pinned official DLL/license for disposable driver validation.

This script never loads a DLL, installs a driver, or modifies an existing output.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import time
import urllib.request
import zipfile

from windows_engine import pinned_path, read_pins, regular_file, require, sha256


def stage_archive(repository: Path, archive: Path, output: Path, pins: dict[str, str]) -> dict[str, object]:
    require(not output.exists(), "Wintun staging output already exists")
    regular_file(archive)
    require(archive.stat().st_size <= 16 * 1024 * 1024, "Wintun archive exceeds its bound")
    require(sha256(archive) == pins["WINTUN_ARCHIVE_SHA256"], "Wintun distribution hash mismatch")
    license_source = pinned_path(repository, pins["WINTUN_BINARY_LICENSE_PATH"])
    require(sha256(license_source) == pins["WINTUN_BINARY_LICENSE_SHA256"], "source Wintun license hash mismatch")
    with zipfile.ZipFile(archive) as bundle:
        require(len(bundle.infolist()) <= 4096, "too many Wintun archive members")
        names = set()
        total = 0
        for entry in bundle.infolist():
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and ".." not in path.parts and ":" not in entry.filename and "\\" not in entry.filename,
                    "unsafe Wintun archive member")
            require(not stat.S_ISLNK(entry.external_attr >> 16), "Wintun archive contains a symlink")
            require(entry.filename.casefold() not in names, "duplicate Wintun archive member")
            names.add(entry.filename.casefold())
            total += entry.file_size
            require(entry.file_size <= 2 * 1024 * 1024 and total <= 16 * 1024 * 1024, "Wintun members exceed their bound")
        dll = bundle.read("wintun/bin/amd64/wintun.dll")
        license_text = bundle.read("wintun/LICENSE.txt")
    require(hashlib.sha256(dll).hexdigest() == pins["WINTUN_WINDOWS_AMD64_SHA256"], "Wintun DLL hash mismatch")
    require(license_text == license_source.read_bytes(), "Wintun original license bytes differ")
    output.mkdir()
    (output / "wintun.dll").write_bytes(dll)
    (output / "LICENSE.txt").write_bytes(license_text)
    receipt = {"version": pins["WINTUN_VERSION"], "archive_sha256": sha256(archive),
               "dll_sha256": sha256(output / "wintun.dll"), "dll_bytes": len(dll),
               "license_sha256": sha256(output / "LICENSE.txt"),
               "loaded_or_installed": False, "release_accepted": False}
    (output / "staging.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    output = args.output.absolute()
    require(not output.exists(), "Wintun validation output already exists")
    pins = read_pins(repository)
    output.mkdir()
    archive = output / "wintun-distribution.zip"
    if args.archive:
        regular_file(args.archive)
        require(args.archive.stat().st_size <= 16 * 1024 * 1024, "Wintun archive exceeds its bound")
        shutil.copyfile(args.archive, archive)
    else:
        deadline = time.monotonic() + 120
        url = f"https://www.wintun.net/builds/wintun-{pins['WINTUN_VERSION']}.zip"
        with urllib.request.urlopen(url, timeout=20) as response, archive.open("xb") as destination:
            require(response.status == 200, "Wintun download did not return an archive")
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                require(total <= 16 * 1024 * 1024 and time.monotonic() < deadline, "Wintun download exceeded its bounds")
                destination.write(chunk)
    print(json.dumps(stage_archive(repository, archive, output / "payload", pins), indent=2))


if __name__ == "__main__":
    main()
