#!/usr/bin/env python3
"""Explicitly prepare Swift debug UI inputs before running Cargo with native-ui.

Never signs, installs, changes networking, or writes into release candidates
or into Cargo's output directories. Every build keeps a fresh attempt with its
logs, products and receipt. The products hold the library and, beside it, its
resource bundle: that is where the library looks for its resources in an
unbundled executable, wherever Cargo puts that executable. A completed attempt
removes its Swift build scratch, which is plain compiler output already copied
into the products; a failed attempt keeps it for diagnosis. Cargo only
validates the completed receipt and its current source/product bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

if __package__:
    from .hash_artifact import build_manifest
    from .publication.bounded_process import BoundedProcessError, run_bounded_process
else:
    from hash_artifact import build_manifest
    from publication.bounded_process import BoundedProcessError, run_bounded_process

LIBRARY = "libCFMNativeDashboard.dylib"
RESOURCES = "CFMNativeDashboard_CFMNativeDashboard.bundle"
SOURCE_PATHS = (
    "native/dashboard/Package.swift", "native/dashboard/Sources",
    "native/dashboard/include", "scripts/prepare_development_native_ui.py",
    "scripts/hash_artifact.py", "scripts/publication/bounded_process.py",
    "scripts/publication/__init__.py", "apps/cfw-tauri-shell/build.rs",
    "apps/cfw-tauri-shell/build_support/macos.rs",
    "apps/cfw-tauri-shell/build_support/development_native_ui.rs",
)


def real_directory(path: Path, *, create: bool = False) -> None:
    if not path.is_absolute() or any(character in str(path) for character in "\r\n"):
        raise ValueError(f"development directory must be absolute: {path}")
    # Validate each existing ancestor before mkdir; resolving after mkdir alone
    # would already have written through a symlink into a different asset.
    missing = []
    current = path
    while not current.exists() and not current.is_symlink():
        missing.append(current)
        current = current.parent
    if current.resolve(strict=True) != current or not current.is_dir():
        raise ValueError(f"development directory is not canonical: {current}")
    if missing and not create:
        raise ValueError(f"development directory is missing: {path}")
    for current in reversed(missing):
        current.mkdir()
    if path.resolve(strict=True) != path or not path.is_dir():
        raise ValueError(f"development directory is not canonical: {path}")


def manifest(path: Path) -> dict:
    if path.resolve(strict=True) != path:
        raise ValueError(f"development input must not use a symlink alias: {path}")
    value = build_manifest(path)
    # Source/resource input symlinks and hard links are never admitted here.
    for entry in value["entries"]:
        if entry["type"] == "symlink":
            raise ValueError(f"development input must not contain a symlink: {path}")
        entry_path = path / entry["path"] if path.is_dir() else path
        if entry["type"] == "file" and entry_path.lstat().st_nlink != 1:
            raise ValueError(f"development input must not contain hard links: {entry_path}")
    # The existing Rust ArtifactManifest has a required, typed metadata map.
    value["metadata"] = {}
    return value


def source_manifests(repository: Path) -> dict:
    return {relative: manifest(repository / relative) for relative in sorted(SOURCE_PATHS)}


def source_digest(sources: dict) -> str:
    return hashlib.sha256("".join(f"{path} {value['sha256']}\n" for path, value in sorted(sources.items())).encode()).hexdigest()


def run_tool(arguments: list[str], attempt: Path, label: str, *, timeout: int) -> subprocess.CompletedProcess:
    policy = {"command": arguments, "timeout_seconds": timeout, "output_limit": 16 * 1024 * 1024}
    try:
        result = run_bounded_process(arguments, cwd=attempt, environment=dict(os.environ),
                                     timeout=timeout, output_limit=policy["output_limit"])
    except BoundedProcessError as error:
        (attempt / (label + ".log")).write_bytes(error.stdout + error.stderr)
        (attempt / (label + ".result.json")).write_text(json.dumps({**policy, "failure": error.reason}, indent=2) + "\n")
        raise ValueError(f"{label} exceeded its process boundary ({error.reason}); retained {attempt}") from error
    (attempt / (label + ".log")).write_bytes(result.stdout + result.stderr)
    (attempt / (label + ".result.json")).write_text(json.dumps({**policy, "returncode": result.returncode}, indent=2) + "\n")
    if result.returncode:
        raise ValueError(f"{label} failed; retained {attempt / (label + '.log')}")
    return result


def prepare(repository: Path) -> Path:
    real_directory(repository)
    sources = source_manifests(repository)
    digest = source_digest(sources)
    attempts = repository / "target/native-ui-development" / digest
    real_directory(attempts, create=True)
    attempt = attempts / uuid.uuid4().hex
    attempt.mkdir(mode=0o700)
    products = attempt / "products"
    products.mkdir()
    scratch = attempt / "swift-build"
    arguments = ["/usr/bin/xcrun", "swift", "build", "--configuration", "debug",
                 "--package-path", str(repository / "native/dashboard"),
                 "--scratch-path", str(scratch), "--disable-automatic-resolution",
                 "--triple", "arm64-apple-macosx15.0"]
    build_arguments = arguments + ["--product", "CFMNativeDashboard", "-Xswiftc", "-warnings-as-errors"]
    run_tool(build_arguments, attempt, "build", timeout=600)
    result = run_tool(arguments + ["--show-bin-path"], attempt, "bin-path", timeout=30)
    if result.stderr:
        raise ValueError(f"Swift product location failed; retained {attempt / 'bin-path.log'}")
    output = Path(result.stdout.decode().strip())
    real_directory(output)
    if not output.is_relative_to(scratch):
        raise ValueError("Swift product location is outside this development attempt")
    architecture = run_tool(["/usr/bin/lipo", "-archs", str(output / LIBRARY)], attempt, "architecture", timeout=30)
    if architecture.stderr or architecture.stdout.strip() != b"arm64":
        raise ValueError("Swift development UI library must be thin arm64")
    platform = run_tool(["/usr/bin/xcrun", "vtool", "-show-build", str(output / LIBRARY)], attempt, "platform", timeout=30)
    platform_text = platform.stdout.decode()
    if platform.stderr or not re.search(r"\bplatform\s+MACOS\b", platform_text) or not re.search(r"\bminos\s+15\.0(?:\s|$)", platform_text):
        raise ValueError("Swift development UI library must target macOS 15.0")
    manifest(output / LIBRARY)
    manifest(output / RESOURCES)
    shutil.copyfile(output / LIBRARY, products / LIBRARY)
    os.chmod(products / LIBRARY, 0o755)
    shutil.copytree(output / RESOURCES, products / RESOURCES)
    product_manifests = {name: manifest(products / name) for name in (LIBRARY, RESOURCES)}
    if source_manifests(repository) != sources:
        raise ValueError(f"UI inputs changed during the build; incomplete attempt retained at {attempt}")
    receipt = {
        "schema_version": 2, "artifact_kind": "development-native-ui-v2", "configuration": "debug",
        "target": "aarch64-apple-darwin", "repository": str(repository), "source_sha256": digest,
        "sources": sources, "products": product_manifests,
    }
    with (products / "receipt.json").open("x") as handle:
        json.dump(receipt, handle, sort_keys=True, indent=2)
        handle.write("\n")
    shutil.rmtree(scratch)
    return products


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        products = prepare(repository)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"error: development native UI: {error}\n")
    print(products)


if __name__ == "__main__":
    main()
