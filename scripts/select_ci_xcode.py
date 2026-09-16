#!/usr/bin/env python3
"""Select and record the newest installed Xcode for GitHub unsigned validation."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
from typing import Sequence

if __package__:
    from .apple_validation_policy import BUILD_RE, version_tuple
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from apple_validation_policy import BUILD_RE, version_tuple


APPLICATIONS = Path("/Applications")
COMMAND_ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
MAX_XCODE_INSTALLATIONS = 32


class XcodeSelectionError(ValueError):
    """Installed Xcode selection or its ownership normalization is ambiguous."""


@dataclass(frozen=True)
class XcodeInstallation:
    application: Path
    version: str
    build: str
    bundle_version: str
    version_plist_sha256: str

    @property
    def developer(self) -> Path:
        return self.application / "Contents/Developer"

    @property
    def rank(self) -> tuple[tuple[int, int, int], tuple[int, ...]]:
        # CFBundleVersion is Apple's monotonically increasing IDE build. Unlike
        # ProductBuildVersion, it correctly orders an RC/final above its betas.
        return version_tuple(self.version), tuple(int(p) for p in self.bundle_version.split("."))

    def record(self) -> dict[str, str]:
        return {"application": str(self.application), "developer_directory": str(self.developer), "version": self.version, "build": self.build, "bundle_version": self.bundle_version, "version_plist_sha256": self.version_plist_sha256}


def read_installation(application: Path, applications: Path = APPLICATIONS) -> XcodeInstallation:
    canonical = application.resolve(strict=True)
    if canonical.parent != applications or not re.fullmatch(r"Xcode[A-Za-z0-9._-]*[.]app", canonical.name):
        raise XcodeSelectionError("Xcode alias escaped the applications directory")
    for directory in (canonical, canonical / "Contents", canonical / "Contents/Developer"):
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink():
            raise XcodeSelectionError("Xcode contains an unsafe directory")
    version_path = canonical / "Contents/version.plist"
    metadata = version_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 65536:
        raise XcodeSelectionError("Xcode version metadata is not a bounded regular file")
    payload = version_path.read_bytes()
    value = plistlib.loads(payload)
    if not isinstance(value, dict):
        raise XcodeSelectionError("Xcode version metadata is not a dictionary")
    version, build, bundle = (value.get(key) for key in ("CFBundleShortVersionString", "ProductBuildVersion", "CFBundleVersion"))
    if not isinstance(version, str) or not isinstance(build, str) or not isinstance(bundle, str):
        raise XcodeSelectionError("Xcode version metadata is incomplete")
    version_tuple(version)
    if not BUILD_RE.fullmatch(build) or not re.fullmatch(r"[0-9]+(?:[.][0-9]+){0,3}", bundle):
        raise XcodeSelectionError("Xcode build metadata is not canonical")
    return XcodeInstallation(canonical, version, build, bundle, hashlib.sha256(payload).hexdigest())


def newest_installation(installations: Sequence[XcodeInstallation]) -> XcodeInstallation:
    unique = {item.application: item for item in installations}
    if not unique or len(unique) > MAX_XCODE_INSTALLATIONS:
        raise XcodeSelectionError("installed Xcode set is empty or exceeds its bound")
    ordered = sorted(unique.values(), key=lambda item: (item.rank, str(item.application)))
    latest = ordered[-1]
    tied = [item for item in ordered if item.rank == latest.rank]
    if any((item.version, item.build, item.version_plist_sha256) != (latest.version, latest.build, latest.version_plist_sha256) for item in tied):
        raise XcodeSelectionError("latest Xcode installations disagree about their identity")
    return latest


def command(argv: list[str], *, developer: Path | None = None) -> str:
    environment = dict(COMMAND_ENVIRONMENT)
    if developer is not None:
        environment["DEVELOPER_DIR"] = str(developer)
    result = subprocess.run(argv, env=environment, capture_output=True, text=True, timeout=300, check=False)
    if result.returncode:
        raise XcodeSelectionError(f"{argv[0]} failed ({result.returncode}): {(result.stderr or result.stdout)[-2048:]}")
    return result.stdout.strip()


def normalize_and_verify(selected: XcodeInstallation) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise XcodeSelectionError("Xcode ownership normalization is limited to a GitHub-hosted job")
    uid = os.geteuid()
    if uid == 0 or 0 in os.getgroups():
        raise XcodeSelectionError("CI must run as a non-root account outside the root group")
    root = str(selected.application)
    before = selected.application.stat()
    command(["/usr/sbin/spctl", "--assess", "--type", "execute", root])
    expected = f"Xcode {selected.version}\nBuild version {selected.build}"
    if command(["/usr/bin/xcodebuild", "-version"], developer=selected.developer) != expected:
        raise XcodeSelectionError("Xcode executable and bundle metadata disagree")
    unsafe = command(["/usr/bin/find", "-P", "-x", root, "(", "(", "!", "-uid", "0", "-a", "!", "-uid", str(uid), ")", "-o", "-perm", "-0002", ")", "-print", "-quit"])
    if unsafe:
        raise XcodeSelectionError("Xcode contains unexpected owners or world-writable entries")
    command(["/usr/bin/sudo", "-n", "/usr/bin/find", "-P", "-x", root, "-exec", "/usr/sbin/chown", "-h", "0:0", "{}", "+"])
    after = selected.application.stat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or read_installation(selected.application) != selected:
        raise XcodeSelectionError("selected Xcode changed during ownership normalization")
    unsafe = command(["/usr/bin/find", "-P", "-x", root, "(", "!", "-uid", "0", "-o", "!", "-gid", "0", "-o", "-perm", "-0002", ")", "-print", "-quit"])
    if unsafe:
        raise XcodeSelectionError("Xcode ownership normalization is incomplete")
    command(["/usr/sbin/spctl", "--assess", "--type", "execute", root])
    if command(["/usr/bin/xcodebuild", "-version"], developer=selected.developer) != expected:
        raise XcodeSelectionError("selected Xcode executable changed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect", action="store_true", help="report selection without modifying any application or environment file")
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.inspect == (args.github_env is not None or args.output is not None):
        parser.error("choose --inspect or both --github-env and --output")
    if not args.inspect and (args.github_env is None or args.output is None):
        parser.error("both --github-env and --output are required")
    try:
        paths = sorted(APPLICATIONS.glob("Xcode*.app"))
        if len(paths) > MAX_XCODE_INSTALLATIONS:
            raise XcodeSelectionError("too many Xcode installations")
        installations = [read_installation(path) for path in paths]
        selected = newest_installation(installations)
        if not args.inspect:
            normalize_and_verify(selected)
        record = {"schema_version": 1, "purpose": "unsigned-ci-validation", "selection": "latest-installed", "selected": selected.record(), "installations": [item.record() for item in sorted({item.application: item for item in installations}.values(), key=lambda item: str(item.application))]}
        if not args.inspect:
            assert args.output is not None and args.github_env is not None
            with args.output.open("x", encoding="utf-8") as output:
                json.dump(record, output, sort_keys=True, indent=2)
                output.write("\n")
            with args.github_env.open("a", encoding="utf-8") as output:
                output.write(f"DEVELOPER_DIR={selected.developer}\nCFW_UNSIGNED_VALIDATION_XCODE_VERSION={selected.version}\nCFW_UNSIGNED_VALIDATION_XCODE_BUILD_VERSION={selected.build}\n")
        print(json.dumps(record, sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"error: CI Xcode selection: {error}") from error


if __name__ == "__main__":
    main()
