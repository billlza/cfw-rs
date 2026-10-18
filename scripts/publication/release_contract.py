from __future__ import annotations

import os
import stat
from pathlib import Path

from .common import PublicationError
from .durable_file import ensure_private_directory_locked, exclusive_rooted_directory_lock
if __package__.startswith("scripts."):
    from scripts.release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        canonical_build_version,
        ga_root,
        ga_signed_native_products_root,
        ga_signed_root,
    )
else:
    from release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        canonical_build_version,
        ga_root,
        ga_signed_native_products_root,
        ga_signed_root,
    )


PRODUCT_NAME = "Clash for Mac"
RELEASE_VERSION = "0.5.0"


def signed_app(repository: Path) -> Path:
    return ga_signed_root(repository) / "Clash for Mac.app"


def native_products_root(repository: Path, build_number: str) -> Path:
    build = canonical_build_version(build_number, "publication build number")
    if build != ACTIVE_RELEASE_IDENTITY.ga_build:
        raise PublicationError(
            "publication native products require the single active GA build"
        )
    return ga_signed_native_products_root(repository)


def _stage_inputs(repository: Path) -> Path:
    return ga_root(repository) / "stage-inputs"


def ensure_private_stage_inputs(repository: Path) -> Path:
    """Create or validate the private stage-input directory before a stage writes.

    The hosted CI receipt and the notarization executor create this directory
    0700 and reject any other mode, so publication writers use the same
    contract instead of inheriting the caller's umask.
    """
    stage_inputs = _stage_inputs(repository)
    with exclusive_rooted_directory_lock(
        repository, stage_inputs.parent, require_private=True
    ) as descriptor:
        ensure_private_directory_locked(descriptor, stage_inputs.parent, stage_inputs.name)
    return stage_inputs


def prepared_root(repository: Path) -> Path:
    return _stage_inputs(repository) / "publication-prepared"


def draft_path(repository: Path) -> Path:
    return _stage_inputs(repository) / "machine-closure.draft.json"


def evidence_root(repository: Path) -> Path:
    return _stage_inputs(repository) / "publication"


def review_template(repository: Path) -> Path:
    return _stage_inputs(repository) / "component-review.json"


def blocker_report(repository: Path) -> Path:
    return _stage_inputs(repository) / "publication-blockers.json"


def require_fixed_path(
    actual: Path, expected: Path, label: str, *, repository: Path
) -> None:
    try:
        metadata = repository.lstat()
        canonical = repository.resolve(strict=True)
    except OSError as error:
        raise PublicationError("publication artifact repository is unavailable") from error
    if (
        not repository.is_absolute()
        or canonical != repository
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise PublicationError("publication artifact repository is not one canonical directory")
    if ".." in actual.parts or ".." in expected.parts:
        raise PublicationError(f"production {label} contains parent traversal")
    actual_absolute = Path(os.path.abspath(actual))
    expected_absolute = Path(os.path.abspath(expected))
    if actual_absolute != expected_absolute:
        raise PublicationError(f"production {label} must use the fixed 0.5.0 path: {expected}")
    try:
        relative = expected_absolute.relative_to(repository)
    except ValueError as error:
        raise PublicationError(f"production {label} is outside the repository") from error
    current = repository
    for part in relative.parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PublicationError(f"production {label} has an unsafe path ancestor: {current}")
    if actual_absolute.is_symlink():
        raise PublicationError(f"production {label} is a symlink: {actual_absolute}")
