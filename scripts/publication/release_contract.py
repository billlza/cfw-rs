from __future__ import annotations

import os
import stat
from pathlib import Path

from .common import PublicationError
if __package__.startswith("scripts."):
    from scripts.release_build_identity import canonical_build_version
else:
    from release_build_identity import canonical_build_version


PRODUCT_NAME = "Clash for Mac"
RELEASE_VERSION = "0.4.0"


def signed_app(repository: Path) -> Path:
    return repository / "target/candidates/0.4.0/signed/Clash for Mac.app"


def native_products_root(repository: Path, build_number: str) -> Path:
    build = canonical_build_version(build_number, "publication build number")
    return repository / f"target/candidates/0.4.0/release-build/{build}/native-products"


def validated_candidate_review(repository: Path) -> Path:
    return repository / "target/candidates/0.4.0/review/validated-candidate.json"


def prepared_root(repository: Path) -> Path:
    return repository / "target/candidates/0.4.0/release/publication-prepared"


def draft_path(repository: Path) -> Path:
    return repository / "target/candidates/0.4.0/release/machine-closure.draft.json"


def evidence_root(repository: Path) -> Path:
    return repository / "target/candidates/0.4.0/release/publication"


def review_template(repository: Path) -> Path:
    return repository / "target/candidates/0.4.0/review/component-review.json"


def blocker_report(repository: Path) -> Path:
    return repository / "target/candidates/0.4.0/review/publication-blockers.json"


def require_fixed_path(actual: Path, expected: Path, label: str) -> None:
    actual_absolute = Path(os.path.abspath(actual))
    expected_absolute = Path(os.path.abspath(expected))
    if actual_absolute != expected_absolute:
        raise PublicationError(f"production {label} must use the fixed 0.4.0 path: {expected}")
    repository = Path(__file__).resolve().parent.parent.parent
    try:
        relative = expected_absolute.relative_to(repository)
    except ValueError as error:
        raise PublicationError(f"production {label} is outside the repository") from error
    current = repository
    for part in relative.parts[:-1]:
        current /= part
        if not current.exists() and not current.is_symlink():
            continue
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PublicationError(f"production {label} has an unsafe path ancestor: {current}")
