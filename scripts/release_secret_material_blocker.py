"""Path/name-only release secret-material blocker (Requirement 8.1).

A secret-material candidate is any ``.key``, ``.pem``, or ``.p8`` file in the
reviewable release workspace. Detection remains deliberately path/name-only,
while response policy distinguishes the known updater signing key, an Apple
App Store Connect ``.p8`` API key, and an otherwise unknown private-key
candidate. If secret material exists in that bounded surface, the gate executes
one atomic, typed security response that:

1. blocks release;
2. inspects and reports **only** the file path and name, never opening or
   reading file contents;
3. requires relocation to an access-controlled external store;
4. prevents omission of any response step; and
5. requires the trust-domain-specific rotation action when backup, archive, or
   sharing exposure is plausible.

This module scans **by path and name only**.  It never calls ``open`` and never
reads a candidate's bytes: detection uses directory entry names and entry
type/symlink metadata (a ``stat``-level fact, not file content).  Exposure
plausibility is likewise decided from path/name signals alone.

The blocker fails **closed**: an unavailable, symlinked, or malformed workspace
root, or any traversal error, raises :class:`SecretMaterialReleaseBlock` rather than
silently reporting "no key material".  Its presence is never downgraded to a
warning and the response can never omit a mandated domain-specific step.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class SecretMaterialReleaseBlock(RuntimeError):
    """Raised when the blocker must fail closed because an input required by
    the path/name scan is unavailable, untrustworthy, or malformed."""


# Secret material is detected by extension only; classification additionally
# uses the path/name contract and never opens a candidate to inspect its bytes.
SECRET_SUFFIXES: frozenset[str] = frozenset({".key", ".p8", ".pem"})
UPDATER_KEY_NAMES: frozenset[str] = frozenset(
    {"cfw-rs.key", "cfw-rs-v2.key", "updater.key", "updater.pem"}
)
PINNED_NOTARY_ASC_KEY_NAME = "AuthKey_DYHRNJ2Z4M.p8"
APPLE_AUTH_KEY_RE = re.compile(r"^AuthKey_[A-Z0-9]{10}\.p8$")

# Directories that are not part of the reviewable source surface. ``.git`` is
# pruned because secret candidates living in workspace *files* are the concern; its
# presence is still read (by name only) as an exposure signal.
PRUNE_DIR_NAMES: frozenset[str] = frozenset(
    {".git", "node_modules", ".build"}
)

# These direct children of ``target`` are large managed caches with independent
# tree-manifest gates. Every other child -- especially ``candidates``, ``tmp``,
# ``release``, and an unexpected name -- remains inside this secret scan.
# A managed child must itself be a real directory; a file or symlink at one of
# these names fails closed rather than hiding content behind the allowlist.
MANAGED_TARGET_ROOTS: frozenset[str] = frozenset(
    {
        "debug",
        "native-dependencies",
        "release-build-cache",
        "sources",
        "toolchains",
        "ui-build",
    }
)

# Path segments that make backup/archive/sharing exposure plausible from the
# path alone.  Matched case-insensitively against each path component.
EXPOSURE_PATH_MARKERS: frozenset[str] = frozenset(
    {
        "backup",
        "backups",
        "archive",
        "archives",
        "shared",
        "share",
        "sync",
        "snapshot",
        "snapshots",
        "dropbox",
        "onedrive",
        "icloud",
        "googledrive",
        "google drive",
        "box",
        "time machine",
    }
)

# The mandated relocation destination.  Reported, never resolved or opened.
RELOCATION_TARGET = "an access-controlled external key store outside the repository workspace"


class SecretMaterialKind(str, Enum):
    """Trust-domain classification derived only from a candidate path/name."""

    UPDATER_SIGNING_KEY = "updater-signing-key"
    APPLE_ASC_NOTARY_KEY = "apple-app-store-connect-notary-api-key"
    APPLE_API_PRIVATE_KEY = "apple-api-private-key-candidate"
    UNKNOWN_PRIVATE_KEY = "unknown-private-key"


class RequiredTrustAction(str, Enum):
    """One complete response selected from exposure and trust domain."""

    RELOCATE_ONLY = "relocate-outside-workspace"
    ROTATE_UPDATER_AND_MIGRATE_TRUST = "rotate-updater-key-and-migrate-updater-trust"
    ROTATE_ASC_AND_REPROVISION_NOTARY = (
        "revoke-and-rotate-app-store-connect-key-and-reprovision-notary-profile"
    )
    IDENTIFY_APPLE_DOMAIN_AND_RELOCATE = (
        "identify-apple-api-domain-and-relocate-credential"
    )
    IDENTIFY_APPLE_DOMAIN_AND_ROTATE = (
        "identify-apple-api-domain-and-revoke-or-rotate-credential"
    )
    IDENTIFY_DOMAIN_AND_RELOCATE = "identify-trust-domain-and-relocate-credential"
    IDENTIFY_DOMAIN_AND_ROTATE = "identify-trust-domain-and-rotate-credential"


@dataclass(frozen=True)
class DetectedSecretMaterial:
    """A secret-material candidate identified by path and name only."""

    path: str
    name: str
    kind: SecretMaterialKind


@dataclass(frozen=True)
class SecurityResponse:
    """The one atomic security response for one detected secret candidate.

    Only ``path`` and ``name`` describe the file; no field ever carries file
    contents.  Every mandated step is an explicit field so omission is
    detectable by :func:`assert_response_complete`.
    """

    detected_path: str
    detected_name: str
    credential_kind: SecretMaterialKind
    block_release: bool
    relocation_required: bool
    relocation_target: str
    exposure_plausible: bool
    rotation_required: bool
    required_trust_action: RequiredTrustAction
    updater_trust_migration_required: bool
    notary_profile_reprovision_required: bool
    trust_domain_identification_required: bool


def has_secret_suffix(name: str) -> bool:
    """Return True for a ``.key``/``.pem``/``.p8`` candidate."""
    return Path(name).suffix.lower() in SECRET_SUFFIXES


def classify_secret_material(path: Path, name: str) -> SecretMaterialKind:
    """Classify a candidate without reading it or guessing from its contents."""

    lowered_name = name.lower()
    if name == PINNED_NOTARY_ASC_KEY_NAME:
        return SecretMaterialKind.APPLE_ASC_NOTARY_KEY
    if APPLE_AUTH_KEY_RE.fullmatch(name):
        return SecretMaterialKind.APPLE_API_PRIVATE_KEY
    if lowered_name in UPDATER_KEY_NAMES or ".tauri" in {
        part.lower() for part in path.parts
    }:
        return SecretMaterialKind.UPDATER_SIGNING_KEY
    return SecretMaterialKind.UNKNOWN_PRIVATE_KEY


def _is_pruned_target(root: Path, path: Path) -> bool:
    """Return whether a canonical in-workspace path is outside scan scope."""
    relative = path.relative_to(root)
    if any(part in PRUNE_DIR_NAMES for part in relative.parts):
        return True
    return (
        len(relative.parts) >= 2
        and relative.parts[0] == "target"
        and relative.parts[1] in MANAGED_TARGET_ROOTS
    )


def _require_acyclic_symlink_edges(
    edges: dict[tuple[int, int], set[tuple[int, int]]],
) -> None:
    """Reject directory-alias cycles without rejecting ordinary framework aliases."""
    visiting: set[tuple[int, int]] = set()
    visited: set[tuple[int, int]] = set()

    def visit(node: tuple[int, int]) -> None:
        if node in visiting:
            raise SecretMaterialReleaseBlock(
                "workspace directory symlinks form a traversal cycle"
            )
        if node in visited:
            return
        visiting.add(node)
        for target in edges.get(node, set()):
            visit(target)
        visiting.remove(node)
        visited.add(node)

    for node in sorted(edges):
        visit(node)


def scan_workspace(
    workspace_root: str | os.PathLike[str],
) -> list[DetectedSecretMaterial]:
    """Scan the bounded release workspace by path and name only.

    Never opens or reads a candidate.  Fails closed on an unavailable,
    symlinked, or unreadable workspace root and on any traversal error.
    """
    root = Path(workspace_root)

    try:
        if root.is_symlink():
            raise SecretMaterialReleaseBlock(
                f"workspace root is a symlink; scan cannot be trusted: {root}"
            )
        if not root.is_dir():
            raise SecretMaterialReleaseBlock(
                f"workspace root is unavailable or not a directory: {root}"
            )
    except OSError as exc:  # pragma: no cover - defensive fail-closed
        raise SecretMaterialReleaseBlock(
            f"workspace root could not be inspected: {root}"
        ) from exc

    try:
        canonical_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SecretMaterialReleaseBlock(
            f"workspace root could not be resolved: {root}"
        ) from exc

    target = root / "target"
    detected: list[DetectedSecretMaterial] = []
    stack: list[Path] = [root]
    visited_directories: set[tuple[int, int]] = set()
    visited_regular_files: set[tuple[int, int]] = set()
    directory_symlink_targets: set[tuple[int, int]] = set()
    file_symlink_targets: set[tuple[int, int]] = set()
    directory_symlink_edges: dict[
        tuple[int, int], set[tuple[int, int]]
    ] = {}
    while stack:
        current = stack.pop()
        try:
            current_metadata = current.stat(follow_symlinks=False)
            if not stat.S_ISDIR(current_metadata.st_mode):
                raise SecretMaterialReleaseBlock(
                    f"workspace traversal reached a non-directory: {current}"
                )
            current_identity = (current_metadata.st_dev, current_metadata.st_ino)
            if current_identity in visited_directories:
                continue
            visited_directories.add(current_identity)
            with os.scandir(current) as iterator:
                for entry in iterator:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                        is_file = entry.is_file(follow_symlinks=False)
                        is_symlink = entry.is_symlink()
                    except OSError as exc:
                        raise SecretMaterialReleaseBlock(
                            f"workspace entry could not be classified: {entry.path}"
                        ) from exc
                    entry_path = Path(entry.path)
                    if current == target and entry.name in MANAGED_TARGET_ROOTS:
                        if not is_dir or is_symlink:
                            raise SecretMaterialReleaseBlock(
                                "managed target root is not a trustworthy real "
                                f"directory: {entry.path}"
                            )
                        continue
                    if is_dir:
                        if entry.name in PRUNE_DIR_NAMES:
                            continue
                        stack.append(entry_path)
                        continue
                    # A key-named symlink blocks by identity without reading
                    # its target. A directory symlink is accepted only when it
                    # resolves to a real, in-scope directory that is already
                    # reachable by its canonical workspace path. We never walk
                    # through the alias; the real path is scanned normally.
                    if is_symlink:
                        if has_secret_suffix(entry.name):
                            detected.append(
                                DetectedSecretMaterial(
                                    path=entry.path,
                                    name=entry.name,
                                    kind=classify_secret_material(entry_path, entry.name),
                                )
                            )
                            continue
                        try:
                            target_metadata = entry.stat(follow_symlinks=True)
                        except OSError as exc:
                            raise SecretMaterialReleaseBlock(
                                "workspace symlink target could not be classified: "
                                f"{entry.path}"
                            ) from exc
                        if stat.S_ISDIR(target_metadata.st_mode):
                            try:
                                resolved_target = entry_path.resolve(strict=True)
                                resolved_target.relative_to(canonical_root)
                            except (OSError, RuntimeError, ValueError) as exc:
                                raise SecretMaterialReleaseBlock(
                                    "workspace directory symlink escapes, loops, or "
                                    f"is unavailable: {entry.path}"
                                ) from exc
                            if _is_pruned_target(canonical_root, resolved_target):
                                raise SecretMaterialReleaseBlock(
                                    "workspace directory symlink reaches an excluded "
                                    f"tree only through an alias: {entry.path}"
                                )
                            resolved_metadata = resolved_target.stat(
                                follow_symlinks=False
                            )
                            if (
                                not stat.S_ISDIR(resolved_metadata.st_mode)
                                or resolved_target.is_symlink()
                            ):
                                raise SecretMaterialReleaseBlock(
                                    "workspace directory symlink does not resolve to "
                                    f"a real directory: {entry.path}"
                                )
                            target_identity = (
                                resolved_metadata.st_dev,
                                resolved_metadata.st_ino,
                            )
                            if target_identity != (
                                target_metadata.st_dev,
                                target_metadata.st_ino,
                            ):
                                raise SecretMaterialReleaseBlock(
                                    "workspace directory symlink changed while resolving: "
                                    f"{entry.path}"
                                )
                            directory_symlink_targets.add(target_identity)
                            directory_symlink_edges.setdefault(
                                current_identity, set()
                            ).add(target_identity)
                            continue
                        if not stat.S_ISREG(target_metadata.st_mode):
                            raise SecretMaterialReleaseBlock(
                                "workspace symlink target is not a regular file: "
                                f"{entry.path}"
                            )
                        try:
                            resolved_target = entry_path.resolve(strict=True)
                            resolved_target.relative_to(canonical_root)
                        except (OSError, RuntimeError, ValueError) as exc:
                            raise SecretMaterialReleaseBlock(
                                "workspace file symlink escapes, loops, or is unavailable: "
                                f"{entry.path}"
                            ) from exc
                        if _is_pruned_target(canonical_root, resolved_target):
                            raise SecretMaterialReleaseBlock(
                                "workspace file symlink reaches an excluded tree only "
                                f"through an alias: {entry.path}"
                            )
                        resolved_metadata = resolved_target.stat(
                            follow_symlinks=False
                        )
                        target_identity = (
                            target_metadata.st_dev,
                            target_metadata.st_ino,
                        )
                        if (
                            not stat.S_ISREG(resolved_metadata.st_mode)
                            or resolved_target.is_symlink()
                            or target_identity
                            != (resolved_metadata.st_dev, resolved_metadata.st_ino)
                        ):
                            raise SecretMaterialReleaseBlock(
                                "workspace file symlink does not resolve to a stable real "
                                f"file: {entry.path}"
                            )
                        file_symlink_targets.add(target_identity)
                        continue
                    if is_file:
                        file_metadata = entry.stat(follow_symlinks=False)
                        if not stat.S_ISREG(file_metadata.st_mode):
                            raise SecretMaterialReleaseBlock(
                                f"workspace file changed while scanning: {entry.path}"
                            )
                        visited_regular_files.add(
                            (file_metadata.st_dev, file_metadata.st_ino)
                        )
                        if has_secret_suffix(entry.name):
                            detected.append(
                                DetectedSecretMaterial(
                                    path=entry.path,
                                    name=entry.name,
                                    kind=classify_secret_material(entry_path, entry.name),
                                )
                            )
        except OSError as exc:
            # A directory we cannot traverse means the scan is incomplete; a
            # partial scan must never be reported as "clean".
            raise SecretMaterialReleaseBlock(
                f"workspace traversal failed under {current}"
            ) from exc

    if not directory_symlink_targets.issubset(visited_directories):
        raise SecretMaterialReleaseBlock(
            "workspace directory symlink target is not reachable by a scanned real path"
        )
    if not file_symlink_targets.issubset(visited_regular_files):
        raise SecretMaterialReleaseBlock(
            "workspace file symlink target is not reachable by a scanned real path"
        )
    _require_acyclic_symlink_edges(directory_symlink_edges)
    detected.sort(key=lambda item: item.path)
    return detected


def exposure_is_plausible(
    detected: DetectedSecretMaterial, workspace_root: str | os.PathLike[str]
) -> bool:
    """Decide, from path/name signals only, whether backup/archive/sharing
    exposure of a detected secret candidate is plausible.

    Signals (any one suffices):

    * a path component that names a backup/archive/sharing location;
    * a sibling ``<name>.pub`` public key, which means an updater trust anchor
      derived from this private key has been distributed; or
    * the workspace being a clonable/shareable repository (a ``.git`` entry at
      the root), so the tree can be committed, archived, or synced.

    None of these signals opens or reads the key.
    """
    candidate = Path(detected.path)

    for part in candidate.parts:
        if part.lower() in EXPOSURE_PATH_MARKERS:
            return True

    # A public counterpart is a path/name-only exposure signal. The response
    # layer decides which trust-domain action is required.
    public_counterpart = candidate.with_name(candidate.name + ".pub")
    try:
        if public_counterpart.exists():
            return True
    except OSError:  # pragma: no cover - fail closed toward "plausible"
        return True

    # A repository root can be cloned, archived, or synced elsewhere.
    try:
        if (Path(workspace_root) / ".git").exists():
            return True
    except OSError:  # pragma: no cover - fail closed toward "plausible"
        return True

    return False


def _response_for_exposure(
    detected: DetectedSecretMaterial, *, exposure_plausible: bool
) -> SecurityResponse:
    """Derive the exact response for an already-established exposure state."""

    action = RequiredTrustAction.RELOCATE_ONLY
    updater_migration = False
    notary_reprovision = False
    identify_domain = detected.kind in {
        SecretMaterialKind.APPLE_API_PRIVATE_KEY,
        SecretMaterialKind.UNKNOWN_PRIVATE_KEY,
    }
    if detected.kind is SecretMaterialKind.APPLE_API_PRIVATE_KEY:
        action = RequiredTrustAction.IDENTIFY_APPLE_DOMAIN_AND_RELOCATE
    elif identify_domain:
        action = RequiredTrustAction.IDENTIFY_DOMAIN_AND_RELOCATE
    if exposure_plausible:
        if detected.kind is SecretMaterialKind.UPDATER_SIGNING_KEY:
            action = RequiredTrustAction.ROTATE_UPDATER_AND_MIGRATE_TRUST
            updater_migration = True
        elif detected.kind is SecretMaterialKind.APPLE_ASC_NOTARY_KEY:
            action = RequiredTrustAction.ROTATE_ASC_AND_REPROVISION_NOTARY
            notary_reprovision = True
        elif detected.kind is SecretMaterialKind.APPLE_API_PRIVATE_KEY:
            action = RequiredTrustAction.IDENTIFY_APPLE_DOMAIN_AND_ROTATE
        else:
            action = RequiredTrustAction.IDENTIFY_DOMAIN_AND_ROTATE
            identify_domain = True
    return SecurityResponse(
        detected_path=detected.path,
        detected_name=detected.name,
        credential_kind=detected.kind,
        block_release=True,
        relocation_required=True,
        relocation_target=RELOCATION_TARGET,
        exposure_plausible=exposure_plausible,
        rotation_required=exposure_plausible,
        required_trust_action=action,
        updater_trust_migration_required=updater_migration,
        notary_profile_reprovision_required=notary_reprovision,
        trust_domain_identification_required=identify_domain,
    )


def build_security_response(
    detected: DetectedSecretMaterial, workspace_root: str | os.PathLike[str]
) -> SecurityResponse:
    """Build one atomic, trust-domain-specific security response.

    Uses only the file's path and name plus path/name-derived exposure signals.
    Exposure requires rotation, but only a known updater key requires updater
    trust migration; an ASC key instead requires notary-profile reprovisioning.
    """

    return _response_for_exposure(
        detected,
        exposure_plausible=exposure_is_plausible(detected, workspace_root),
    )


def assert_response_complete(response: SecurityResponse) -> None:
    """Ensure no mandated response step was omitted.

    Raises :class:`SecretMaterialReleaseBlock` when the response omits a common
    custody step or selects an action inconsistent with its credential kind.
    """
    if not response.block_release:
        raise SecretMaterialReleaseBlock(
            "atomic response omitted the release-block step"
        )
    if not response.detected_path or not response.detected_name:
        raise SecretMaterialReleaseBlock(
            "atomic response omitted the path/name report step"
        )
    if not response.relocation_required or not response.relocation_target:
        raise SecretMaterialReleaseBlock(
            "atomic response omitted the external-relocation step"
        )
    expected = _response_for_exposure(
        DetectedSecretMaterial(
            path=response.detected_path,
            name=response.detected_name,
            kind=response.credential_kind,
        ),
        exposure_plausible=response.exposure_plausible,
    )
    if response != expected:
        raise SecretMaterialReleaseBlock(
            "atomic response trust action differs from its credential kind/exposure"
        )


def evaluate_workspace(
    workspace_root: str | os.PathLike[str],
) -> list[SecurityResponse]:
    """Return the complete, validated atomic responses for a workspace.

    An empty list means no secret material was found and this gate does not
    block release.  A non-empty list blocks release.  Fails closed by raising
    on any scan or completeness failure.
    """
    detected = scan_workspace(workspace_root)
    responses = [build_security_response(item, workspace_root) for item in detected]
    for response in responses:
        assert_response_complete(response)
    return responses


def format_response(response: SecurityResponse) -> str:
    """Render a response using only path and name; contents are never read."""
    lines = [
        f"blocked release secret-material file: {response.detected_path}",
        f"  name: {response.detected_name}",
        f"  credential kind: {response.credential_kind.value}",
        "  step 1 block release: yes",
        "  step 2 report (path/name only, contents never read): yes",
        f"  step 3 relocate to {response.relocation_target}: required",
        f"  backup/archive/sharing exposure plausible: "
        f"{'yes' if response.exposure_plausible else 'no'}",
        f"  step 4 rotate credential: "
        f"{'required' if response.rotation_required else 'not required'}",
        f"  required trust action: {response.required_trust_action.value}",
        f"  updater trust migration: "
        f"{'required' if response.updater_trust_migration_required else 'not required'}",
        f"  notary profile reprovision: "
        f"{'required' if response.notary_profile_reprovision_required else 'not required'}",
        f"  trust-domain identification: "
        f"{'required' if response.trust_domain_identification_required else 'not required'}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Atomically block release when secret material exists in the "
            "reviewable source/candidate/release workspace (path/name scan "
            "only; never reads file contents)."
        )
    )
    parser.add_argument(
        "workspace_root",
        nargs="?",
        default=os.getcwd(),
        help="Absolute path to the repository workspace root to scan.",
    )
    args = parser.parse_args(argv)

    try:
        responses = evaluate_workspace(args.workspace_root)
    except SecretMaterialReleaseBlock as exc:
        print(
            f"error: release secret-material blocker failed closed: {exc}",
            file=sys.stderr,
        )
        return 1

    if responses:
        for response in responses:
            print(format_response(response), file=sys.stderr)
        print(
            "error: release secret material is present in the workspace; "
            "release is blocked until the atomic security response is completed",
            file=sys.stderr,
        )
        return 1

    print("no release secret material found; this gate does not block release")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
