"""Updater-key atomic release blocker (Requirement 8.1).

An ``Updater_Key_File`` is any updater-key-named ``.key`` or ``.pem`` file in
the reviewable release workspace: repository source files plus every generated
``target`` subtree except a small allowlist of managed, content-addressed heavy
roots (for example ``.tauri/cfw-rs.key`` or
``target/candidates/0.4.0/review/updater.pem``). If key material exists anywhere
in that bounded surface, the release gate must execute *one atomic security
response* that:

1. blocks release;
2. inspects and reports **only** the file path and name, never opening or
   reading file contents;
3. requires relocation to an access-controlled external store;
4. prevents omission of any response step; and
5. requires key rotation **plus** an updater trust migration when backup,
   archive, or sharing exposure is plausible.

This module scans **by path and name only**.  It never calls ``open`` and never
reads a candidate's bytes: detection uses directory entry names and entry
type/symlink metadata (a ``stat``-level fact, not file content).  Exposure
plausibility is likewise decided from path/name signals alone.

The blocker fails **closed**: an unavailable, symlinked, or malformed workspace
root, or any traversal error, raises :class:`UpdaterKeyReleaseBlock` rather than
silently reporting "no key material".  Its presence is never downgraded to a
warning and the response can never omit a mandated step.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


class UpdaterKeyReleaseBlock(RuntimeError):
    """Raised when the blocker must fail closed because an input required by
    the path/name scan is unavailable, untrustworthy, or malformed."""


# Updater-key material is identified by extension only; the blocker never opens
# a candidate to confirm it.
KEY_SUFFIXES: frozenset[str] = frozenset({".key", ".pem"})

# Directories that are not part of the reviewable source surface. ``.git`` is
# pruned because updater keys living in workspace *files* are the concern; its
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


@dataclass(frozen=True)
class DetectedUpdaterKey:
    """An updater-key candidate identified by path and name only."""

    path: str
    name: str


@dataclass(frozen=True)
class SecurityResponse:
    """The one atomic security response for a single detected updater key.

    Only ``path`` and ``name`` describe the file; no field ever carries file
    contents.  Every mandated step is an explicit field so omission is
    detectable by :func:`assert_response_complete`.
    """

    detected_path: str
    detected_name: str
    block_release: bool
    relocation_required: bool
    relocation_target: str
    exposure_plausible: bool
    rotation_required: bool
    trust_migration_required: bool


def has_key_suffix(name: str) -> bool:
    """Return True if ``name`` is an updater-key-named ``.key``/``.pem`` file."""
    return Path(name).suffix.lower() in KEY_SUFFIXES


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
            raise UpdaterKeyReleaseBlock(
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


def scan_workspace(workspace_root: str | os.PathLike[str]) -> list[DetectedUpdaterKey]:
    """Scan the bounded release workspace by path and name only.

    Never opens or reads a candidate.  Fails closed on an unavailable,
    symlinked, or unreadable workspace root and on any traversal error.
    """
    root = Path(workspace_root)

    try:
        if root.is_symlink():
            raise UpdaterKeyReleaseBlock(
                f"workspace root is a symlink; scan cannot be trusted: {root}"
            )
        if not root.is_dir():
            raise UpdaterKeyReleaseBlock(
                f"workspace root is unavailable or not a directory: {root}"
            )
    except OSError as exc:  # pragma: no cover - defensive fail-closed
        raise UpdaterKeyReleaseBlock(
            f"workspace root could not be inspected: {root}"
        ) from exc

    try:
        canonical_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UpdaterKeyReleaseBlock(
            f"workspace root could not be resolved: {root}"
        ) from exc

    target = root / "target"
    detected: list[DetectedUpdaterKey] = []
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
                raise UpdaterKeyReleaseBlock(
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
                        raise UpdaterKeyReleaseBlock(
                            f"workspace entry could not be classified: {entry.path}"
                        ) from exc
                    entry_path = Path(entry.path)
                    if current == target and entry.name in MANAGED_TARGET_ROOTS:
                        if not is_dir or is_symlink:
                            raise UpdaterKeyReleaseBlock(
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
                        if has_key_suffix(entry.name):
                            detected.append(
                                DetectedUpdaterKey(path=entry.path, name=entry.name)
                            )
                            continue
                        try:
                            target_metadata = entry.stat(follow_symlinks=True)
                        except OSError as exc:
                            raise UpdaterKeyReleaseBlock(
                                "workspace symlink target could not be classified: "
                                f"{entry.path}"
                            ) from exc
                        if stat.S_ISDIR(target_metadata.st_mode):
                            try:
                                resolved_target = entry_path.resolve(strict=True)
                                resolved_target.relative_to(canonical_root)
                            except (OSError, RuntimeError, ValueError) as exc:
                                raise UpdaterKeyReleaseBlock(
                                    "workspace directory symlink escapes, loops, or "
                                    f"is unavailable: {entry.path}"
                                ) from exc
                            if _is_pruned_target(canonical_root, resolved_target):
                                raise UpdaterKeyReleaseBlock(
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
                                raise UpdaterKeyReleaseBlock(
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
                                raise UpdaterKeyReleaseBlock(
                                    "workspace directory symlink changed while resolving: "
                                    f"{entry.path}"
                                )
                            directory_symlink_targets.add(target_identity)
                            directory_symlink_edges.setdefault(
                                current_identity, set()
                            ).add(target_identity)
                            continue
                        if not stat.S_ISREG(target_metadata.st_mode):
                            raise UpdaterKeyReleaseBlock(
                                "workspace symlink target is not a regular file: "
                                f"{entry.path}"
                            )
                        try:
                            resolved_target = entry_path.resolve(strict=True)
                            resolved_target.relative_to(canonical_root)
                        except (OSError, RuntimeError, ValueError) as exc:
                            raise UpdaterKeyReleaseBlock(
                                "workspace file symlink escapes, loops, or is unavailable: "
                                f"{entry.path}"
                            ) from exc
                        if _is_pruned_target(canonical_root, resolved_target):
                            raise UpdaterKeyReleaseBlock(
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
                            raise UpdaterKeyReleaseBlock(
                                "workspace file symlink does not resolve to a stable real "
                                f"file: {entry.path}"
                            )
                        file_symlink_targets.add(target_identity)
                        continue
                    if is_file:
                        file_metadata = entry.stat(follow_symlinks=False)
                        if not stat.S_ISREG(file_metadata.st_mode):
                            raise UpdaterKeyReleaseBlock(
                                f"workspace file changed while scanning: {entry.path}"
                            )
                        visited_regular_files.add(
                            (file_metadata.st_dev, file_metadata.st_ino)
                        )
                        if has_key_suffix(entry.name):
                            detected.append(
                                DetectedUpdaterKey(
                                    path=entry.path, name=entry.name
                                )
                            )
        except OSError as exc:
            # A directory we cannot traverse means the scan is incomplete; a
            # partial scan must never be reported as "clean".
            raise UpdaterKeyReleaseBlock(
                f"workspace traversal failed under {current}"
            ) from exc

    if not directory_symlink_targets.issubset(visited_directories):
        raise UpdaterKeyReleaseBlock(
            "workspace directory symlink target is not reachable by a scanned real path"
        )
    if not file_symlink_targets.issubset(visited_regular_files):
        raise UpdaterKeyReleaseBlock(
            "workspace file symlink target is not reachable by a scanned real path"
        )
    _require_acyclic_symlink_edges(directory_symlink_edges)
    detected.sort(key=lambda item: item.path)
    return detected


def exposure_is_plausible(
    detected: DetectedUpdaterKey, workspace_root: str | os.PathLike[str]
) -> bool:
    """Decide, from path/name signals only, whether backup/archive/sharing
    exposure of a detected updater key is plausible.

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

    # A distributed public counterpart makes updater trust migration necessary.
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


def build_security_response(
    detected: DetectedUpdaterKey, workspace_root: str | os.PathLike[str]
) -> SecurityResponse:
    """Build the one atomic security response for a detected updater key.

    Uses only the file's path and name plus path/name-derived exposure signals.
    Rotation and updater trust migration are jointly required exactly when
    exposure is plausible.
    """
    plausible = exposure_is_plausible(detected, workspace_root)
    return SecurityResponse(
        detected_path=detected.path,
        detected_name=detected.name,
        block_release=True,
        relocation_required=True,
        relocation_target=RELOCATION_TARGET,
        exposure_plausible=plausible,
        rotation_required=plausible,
        trust_migration_required=plausible,
    )


def assert_response_complete(response: SecurityResponse) -> None:
    """Ensure no mandated response step was omitted.

    Raises :class:`UpdaterKeyReleaseBlock` when the response fails to block, has
    no file identity, fails to require relocation, or requires rotation without
    the paired updater trust migration (or vice versa) when exposure is
    plausible.
    """
    if not response.block_release:
        raise UpdaterKeyReleaseBlock(
            "atomic response omitted the release-block step"
        )
    if not response.detected_path or not response.detected_name:
        raise UpdaterKeyReleaseBlock(
            "atomic response omitted the path/name report step"
        )
    if not response.relocation_required or not response.relocation_target:
        raise UpdaterKeyReleaseBlock(
            "atomic response omitted the external-relocation step"
        )
    if response.exposure_plausible:
        if not response.rotation_required:
            raise UpdaterKeyReleaseBlock(
                "atomic response omitted the key-rotation step under plausible exposure"
            )
        if not response.trust_migration_required:
            raise UpdaterKeyReleaseBlock(
                "atomic response omitted the updater-trust-migration step "
                "under plausible exposure"
            )
    # Rotation and trust migration are inseparable: a rotated key without a
    # trust migration would leave the distributed anchor trusting a dead key.
    if response.rotation_required != response.trust_migration_required:
        raise UpdaterKeyReleaseBlock(
            "atomic response split key rotation from updater trust migration"
        )


def evaluate_workspace(
    workspace_root: str | os.PathLike[str],
) -> list[SecurityResponse]:
    """Return the complete, validated atomic responses for a workspace.

    An empty list means no updater-key material was found and this gate does not
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
        f"blocked updater-key file: {response.detected_path}",
        f"  name: {response.detected_name}",
        "  step 1 block release: yes",
        "  step 2 report (path/name only, contents never read): yes",
        f"  step 3 relocate to {response.relocation_target}: required",
        f"  backup/archive/sharing exposure plausible: "
        f"{'yes' if response.exposure_plausible else 'no'}",
        f"  step 4 rotate updater key: "
        f"{'required' if response.rotation_required else 'not required'}",
        f"  step 5 migrate updater trust: "
        f"{'required' if response.trust_migration_required else 'not required'}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Atomically block release when an updater-key file exists in the "
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
    except UpdaterKeyReleaseBlock as exc:
        print(f"error: updater-key release blocker failed closed: {exc}", file=sys.stderr)
        return 1

    if responses:
        for response in responses:
            print(format_response(response), file=sys.stderr)
        print(
            "error: updater signing key material is present in the workspace; "
            "release is blocked until the atomic security response is completed",
            file=sys.stderr,
        )
        return 1

    print("no updater-key material found; this gate does not block release")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
