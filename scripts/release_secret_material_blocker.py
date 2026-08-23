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

This module detects secret candidates **by path and name only**. It never opens
or reads a candidate's bytes: detection uses directory entry names and entry
type/symlink metadata (a ``stat``-level fact, not file content). To authenticate
nested release-worktree cache boundaries, it performs
bounded, descriptor-relative reads of fixed control files in Git's independent
administrative registry and the reciprocal worktree marker. It never opens a
source, cache, candidate, or secret-material file. Exposure plausibility is
likewise decided from path/name signals alone.

The blocker fails **closed**: an unavailable, symlinked, or malformed workspace
root, or any traversal error, raises :class:`SecretMaterialReleaseBlock` rather than
silently reporting "no key material".  Its presence is never downgraded to a
warning and the response can never omit a mandated domain-specific step.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import sys
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class SecretMaterialReleaseBlock(RuntimeError):
    """Raised when the blocker must fail closed because an input required by
    the path/name scan is unavailable, untrustworthy, or malformed."""


RELEASE_WORKTREE_CACHE_SCOPE_SCHEMA = "cfm-release-worktree-cache-scope-v1"
RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT = (
    "cfm-release-worktree-cache-scope-v1.json"
)
RELEASE_WORKTREE_CACHE_SCOPE_PENDING = (
    ".cfm-release-worktree-cache-scope-v1.json.pending"
)
RELEASE_WORKTREE_CACHE_SCOPE_LOCK = ".cfm-release-worktree-cache-scope-v1.lock"


class ReleaseWorktreeCacheScopeError(ValueError):
    """The lifecycle receipt is malformed or non-canonical."""


@dataclass(frozen=True)
class StablePathIdentity:
    device: int
    inode: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.device, bool)
            or isinstance(self.inode, bool)
            or not isinstance(self.device, int)
            or not isinstance(self.inode, int)
            or self.device <= 0
            or self.inode <= 0
        ):
            raise ReleaseWorktreeCacheScopeError(
                "release-worktree path identity is invalid"
            )

    def as_dict(self) -> dict[str, int]:
        return {"device": self.device, "inode": self.inode}


@dataclass(frozen=True)
class ReleaseWorktreeCacheScopeReceipt:
    build: str
    worktree_path: str
    head: str
    admin: StablePathIdentity
    worktree: StablePathIdentity
    marker: StablePathIdentity
    target: StablePathIdentity

    def as_dict(self) -> dict[str, object]:
        return {
            "adminIdentity": self.admin.as_dict(),
            "build": self.build,
            "head": self.head,
            "markerIdentity": self.marker.as_dict(),
            "schema": RELEASE_WORKTREE_CACHE_SCOPE_SCHEMA,
            "targetIdentity": self.target.as_dict(),
            "worktreeIdentity": self.worktree.as_dict(),
            "worktreePath": self.worktree_path,
        }


def canonical_scope_receipt_bytes(
    receipt: ReleaseWorktreeCacheScopeReceipt,
) -> bytes:
    return (
        json.dumps(
            receipt.as_dict(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _unique_scope_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseWorktreeCacheScopeError(
                "release-worktree receipt contains a duplicate key"
            )
        value[key] = item
    return value


def _reject_scope_constant(token: str) -> object:
    raise ReleaseWorktreeCacheScopeError(
        f"release-worktree receipt contains {token}"
    )


def _scope_path_identity(value: object, label: str) -> StablePathIdentity:
    if not isinstance(value, dict) or set(value) != {"device", "inode"}:
        raise ReleaseWorktreeCacheScopeError(
            f"release-worktree receipt {label} identity is malformed"
        )
    return StablePathIdentity(device=value["device"], inode=value["inode"])


def parse_scope_receipt(data: bytes) -> ReleaseWorktreeCacheScopeReceipt:
    try:
        value = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_unique_scope_object,
            parse_constant=_reject_scope_constant,
        )
    except ReleaseWorktreeCacheScopeError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise ReleaseWorktreeCacheScopeError(
            "release-worktree receipt is not canonical JSON"
        ) from exc
    expected_keys = {
        "adminIdentity",
        "build",
        "head",
        "markerIdentity",
        "schema",
        "targetIdentity",
        "worktreeIdentity",
        "worktreePath",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ReleaseWorktreeCacheScopeError(
            "release-worktree receipt fields are malformed"
        )
    if value["schema"] != RELEASE_WORKTREE_CACHE_SCOPE_SCHEMA:
        raise ReleaseWorktreeCacheScopeError(
            "release-worktree receipt schema is unsupported"
        )
    if not all(
        isinstance(value[field], str)
        for field in ("build", "head", "worktreePath")
    ):
        raise ReleaseWorktreeCacheScopeError(
            "release-worktree receipt string fields are malformed"
        )
    receipt = ReleaseWorktreeCacheScopeReceipt(
        build=value["build"],
        worktree_path=value["worktreePath"],
        head=value["head"],
        admin=_scope_path_identity(value["adminIdentity"], "admin"),
        worktree=_scope_path_identity(value["worktreeIdentity"], "worktree"),
        marker=_scope_path_identity(value["markerIdentity"], "marker"),
        target=_scope_path_identity(value["targetIdentity"], "target"),
    )
    if canonical_scope_receipt_bytes(receipt) != data:
        raise ReleaseWorktreeCacheScopeError(
            "release-worktree receipt is not in canonical form"
        )
    return receipt


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

# Fixed release builds use five-digit numeric directory names. The numeric
# shape is necessary but never sufficient to grant an exclusion: the main
# repository's independent Git administrative registry and the reciprocal
# worktree marker must identify the path as a live detached worktree.
RELEASE_WORKTREE_BUILD_RE = re.compile(r"^[1-9][0-9]{4}$")
GIT_DETACHED_HEAD_RE = re.compile(rb"^[0-9a-f]{40}\n$")
MAXIMUM_GIT_CONTROL_FILE_BYTES = 4_096
_SCOPE_ENROLLMENT_LOCK = threading.Lock()

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
class _RegisteredReleaseWorktreeIdentity:
    owner: int
    admin_path: Path
    admin: tuple[int, int]
    path: Path
    head: str
    worktree: tuple[int, int]
    marker: tuple[int, int]
    marker_data: bytes
    target: tuple[int, int]
    receipt: tuple[int, int] | None
    receipt_data: bytes | None


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


def _is_release_worktree_target_parts(parts: tuple[str, ...]) -> bool:
    """Return whether parts name an exact release-worktree target directory."""
    return (
        len(parts) == 4
        and parts[0] == "target"
        and parts[1] == "release-worktrees"
        and RELEASE_WORKTREE_BUILD_RE.fullmatch(parts[2]) is not None
        and parts[3] == "target"
    )


def _open_verified_directory(
    path: str | os.PathLike[str],
    *,
    expected_owner: int,
    label: str,
    dir_fd: int | None = None,
) -> tuple[int, tuple[int, int]]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise SecretMaterialReleaseBlock(
            f"{label} is unavailable or is not a trustworthy real directory"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise SecretMaterialReleaseBlock(
            f"{label} identity could not be inspected"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != expected_owner:
        os.close(descriptor)
        raise SecretMaterialReleaseBlock(
            f"{label} has an unsafe type or owner"
        )
    return descriptor, (metadata.st_dev, metadata.st_ino)


def _read_git_control_file(
    directory_fd: int,
    name: str,
    *,
    expected_owner: int,
) -> tuple[bytes, tuple[int, int]]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise SecretMaterialReleaseBlock(
            f"Git worktree control file is unavailable: {name}"
        ) from exc
    try:
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != expected_owner
                or before.st_nlink != 1
                or before.st_mode & 0o022
                or before.st_size <= 0
                or before.st_size > MAXIMUM_GIT_CONTROL_FILE_BYTES
            ):
                raise SecretMaterialReleaseBlock(
                    f"Git worktree control file has unsafe metadata: {name}"
                )
            data = bytearray()
            while len(data) <= MAXIMUM_GIT_CONTROL_FILE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(1_024, MAXIMUM_GIT_CONTROL_FILE_BYTES + 1 - len(data)),
                )
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
        except OSError as exc:
            raise SecretMaterialReleaseBlock(
                f"Git worktree control file could not be read safely: {name}"
            ) from exc
        if (
            len(data) > MAXIMUM_GIT_CONTROL_FILE_BYTES
            or len(data) != before.st_size
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
                after.st_size,
            )
        ):
            raise SecretMaterialReleaseBlock(
                f"Git worktree control file changed while reading: {name}"
            )
        return bytes(data), (before.st_dev, before.st_ino)
    finally:
        os.close(descriptor)


def _decode_gitdir_control(data: bytes) -> Path:
    if (
        not data.endswith(b"\n")
        or data.count(b"\n") != 1
        or b"\0" in data
    ):
        raise SecretMaterialReleaseBlock("Git worktree gitdir control is malformed")
    try:
        path = Path(os.fsdecode(data[:-1]))
    except (UnicodeError, ValueError) as exc:
        raise SecretMaterialReleaseBlock(
            "Git worktree gitdir path is malformed"
        ) from exc
    if not path.is_absolute() or path.name != ".git":
        raise SecretMaterialReleaseBlock(
            "Git worktree gitdir path is not an absolute marker path"
        )
    return path


def _scope_identity(identity: tuple[int, int]) -> StablePathIdentity:
    return StablePathIdentity(device=identity[0], inode=identity[1])


def _scope_receipt(
    *,
    build: str,
    worktree_path: Path,
    head: str,
    admin: tuple[int, int],
    worktree: tuple[int, int],
    marker: tuple[int, int],
    target: tuple[int, int],
) -> ReleaseWorktreeCacheScopeReceipt:
    return ReleaseWorktreeCacheScopeReceipt(
        build=build,
        worktree_path=str(worktree_path),
        head=head,
        admin=_scope_identity(admin),
        worktree=_scope_identity(worktree),
        marker=_scope_identity(marker),
        target=_scope_identity(target),
    )


def _registered_release_worktree_targets(
    canonical_root: Path,
    *,
    require_scope_receipt: bool = True,
) -> dict[str, _RegisteredReleaseWorktreeIdentity]:
    """Authenticate nested release targets through fixed Git control files."""
    try:
        root_metadata = canonical_root.stat(follow_symlinks=False)
        git_metadata = (canonical_root / ".git").stat(follow_symlinks=False)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise SecretMaterialReleaseBlock(
            "workspace Git administrative root could not be inspected"
        ) from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise SecretMaterialReleaseBlock("canonical workspace root is not a directory")
    root_owner = root_metadata.st_uid
    if not stat.S_ISDIR(git_metadata.st_mode):
        return {}

    git_fd, _ = _open_verified_directory(
        canonical_root / ".git",
        expected_owner=root_owner,
        label="workspace Git administrative root",
    )
    try:
        try:
            registry_fd, registry_identity = _open_verified_directory(
                "worktrees",
                expected_owner=root_owner,
                label="Git worktree registry",
                dir_fd=git_fd,
            )
        except SecretMaterialReleaseBlock as exc:
            try:
                os.stat("worktrees", dir_fd=git_fd, follow_symlinks=False)
            except FileNotFoundError:
                return {}
            except OSError:
                pass
            raise exc
        try:
            admin_names: list[str] = []
            try:
                with os.scandir(registry_fd) as entries:
                    for entry in entries:
                        admin_names.append(entry.name)
                        if len(admin_names) > 4_096:
                            raise SecretMaterialReleaseBlock(
                                "Git worktree registry entry count exceeds the parser limit"
                            )
            except OSError as exc:
                raise SecretMaterialReleaseBlock(
                    "Git worktree registry could not be enumerated"
                ) from exc
            admin_names.sort()
            targets: dict[str, _RegisteredReleaseWorktreeIdentity] = {}
            for admin_name in admin_names:
                admin_fd, admin_identity = _open_verified_directory(
                    admin_name,
                    expected_owner=root_owner,
                    label="Git worktree administrative entry",
                    dir_fd=registry_fd,
                )
                try:
                    gitdir_data, _ = _read_git_control_file(
                        admin_fd, "gitdir", expected_owner=root_owner
                    )
                    commondir_data, _ = _read_git_control_file(
                        admin_fd, "commondir", expected_owner=root_owner
                    )
                    head_data, _ = _read_git_control_file(
                        admin_fd, "HEAD", expected_owner=root_owner
                    )
                    if commondir_data != b"../..\n":
                        raise SecretMaterialReleaseBlock(
                            "Git worktree commondir control is malformed"
                        )
                    marker_path = _decode_gitdir_control(gitdir_data)
                    worktree_path = marker_path.parent
                    try:
                        relative = worktree_path.relative_to(canonical_root)
                    except ValueError:
                        continue
                    if (
                        len(relative.parts) != 3
                        or relative.parts[:2] != (
                            "target",
                            "release-worktrees",
                        )
                        or RELEASE_WORKTREE_BUILD_RE.fullmatch(relative.parts[2])
                        is None
                    ):
                        continue
                    build = relative.parts[2]
                    expected_worktree = (
                        canonical_root / "target/release-worktrees" / build
                    )
                    try:
                        resolved_worktree = expected_worktree.resolve(strict=True)
                    except FileNotFoundError:
                        # A stale administrative entry has no live surface to prune.
                        continue
                    except (OSError, RuntimeError) as exc:
                        raise SecretMaterialReleaseBlock(
                            "registered release worktree could not be resolved"
                        ) from exc
                    if (
                        worktree_path != expected_worktree
                        or resolved_worktree != expected_worktree
                    ):
                        raise SecretMaterialReleaseBlock(
                            "registered release worktree path is not canonical"
                        )
                    if GIT_DETACHED_HEAD_RE.fullmatch(head_data) is None:
                        raise SecretMaterialReleaseBlock(
                            "registered release worktree is not detached"
                        )
                    if build in targets:
                        raise SecretMaterialReleaseBlock(
                            "registered release worktree build is duplicated"
                        )
                    worktree_fd, worktree_identity = _open_verified_directory(
                        expected_worktree,
                        expected_owner=root_owner,
                        label="registered release worktree",
                    )
                    try:
                        marker_data, marker_identity = _read_git_control_file(
                            worktree_fd, ".git", expected_owner=root_owner
                        )
                        expected_admin_path = (
                            canonical_root / ".git/worktrees" / admin_name
                        )
                        if marker_data != (
                            b"gitdir: " + os.fsencode(expected_admin_path) + b"\n"
                        ):
                            raise SecretMaterialReleaseBlock(
                                "registered release worktree marker is not reciprocal"
                            )
                        target_fd, target_identity = _open_verified_directory(
                            "target",
                            expected_owner=root_owner,
                            label="registered release worktree target",
                            dir_fd=worktree_fd,
                        )
                        os.close(target_fd)
                    finally:
                        os.close(worktree_fd)
                    head = head_data[:-1].decode("ascii")
                    expected_scope_receipt = _scope_receipt(
                        build=build,
                        worktree_path=expected_worktree,
                        head=head,
                        admin=admin_identity,
                        worktree=worktree_identity,
                        marker=marker_identity,
                        target=target_identity,
                    )
                    receipt_identity: tuple[int, int] | None = None
                    receipt_data: bytes | None = None
                    try:
                        receipt_metadata = os.stat(
                            RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT,
                            dir_fd=admin_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        if require_scope_receipt:
                            continue
                    except OSError as exc:
                        raise SecretMaterialReleaseBlock(
                            "release-worktree cache-scope receipt could not be inspected"
                        ) from exc
                    else:
                        recoverable_linked_publish = False
                        if (
                            not require_scope_receipt
                            and receipt_metadata.st_nlink == 2
                        ):
                            try:
                                pending_metadata = os.stat(
                                    RELEASE_WORKTREE_CACHE_SCOPE_PENDING,
                                    dir_fd=admin_fd,
                                    follow_symlinks=False,
                                )
                            except OSError as exc:
                                raise SecretMaterialReleaseBlock(
                                    "release-worktree linked receipt lacks its pending peer"
                                ) from exc
                            recoverable_linked_publish = (
                                pending_metadata.st_nlink == 2
                                and (
                                    receipt_metadata.st_dev,
                                    receipt_metadata.st_ino,
                                )
                                == (
                                    pending_metadata.st_dev,
                                    pending_metadata.st_ino,
                                )
                            )
                            if not recoverable_linked_publish:
                                raise SecretMaterialReleaseBlock(
                                    "release-worktree linked receipt state is contradictory"
                                )
                        if not recoverable_linked_publish:
                            receipt_data, receipt_identity = _read_scope_file(
                                admin_fd,
                                RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT,
                                expected_owner=root_owner,
                            )
                            try:
                                parsed_receipt = parse_scope_receipt(receipt_data)
                            except ReleaseWorktreeCacheScopeError as exc:
                                raise SecretMaterialReleaseBlock(
                                    "release-worktree cache-scope receipt is malformed"
                                ) from exc
                            if parsed_receipt != expected_scope_receipt:
                                raise SecretMaterialReleaseBlock(
                                    "release-worktree cache-scope receipt identity is stale"
                                )
                    try:
                        current_admin = os.fstat(admin_fd)
                        visible_admin = os.stat(
                            admin_name,
                            dir_fd=registry_fd,
                            follow_symlinks=False,
                        )
                    except OSError as exc:
                        raise SecretMaterialReleaseBlock(
                            "Git worktree administrative entry could not be revalidated"
                        ) from exc
                    if (
                        (current_admin.st_dev, current_admin.st_ino)
                        != admin_identity
                        or not stat.S_ISDIR(visible_admin.st_mode)
                        or visible_admin.st_uid != root_owner
                        or (visible_admin.st_dev, visible_admin.st_ino)
                        != admin_identity
                    ):
                        raise SecretMaterialReleaseBlock(
                            "Git worktree administrative entry changed while reading"
                        )
                    targets[build] = _RegisteredReleaseWorktreeIdentity(
                        owner=root_owner,
                        admin_path=expected_admin_path,
                        admin=admin_identity,
                        path=expected_worktree,
                        head=head,
                        worktree=worktree_identity,
                        marker=marker_identity,
                        marker_data=marker_data,
                        target=target_identity,
                        receipt=receipt_identity,
                        receipt_data=receipt_data,
                    )
                finally:
                    os.close(admin_fd)
            try:
                current_registry = os.fstat(registry_fd)
                visible_registry = os.stat(
                    "worktrees", dir_fd=git_fd, follow_symlinks=False
                )
            except OSError as exc:
                raise SecretMaterialReleaseBlock(
                    "Git worktree registry could not be revalidated"
                ) from exc
            if (
                current_registry.st_dev,
                current_registry.st_ino,
            ) != registry_identity or (
                not stat.S_ISDIR(visible_registry.st_mode)
                or visible_registry.st_uid != root_owner
                or (visible_registry.st_dev, visible_registry.st_ino)
                != registry_identity
            ):
                raise SecretMaterialReleaseBlock(
                    "Git worktree registry changed while reading"
                )
            return targets
        finally:
            os.close(registry_fd)
    finally:
        os.close(git_fd)


def _scope_file_metadata_is_safe(
    metadata: os.stat_result,
    *,
    expected_owner: int,
    expected_links: int = 1,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == expected_owner
        and metadata.st_nlink == expected_links
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def _read_scope_file(
    admin_fd: int,
    name: str,
    *,
    expected_owner: int,
    expected_links: int = 1,
) -> tuple[bytes, tuple[int, int]]:
    return _read_linked_scope_file(
        admin_fd,
        name,
        expected_owner=expected_owner,
        expected_links=expected_links,
    )


def _read_linked_scope_file(
    admin_fd: int,
    name: str,
    *,
    expected_owner: int,
    expected_links: int,
) -> tuple[bytes, tuple[int, int]]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=admin_fd)
    except OSError as exc:
        raise SecretMaterialReleaseBlock(
            f"release-worktree cache-scope file is unavailable: {name}"
        ) from exc
    try:
        try:
            before = os.fstat(descriptor)
            if (
                not _scope_file_metadata_is_safe(
                    before,
                    expected_owner=expected_owner,
                    expected_links=expected_links,
                )
                or before.st_size <= 0
                or before.st_size > MAXIMUM_GIT_CONTROL_FILE_BYTES
            ):
                raise SecretMaterialReleaseBlock(
                    f"release-worktree cache-scope file has unsafe metadata: {name}"
                )
            data = bytearray()
            while len(data) <= MAXIMUM_GIT_CONTROL_FILE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(1_024, MAXIMUM_GIT_CONTROL_FILE_BYTES + 1 - len(data)),
                )
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
        except OSError as exc:
            raise SecretMaterialReleaseBlock(
                f"release-worktree cache-scope file could not be read: {name}"
            ) from exc
        if (
            len(data) != before.st_size
            or len(data) > MAXIMUM_GIT_CONTROL_FILE_BYTES
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
                after.st_size,
            )
        ):
            raise SecretMaterialReleaseBlock(
                f"release-worktree cache-scope file changed while reading: {name}"
            )
        return bytes(data), (before.st_dev, before.st_ino)
    finally:
        os.close(descriptor)


def _scope_file_exists(admin_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=admin_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SecretMaterialReleaseBlock(
            f"release-worktree cache-scope file could not be inspected: {name}"
        ) from exc
    return True


def _write_scope_pending(admin_fd: int, data: bytes, owner: int) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )
    try:
        descriptor = os.open(
            RELEASE_WORKTREE_CACHE_SCOPE_PENDING,
            flags,
            0o600,
            dir_fd=admin_fd,
        )
    except OSError as exc:
        raise SecretMaterialReleaseBlock(
            "release-worktree cache-scope pending file could not be created"
        ) from exc
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise SecretMaterialReleaseBlock(
                    "release-worktree cache-scope pending write made no progress"
                )
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not _scope_file_metadata_is_safe(metadata, expected_owner=owner)
            or metadata.st_size != len(data)
        ):
            raise SecretMaterialReleaseBlock(
                "release-worktree cache-scope pending file is not stable"
            )
    except OSError as exc:
        raise SecretMaterialReleaseBlock(
            "release-worktree cache-scope pending file could not be committed"
        ) from exc
    finally:
        os.close(descriptor)


def _fsync_scope_pending(
    admin_fd: int,
    *,
    expected_owner: int,
    expected_identity: tuple[int, int],
    expected_size: int,
) -> None:
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(
            RELEASE_WORKTREE_CACHE_SCOPE_PENDING,
            flags,
            dir_fd=admin_fd,
        )
    except OSError as exc:
        raise SecretMaterialReleaseBlock(
            "release-worktree cache-scope pending file could not be reopened"
        ) from exc
    try:
        try:
            before = os.fstat(descriptor)
            if (
                not _scope_file_metadata_is_safe(
                    before, expected_owner=expected_owner
                )
                or (before.st_dev, before.st_ino) != expected_identity
                or before.st_size != expected_size
            ):
                raise SecretMaterialReleaseBlock(
                    "release-worktree cache-scope pending identity is stale"
                )
            os.fsync(descriptor)
            after = os.fstat(descriptor)
        except OSError as exc:
            raise SecretMaterialReleaseBlock(
                "release-worktree cache-scope pending durability could not be proven"
            ) from exc
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
        ):
            raise SecretMaterialReleaseBlock(
                "release-worktree cache-scope pending changed during fsync"
            )
    finally:
        os.close(descriptor)


def _publish_scope_receipt(
    registered: _RegisteredReleaseWorktreeIdentity,
) -> None:
    expected_receipt = _scope_receipt(
        build=registered.path.name,
        worktree_path=registered.path,
        head=registered.head,
        admin=registered.admin,
        worktree=registered.worktree,
        marker=registered.marker,
        target=registered.target,
    )
    expected_data = canonical_scope_receipt_bytes(expected_receipt)
    admin_fd, admin_identity = _open_verified_directory(
        registered.admin_path,
        expected_owner=registered.owner,
        label="release-worktree administrative entry",
    )
    if admin_identity != registered.admin:
        os.close(admin_fd)
        raise SecretMaterialReleaseBlock(
            "release-worktree administrative identity changed before enrollment"
        )
    lock_fd: int | None = None
    lock_acquired = False
    try:
        lock_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
        )
        try:
            lock_fd = os.open(
                RELEASE_WORKTREE_CACHE_SCOPE_LOCK,
                lock_flags,
                0o600,
                dir_fd=admin_fd,
            )
            lock_metadata = os.fstat(lock_fd)
        except OSError as exc:
            raise SecretMaterialReleaseBlock(
                "release-worktree cache-scope lock is unavailable"
            ) from exc
        if not _scope_file_metadata_is_safe(
            lock_metadata, expected_owner=registered.owner
        ):
            raise SecretMaterialReleaseBlock(
                "release-worktree cache-scope lock has unsafe metadata"
            )
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            lock_acquired = True
        except OSError as exc:
            raise SecretMaterialReleaseBlock(
                "release-worktree cache-scope enrollment is already active"
            ) from exc

        final_exists = _scope_file_exists(
            admin_fd, RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT
        )
        pending_exists = _scope_file_exists(
            admin_fd, RELEASE_WORKTREE_CACHE_SCOPE_PENDING
        )
        if final_exists and pending_exists:
            try:
                final_metadata = os.stat(
                    RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT,
                    dir_fd=admin_fd,
                    follow_symlinks=False,
                )
                pending_metadata = os.stat(
                    RELEASE_WORKTREE_CACHE_SCOPE_PENDING,
                    dir_fd=admin_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise SecretMaterialReleaseBlock(
                    "release-worktree cache-scope publish state could not be inspected"
                ) from exc
            if (
                (final_metadata.st_dev, final_metadata.st_ino)
                != (pending_metadata.st_dev, pending_metadata.st_ino)
                or final_metadata.st_nlink != 2
                or pending_metadata.st_nlink != 2
            ):
                raise SecretMaterialReleaseBlock(
                    "release-worktree cache-scope publish state is contradictory"
                )
            linked_data, _ = _read_linked_scope_file(
                admin_fd,
                RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT,
                expected_owner=registered.owner,
                expected_links=2,
            )
            if linked_data != expected_data:
                raise SecretMaterialReleaseBlock(
                    "release-worktree cache-scope linked receipt is stale"
                )
            try:
                os.unlink(RELEASE_WORKTREE_CACHE_SCOPE_PENDING, dir_fd=admin_fd)
                os.fsync(admin_fd)
            except OSError as exc:
                raise SecretMaterialReleaseBlock(
                    "release-worktree cache-scope linked publish could not recover"
                ) from exc
            pending_exists = False

        if final_exists:
            final_data, _ = _read_scope_file(
                admin_fd,
                RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT,
                expected_owner=registered.owner,
            )
            if final_data != expected_data:
                raise SecretMaterialReleaseBlock(
                    "release-worktree cache-scope receipt is stale"
                )
            return

        if pending_exists:
            pending_data, pending_identity = _read_scope_file(
                admin_fd,
                RELEASE_WORKTREE_CACHE_SCOPE_PENDING,
                expected_owner=registered.owner,
            )
        else:
            _write_scope_pending(admin_fd, expected_data, registered.owner)
            pending_data, pending_identity = _read_scope_file(
                admin_fd,
                RELEASE_WORKTREE_CACHE_SCOPE_PENDING,
                expected_owner=registered.owner,
            )
        if pending_data != expected_data:
            raise SecretMaterialReleaseBlock(
                "release-worktree cache-scope pending receipt is stale"
            )
        _fsync_scope_pending(
            admin_fd,
            expected_owner=registered.owner,
            expected_identity=pending_identity,
            expected_size=len(expected_data),
        )

        try:
            os.link(
                RELEASE_WORKTREE_CACHE_SCOPE_PENDING,
                RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT,
                src_dir_fd=admin_fd,
                dst_dir_fd=admin_fd,
                follow_symlinks=False,
            )
            os.fsync(admin_fd)
            os.unlink(RELEASE_WORKTREE_CACHE_SCOPE_PENDING, dir_fd=admin_fd)
            os.fsync(admin_fd)
        except OSError as exc:
            raise SecretMaterialReleaseBlock(
                "release-worktree cache-scope receipt could not be published"
            ) from exc
        final_data, _ = _read_scope_file(
            admin_fd,
            RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT,
            expected_owner=registered.owner,
        )
        if final_data != expected_data:
            raise SecretMaterialReleaseBlock(
                "published release-worktree cache-scope receipt is stale"
            )
    finally:
        active_exception = sys.exception()
        cleanup_error: OSError | None = None
        if lock_fd is not None:
            if lock_acquired:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError as exc:
                    cleanup_error = exc
            try:
                os.close(lock_fd)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        try:
            os.close(admin_fd)
        except OSError as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if cleanup_error is not None and active_exception is None:
            raise SecretMaterialReleaseBlock(
                "release-worktree cache-scope enrollment cleanup failed"
            ) from cleanup_error


def _authorize_release_worktree_cache_scope(
    workspace_root: str | os.PathLike[str],
    build: str,
) -> Path:
    """Explicitly enroll one trusted detached worktree before cache writes."""
    if RELEASE_WORKTREE_BUILD_RE.fullmatch(build) is None:
        raise SecretMaterialReleaseBlock(
            "release-worktree cache-scope build is not five digits"
        )
    root = Path(workspace_root)
    try:
        if root.is_symlink():
            raise SecretMaterialReleaseBlock(
                "workspace root is a symlink during cache-scope enrollment"
            )
        canonical_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SecretMaterialReleaseBlock(
            "workspace root could not be resolved for cache-scope enrollment"
        ) from exc
    registered_targets = _registered_release_worktree_targets(
        canonical_root, require_scope_receipt=False
    )
    registered = registered_targets.get(build)
    if registered is None:
        raise SecretMaterialReleaseBlock(
            "release worktree is not an exact live detached Git registration"
        )
    if registered.receipt_data is not None:
        return registered.admin_path / RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT
    try:
        with os.scandir(registered.path / "target") as entries:
            target_has_entries = next(entries, None) is not None
    except OSError as exc:
        raise SecretMaterialReleaseBlock(
            "release-worktree target could not be checked before enrollment"
        ) from exc
    if target_has_entries:
        raise SecretMaterialReleaseBlock(
            "release-worktree target must be empty before cache-scope enrollment"
        )
    refreshed = _registered_release_worktree_targets(
        canonical_root, require_scope_receipt=False
    ).get(build)
    if refreshed is None:
        raise SecretMaterialReleaseBlock(
            "release worktree changed before cache-scope enrollment"
        )
    _publish_scope_receipt(refreshed)
    verified = _registered_release_worktree_targets(canonical_root).get(build)
    if verified is None or verified.receipt_data is None:
        raise SecretMaterialReleaseBlock(
            "release-worktree cache-scope enrollment did not verify"
        )
    return verified.admin_path / RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT


def authorize_release_worktree_cache_scope(
    workspace_root: str | os.PathLike[str],
    build: str,
) -> Path:
    """Serialize explicit enrollment within this process and across processes."""
    with _SCOPE_ENROLLMENT_LOCK:
        return _authorize_release_worktree_cache_scope(workspace_root, build)


def _require_current_release_worktree_identity(
    build: str,
    registered_release_targets: dict[str, _RegisteredReleaseWorktreeIdentity],
) -> _RegisteredReleaseWorktreeIdentity | None:
    registered = registered_release_targets.get(build)
    if registered is None:
        return None
    worktree = registered.path
    if worktree.name != build:
        raise SecretMaterialReleaseBlock(
            "registered release worktree build identity changed during the scan"
        )
    try:
        if worktree.resolve(strict=True) != worktree:
            raise SecretMaterialReleaseBlock(
                "registered release worktree path changed during the scan"
            )
    except (OSError, RuntimeError) as exc:
        raise SecretMaterialReleaseBlock(
            "registered release worktree path changed during the scan"
        ) from exc
    if registered.receipt is None or registered.receipt_data is None:
        raise SecretMaterialReleaseBlock(
            "registered release worktree lacks a cache-scope receipt"
        )
    try:
        if registered.admin_path.resolve(strict=True) != registered.admin_path:
            raise SecretMaterialReleaseBlock(
                "release-worktree administrative path changed during the scan"
            )
    except (OSError, RuntimeError) as exc:
        raise SecretMaterialReleaseBlock(
            "release-worktree administrative path changed during the scan"
        ) from exc
    admin_fd, current_admin = _open_verified_directory(
        registered.admin_path,
        expected_owner=registered.owner,
        label="release-worktree administrative entry",
    )
    try:
        current_receipt_data, current_receipt = _read_scope_file(
            admin_fd,
            RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT,
            expected_owner=registered.owner,
        )
        current_head, _ = _read_git_control_file(
            admin_fd, "HEAD", expected_owner=registered.owner
        )
    finally:
        os.close(admin_fd)
    if (
        current_admin != registered.admin
        or current_receipt != registered.receipt
        or current_receipt_data != registered.receipt_data
        or current_head != registered.head.encode("ascii") + b"\n"
    ):
        raise SecretMaterialReleaseBlock(
            "release-worktree administrative identity changed during the scan"
        )
    worktree_fd, current_worktree = _open_verified_directory(
        worktree,
        expected_owner=registered.owner,
        label="registered release worktree",
    )
    try:
        current_marker_data, current_marker = _read_git_control_file(
            worktree_fd, ".git", expected_owner=registered.owner
        )
        target_fd, current_target = _open_verified_directory(
            "target",
            expected_owner=registered.owner,
            label="registered release worktree target",
            dir_fd=worktree_fd,
        )
        os.close(target_fd)
    finally:
        os.close(worktree_fd)
    if (
        current_worktree != registered.worktree
        or current_marker != registered.marker
        or current_marker_data != registered.marker_data
        or current_target != registered.target
    ):
        raise SecretMaterialReleaseBlock(
            "registered release worktree identity changed during the scan"
        )
    return registered


def _managed_target_owner(
    root: Path,
    path: Path,
    current_identity: tuple[int, int],
    registered_release_targets: dict[str, _RegisteredReleaseWorktreeIdentity],
) -> int | None:
    """Return the authenticated owner when managed children may be pruned."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return None
    if parts == ("target",):
        try:
            return root.stat(follow_symlinks=False).st_uid
        except OSError as exc:
            raise SecretMaterialReleaseBlock(
                "workspace root owner could not be revalidated"
            ) from exc
    if not _is_release_worktree_target_parts(parts):
        return None
    registered = _require_current_release_worktree_identity(
        parts[2], registered_release_targets
    )
    if registered is None or registered.target != current_identity:
        return None
    return registered.owner


def _is_pruned_target(
    root: Path,
    path: Path,
    registered_release_targets: dict[str, _RegisteredReleaseWorktreeIdentity],
) -> bool:
    """Return whether a canonical in-workspace path is outside scan scope."""
    relative = path.relative_to(root)
    if any(part in PRUNE_DIR_NAMES for part in relative.parts):
        return True
    if (
        len(relative.parts) >= 2
        and relative.parts[0] == "target"
        and relative.parts[1] in MANAGED_TARGET_ROOTS
    ):
        return True
    if not (
        len(relative.parts) >= 5
        and _is_release_worktree_target_parts(relative.parts[:4])
        and relative.parts[4] in MANAGED_TARGET_ROOTS
    ):
        return False
    build = relative.parts[2]
    registered = _require_current_release_worktree_identity(
        build, registered_release_targets
    )
    return registered is not None


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

    Never opens or reads a candidate. Fails closed on an unavailable,
    symlinked, or unreadable workspace root, an untrustworthy live Git
    worktree registry, and any traversal error.
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

    registered_release_targets = _registered_release_worktree_targets(canonical_root)
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
                    managed_target_owner = _managed_target_owner(
                        root,
                        current,
                        current_identity,
                        registered_release_targets,
                    )
                    if (
                        managed_target_owner is not None
                        and entry.name in MANAGED_TARGET_ROOTS
                    ):
                        if not is_dir or is_symlink:
                            raise SecretMaterialReleaseBlock(
                                "managed target root is not a trustworthy real "
                                f"directory: {entry.path}"
                            )
                        try:
                            entry_metadata = entry.stat(follow_symlinks=False)
                            fresh_metadata = entry_path.stat(follow_symlinks=False)
                        except OSError as exc:
                            raise SecretMaterialReleaseBlock(
                                "managed target root identity could not be verified: "
                                f"{entry.path}"
                            ) from exc
                        if (
                            not stat.S_ISDIR(entry_metadata.st_mode)
                            or not stat.S_ISDIR(fresh_metadata.st_mode)
                            or entry_metadata.st_uid != managed_target_owner
                            or fresh_metadata.st_uid != managed_target_owner
                            or (
                                entry_metadata.st_dev,
                                entry_metadata.st_ino,
                                entry_metadata.st_mode,
                                entry_metadata.st_uid,
                            )
                            != (
                                fresh_metadata.st_dev,
                                fresh_metadata.st_ino,
                                fresh_metadata.st_mode,
                                fresh_metadata.st_uid,
                            )
                        ):
                            raise SecretMaterialReleaseBlock(
                                "managed target root changed or has an unsafe owner: "
                                f"{entry.path}"
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
                            if _is_pruned_target(
                                canonical_root,
                                resolved_target,
                                registered_release_targets,
                            ):
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
                        if _is_pruned_target(
                            canonical_root,
                            resolved_target,
                            registered_release_targets,
                        ):
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
            "only; never reads candidate contents), or explicitly enroll one "
            "trusted detached release worktree before managed-cache writes."
        )
    )
    parser.add_argument(
        "workspace_root",
        nargs="?",
        default=os.getcwd(),
        help="Absolute path to the repository workspace root to scan.",
    )
    parser.add_argument(
        "--authorize-release-worktree",
        metavar="BUILD",
        help=(
            "Explicitly publish the main-Git-admin cache-scope receipt for one "
            "live detached five-digit release worktree."
        ),
    )
    args = parser.parse_args(argv)

    try:
        if args.authorize_release_worktree:
            receipt = authorize_release_worktree_cache_scope(
                args.workspace_root,
                args.authorize_release_worktree,
            )
            print(f"release-worktree cache scope enrolled: {receipt}")
            return 0
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
