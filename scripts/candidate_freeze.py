#!/usr/bin/env python3
"""Durably freeze the one v0.4.0 GA candidate before any signing starts.

The builder owns the fixed ``ga-preflight`` tree.  This module validates and
binds every signing input, commits one exclusive consumption intent, and then
atomically promotes the complete tree to the fixed ``ga`` root.  It never runs
``codesign``, ``notarytool``, or any other signing command.

An intent that exists at either root means that the GA build is consumed.  A
fresh freeze never resumes such an intent implicitly.  ``recover_candidate`` is
the only continuation entry point after an interrupted or outcome-unknown
promotion.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
from typing import Any, Callable, Final

if __package__:
    from .macos_durability import full_fsync
    from .release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        ga_preflight_root,
        ga_root,
    )
    from .repository_source_identity import SourceIdentityError, current_identity
    from .release_signing_preflight import (
        SigningPreflightError,
        load_preflight_manifest,
        verify_live_custody_metadata,
        verify_live_profile_validity,
        verify_materialized_profiles,
    )
    from .release_signing_plan import SigningPlanError, validate_plan
    from .updater_key_possession_proof import (
        UpdaterKeyPossessionError,
        verify_possession_proof,
    )
    from .verify_release_build_allocations import (
        ReleaseBuildAllocationError,
        validate_contract as validate_allocation_contract,
    )
else:
    from macos_durability import full_fsync
    from release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_preflight_root, ga_root
    from repository_source_identity import SourceIdentityError, current_identity
    from release_signing_preflight import (
        SigningPreflightError,
        load_preflight_manifest,
        verify_live_custody_metadata,
        verify_live_profile_validity,
        verify_materialized_profiles,
    )
    from release_signing_plan import SigningPlanError, validate_plan
    from updater_key_possession_proof import (
        UpdaterKeyPossessionError,
        verify_possession_proof,
    )
    from verify_release_build_allocations import (
        ReleaseBuildAllocationError,
        validate_contract as validate_allocation_contract,
    )


DOCUMENT: Final = "cfm-candidate-freeze-intent-v3"
SCHEMA_VERSION: Final = 3
CONSUMPTION_STATE: Final = "candidate_frozen_consumed"
QUARANTINED_STATE: Final = "quarantined_outcome_unknown"
LEDGER_RELATIVE_PATH: Final = Path("docs/release/build-allocations-v040.json")
INTENT_RELATIVE_PATH: Final = Path("candidate-freeze/intent.json")
MAX_JSON_BYTES: Final = 4 * 1024 * 1024
MAX_TREE_ENTRIES: Final = 250_000
MAX_TREE_BYTES: Final = 16 * 1024 * 1024 * 1024
SHA256_RE: Final = re.compile(r"\A[0-9a-f]{64}\Z")
COMMIT_RE: Final = re.compile(r"\A[0-9a-f]{40}\Z")
COMPONENT_ID_RE: Final = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")

RENAME_EXCL: Final = 0x00000004
RENAME_NOFOLLOW_ANY: Final = 0x00000010
RENAME_FLAGS: Final = RENAME_EXCL | RENAME_NOFOLLOW_ANY

_REQUIRED_ROOT_ENTRIES: Final = frozenset(
    {
        "pre-sign",
        "native-products",
        "profiles",
        "entitlements",
        "product-input.json",
        "signing-plan.json",
    }
)
_POST_FREEZE_ROOT_ENTRIES: Final = frozenset(
    {
        "ga-acceptance",
        "packages",
        "prepackage",
        "publication",
        "signed",
        "signing-output",
        "stage-inputs",
        "transactions",
    }
)
_PROFILE_ENTRIES: Final = frozenset(
    {
        "host.plist",
        "host.provisionprofile",
        "packet-tunnel.plist",
        "packet-tunnel.provisionprofile",
        "proxy-agent.plist",
        "proxy-agent.provisionprofile",
        "signing-identities.txt",
        "signing-preflight.json",
        "updater-key-possession",
    }
)
_ENTITLEMENT_ENTRIES: Final = frozenset(
    {
        "GlobalAuthority.entitlements",
        "Host.release.xcent",
        "PacketTunnel.release.xcent",
        "ProxyAgent.release.xcent",
        "signing-order.json",
    }
)
_INTENT_FIELDS: Final = frozenset(
    {
        "allocation_ledger_sha256",
        "build_number",
        "consumption_state",
        "document",
        "entitlements_tree_sha256",
        "native_products_tree_sha256",
        "pre_sign_app_tree_sha256",
        "pre_sign_tree_sha256",
        "product_input_document_sha256",
        "product_input_sha256",
        "product_version",
        "profiles_tree_sha256",
        "release_source_sha256",
        "repository_commit",
        "schema_version",
        "signing_preflight_sha256",
        "signing_plan_sha256",
        "updater_embedded_public_key_sha256",
        "updater_key_possession_proof_sha256",
        "updater_tauri_config_sha256",
    }
)
_PRODUCT_INPUT_FIELDS: Final = frozenset(
    {"document", "product", "schema_version", "source", "toolchain"}
)
_PRODUCT_FIELDS: Final = frozenset({"build_number", "version"})
_SOURCE_FIELDS: Final = frozenset({"release_source_sha256", "repository_commit"})
_TOOLCHAIN_FIELDS: Final = frozenset(
    {
        "cargoWorkspaceSourcesTreeSha256",
        "goModuleCacheTreeSha256",
        "goToolchainTreeSha256",
        "goToolsTreeSha256",
        "nodeToolchainTreeSha256",
        "tauriToolchainTreeSha256",
        "toolchainSha256",
        "uiDependenciesTreeSha256",
        "xcodegenToolchainTreeSha256",
    }
)
_SIGNING_PLAN_FIELDS: Final = frozenset(
    {"components", "document", "order", "product", "schema_version"}
)
_SIGNING_COMPONENT_ORDER: Final = (
    "native-bridge",
    "global-authority",
    "proxy-agent",
    "packet-tunnel",
    "legacy-tombstone",
    "host",
)
_FRAMEWORK_SYMLINK_TARGETS: Final = {
    "CFWNativeBridge": "Versions/Current/CFWNativeBridge",
    "Headers": "Versions/Current/Headers",
    "Modules": "Versions/Current/Modules",
    "Resources": "Versions/Current/Resources",
    "Versions/Current": "A",
}
_PREFLIGHT_FRAMEWORK_PREFIXES: Final = frozenset(
    {
        ("native-products",),
        ("pre-sign", "Clash for Mac.app", "Contents", "Frameworks"),
    }
)


class CandidateFreezeError(RuntimeError):
    """The candidate cannot safely cross the freeze boundary."""

    def __init__(self, code: str, message: str, *, consumed: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.consumed = consumed


class CandidateAlreadyConsumed(CandidateFreezeError):
    """A durable intent exists, so only explicit recovery is permitted."""

    def __init__(self, message: str) -> None:
        super().__init__("candidate_already_consumed", message, consumed=True)


class CandidateFreezeQuarantined(CandidateFreezeError):
    """The build is consumed but its exact frozen state cannot be accepted."""

    def __init__(self, message: str) -> None:
        super().__init__("candidate_freeze_quarantined", message, consumed=True)
        self.state = QUARANTINED_STATE


class CandidateFreezeOutcomeUnknown(CandidateFreezeError):
    """A durable mutation may have completed; exact recovery is mandatory."""

    def __init__(self, message: str) -> None:
        super().__init__("candidate_freeze_outcome_unknown", message, consumed=True)
        self.state = QUARANTINED_STATE


@dataclass(frozen=True, slots=True)
class FrozenCandidate:
    root: Path
    intent_path: Path
    intent_sha256: str
    product_version: str
    build_number: str
    recovered: bool


@dataclass(frozen=True, slots=True)
class _TreeIdentity:
    sha256: str
    entry_count: int
    total_bytes: int


def _canonical_json(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise CandidateFreezeError(
            "noncanonical_json", "candidate-freeze value cannot be canonical JSON"
        ) from error
    return (encoded + "\n").encode("ascii")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CandidateFreezeError(
                "duplicate_json_key", f"candidate-freeze JSON repeats key {key!r}"
            )
        value[key] = item
    return value


def _reject_json_constant(token: str) -> Any:
    raise CandidateFreezeError(
        "invalid_json", f"candidate-freeze JSON contains non-finite constant {token}"
    )


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _required_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int:
        raise CandidateFreezeError(
            "filesystem_capability_unavailable",
            f"candidate freeze requires {name}",
        )
    return value


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | _required_open_flag("O_DIRECTORY")
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
    )


def _file_open_flags() -> int:
    return (
        os.O_RDONLY
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
    )


def _file_create_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
    )


def _require_canonical_repository(repository: Path) -> Path:
    repository = Path(repository)
    if not repository.is_absolute():
        raise CandidateFreezeError(
            "repository_path_invalid", "candidate-freeze repository must be absolute"
        )
    try:
        resolved = repository.resolve(strict=True)
        metadata = repository.lstat()
    except OSError as error:
        raise CandidateFreezeError(
            "repository_unavailable", "candidate-freeze repository is unavailable"
        ) from error
    if resolved != repository or not stat.S_ISDIR(metadata.st_mode) or repository.is_symlink():
        raise CandidateFreezeError(
            "repository_path_invalid", "candidate-freeze repository is not canonical"
        )
    if metadata.st_uid != os.geteuid():
        raise CandidateFreezeError(
            "repository_owner_invalid", "candidate-freeze repository has the wrong owner"
        )
    return repository


def _fixed_roots(repository: Path) -> tuple[Path, Path]:
    identity = ACTIVE_RELEASE_IDENTITY
    if (
        not isinstance(identity.product_version, str)
        or not isinstance(identity.ga_build, str)
        or identity.product_version != "0.4.0"
        or identity.ga_build != "40034"
    ):
        raise CandidateFreezeError(
            "active_release_identity_invalid",
            "candidate freeze requires the fixed v0.4.0 build 40034 identity",
        )
    base = repository / "target/candidates/0.4.0"
    preflight = ga_preflight_root(repository)
    frozen = ga_root(repository)
    if preflight != base / "ga-preflight/40034" or frozen != base / "ga/40034":
        raise CandidateFreezeError(
            "active_release_path_invalid",
            "candidate-freeze roots differ from the fixed active release identity",
        )
    return preflight, frozen


def _open_directory(path: Path) -> int:
    try:
        before = path.lstat()
    except OSError as error:
        raise CandidateFreezeError(
            "directory_unavailable", f"candidate-freeze directory is unavailable: {path}"
        ) from error
    if path.is_symlink() or not stat.S_ISDIR(before.st_mode):
        raise CandidateFreezeError(
            "unsafe_directory", f"candidate-freeze path is not a real directory: {path}"
        )
    if before.st_uid != os.geteuid():
        raise CandidateFreezeError(
            "unsafe_directory", f"candidate-freeze directory has the wrong owner: {path}"
        )
    try:
        descriptor = os.open(path, _directory_open_flags())
        opened = os.fstat(descriptor)
        rebound = path.stat(follow_symlinks=False)
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise CandidateFreezeError(
            "directory_unavailable", f"cannot securely open directory: {path}"
        ) from error
    if (
        _metadata_identity(before) != _metadata_identity(opened)
        or _metadata_identity(before) != _metadata_identity(rebound)
    ):
        os.close(descriptor)
        raise CandidateFreezeError(
            "directory_changed", f"candidate-freeze directory changed while opening: {path}"
        )
    return descriptor


def _read_regular_file(path: Path, *, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise CandidateFreezeError(
            "input_unavailable", f"candidate-freeze input is unavailable: {path}"
        ) from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or before.st_size > maximum
    ):
        raise CandidateFreezeError(
            "unsafe_input", f"candidate-freeze input is not one bounded regular file: {path}"
        )
    descriptor = -1
    try:
        descriptor = os.open(path, _file_open_flags())
        opened = os.fstat(descriptor)
        if _metadata_identity(before) != _metadata_identity(opened):
            raise CandidateFreezeError(
                "input_changed", f"candidate-freeze input changed while opening: {path}"
            )
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise CandidateFreezeError(
                    "input_changed", f"candidate-freeze input returned a short read: {path}"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CandidateFreezeError(
                "input_changed", f"candidate-freeze input grew while reading: {path}"
            )
        after = os.fstat(descriptor)
        rebound = path.stat(follow_symlinks=False)
        if (
            _metadata_identity(before) != _metadata_identity(after)
            or _metadata_identity(before) != _metadata_identity(rebound)
        ):
            raise CandidateFreezeError(
                "input_changed", f"candidate-freeze input changed while reading: {path}"
            )
        return b"".join(chunks)
    except OSError as error:
        raise CandidateFreezeError(
            "input_unavailable", f"cannot securely read candidate-freeze input: {path}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_canonical_json(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, maximum=MAX_JSON_BYTES)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except CandidateFreezeError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CandidateFreezeError(
            "invalid_json", f"{label} is not strict JSON"
        ) from error
    if type(value) is not dict or not value:
        raise CandidateFreezeError(
            "invalid_json", f"{label} must be a non-empty JSON object"
        )
    canonical = _canonical_json(value)
    if raw != canonical:
        raise CandidateFreezeError(
            "noncanonical_json", f"{label} is not canonical JSON"
        )
    return value, raw


def _require_safe_name(name: str, path: Path) -> None:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise CandidateFreezeError(
            "unsafe_tree_entry", f"candidate tree contains an unsafe name: {path}"
        )


def _framework_symlink_target(
    descriptor: int,
    name: str,
    child_relative: str,
    before: os.stat_result,
    allowed_prefixes: frozenset[tuple[str, ...]],
) -> str:
    parts = PurePosixPath(child_relative).parts
    try:
        framework_index = parts.index("CFWNativeBridge.framework")
    except ValueError as error:
        raise CandidateFreezeError(
            "symlink_forbidden",
            f"candidate tree contains an unapproved symlink: {child_relative}",
        ) from error
    prefix = parts[:framework_index]
    suffix = "/".join(parts[framework_index + 1 :])
    expected_target = _FRAMEWORK_SYMLINK_TARGETS.get(suffix)
    if prefix not in allowed_prefixes or expected_target is None:
        raise CandidateFreezeError(
            "symlink_forbidden",
            f"candidate tree contains an unapproved framework symlink: {child_relative}",
        )
    if before.st_nlink != 1:
        raise CandidateFreezeError(
            "symlink_forbidden",
            f"candidate framework symlink has multiple hard links: {child_relative}",
        )
    try:
        target = os.readlink(name, dir_fd=descriptor)
        rebound = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except OSError as error:
        raise CandidateFreezeError(
            "tree_unavailable",
            f"cannot read candidate framework symlink: {child_relative}",
        ) from error
    if (
        target != expected_target
        or _metadata_identity(before) != _metadata_identity(rebound)
    ):
        raise CandidateFreezeError(
            "symlink_forbidden",
            f"candidate framework symlink differs from the fixed layout: {child_relative}",
        )
    return target


def _tree_identity(root: Path, *, require_nonempty: bool = True) -> _TreeIdentity:
    root_descriptor = _open_directory(root)
    root_metadata = os.fstat(root_descriptor)
    root_device = root_metadata.st_dev
    records: list[dict[str, Any]] = [
        {
            "mode": f"{stat.S_IMODE(root_metadata.st_mode):04o}",
            "path": ".",
            "type": "directory",
        }
    ]
    seen_directories = {(root_metadata.st_dev, root_metadata.st_ino)}
    entry_count = 0
    total_bytes = 0
    framework_prefixes = {
        "Clash for Mac.app": frozenset({("Contents", "Frameworks")}),
        "native-products": frozenset({()}),
        "pre-sign": frozenset(
            {("Clash for Mac.app", "Contents", "Frameworks")}
        ),
    }.get(root.name, frozenset())

    def scan(descriptor: int, directory: Path, relative: str) -> None:
        nonlocal entry_count, total_bytes
        try:
            names = os.listdir(descriptor)
        except OSError as error:
            raise CandidateFreezeError(
                "tree_unavailable", f"cannot enumerate candidate tree: {directory}"
            ) from error
        if len(names) != len(set(names)):
            raise CandidateFreezeError(
                "duplicate_tree_entry", f"candidate tree repeats an entry: {directory}"
            )
        for name in sorted(names):
            child = directory / name
            _require_safe_name(name, child)
            child_relative = name if relative == "." else f"{relative}/{name}"
            try:
                before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise CandidateFreezeError(
                    "tree_unavailable", f"cannot inspect candidate tree entry: {child}"
                ) from error
            if before.st_uid != os.geteuid() or before.st_dev != root_device:
                raise CandidateFreezeError(
                    "unsafe_tree_entry", f"candidate tree entry has unsafe ownership or device: {child}"
                )
            entry_count += 1
            if entry_count > MAX_TREE_ENTRIES:
                raise CandidateFreezeError(
                    "tree_too_large", "candidate tree contains too many entries"
                )
            entry_type = stat.S_IFMT(before.st_mode)
            if entry_type == stat.S_IFLNK:
                target = _framework_symlink_target(
                    descriptor,
                    name,
                    child_relative,
                    before,
                    framework_prefixes,
                )
                total_bytes += len(os.fsencode(target))
                if total_bytes > MAX_TREE_BYTES:
                    raise CandidateFreezeError(
                        "tree_too_large", "candidate tree contains too many bytes"
                    )
                records.append(
                    {
                        "path": child_relative,
                        "target": target,
                        "type": "symlink",
                    }
                )
                continue
            if entry_type == stat.S_IFDIR:
                directory_identity = (before.st_dev, before.st_ino)
                if directory_identity in seen_directories:
                    raise CandidateFreezeError(
                        "directory_alias_forbidden", f"candidate tree repeats a directory inode: {child}"
                    )
                seen_directories.add(directory_identity)
                child_descriptor = -1
                try:
                    child_descriptor = os.open(
                        name, _directory_open_flags(), dir_fd=descriptor
                    )
                    opened = os.fstat(child_descriptor)
                    if _metadata_identity(before) != _metadata_identity(opened):
                        raise CandidateFreezeError(
                            "tree_changed", f"candidate directory changed while opening: {child}"
                        )
                    records.append(
                        {
                            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
                            "path": child_relative,
                            "type": "directory",
                        }
                    )
                    scan(child_descriptor, child, child_relative)
                    rebound = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if _metadata_identity(before) != _metadata_identity(rebound):
                        raise CandidateFreezeError(
                            "tree_changed", f"candidate directory changed while reading: {child}"
                        )
                except OSError as error:
                    raise CandidateFreezeError(
                        "tree_unavailable", f"cannot securely open candidate directory: {child}"
                    ) from error
                finally:
                    if child_descriptor >= 0:
                        os.close(child_descriptor)
                continue
            if entry_type != stat.S_IFREG:
                raise CandidateFreezeError(
                    "special_file_forbidden", f"candidate tree contains a special file: {child}"
                )
            if before.st_nlink != 1:
                raise CandidateFreezeError(
                    "hardlink_forbidden", f"candidate tree contains a hard-linked file: {child}"
                )
            file_descriptor = -1
            try:
                file_descriptor = os.open(name, _file_open_flags(), dir_fd=descriptor)
                opened = os.fstat(file_descriptor)
                if _metadata_identity(before) != _metadata_identity(opened):
                    raise CandidateFreezeError(
                        "tree_changed", f"candidate file changed while opening: {child}"
                    )
                digest = hashlib.sha256()
                remaining = before.st_size
                while remaining:
                    chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
                    if not chunk:
                        raise CandidateFreezeError(
                            "tree_changed", f"candidate file returned a short read: {child}"
                        )
                    digest.update(chunk)
                    remaining -= len(chunk)
                if os.read(file_descriptor, 1):
                    raise CandidateFreezeError(
                        "tree_changed", f"candidate file grew while reading: {child}"
                    )
                after = os.fstat(file_descriptor)
                rebound = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (
                    _metadata_identity(before) != _metadata_identity(after)
                    or _metadata_identity(before) != _metadata_identity(rebound)
                ):
                    raise CandidateFreezeError(
                        "tree_changed", f"candidate file changed while reading: {child}"
                    )
                total_bytes += before.st_size
                if total_bytes > MAX_TREE_BYTES:
                    raise CandidateFreezeError(
                        "tree_too_large", "candidate tree contains too many file bytes"
                    )
                records.append(
                    {
                        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
                        "path": child_relative,
                        "sha256": digest.hexdigest(),
                        "size": before.st_size,
                        "type": "file",
                    }
                )
            except OSError as error:
                raise CandidateFreezeError(
                    "tree_unavailable", f"cannot securely read candidate file: {child}"
                ) from error
            finally:
                if file_descriptor >= 0:
                    os.close(file_descriptor)

    try:
        scan(root_descriptor, root, ".")
        after = os.fstat(root_descriptor)
        rebound = root.stat(follow_symlinks=False)
        if (
            _metadata_identity(root_metadata) != _metadata_identity(after)
            or _metadata_identity(root_metadata) != _metadata_identity(rebound)
        ):
            raise CandidateFreezeError(
                "tree_changed", f"candidate tree root changed while reading: {root}"
            )
    finally:
        os.close(root_descriptor)
    if require_nonempty and entry_count == 0:
        raise CandidateFreezeError(
            "empty_tree", f"candidate-freeze tree must not be empty: {root}"
        )
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: str(item["path"])):
        digest.update(_canonical_json(record))
    return _TreeIdentity(digest.hexdigest(), entry_count, total_bytes)


def _validate_root_layout(root: Path, *, require_intent: bool) -> None:
    descriptor = _open_directory(root)
    try:
        names = os.listdir(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise CandidateFreezeError(
            "candidate_root_unavailable", f"cannot enumerate candidate root: {root}"
        ) from error
    finally:
        if "names" in locals():
            os.close(descriptor)
    actual = set(names)
    allowed = set(_REQUIRED_ROOT_ENTRIES) | {"candidate-freeze"}
    if root.parent.name == "ga":
        allowed.update(_POST_FREEZE_ROOT_ENTRIES)
    if not _REQUIRED_ROOT_ENTRIES.issubset(actual) or not actual.issubset(allowed):
        raise CandidateFreezeError(
            "candidate_root_layout_invalid",
            f"candidate root entries differ from the fixed freeze layout: {root}",
        )
    for name in sorted(actual & _POST_FREEZE_ROOT_ENTRIES):
        descriptor = _open_directory(root / name)
        os.close(descriptor)
    claim = root / "candidate-freeze"
    if "candidate-freeze" not in actual:
        if require_intent:
            raise CandidateFreezeQuarantined("candidate-freeze intent directory is absent")
        return
    claim_descriptor = _open_directory(claim)
    try:
        if stat.S_IMODE(os.fstat(claim_descriptor).st_mode) != 0o700:
            raise CandidateFreezeQuarantined(
                "candidate-freeze intent directory mode is not 0700"
            )
        claim_names = os.listdir(claim_descriptor)
    except OSError as error:
        raise CandidateFreezeError(
            "candidate_claim_unavailable", "cannot enumerate candidate-freeze intent directory"
        ) from error
    finally:
        os.close(claim_descriptor)
    expected = {"intent.json"} if require_intent else set()
    if set(claim_names) not in (expected, {"intent.json"}):
        raise CandidateFreezeQuarantined(
            "candidate-freeze intent directory contains an unexpected entry"
        )
    if require_intent and set(claim_names) != expected:
        raise CandidateFreezeQuarantined("candidate-freeze intent is absent")


def _require_exact_private_material_directory(
    path: Path,
    expected: frozenset[str],
    *,
    directory_names: frozenset[str] = frozenset(),
) -> None:
    descriptor = _open_directory(path)
    try:
        metadata = os.fstat(descriptor)
        names = os.listdir(descriptor)
    except OSError as error:
        raise CandidateFreezeError(
            "signing_material_layout_invalid",
            f"cannot enumerate signing material directory: {path}",
        ) from error
    finally:
        os.close(descriptor)
    if "signing-preflight.json" in expected and "signing-preflight.json" not in names:
        raise CandidateFreezeError(
            "signing_material_layout_invalid",
            f"signing preflight is absent from the fixed private layout: {path}",
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700 or set(names) != set(expected):
        raise CandidateFreezeError(
            "signing_material_layout_invalid",
            f"signing material directory differs from the fixed private layout: {path}",
        )
    for name in sorted(expected):
        child = path / name
        if name in directory_names:
            child_descriptor = _open_directory(child)
            try:
                if stat.S_IMODE(os.fstat(child_descriptor).st_mode) != 0o700:
                    raise CandidateFreezeError(
                        "signing_material_layout_invalid",
                        f"signing material directory mode is not 0700: {child}",
                    )
            finally:
                os.close(child_descriptor)
            continue
        _read_regular_file(child, maximum=MAX_JSON_BYTES)


def _validate_signing_material_layout(root: Path) -> None:
    _require_exact_private_material_directory(
        root / "profiles",
        _PROFILE_ENTRIES,
        directory_names=frozenset({"updater-key-possession"}),
    )
    _require_exact_private_material_directory(
        root / "entitlements",
        _ENTITLEMENT_ENTRIES,
    )


def _read_source_identity(repository: Path) -> dict[str, str]:
    try:
        value = current_identity(repository, require_clean=True)
    except (OSError, SourceIdentityError) as error:
        raise CandidateFreezeError(
            "source_identity_unavailable",
            "candidate freeze requires one clean release source identity",
        ) from error
    if (
        type(value) is not dict
        or set(value) != {"repositoryCommit", "releaseSourceSha256"}
        or not isinstance(value.get("repositoryCommit"), str)
        or not COMMIT_RE.fullmatch(value["repositoryCommit"])
        or not isinstance(value.get("releaseSourceSha256"), str)
        or not SHA256_RE.fullmatch(value["releaseSourceSha256"])
    ):
        raise CandidateFreezeError(
            "source_identity_invalid", "release source identity is malformed"
        )
    return value


def _require_exact_fields(
    value: Any, expected: frozenset[str], *, label: str
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise CandidateFreezeError(
            "document_schema_invalid", f"{label} has missing or unknown fields"
        )
    return value


def _validate_product(
    value: Any, *, label: str
) -> dict[str, Any]:
    product = _require_exact_fields(value, _PRODUCT_FIELDS, label=label)
    if (
        product["version"] != ACTIVE_RELEASE_IDENTITY.product_version
        or product["build_number"] != ACTIVE_RELEASE_IDENTITY.ga_build
    ):
        raise CandidateFreezeError(
            "product_identity_invalid", f"{label} differs from the active GA identity"
        )
    return product


def _validate_product_input(
    value: dict[str, Any], source_identity: dict[str, str]
) -> None:
    document = _require_exact_fields(
        value, _PRODUCT_INPUT_FIELDS, label="candidate product input"
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["document"] != "cfm-ga-product-input-v1"
    ):
        raise CandidateFreezeError(
            "product_input_schema_invalid",
            "candidate product input has the wrong schema identity",
        )
    _validate_product(document["product"], label="candidate product input product")
    source = _require_exact_fields(
        document["source"], _SOURCE_FIELDS, label="candidate product input source"
    )
    expected_source = {
        "repository_commit": source_identity["repositoryCommit"],
        "release_source_sha256": source_identity["releaseSourceSha256"],
    }
    if source != expected_source:
        raise CandidateFreezeError(
            "product_input_source_mismatch",
            "candidate product input source differs from the clean repository identity",
        )
    toolchain = _require_exact_fields(
        document["toolchain"],
        _TOOLCHAIN_FIELDS,
        label="candidate product input toolchain",
    )
    for field, digest in toolchain.items():
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise CandidateFreezeError(
                "product_input_toolchain_invalid",
                f"candidate product input toolchain {field} is not a SHA-256 digest",
            )


def _validate_signing_plan(value: dict[str, Any]) -> None:
    document = _require_exact_fields(
        value, _SIGNING_PLAN_FIELDS, label="candidate signing plan"
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["document"] != "cfm-ga-signing-plan-v1"
    ):
        raise CandidateFreezeError(
            "signing_plan_schema_invalid",
            "candidate signing plan has the wrong schema identity",
        )
    _validate_product(document["product"], label="candidate signing plan product")
    components = document["components"]
    order = document["order"]
    if (
        type(components) is not dict
        or set(components) != set(_SIGNING_COMPONENT_ORDER)
    ):
        raise CandidateFreezeError(
            "signing_plan_components_invalid",
            "candidate signing plan components do not match the fixed native product graph",
        )
    for component, digest in components.items():
        if (
            not isinstance(component, str)
            or not COMPONENT_ID_RE.fullmatch(component)
            or not isinstance(digest, str)
            or not SHA256_RE.fullmatch(digest)
        ):
            raise CandidateFreezeError(
                "signing_plan_components_invalid",
                "candidate signing plan component IDs and digests are malformed",
            )
    if (
        type(order) is not list
        or tuple(order) != _SIGNING_COMPONENT_ORDER
    ):
        raise CandidateFreezeError(
            "signing_plan_order_invalid",
            "candidate signing plan order differs from the fixed inside-out order",
        )


def _expected_intent(repository: Path, root: Path, *, require_intent: bool) -> dict[str, Any]:
    _validate_root_layout(root, require_intent=require_intent)
    _validate_signing_material_layout(root)
    source_identity = _read_source_identity(repository)
    product_input, product_input_raw = _read_canonical_json(
        root / "product-input.json", label="candidate product input"
    )
    _validate_product_input(product_input, source_identity)
    signing_plan, signing_plan_raw = _read_canonical_json(
        root / "signing-plan.json", label="candidate signing plan"
    )
    _validate_signing_plan(signing_plan)
    try:
        validate_plan(repository, root, signing_plan)
    except SigningPlanError as error:
        raise CandidateFreezeError(
            "signing_plan_material_mismatch",
            "candidate signing plan does not bind the exact frozen signing inputs",
        ) from error
    signing_preflight_path = root / "profiles/signing-preflight.json"
    try:
        load_preflight_manifest(signing_preflight_path)
    except SigningPreflightError as error:
        raise CandidateFreezeError(
            "signing_preflight_receipt_invalid",
            f"candidate signing-preflight receipt is invalid: {error}",
        ) from error
    try:
        verify_materialized_profiles(
            signing_preflight_path,
            {
                "host": root / "profiles/host.provisionprofile",
                "packet-tunnel": root / "profiles/packet-tunnel.provisionprofile",
                "proxy-agent": root / "profiles/proxy-agent.provisionprofile",
            },
        )
    except SigningPreflightError as error:
        raise CandidateFreezeError(
            "materialized_profile_mismatch",
            f"candidate provisioning profiles differ from the preflight receipt: {error}",
        ) from error
    try:
        updater_possession = verify_possession_proof(repository, root)
    except UpdaterKeyPossessionError as error:
        raise CandidateFreezeError(
            "updater_key_possession_invalid",
            "candidate freeze requires a live updater-key possession proof for the embedded public key",
        ) from error
    signing_preflight_raw = _read_regular_file(
        signing_preflight_path,
        maximum=MAX_JSON_BYTES,
    )
    ledger, ledger_raw = _read_canonical_json(
        repository / LEDGER_RELATIVE_PATH, label="release build allocation ledger"
    )
    try:
        validate_allocation_contract(
            ledger, expected_ga=ACTIVE_RELEASE_IDENTITY.ga_build
        )
    except ReleaseBuildAllocationError as error:
        raise CandidateFreezeError(
            "allocation_ledger_invalid",
            "release build allocation ledger is incompatible with the active GA identity",
        ) from error
    pre_sign = _tree_identity(root / "pre-sign")
    app = _tree_identity(root / "pre-sign/Clash for Mac.app")
    native = _tree_identity(root / "native-products")
    profiles = _tree_identity(root / "profiles")
    entitlements = _tree_identity(root / "entitlements")
    product_input_document_sha256 = hashlib.sha256(product_input_raw).hexdigest()
    semantic_product_input = {
        "document_sha256": product_input_document_sha256,
        "entitlements_tree_sha256": entitlements.sha256,
        "profiles_tree_sha256": profiles.sha256,
    }
    product_input_sha256 = hashlib.sha256(
        _canonical_json(semantic_product_input)
    ).hexdigest()
    return {
        "allocation_ledger_sha256": hashlib.sha256(ledger_raw).hexdigest(),
        "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
        "consumption_state": CONSUMPTION_STATE,
        "document": DOCUMENT,
        "entitlements_tree_sha256": entitlements.sha256,
        "native_products_tree_sha256": native.sha256,
        "pre_sign_app_tree_sha256": app.sha256,
        "pre_sign_tree_sha256": pre_sign.sha256,
        "product_input_document_sha256": product_input_document_sha256,
        "product_input_sha256": product_input_sha256,
        "product_version": ACTIVE_RELEASE_IDENTITY.product_version,
        "profiles_tree_sha256": profiles.sha256,
        "release_source_sha256": source_identity["releaseSourceSha256"],
        "repository_commit": source_identity["repositoryCommit"],
        "schema_version": SCHEMA_VERSION,
        "signing_preflight_sha256": hashlib.sha256(
            signing_preflight_raw
        ).hexdigest(),
        "signing_plan_sha256": hashlib.sha256(signing_plan_raw).hexdigest(),
        "updater_embedded_public_key_sha256": (
            updater_possession.embedded_public_key_sha256
        ),
        "updater_key_possession_proof_sha256": updater_possession.proof_sha256,
        "updater_tauri_config_sha256": updater_possession.tauri_config_sha256,
    }


def _validate_intent(value: dict[str, Any]) -> None:
    if set(value) != _INTENT_FIELDS:
        raise CandidateFreezeQuarantined(
            "candidate-freeze intent has missing or unknown fields"
        )
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise CandidateFreezeQuarantined("candidate-freeze intent schema is invalid")
    exact = {
        "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
        "consumption_state": CONSUMPTION_STATE,
        "document": DOCUMENT,
        "product_version": ACTIVE_RELEASE_IDENTITY.product_version,
    }
    for field, expected in exact.items():
        if value[field] != expected:
            raise CandidateFreezeQuarantined(
                f"candidate-freeze intent {field} differs from the active release"
            )
    for field in _INTENT_FIELDS - set(exact) - {"schema_version", "repository_commit"}:
        if not isinstance(value[field], str) or not SHA256_RE.fullmatch(value[field]):
            raise CandidateFreezeQuarantined(
                f"candidate-freeze intent {field} is not a SHA-256 digest"
            )
    if (
        not isinstance(value["repository_commit"], str)
        or not COMMIT_RE.fullmatch(value["repository_commit"])
    ):
        raise CandidateFreezeQuarantined(
            "candidate-freeze intent repository commit is malformed"
        )


def _load_intent(root: Path) -> tuple[dict[str, Any], bytes]:
    intent_path = root / INTENT_RELATIVE_PATH
    try:
        intent_metadata = intent_path.lstat()
    except OSError as error:
        raise CandidateFreezeQuarantined(
            "candidate-freeze intent is unavailable"
        ) from error
    if stat.S_IMODE(intent_metadata.st_mode) != 0o600:
        raise CandidateFreezeQuarantined(
            "candidate-freeze intent mode is not 0600"
        )
    try:
        value, raw = _read_canonical_json(
            intent_path, label="candidate-freeze intent"
        )
        _validate_intent(value)
    except CandidateFreezeQuarantined:
        raise
    except CandidateFreezeError as error:
        raise CandidateFreezeQuarantined(
            f"candidate-freeze intent cannot be trusted: {error}"
        ) from error
    return value, raw


def _ensure_claim_directory(root: Path) -> Path:
    claim = root / "candidate-freeze"
    try:
        os.mkdir(claim, 0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise CandidateFreezeError(
            "claim_directory_unavailable", "cannot create candidate-freeze intent directory"
        ) from error
    descriptor = _open_directory(claim)
    try:
        metadata = os.fstat(descriptor)
        names = os.listdir(descriptor)
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise CandidateFreezeError(
                "claim_directory_unsafe", "candidate-freeze intent directory mode is not 0700"
            )
        if names and set(names) != {"intent.json"}:
            raise CandidateFreezeQuarantined(
                "candidate-freeze intent directory contains unexpected entries"
            )
    finally:
        os.close(descriptor)
    return claim


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "candidate-freeze intent write made no progress")
        offset += written


_stable_sync: Callable[[int], None] = full_fsync


def _sync_directory(path: Path) -> None:
    descriptor = _open_directory(path)
    try:
        _stable_sync(descriptor)
    except OSError as error:
        raise CandidateFreezeError(
            "directory_durability_unknown",
            f"candidate-freeze directory durability is unknown: {path}",
        ) from error
    finally:
        os.close(descriptor)


def _create_intent(root: Path, intent: dict[str, Any]) -> bytes:
    claim = _ensure_claim_directory(root)
    path = claim / "intent.json"
    raw = _canonical_json(intent)
    descriptor = -1
    opened = False
    try:
        descriptor = os.open(path, _file_create_flags(), 0o600)
        opened = True
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, raw)
        _stable_sync(descriptor)
    except FileExistsError as error:
        try:
            existing, _existing_raw = _load_intent(root)
        except CandidateFreezeError as validation_error:
            raise CandidateFreezeQuarantined(
                "an existing candidate-freeze intent cannot be validated"
            ) from validation_error
        if existing != intent:
            raise CandidateFreezeQuarantined(
                "an existing candidate-freeze intent binds different inputs"
            ) from error
        raise CandidateAlreadyConsumed(
            "candidate-freeze intent already exists; use explicit recovery"
        ) from error
    except (OSError, CandidateFreezeError) as error:
        if opened or os.path.lexists(path):
            raise CandidateFreezeOutcomeUnknown(
                "candidate-freeze intent write outcome is unknown; the build is consumed"
            ) from error
        raise CandidateFreezeError(
            "intent_create_failed", "cannot create candidate-freeze intent"
        ) from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                raise CandidateFreezeOutcomeUnknown(
                    "candidate-freeze intent close outcome is unknown; the build is consumed"
                ) from error
    try:
        _sync_directory(claim)
        _sync_directory(root)
    except CandidateFreezeError as error:
        raise CandidateFreezeOutcomeUnknown(
            "candidate-freeze intent parent durability is unknown; the build is consumed"
        ) from error
    return raw


def _sync_tree(root: Path) -> None:
    descriptor = _open_directory(root)

    def sync_directory(
        descriptor_to_sync: int, directory: Path, relative: str
    ) -> None:
        try:
            names = os.listdir(descriptor_to_sync)
        except OSError as error:
            raise CandidateFreezeError(
                "tree_durability_unknown", f"cannot enumerate tree for fsync: {directory}"
            ) from error
        for name in sorted(names):
            child = directory / name
            before = os.stat(name, dir_fd=descriptor_to_sync, follow_symlinks=False)
            child_relative = name if relative == "." else f"{relative}/{name}"
            if stat.S_ISDIR(before.st_mode):
                child_descriptor = os.open(
                    name, _directory_open_flags(), dir_fd=descriptor_to_sync
                )
                try:
                    if _metadata_identity(before) != _metadata_identity(
                        os.fstat(child_descriptor)
                    ):
                        raise CandidateFreezeError(
                            "tree_changed", f"candidate directory changed before fsync: {child}"
                        )
                    sync_directory(child_descriptor, child, child_relative)
                finally:
                    os.close(child_descriptor)
            elif stat.S_ISLNK(before.st_mode):
                _framework_symlink_target(
                    descriptor_to_sync,
                    name,
                    child_relative,
                    before,
                    _PREFLIGHT_FRAMEWORK_PREFIXES,
                )
            elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
                file_descriptor = os.open(name, _file_open_flags(), dir_fd=descriptor_to_sync)
                try:
                    if _metadata_identity(before) != _metadata_identity(
                        os.fstat(file_descriptor)
                    ):
                        raise CandidateFreezeError(
                            "tree_changed", f"candidate file changed before fsync: {child}"
                        )
                    _stable_sync(file_descriptor)
                    rebound = os.stat(name, dir_fd=descriptor_to_sync, follow_symlinks=False)
                    if _metadata_identity(before) != _metadata_identity(rebound):
                        raise CandidateFreezeError(
                            "tree_changed", f"candidate file changed during fsync: {child}"
                        )
                finally:
                    os.close(file_descriptor)
            else:
                raise CandidateFreezeError(
                    "unsafe_tree_entry", f"candidate tree became unsafe before fsync: {child}"
                )
        try:
            _stable_sync(descriptor_to_sync)
        except OSError as error:
            raise CandidateFreezeError(
                "tree_durability_unknown",
                f"candidate tree directory durability is unknown: {directory}",
            ) from error

    try:
        sync_directory(descriptor, root, ".")
    except OSError as error:
        raise CandidateFreezeError(
            "tree_durability_unknown", f"candidate tree durability is unknown: {root}"
        ) from error
    finally:
        os.close(descriptor)


def _ensure_destination_parent(final_root: Path) -> None:
    candidate_base = final_root.parent.parent
    _open_and_close_directory(candidate_base)
    try:
        os.mkdir(final_root.parent, 0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise CandidateFreezeError(
            "destination_parent_unavailable", "cannot create fixed GA candidate parent"
        ) from error
    descriptor = _open_directory(final_root.parent)
    try:
        if stat.S_IMODE(os.fstat(descriptor).st_mode) & 0o022:
            raise CandidateFreezeError(
                "destination_parent_unsafe", "fixed GA candidate parent is group/world writable"
            )
    finally:
        os.close(descriptor)
    _sync_directory(candidate_base)


def _open_and_close_directory(path: Path) -> None:
    descriptor = _open_directory(path)
    os.close(descriptor)


def _rename_exclusive(source: Path, destination: Path) -> None:
    source_parent = _open_directory(source.parent)
    destination_parent = _open_directory(destination.parent)
    try:
        try:
            rename = ctypes.CDLL(None, use_errno=True).renameatx_np
        except AttributeError as error:
            raise CandidateFreezeError(
                "rename_exclusive_unavailable",
                "candidate freeze requires macOS renameatx_np",
            ) from error
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(
            source_parent,
            os.fsencode(source.name),
            destination_parent,
            os.fsencode(destination.name),
            RENAME_FLAGS,
        )
        if result != 0:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number), str(destination))
    finally:
        os.close(destination_parent)
        os.close(source_parent)


def _sync_publish_parents(preflight_root: Path, final_root: Path) -> None:
    _sync_directory(final_root)
    _sync_directory(preflight_root.parent)
    _sync_directory(final_root.parent)


def _require_only_one_root(preflight_root: Path, final_root: Path) -> str:
    preflight_exists = os.path.lexists(preflight_root)
    final_exists = os.path.lexists(final_root)
    if preflight_exists and final_exists:
        raise CandidateFreezeQuarantined(
            "both candidate preflight and frozen roots exist"
        )
    if final_exists:
        return "final"
    if preflight_exists:
        return "preflight"
    raise CandidateFreezeError(
        "candidate_missing", "neither fixed candidate preflight nor frozen root exists"
    )


def _receipt(root: Path, intent_raw: bytes, *, recovered: bool) -> FrozenCandidate:
    return FrozenCandidate(
        root=root,
        intent_path=root / INTENT_RELATIVE_PATH,
        intent_sha256=hashlib.sha256(intent_raw).hexdigest(),
        product_version=ACTIVE_RELEASE_IDENTITY.product_version,
        build_number=ACTIVE_RELEASE_IDENTITY.ga_build,
        recovered=recovered,
    )


def _verify_exact_intent(repository: Path, root: Path) -> bytes:
    value, raw = _load_intent(root)
    try:
        expected = _expected_intent(repository, root, require_intent=True)
    except CandidateFreezeQuarantined:
        raise
    except CandidateFreezeError as error:
        raise CandidateFreezeQuarantined(
            "consumed candidate inputs cannot be reopened exactly"
        ) from error
    if value != expected:
        raise CandidateFreezeQuarantined(
            "candidate-freeze intent differs from current exact source or pre-sign inputs"
        )
    return raw


def freeze_candidate(repository: Path) -> FrozenCandidate:
    """Consume and atomically freeze the one active GA candidate.

    This fresh entry point refuses every existing intent.  Use
    :func:`recover_candidate` after any interrupted attempt.
    """

    repository = _require_canonical_repository(repository)
    preflight_root, final_root = _fixed_roots(repository)
    state = _require_only_one_root(preflight_root, final_root)
    if state == "final":
        raise CandidateAlreadyConsumed(
            "the frozen GA candidate already exists; fresh freeze is forbidden"
        )
    expected = _expected_intent(repository, preflight_root, require_intent=False)
    signing_preflight_path = preflight_root / "profiles/signing-preflight.json"
    try:
        verify_live_profile_validity(signing_preflight_path)
    except SigningPreflightError as error:
        raise CandidateFreezeError(
            "signing_profile_readiness_invalid",
            f"candidate provisioning profiles are not currently signable: {error}",
        ) from error
    try:
        verify_live_custody_metadata(
            signing_preflight_path,
            repository=repository,
        )
    except SigningPreflightError as error:
        raise CandidateFreezeError(
            "signing_custody_readiness_invalid",
            f"candidate updater custody is not currently ready: {error}",
        ) from error
    _ensure_destination_parent(final_root)
    try:
        intent_raw = _create_intent(preflight_root, expected)
    except CandidateAlreadyConsumed:
        if os.path.lexists(final_root) and not os.path.lexists(preflight_root):
            raise CandidateAlreadyConsumed(
                "another freezer published the GA candidate; fresh freeze is forbidden"
            ) from None
        raise
    observed = _expected_intent(repository, preflight_root, require_intent=True)
    if observed != expected:
        raise CandidateFreezeQuarantined(
            "candidate source or pre-sign inputs changed after intent consumption"
        )
    try:
        _sync_tree(preflight_root)
    except CandidateFreezeError as error:
        raise CandidateFreezeOutcomeUnknown(
            "candidate preflight durability is unknown after intent consumption"
        ) from error
    try:
        _rename_exclusive(preflight_root, final_root)
    except OSError as error:
        if error.errno == errno.EEXIST:
            raise CandidateFreezeQuarantined(
                "fixed GA destination already exists after intent consumption"
            ) from error
        raise CandidateFreezeOutcomeUnknown(
            "candidate promotion result is unknown; explicit recovery is required"
        ) from error
    except CandidateFreezeError as error:
        raise CandidateFreezeOutcomeUnknown(
            "candidate promotion result is unknown; explicit recovery is required"
        ) from error
    try:
        if _verify_exact_intent(repository, final_root) != intent_raw:
            raise CandidateFreezeQuarantined(
                "promoted candidate intent bytes changed during publication"
            )
        _sync_tree(final_root)
        _sync_publish_parents(preflight_root, final_root)
        if os.path.lexists(preflight_root):
            raise CandidateFreezeQuarantined(
                "candidate preflight root remained after exclusive promotion"
            )
        verified_raw = _verify_exact_intent(repository, final_root)
    except CandidateFreezeQuarantined:
        raise
    except CandidateFreezeError as error:
        raise CandidateFreezeOutcomeUnknown(
            "candidate publication durability is unknown; explicit recovery is required"
        ) from error
    return _receipt(final_root, verified_raw, recovered=False)


def recover_candidate(repository: Path) -> FrozenCandidate:
    """Recover exactly one consumed candidate without replacing or re-signing it."""

    repository = _require_canonical_repository(repository)
    preflight_root, final_root = _fixed_roots(repository)
    state = _require_only_one_root(preflight_root, final_root)
    root = final_root if state == "final" else preflight_root
    intent_raw = _verify_exact_intent(repository, root)
    if state == "preflight":
        _ensure_destination_parent(final_root)
        try:
            _sync_tree(preflight_root)
            _rename_exclusive(preflight_root, final_root)
        except (OSError, CandidateFreezeError) as error:
            raise CandidateFreezeOutcomeUnknown(
                "candidate recovery promotion result is unknown"
            ) from error
    try:
        if _verify_exact_intent(repository, final_root) != intent_raw:
            raise CandidateFreezeQuarantined(
                "recovered candidate intent bytes differ from the consumed intent"
            )
        _sync_tree(final_root)
        _sync_publish_parents(preflight_root, final_root)
        if os.path.lexists(preflight_root):
            raise CandidateFreezeQuarantined(
                "candidate preflight root remained after recovery"
            )
        verified_raw = _verify_exact_intent(repository, final_root)
    except CandidateFreezeQuarantined:
        raise
    except CandidateFreezeError as error:
        raise CandidateFreezeOutcomeUnknown(
            "candidate recovery durability remains unknown"
        ) from error
    return _receipt(final_root, verified_raw, recovered=True)


def verify_frozen_candidate(repository: Path) -> FrozenCandidate:
    """Reopen and verify the exact frozen candidate without mutating it."""

    repository = _require_canonical_repository(repository)
    preflight_root, final_root = _fixed_roots(repository)
    state = _require_only_one_root(preflight_root, final_root)
    if state != "final":
        raise CandidateFreezeQuarantined(
            "candidate-freeze intent exists only in the unpublished preflight root"
        )
    raw = _verify_exact_intent(repository, final_root)
    return _receipt(final_root, raw, recovered=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("freeze", "recover", "verify"))
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "freeze":
            result = freeze_candidate(repository)
        elif arguments.command == "recover":
            result = recover_candidate(repository)
        else:
            result = verify_frozen_candidate(repository)
    except CandidateFreezeError as error:
        raise SystemExit(f"error: candidate freeze [{error.code}]: {error}") from error
    print(
        f"candidate freeze verified: {result.product_version}/{result.build_number} "
        f"intent_sha256={result.intent_sha256}"
    )


if __name__ == "__main__":
    main()
