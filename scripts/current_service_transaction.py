#!/usr/bin/env python3
"""Crash-safe current-service maintenance around the fixed dormant install.

The transaction controls only the current ProxyAgent and GlobalAuthority
SMAppServices through the signed candidate Host.  It never addresses the
one-way legacy tombstone and never signals or mutates Clash for Windows.  Each
completed mutation is recorded as a new, canonical, fsynced event whose CFW
guard proves the existing network lifeline did not change.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable, Final, Iterator
import uuid

if __package__:
    from . import dormant_app_install as install
    from . import ga_acceptance_environment as ga_environment
    from .release_build_identity import ACTIVE_RELEASE_IDENTITY
else:
    import dormant_app_install as install
    import ga_acceptance_environment as ga_environment
    from release_build_identity import ACTIVE_RELEASE_IDENTITY


DOCUMENT: Final = "cfw-current-service-transaction-v3"
SCHEMA_VERSION: Final = 3
if (
    DOCUMENT != install.SERVICE_TRANSACTION_DOCUMENT
    or SCHEMA_VERSION != install.SERVICE_TRANSACTION_SCHEMA_VERSION
):
    raise RuntimeError("service transaction contract differs from installer binding")
TRANSACTION_DIRECTORY: Final = (
    install.GA_INSTALL_PROFILE.service_transaction_directory
)
PENDING_DIRECTORY: Final = (
    install.GA_INSTALL_PROFILE.service_pending_directory
)
LOCK_NAME: Final = install.GA_INSTALL_PROFILE.service_lock_name
INTENT_NAME: Final = "intent.json"
ENVIRONMENT_NAME: Final = "environment.json"
RETIRED_TRANSACTION_NAMES: Final = install.RETIRED_SERVICE_TRANSACTION_NAMES
EVENT_PREFIX: Final = "event-"
PENDING_EVENT_PREFIX: Final = ".event-"
PENDING_EVENT_SUFFIX: Final = ".pending"
AUTHORITY_RECOVERY_INTENT_NAME: Final = install.AUTHORITY_RECOVERY_INTENT_NAME
AUTHORITY_RECOVERY_PENDING_INTENT_NAME: Final = (
    install.AUTHORITY_RECOVERY_PENDING_INTENT_NAME
)
AUTHORITY_RECOVERY_INTENT_DOCUMENT: Final = (
    install.AUTHORITY_RECOVERY_INTENT_DOCUMENT
)
AUTHORITY_RECOVERY_INTENT_SCHEMA_VERSION: Final = (
    install.AUTHORITY_RECOVERY_INTENT_SCHEMA_VERSION
)
if (
    install.INSTALLED_40019_RECOVERY_ACTION
    != "recover-installed-40019-global-authority"
    or AUTHORITY_RECOVERY_INTENT_DOCUMENT
    != "cfw-current-service-authority-recovery-intent-v1"
):
    raise RuntimeError("Authority recovery contract differs from installer binding")
MAX_DOCUMENT_BYTES: Final = 1024 * 1024
MAX_EVENTS: Final = 16
POLL_INTERVAL_SECONDS: Final = 0.1
POLL_ATTEMPTS: Final = 100
PROC_PIDPATH_BUFFER_SIZE: Final = 4096

PHASES: Final = (
    "prepared",
    "proxy_unregistered",
    "authority_unregistered",
    "decommissioned",
    "authority_registered",
    "proxy_registered",
    "recommissioned",
)
ACTIONS: Final = install.GA_INSTALL_PROFILE.service_actions
if ACTIONS != (
    "prepare",
    "unregister-installed-40019-proxy-agent",
    "unregister-installed-40019-global-authority",
    "verify-dormant",
    "register-global-authority",
    "register-proxy-agent",
    "prove-off",
):
    raise RuntimeError("service maintenance profile actions differ from fixed transaction")
if (
    install.VERSION != ACTIVE_RELEASE_IDENTITY.product_version
    or install.GA_INSTALL_PROFILE.build_number != ACTIVE_RELEASE_IDENTITY.ga_build
    or install.GA_INSTALL_PROFILE.previous_build_number != "40019"
):
    raise RuntimeError("service maintenance profile differs from active GA identity")
PROXY_DOMAIN_TEMPLATE: Final = "gui/{uid}/com.bill.clashformac.proxy-agent"
AUTHORITY_DOMAIN: Final = "system/com.bill.clashformac.global-authority"
TOMBSTONE_DOMAIN: Final = "system/com.bill.clashformac.helper"
PROXY_PROGRAM: Final = (
    "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
)
AUTHORITY_PROGRAM: Final = "Contents/Library/HelperTools/CFWGlobalAuthority"
PROXY_PROCESS_SUFFIX: Final = f"/Contents/Library/LoginItems/{PROXY_PROGRAM.split('/', 3)[-1]}"
AUTHORITY_PROCESS_SUFFIX: Final = f"/Contents/Library/HelperTools/CFWGlobalAuthority"
HOST_PROCESS_SUFFIX: Final = "/Contents/MacOS/clash-for-mac"
TUNNEL_PROCESS_SUFFIX: Final = "/Contents/MacOS/CFWPacketTunnel"


@dataclass(frozen=True)
class ServicePaths:
    install_paths: install.InstallPaths
    transaction_parent: Path

    @classmethod
    def production(cls) -> "ServicePaths":
        return cls(
            install_paths=install.InstallPaths.production(),
            transaction_parent=Path("/Applications"),
        )

    @property
    def transaction_directory(self) -> Path:
        return (
            self.transaction_parent
            / self.install_paths.profile.service_transaction_directory
        )

    @property
    def pending_directory(self) -> Path:
        return (
            self.transaction_parent
            / self.install_paths.profile.service_pending_directory
        )

    @property
    def transaction_directory_name(self) -> str:
        return self.install_paths.profile.service_transaction_directory

    @property
    def pending_directory_name(self) -> str:
        return self.install_paths.profile.service_pending_directory

    @property
    def lock_name(self) -> str:
        return self.install_paths.profile.service_lock_name

    @property
    def target_executable(self) -> Path:
        return self.install_paths.target_app / "Contents/MacOS/clash-for-mac"


@dataclass(frozen=True)
class ServiceRuntime:
    runner: install.CommandRunner
    observe_environment: ga_environment.EnvironmentObserver

    @classmethod
    def production(cls) -> "ServiceRuntime":
        return cls(
            runner=install.production_command_runner,
            observe_environment=ga_environment.observe_environment,
        )

    def capture_guard(self) -> dict[str, Any]:
        return install.capture_cfw_guard(self.runner, require_cfm_absent=False)


@dataclass(frozen=True)
class ServiceJournalFileSnapshot:
    """One stable private service-journal file read under the service lock."""

    name: str
    data: bytes
    metadata: os.stat_result


@dataclass(frozen=True)
class TerminalServiceJournalSnapshot:
    """The exact validated recommissioned service transaction tree."""

    environment: dict[str, Any]
    intent: dict[str, Any]
    events: tuple[dict[str, Any], ...]
    files: tuple[ServiceJournalFileSnapshot, ...]
    directory_metadata: os.stat_result


def _canonical_json(value: object) -> bytes:
    return install._canonical_json(value)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _journal_metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _strict_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    if not data or len(data) > MAX_DOCUMENT_BYTES:
        raise install.InstallError("service_journal_invalid", f"{label} size is invalid")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=install._reject_duplicate_keys,
            parse_constant=install._reject_nonfinite_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise install.InstallError(
            "service_journal_invalid", f"{label} is not strict JSON"
        ) from error
    if not isinstance(value, dict):
        raise install.InstallError(
            "service_journal_invalid", f"{label} is not canonical JSON"
        )
    try:
        encoded = _canonical_json(value)
    except RecursionError as error:
        raise install.InstallError(
            "service_journal_invalid", f"{label} is not canonical JSON"
        ) from error
    if data != encoded:
        raise install.InstallError(
            "service_journal_invalid", f"{label} is not canonical JSON"
        )
    return value


def _validate_app(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "build_number",
        "tree_sha256",
        "version",
    }:
        raise install.InstallError("service_journal_invalid", f"{label} shape is invalid")
    if (
        value.get("version") != install.VERSION
        or not isinstance(value.get("build_number"), str)
        or re.fullmatch(r"[1-9][0-9]*", value["build_number"]) is None
        or not isinstance(value.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["tree_sha256"]) is None
    ):
        raise install.InstallError(
            "service_journal_invalid", f"{label} identity is invalid"
        )
    return value


def _validate_candidate(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "build_number",
        "manifest_sha256",
        "release_source_sha256",
        "repository_commit",
        "tree_sha256",
        "version",
    }:
        raise install.InstallError(
            "service_journal_invalid", "candidate identity shape is invalid"
        )
    _validate_app(
        {key: value[key] for key in ("build_number", "tree_sha256", "version")},
        "candidate",
    )
    for key in ("manifest_sha256", "release_source_sha256"):
        if not isinstance(value[key], str) or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None:
            raise install.InstallError(
                "service_journal_invalid", f"candidate {key} is invalid"
            )
    if not isinstance(value["repository_commit"], str) or re.fullmatch(
        r"[0-9a-f]{40}", value["repository_commit"]
    ) is None:
        raise install.InstallError(
            "service_journal_invalid", "candidate repository commit is invalid"
        )
    return value


def validate_intent(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "candidate",
        "document",
        "ga_environment_sha256",
        "off_proof_profile",
        "previous",
        "schema_version",
        "transaction_id",
    }:
        raise install.InstallError("service_journal_invalid", "service intent shape is invalid")
    if (
        value["document"] != DOCUMENT
        or type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
    ):
        raise install.InstallError("service_journal_invalid", "service intent schema is invalid")
    if (
        not isinstance(value["ga_environment_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["ga_environment_sha256"]) is None
    ):
        raise install.InstallError(
            "service_journal_invalid", "service intent GA environment digest is invalid"
        )
    if not isinstance(value["off_proof_profile"], str) or value[
        "off_proof_profile"
    ] not in {
        install.INSTALLED_40019_OFF_PROOF_PROFILE,
        install.CURRENT_OFF_PROOF_PROFILE,
    }:
        raise install.InstallError(
            "service_journal_invalid", "service intent proof profile is invalid"
        )
    try:
        canonical_id = str(uuid.UUID(value["transaction_id"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise install.InstallError(
            "service_journal_invalid", "service transaction id is invalid"
        ) from error
    if canonical_id != value["transaction_id"]:
        raise install.InstallError(
            "service_journal_invalid", "service transaction id is not canonical"
        )
    candidate = _validate_candidate(value["candidate"])
    previous = _validate_app(value["previous"], "previous application")
    if int(candidate["build_number"]) <= int(previous["build_number"]):
        raise install.InstallError(
            "service_journal_invalid", "service candidate is not newer than previous"
        )
    return value


def validate_event(
    value: object,
    *,
    expected_sequence: int,
    previous_event_sha256: str | None,
    expected_guard: dict[str, Any] | None,
    intent_sha256: str,
    expected_actions: frozenset[str],
    expected_off_proof_profiles: frozenset[str],
) -> dict[str, Any]:
    if type(expected_sequence) is not int or not 0 <= expected_sequence < len(PHASES):
        raise install.InstallError(
            "service_journal_invalid", "service event sequence is out of range"
        )
    if not isinstance(value, dict) or set(value) != {
        "action",
        "document",
        "guard_after",
        "guard_before",
        "intent_sha256",
        "off_proof_profile",
        "phase",
        "previous_event_sha256",
        "schema_version",
        "sequence",
    }:
        raise install.InstallError("service_journal_invalid", "service event shape is invalid")
    if (
        value["document"] != DOCUMENT
        or type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
        or type(value["sequence"]) is not int
        or value["sequence"] != expected_sequence
        or value["phase"] != PHASES[expected_sequence]
        or value["previous_event_sha256"] != previous_event_sha256
        or value["intent_sha256"] != intent_sha256
        or not isinstance(value["action"], str)
        or value["action"] not in expected_actions
        or not isinstance(value["off_proof_profile"], str)
        or value["off_proof_profile"] not in expected_off_proof_profiles
    ):
        raise install.InstallError(
            "service_journal_invalid", "service event lineage is invalid"
        )
    before = install._validate_guard(value["guard_before"])
    after = install._validate_guard(value["guard_after"])
    if before != after:
        raise install.InstallError(
            "service_journal_invalid", "service event records CFW guard drift"
        )
    if expected_guard is not None and before != expected_guard:
        raise install.InstallError(
            "service_journal_invalid",
            "service event CFW guard differs from the transaction baseline",
        )
    return value


def validate_authority_recovery_intent(
    value: object,
    *,
    intent: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "action",
        "document",
        "guard",
        "intent_sha256",
        "off_proof_profile",
        "previous_event_sha256",
        "schema_version",
        "sequence",
        "transaction_id",
    }:
        raise install.InstallError(
            "service_journal_invalid",
            "Authority recovery intent shape is invalid",
        )
    if len(events) < 2 or events[1]["phase"] != "proxy_unregistered":
        raise install.InstallError(
            "service_journal_invalid",
            "Authority recovery intent has no proxy-unregistered boundary",
        )
    guard = install._validate_guard(value["guard"])
    if (
        value["document"] != AUTHORITY_RECOVERY_INTENT_DOCUMENT
        or type(value["schema_version"]) is not int
        or value["schema_version"] != AUTHORITY_RECOVERY_INTENT_SCHEMA_VERSION
        or value["action"] != install.INSTALLED_40019_RECOVERY_ACTION
        or value["off_proof_profile"]
        != install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
        or type(value["sequence"]) is not int
        or value["sequence"] != 2
        or value["transaction_id"] != intent["transaction_id"]
        or value["intent_sha256"] != events[0]["intent_sha256"]
        or value["previous_event_sha256"]
        != _sha256(_canonical_json(events[1]))
        or guard != events[0]["guard_after"]
    ):
        raise install.InstallError(
            "service_journal_invalid",
            "Authority recovery intent lineage is invalid",
        )
    return value


def validate_terminal_snapshot_files(
    files: dict[str, bytes],
    profile: install.InstallProfile = install.GA_INSTALL_PROFILE,
) -> tuple[dict[str, Any], dict[str, Any], tuple[dict[str, Any], ...]]:
    """Validate exact canonical bytes from one recommissioned service tree."""

    if not isinstance(files, dict) or any(
        type(name) is not str or not isinstance(data, bytes)
        for name, data in files.items()
    ):
        raise install.InstallError(
            "service_journal_invalid",
            "service snapshot file map is invalid",
        )
    event_names = tuple(
        f"{EVENT_PREFIX}{sequence:08d}.json" for sequence in range(len(PHASES))
    )
    authority_recovery_prepared = AUTHORITY_RECOVERY_INTENT_NAME in files
    expected_names = {
        ENVIRONMENT_NAME,
        INTENT_NAME,
        *event_names,
        *(
            {AUTHORITY_RECOVERY_INTENT_NAME}
            if authority_recovery_prepared
            else set()
        ),
    }
    if set(files) != expected_names:
        raise install.InstallError(
            "service_journal_invalid",
            "terminal service snapshot inventory is invalid",
        )
    intent = validate_intent(_strict_json_bytes(files[INTENT_NAME], "service intent"))
    if (
        intent["candidate"]["build_number"] != profile.build_number
        or intent["previous"]["build_number"] != profile.previous_build_number
        or intent["off_proof_profile"] != profile.off_proof_profile
    ):
        raise install.InstallError(
            "service_journal_invalid",
            "service snapshot is not for the fixed GA identity",
        )
    try:
        environment = ga_environment.validate_environment(
            _strict_json_bytes(
                files[ENVIRONMENT_NAME],
                "GA environment identity",
            )
        )
    except ga_environment.GAAcceptanceEnvironmentError as error:
        raise install.InstallError(
            "service_journal_invalid",
            "service GA environment identity is invalid",
        ) from error
    if (
        ga_environment.environment_sha256(environment)
        != intent["ga_environment_sha256"]
    ):
        raise install.InstallError(
            "service_journal_invalid",
            "service intent does not bind its GA environment identity",
        )

    intent_sha256 = _sha256(files[INTENT_NAME])
    previous_event_sha256: str | None = None
    baseline_guard: dict[str, Any] | None = None
    events: list[dict[str, Any]] = []
    for sequence, name in enumerate(event_names):
        allowed_actions, allowed_profiles = profile.service_event_contract(
            sequence,
            authority_recovery_prepared=authority_recovery_prepared,
        )
        event = validate_event(
            _strict_json_bytes(files[name], f"service event {sequence}"),
            expected_sequence=sequence,
            previous_event_sha256=previous_event_sha256,
            expected_guard=baseline_guard,
            intent_sha256=intent_sha256,
            expected_actions=allowed_actions,
            expected_off_proof_profiles=allowed_profiles,
        )
        events.append(event)
        if baseline_guard is None:
            baseline_guard = event["guard_after"]
        previous_event_sha256 = _sha256(files[name])
    if events[-1]["phase"] != "recommissioned":
        raise install.InstallError(
            "service_journal_not_terminal",
            "service transaction is not at the recommissioned phase",
        )
    if authority_recovery_prepared:
        validate_authority_recovery_intent(
            _strict_json_bytes(
                files[AUTHORITY_RECOVERY_INTENT_NAME],
                "Authority recovery intent",
            ),
            intent=intent,
            events=events,
        )
    return environment, intent, tuple(events)


class ServiceEventStore:
    def __init__(self, paths: ServicePaths) -> None:
        self.paths = paths
        self.parent_fd = install._open_directory(paths.transaction_parent)

    def close(self) -> None:
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1

    def __enter__(self) -> "ServiceEventStore":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def _require_profile_intent(self, intent: dict[str, Any]) -> None:
        profile = self.paths.install_paths.profile
        if (
            intent["candidate"]["build_number"] != profile.build_number
            or intent["previous"]["build_number"]
            != profile.previous_build_number
            or intent["off_proof_profile"] != profile.off_proof_profile
        ):
            raise install.InstallError(
                "service_journal_invalid",
                "service intent is not for the fixed GA identity",
            )

    def _reject_retired_namespace(self) -> None:
        install.require_retired_service_transaction_names_absent(self.parent_fd)

    @contextmanager
    def locked(self, *, require_existing: bool = False) -> Iterator[None]:
        self._reject_retired_namespace()
        with install.exclusive_release_maintenance_lock(
            self.paths.transaction_parent,
            require_existing=require_existing,
        ):
            self._reject_retired_namespace()
            flags = (
                (os.O_RDONLY if require_existing else os.O_RDWR | os.O_CREAT)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(
                    self.paths.lock_name,
                    flags,
                    0o600,
                    dir_fd=self.parent_fd,
                )
            except OSError as error:
                raise install.InstallError(
                    "service_lock_unavailable", "cannot open service transaction lock"
                ) from error
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise install.InstallError(
                        "service_lock_unsafe", "service transaction lock is unsafe"
                    )
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    raise install.InstallError(
                        "service_transaction_busy",
                        "another service transaction is active",
                    ) from error
                self._require_path_identity(
                    descriptor, self.paths.lock_name, "service transaction lock"
                )
                try:
                    yield
                finally:
                    self._require_path_identity(
                        descriptor,
                        self.paths.lock_name,
                        "service transaction lock",
                    )
            finally:
                os.close(descriptor)

    def _require_path_identity(self, descriptor: int, name: str, label: str) -> None:
        opened = os.fstat(descriptor)
        try:
            visible = os.stat(name, dir_fd=self.parent_fd, follow_symlinks=False)
        except OSError as error:
            raise install.InstallError(
                "service_path_identity_drift", f"{label} path is unavailable"
            ) from error
        if (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino):
            raise install.InstallError(
                "service_path_identity_drift", f"{label} path was rebound"
            )

    def _open_transaction_directory(self, name: str | None = None) -> int:
        directory_name = name or self.paths.transaction_directory_name
        try:
            descriptor = os.open(
                directory_name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self.parent_fd,
            )
        except FileNotFoundError:
            raise
        except OSError as error:
            raise install.InstallError(
                "service_journal_unavailable", "cannot open service transaction directory"
            ) from error
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise install.InstallError(
                "service_journal_unsafe", "service transaction directory is unsafe"
            )
        self._require_path_identity(
            descriptor,
            directory_name,
            "service transaction directory",
        )
        return descriptor

    @staticmethod
    def _write_new(directory_fd: int, name: str, value: object) -> bytes:
        data = _canonical_json(value)
        if len(data) > MAX_DOCUMENT_BYTES:
            raise install.InstallError(
                "service_journal_invalid", "service transaction document is oversized"
            )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        except OSError as error:
            raise install.InstallError(
                "service_journal_exists", "service transaction event already exists"
            ) from error
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise install.InstallError(
                        "service_journal_write_failed", "service event write was short"
                    )
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        install._fsync_directory_fd(directory_fd)
        return data

    @staticmethod
    def _read(
        directory_fd: int,
        name: str,
        label: str,
        *,
        allow_empty: bool = False,
        sync_before_return: bool = False,
    ) -> bytes:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except OSError as error:
            raise install.InstallError(
                "service_journal_unavailable", f"cannot open {label}"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or (metadata.st_size <= 0 and not allow_empty)
                or metadata.st_size > MAX_DOCUMENT_BYTES
            ):
                raise install.InstallError(
                    "service_journal_unsafe", f"{label} file is unsafe"
                )
            try:
                visible = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise install.InstallError(
                    "service_journal_identity_drift", f"{label} path is unavailable"
                ) from error
            if (metadata.st_dev, metadata.st_ino) != (visible.st_dev, visible.st_ino):
                raise install.InstallError(
                    "service_journal_identity_drift", f"{label} path was rebound"
                )
            data = install._read_fd_bytes(descriptor, MAX_DOCUMENT_BYTES)
            if sync_before_return:
                os.fsync(descriptor)
            after = os.fstat(descriptor)
            try:
                visible_after = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
            except OSError as error:
                raise install.InstallError(
                    "service_journal_identity_drift", f"{label} path disappeared"
                ) from error
        finally:
            os.close(descriptor)
        if (metadata.st_size, metadata.st_mtime_ns) != (
            after.st_size,
            after.st_mtime_ns,
        ) or (after.st_dev, after.st_ino) != (
            visible_after.st_dev,
            visible_after.st_ino,
        ):
            raise install.InstallError(
                "service_journal_identity_drift", f"{label} changed while reading"
            )
        return data

    @staticmethod
    def _publish_pending_event(directory_fd: int, source: str, target: str) -> None:
        library = ctypes.CDLL(None, use_errno=True)
        rename = library.renameatx_np
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        if (
            rename(
                directory_fd,
                os.fsencode(source),
                directory_fd,
                os.fsencode(target),
                install.RENAME_EXCL | install.RENAME_NOFOLLOW_ANY,
            )
            != 0
        ):
            raise install.InstallError(
                "service_journal_publish_failed", "cannot publish service event"
            )
        install._fsync_directory_fd(directory_fd)

    @staticmethod
    def _discard_incomplete_pending_event(directory_fd: int, name: str) -> None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        except OSError as error:
            raise install.InstallError(
                "service_journal_identity_drift", "pending service event disappeared"
            ) from error
        try:
            opened = os.fstat(descriptor)
            visible = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
            ):
                raise install.InstallError(
                    "service_journal_unsafe", "pending service event is unsafe"
                )
            os.unlink(name, dir_fd=directory_fd)
        finally:
            os.close(descriptor)
        install._fsync_directory_fd(directory_fd)

    def _discard_incomplete_initial_transaction(self) -> None:
        directory_fd = self._open_transaction_directory(
            self.paths.pending_directory_name
        )
        try:
            names = os.listdir(directory_fd)
            allowed = {
                ENVIRONMENT_NAME,
                INTENT_NAME,
                f"{EVENT_PREFIX}00000000.json",
            }
            if not set(names) <= allowed:
                raise install.InstallError(
                    "service_journal_unsafe",
                    "incomplete initial service transaction has unexpected entries",
                )
            for name in names:
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    descriptor = os.open(name, flags, dir_fd=directory_fd)
                except OSError as error:
                    raise install.InstallError(
                        "service_journal_identity_drift",
                        "incomplete initial service document disappeared",
                    ) from error
                try:
                    opened = os.fstat(descriptor)
                    visible = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or opened.st_nlink != 1
                        or opened.st_uid != os.geteuid()
                        or stat.S_IMODE(opened.st_mode) != 0o600
                        or (opened.st_dev, opened.st_ino)
                        != (visible.st_dev, visible.st_ino)
                    ):
                        raise install.InstallError(
                            "service_journal_unsafe",
                            "incomplete initial service document is unsafe",
                        )
                    os.unlink(name, dir_fd=directory_fd)
                finally:
                    os.close(descriptor)
            install._fsync_directory_fd(directory_fd)
            self._require_path_identity(
                directory_fd,
                self.paths.pending_directory_name,
                "pending service transaction directory",
            )
        finally:
            os.close(directory_fd)
        try:
            os.rmdir(self.paths.pending_directory_name, dir_fd=self.parent_fd)
        except OSError as error:
            raise install.InstallError(
                "service_journal_identity_drift",
                "cannot remove incomplete initial service transaction",
            ) from error
        install._fsync_directory_fd(self.parent_fd)

    def _event_contract(
        self,
        sequence: int,
        *,
        authority_recovery_prepared: bool,
    ) -> tuple[frozenset[str], frozenset[str]]:
        return self.paths.install_paths.profile.service_event_contract(
            sequence,
            authority_recovery_prepared=authority_recovery_prepared,
        )

    def _read_authority_recovery_intent(
        self,
        directory_fd: int,
        intent: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if AUTHORITY_RECOVERY_INTENT_NAME not in os.listdir(directory_fd):
            return None
        if self.paths.install_paths.profile.unregister_authority_action != (
            "unregister-installed-40019-global-authority"
        ):
            raise install.InstallError(
                "service_journal_invalid",
                "Authority recovery intent is outside the fixed GA install profile",
            )
        return validate_authority_recovery_intent(
            _strict_json_bytes(
                self._read(
                    directory_fd,
                    AUTHORITY_RECOVERY_INTENT_NAME,
                    "Authority recovery intent",
                ),
                "Authority recovery intent",
            ),
            intent=intent,
            events=events,
        )

    def authority_recovery_prepared(
        self,
        intent: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> bool:
        directory_fd = self._open_transaction_directory()
        try:
            return (
                self._read_authority_recovery_intent(
                    directory_fd, intent, events
                )
                is not None
            )
        finally:
            os.close(directory_fd)

    def prepare_authority_recovery(
        self,
        intent: dict[str, Any],
        events: list[dict[str, Any]],
        guard: dict[str, Any],
    ) -> dict[str, Any]:
        if (
            self.paths.install_paths.profile.unregister_authority_action
            != "unregister-installed-40019-global-authority"
            or len(events) != 2
            or events[-1]["phase"] != "proxy_unregistered"
            or guard != events[0]["guard_after"]
        ):
            raise install.InstallError(
                "service_journal_transition_invalid",
                "Authority recovery intent is outside its fixed boundary",
            )
        directory_fd = self._open_transaction_directory()
        try:
            existing = self._read_authority_recovery_intent(
                directory_fd, intent, events
            )
            if existing is not None:
                return existing
            value = validate_authority_recovery_intent(
                {
                    "action": install.INSTALLED_40019_RECOVERY_ACTION,
                    "document": AUTHORITY_RECOVERY_INTENT_DOCUMENT,
                    "guard": guard,
                    "intent_sha256": events[0]["intent_sha256"],
                    "off_proof_profile": (
                        install.INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
                    ),
                    "previous_event_sha256": _sha256(
                        _canonical_json(events[1])
                    ),
                    "schema_version": AUTHORITY_RECOVERY_INTENT_SCHEMA_VERSION,
                    "sequence": 2,
                    "transaction_id": intent["transaction_id"],
                },
                intent=intent,
                events=events,
            )
            if (
                AUTHORITY_RECOVERY_PENDING_INTENT_NAME
                in os.listdir(directory_fd)
            ):
                raise install.InstallError(
                    "service_journal_pending",
                    "pending Authority recovery intent requires load recovery",
                )
            self._write_new(
                directory_fd,
                AUTHORITY_RECOVERY_PENDING_INTENT_NAME,
                value,
            )
            validate_authority_recovery_intent(
                _strict_json_bytes(
                    self._read(
                        directory_fd,
                        AUTHORITY_RECOVERY_PENDING_INTENT_NAME,
                        "pending Authority recovery intent",
                    ),
                    "pending Authority recovery intent",
                ),
                intent=intent,
                events=events,
            )
            self._publish_pending_event(
                directory_fd,
                AUTHORITY_RECOVERY_PENDING_INTENT_NAME,
                AUTHORITY_RECOVERY_INTENT_NAME,
            )
            published = self._read_authority_recovery_intent(
                directory_fd, intent, events
            )
            if published is None:
                raise install.InstallError(
                    "service_journal_identity_drift",
                    "published Authority recovery intent disappeared",
                )
            return published
        finally:
            os.close(directory_fd)

    def create(
        self,
        candidate: install.CandidateIdentity,
        previous: install.AppIdentity,
        guard: dict[str, Any],
        environment: object,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        self._reject_retired_namespace()
        if self.paths.transaction_directory.exists() or self.paths.transaction_directory.is_symlink():
            raise install.InstallError(
                "service_journal_exists", "service transaction already exists"
            )
        if self.paths.pending_directory.exists() or self.paths.pending_directory.is_symlink():
            raise install.InstallError(
                "service_journal_pending", "pending service transaction requires recovery"
            )
        try:
            os.mkdir(
                self.paths.pending_directory_name,
                0o700,
                dir_fd=self.parent_fd,
            )
        except OSError as error:
            raise install.InstallError(
                "service_journal_create_failed", "cannot create pending service transaction"
            ) from error
        pending_fd = self._open_transaction_directory(
            self.paths.pending_directory_name
        )
        try:
            try:
                normalized_environment = ga_environment.validate_environment(
                    environment
                )
                environment_sha256 = ga_environment.environment_sha256(
                    normalized_environment
                )
            except ga_environment.GAAcceptanceEnvironmentError as error:
                raise install.InstallError(
                    "service_environment_invalid",
                    "service transaction GA environment is invalid",
                ) from error
            intent = validate_intent(
                {
                    "candidate": candidate.document(),
                    "document": DOCUMENT,
                    "ga_environment_sha256": environment_sha256,
                    "off_proof_profile": (
                        self.paths.install_paths.profile.service_event_proof_profiles[0]
                    ),
                    "previous": previous.document(),
                    "schema_version": SCHEMA_VERSION,
                    "transaction_id": str(uuid.uuid4()),
                }
            )
            self._require_profile_intent(intent)
            intent_sha256 = _sha256(_canonical_json(intent))
            self._write_new(pending_fd, ENVIRONMENT_NAME, normalized_environment)
            self._write_new(pending_fd, INTENT_NAME, intent)
            event = validate_event(
                {
                    "action": "prepare",
                    "document": DOCUMENT,
                    "guard_after": guard,
                    "guard_before": guard,
                    "intent_sha256": intent_sha256,
                    "off_proof_profile": self.paths.install_paths.profile.off_proof_profile,
                    "phase": "prepared",
                    "previous_event_sha256": None,
                    "schema_version": SCHEMA_VERSION,
                    "sequence": 0,
                },
                expected_sequence=0,
                previous_event_sha256=None,
                expected_guard=guard,
                intent_sha256=intent_sha256,
                expected_actions=(
                    self.paths.install_paths.profile.service_event_allowed_actions[0]
                ),
                expected_off_proof_profiles=(
                    self.paths.install_paths.profile.service_event_allowed_proof_profiles[0]
                ),
            )
            self._write_new(pending_fd, f"{EVENT_PREFIX}00000000.json", event)
            install._fsync_directory_fd(pending_fd)
        finally:
            os.close(pending_fd)
        library = ctypes.CDLL(None, use_errno=True)
        rename = library.renameatx_np
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        if (
            rename(
                self.parent_fd,
                os.fsencode(self.paths.pending_directory_name),
                self.parent_fd,
                os.fsencode(self.paths.transaction_directory_name),
                install.RENAME_EXCL | install.RENAME_NOFOLLOW_ANY,
            )
            != 0
        ):
            raise install.InstallError(
                "service_journal_publish_failed", "cannot publish service transaction"
            )
        install._fsync_directory_fd(self.parent_fd)
        return intent, [event]

    def _load_directory(
        self, name: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        directory_fd = self._open_transaction_directory(name)
        try:
            names = os.listdir(directory_fd)
            authority_recovery_prepared = AUTHORITY_RECOVERY_INTENT_NAME in names
            authority_recovery_pending = (
                AUTHORITY_RECOVERY_PENDING_INTENT_NAME in names
            )
            if authority_recovery_prepared and authority_recovery_pending:
                raise install.InstallError(
                    "service_journal_invalid",
                    "published and pending Authority recovery intents coexist",
                )
            if (
                authority_recovery_prepared or authority_recovery_pending
            ) and self.paths.install_paths.profile.unregister_authority_action != (
                "unregister-installed-40019-global-authority"
            ):
                raise install.InstallError(
                    "service_journal_invalid",
                    "Authority recovery intent is forbidden for this install profile",
                )
            event_names = sorted(
                entry
                for entry in names
                if re.fullmatch(r"event-[0-9]{8}\.json", entry) is not None
            )
            pending_names = sorted(
                entry
                for entry in names
                if re.fullmatch(r"\.event-[0-9]{8}\.json\.pending", entry)
                is not None
            )
            if (
                set(names)
                != {
                    ENVIRONMENT_NAME,
                    INTENT_NAME,
                    *event_names,
                    *pending_names,
                    *(
                        {AUTHORITY_RECOVERY_INTENT_NAME}
                        if authority_recovery_prepared
                        else set()
                    ),
                    *(
                        {AUTHORITY_RECOVERY_PENDING_INTENT_NAME}
                        if authority_recovery_pending
                        else set()
                    ),
                }
                or len(pending_names) > 1
                or not 1 <= len(event_names) <= min(MAX_EVENTS, len(PHASES))
            ):
                raise install.InstallError(
                    "service_journal_invalid", "service transaction inventory is invalid"
                )
            expected_names = [f"{EVENT_PREFIX}{index:08d}.json" for index in range(len(event_names))]
            if event_names != expected_names:
                raise install.InstallError(
                    "service_journal_invalid", "service event sequence has a gap"
                )
            intent = validate_intent(
                _strict_json_bytes(
                    self._read(directory_fd, INTENT_NAME, "service intent"),
                    "service intent",
                )
            )
            self._require_profile_intent(intent)
            try:
                environment = ga_environment.validate_environment(
                    _strict_json_bytes(
                        self._read(
                            directory_fd,
                            ENVIRONMENT_NAME,
                            "GA environment identity",
                        ),
                        "GA environment identity",
                    )
                )
                environment_sha256 = ga_environment.environment_sha256(environment)
            except ga_environment.GAAcceptanceEnvironmentError as error:
                raise install.InstallError(
                    "service_journal_invalid",
                    "service GA environment identity is invalid",
                ) from error
            if environment_sha256 != intent["ga_environment_sha256"]:
                raise install.InstallError(
                    "service_journal_invalid",
                    "service intent does not bind its GA environment identity",
                )
            intent_sha256 = _sha256(_canonical_json(intent))
            events: list[dict[str, Any]] = []
            previous_digest: str | None = None
            baseline_guard: dict[str, Any] | None = None
            initial_count = min(2, len(event_names))
            for sequence, event_name in enumerate(event_names[:initial_count]):
                data = self._read(directory_fd, event_name, "service event")
                allowed_actions, allowed_profiles = self._event_contract(
                    sequence,
                    authority_recovery_prepared=False,
                )
                event = validate_event(
                    _strict_json_bytes(data, "service event"),
                    expected_sequence=sequence,
                    previous_event_sha256=previous_digest,
                    expected_guard=baseline_guard,
                    intent_sha256=intent_sha256,
                    expected_actions=allowed_actions,
                    expected_off_proof_profiles=allowed_profiles,
                )
                events.append(event)
                if baseline_guard is None:
                    baseline_guard = event["guard_after"]
                previous_digest = _sha256(data)

            if authority_recovery_pending:
                if len(events) < 2:
                    self._discard_incomplete_pending_event(
                        directory_fd, AUTHORITY_RECOVERY_PENDING_INTENT_NAME
                    )
                    authority_recovery_pending = False
                else:
                    try:
                        pending_recovery_data = self._read(
                            directory_fd,
                            AUTHORITY_RECOVERY_PENDING_INTENT_NAME,
                            "pending Authority recovery intent",
                            allow_empty=True,
                            sync_before_return=True,
                        )
                        validate_authority_recovery_intent(
                            _strict_json_bytes(
                                pending_recovery_data,
                                "pending Authority recovery intent",
                            ),
                            intent=intent,
                            events=events,
                        )
                    except install.InstallError as error:
                        if error.code != "service_journal_invalid":
                            raise
                        self._discard_incomplete_pending_event(
                            directory_fd,
                            AUTHORITY_RECOVERY_PENDING_INTENT_NAME,
                        )
                        authority_recovery_pending = False
                    else:
                        self._publish_pending_event(
                            directory_fd,
                            AUTHORITY_RECOVERY_PENDING_INTENT_NAME,
                            AUTHORITY_RECOVERY_INTENT_NAME,
                        )
                        authority_recovery_pending = False
                        authority_recovery_prepared = True

            if authority_recovery_prepared:
                if len(events) < 2:
                    raise install.InstallError(
                        "service_journal_invalid",
                        "Authority recovery intent precedes proxy unregistration",
                    )
                recovery_intent = self._read_authority_recovery_intent(
                    directory_fd, intent, events
                )
                if recovery_intent is None:
                    raise install.InstallError(
                        "service_journal_invalid",
                        "Authority recovery intent disappeared during load",
                    )

            for sequence, event_name in enumerate(
                event_names[initial_count:],
                start=initial_count,
            ):
                data = self._read(directory_fd, event_name, "service event")
                allowed_actions, allowed_profiles = self._event_contract(
                    sequence,
                    authority_recovery_prepared=authority_recovery_prepared,
                )
                event = validate_event(
                    _strict_json_bytes(data, "service event"),
                    expected_sequence=sequence,
                    previous_event_sha256=previous_digest,
                    expected_guard=baseline_guard,
                    intent_sha256=intent_sha256,
                    expected_actions=allowed_actions,
                    expected_off_proof_profiles=allowed_profiles,
                )
                events.append(event)
                if baseline_guard is None:
                    baseline_guard = event["guard_after"]
                previous_digest = _sha256(data)
            if pending_names:
                sequence = len(events)
                expected_pending = (
                    f"{PENDING_EVENT_PREFIX}{sequence:08d}.json{PENDING_EVENT_SUFFIX}"
                )
                if sequence >= len(PHASES) or pending_names != [expected_pending]:
                    raise install.InstallError(
                        "service_journal_invalid",
                        "pending service event sequence is invalid",
                    )
                try:
                    pending_data = self._read(
                        directory_fd,
                        expected_pending,
                        "pending service event",
                        allow_empty=True,
                        sync_before_return=True,
                    )
                    allowed_actions, allowed_profiles = self._event_contract(
                        sequence,
                        authority_recovery_prepared=authority_recovery_prepared,
                    )
                    pending_event = validate_event(
                        _strict_json_bytes(pending_data, "pending service event"),
                        expected_sequence=sequence,
                        previous_event_sha256=previous_digest,
                        expected_guard=baseline_guard,
                        intent_sha256=intent_sha256,
                        expected_actions=allowed_actions,
                        expected_off_proof_profiles=allowed_profiles,
                    )
                except install.InstallError as error:
                    if error.code != "service_journal_invalid":
                        raise
                    self._discard_incomplete_pending_event(
                        directory_fd, expected_pending
                    )
                else:
                    final_name = f"{EVENT_PREFIX}{sequence:08d}.json"
                    self._publish_pending_event(
                        directory_fd, expected_pending, final_name
                    )
                    events.append(pending_event)
            if authority_recovery_pending:
                raise install.InstallError(
                    "service_journal_invalid",
                    "pending Authority recovery intent was not reconciled",
                )
            return intent, events
        finally:
            os.close(directory_fd)

    def load(self) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        self._reject_retired_namespace()
        published = self.paths.transaction_directory.exists()
        pending = self.paths.pending_directory.exists()
        if self.paths.transaction_directory.is_symlink() or self.paths.pending_directory.is_symlink():
            raise install.InstallError(
                "service_journal_unsafe", "service transaction path is a symlink"
            )
        if published and pending:
            raise install.InstallError(
                "service_journal_pending", "published and pending service transactions coexist"
            )
        if not published and not pending:
            return None
        if published:
            return self._load_directory(self.paths.transaction_directory_name)
        try:
            intent, events = self._load_directory(
                self.paths.pending_directory_name
            )
            if len(events) != 1 or events[0]["phase"] != "prepared":
                raise install.InstallError(
                    "service_journal_pending",
                    "pending service transaction is not initial",
                )
        except install.InstallError:
            self._discard_incomplete_initial_transaction()
            return None
        library = ctypes.CDLL(None, use_errno=True)
        rename = library.renameatx_np
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        if (
            rename(
                self.parent_fd,
                os.fsencode(self.paths.pending_directory_name),
                self.parent_fd,
                os.fsencode(self.paths.transaction_directory_name),
                install.RENAME_EXCL | install.RENAME_NOFOLLOW_ANY,
            )
            != 0
        ):
            raise install.InstallError(
                "service_journal_publish_failed",
                "cannot recover pending service transaction",
            )
        install._fsync_directory_fd(self.parent_fd)
        return intent, events

    def terminal_snapshot(self) -> TerminalServiceJournalSnapshot:
        """Read the exact recommissioned tree; the caller must hold ``locked``."""

        try:
            pending_metadata = os.stat(
                self.paths.pending_directory_name,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pending_metadata = None
        except OSError as error:
            raise install.InstallError(
                "service_journal_unavailable",
                "cannot inspect pending service transaction",
            ) from error
        if pending_metadata is not None:
            raise install.InstallError(
                "service_journal_pending",
                "terminal service snapshot refuses a pending transaction",
            )

        directory_fd = self._open_transaction_directory()
        try:
            names = set(os.listdir(directory_fd))
            if any(
                re.fullmatch(r"\.event-[0-9]{8}\.json\.pending", name)
                is not None
                for name in names
            ) or AUTHORITY_RECOVERY_PENDING_INTENT_NAME in names:
                raise install.InstallError(
                    "service_journal_pending",
                    "terminal service snapshot refuses pending journal entries",
                )
        finally:
            os.close(directory_fd)

        intent, events = self._load_directory(self.paths.transaction_directory_name)
        if len(events) != len(PHASES) or events[-1]["phase"] != "recommissioned":
            raise install.InstallError(
                "service_journal_not_terminal",
                "service transaction is not at the recommissioned phase",
            )

        directory_fd = self._open_transaction_directory()
        try:
            directory_metadata = os.fstat(directory_fd)
            names = sorted(os.listdir(directory_fd))
            snapshots: list[ServiceJournalFileSnapshot] = []
            for name in names:
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                data = self._read(directory_fd, name, f"service journal {name}")
                after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if _journal_metadata_identity(before) != _journal_metadata_identity(
                    after
                ):
                    raise install.InstallError(
                        "service_journal_identity_drift",
                        f"service journal {name} changed while snapshotting",
                    )
                snapshots.append(
                    ServiceJournalFileSnapshot(
                        name=name,
                        data=data,
                        metadata=before,
                    )
                )
            after_directory = os.fstat(directory_fd)
            visible_directory = os.stat(
                self.paths.transaction_directory_name,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
            if (
                _journal_metadata_identity(directory_metadata)
                != _journal_metadata_identity(after_directory)
                or _journal_metadata_identity(directory_metadata)
                != _journal_metadata_identity(visible_directory)
            ):
                raise install.InstallError(
                    "service_journal_identity_drift",
                    "service transaction directory changed while snapshotting",
                )
        finally:
            os.close(directory_fd)

        environment, observed_intent, observed_events = validate_terminal_snapshot_files(
            {snapshot.name: snapshot.data for snapshot in snapshots},
            self.paths.install_paths.profile,
        )
        if observed_intent != intent or observed_events != tuple(events):
            raise install.InstallError(
                "service_journal_identity_drift",
                "service journal changed between validation and snapshot",
            )
        return TerminalServiceJournalSnapshot(
            environment=environment,
            intent=observed_intent,
            events=observed_events,
            files=tuple(snapshots),
            directory_metadata=directory_metadata,
        )

    def append(
        self,
        events: list[dict[str, Any]],
        *,
        phase: str,
        action: str,
        guard: dict[str, Any],
        off_proof_profile: str | None = None,
    ) -> dict[str, Any]:
        sequence = len(events)
        if (
            not events
            or sequence >= len(PHASES)
            or PHASES[sequence] != phase
        ):
            raise install.InstallError(
                "service_journal_transition_invalid", "service phase transition is invalid"
            )
        directory_fd = self._open_transaction_directory()
        try:
            previous_data = _canonical_json(events[-1])
            authority_recovery_prepared = (
                AUTHORITY_RECOVERY_INTENT_NAME in os.listdir(directory_fd)
            )
            allowed_actions, allowed_profiles = self._event_contract(
                sequence,
                authority_recovery_prepared=authority_recovery_prepared,
            )
            actual_profile = (
                (
                    events[-1]["off_proof_profile"]
                    if action == "verify-dormant"
                    else self.paths.install_paths.profile.service_event_proof_profiles[
                        sequence
                    ]
                )
                if off_proof_profile is None
                else off_proof_profile
            )
            event = validate_event(
                {
                    "action": action,
                    "document": DOCUMENT,
                    "guard_after": guard,
                    "guard_before": guard,
                    "intent_sha256": events[0]["intent_sha256"],
                    "off_proof_profile": actual_profile,
                    "phase": phase,
                    "previous_event_sha256": _sha256(previous_data),
                    "schema_version": SCHEMA_VERSION,
                    "sequence": sequence,
                },
                expected_sequence=sequence,
                previous_event_sha256=_sha256(previous_data),
                expected_guard=events[0]["guard_after"],
                intent_sha256=events[0]["intent_sha256"],
                expected_actions=allowed_actions,
                expected_off_proof_profiles=allowed_profiles,
            )
            pending_name = (
                f"{PENDING_EVENT_PREFIX}{sequence:08d}.json{PENDING_EVENT_SUFFIX}"
            )
            final_name = f"{EVENT_PREFIX}{sequence:08d}.json"
            self._write_new(directory_fd, pending_name, event)
            self._publish_pending_event(directory_fd, pending_name, final_name)
            return event
        finally:
            os.close(directory_fd)


def _service_receipt(
    runtime: ServiceRuntime,
    executable: Path,
    action: str,
) -> dict[str, Any]:
    return install.parse_service_maintenance_receipt(
        runtime.runner((str(executable), install.SERVICE_MAINTENANCE_FLAG, action)),
        action,
    )


def _require_pair(
    receipt: dict[str, Any],
    *,
    proxy: set[str],
    authority: set[str],
) -> None:
    if receipt["proxy_agent"] not in proxy or receipt["global_authority"] not in authority:
        raise install.InstallError(
            "service_state_invalid", "current SMAppService pair is not at the required boundary"
        )


def _launchctl_domain(
    runtime: ServiceRuntime,
    domain: str,
) -> install.CommandResult:
    return runtime.runner(("/bin/launchctl", "print", domain))


def _registered_job_pid(
    result: install.CommandResult,
    *,
    domain: str,
    program: str,
    parent_build: str,
    signing_identifier: str,
) -> int:
    if result.returncode != 0 or result.stderr:
        raise install.InstallError(
            "service_job_invalid", f"registered service job is unavailable: {domain}"
        )
    lines = result.stdout.splitlines()
    if not lines or lines[0] != f"{domain} = {{" or lines[-1] != "}":
        raise install.InstallError("service_job_invalid", f"service job is malformed: {domain}")
    stripped = [line.strip() for line in lines]
    required = {
        "managed_by = com.apple.xpc.ServiceManagement",
        "state = running",
        f"program identifier = {program} (mode: 2)",
        "parent bundle identifier = com.bill.clashformac",
        f"parent bundle version = {parent_build}",
        f'"signing-identifier" => "{signing_identifier}"',
        '"team-identifier" => "YKUPL7Z869"',
    }
    if any(stripped.count(value) != 1 for value in required):
        raise install.InstallError(
            "service_job_invalid", f"service job identity differs from the fixed contract: {domain}"
        )
    pids = [line.removeprefix("pid = ") for line in stripped if line.startswith("pid = ")]
    if len(pids) != 1 or re.fullmatch(r"[1-9][0-9]*", pids[0]) is None:
        raise install.InstallError("service_job_invalid", f"service job pid is invalid: {domain}")
    return int(pids[0])


def _processes(runtime: ServiceRuntime) -> list[dict[str, Any]]:
    result = runtime.runner(("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="))
    if result.returncode != 0 or result.stderr:
        raise install.InstallError(
            "service_process_observation_failed", "cannot observe current service processes"
        )
    return install._parse_processes(result.stdout)


def _absolute_process_path(pid: int) -> str:
    if type(pid) is not int or pid <= 0:
        raise install.InstallError(
            "service_process_identity_invalid", "service process pid is invalid"
        )
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    proc_pidpath = library.proc_pidpath
    proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    proc_pidpath.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(PROC_PIDPATH_BUFFER_SIZE)
    length = proc_pidpath(pid, buffer, PROC_PIDPATH_BUFFER_SIZE)
    if length <= 0 or length >= PROC_PIDPATH_BUFFER_SIZE:
        raise install.InstallError(
            "service_process_identity_invalid",
            "cannot resolve the absolute service process path",
        )
    try:
        path = buffer.raw[:length].rstrip(b"\0").decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise install.InstallError(
            "service_process_identity_invalid",
            "service process path is not strict UTF-8",
        ) from error
    if not path.startswith("/") or "\0" in path:
        raise install.InstallError(
            "service_process_identity_invalid",
            "service process path is not canonical absolute text",
        )
    return path


def _require_no_host_or_tunnel_process(processes: list[dict[str, Any]]) -> None:
    if any(
        process["path"].endswith((HOST_PROCESS_SUFFIX, TUNNEL_PROCESS_SUFFIX))
        for process in processes
    ):
        raise install.InstallError(
            "service_host_running", "Clash for Mac Host or Packet Tunnel is still running"
        )


def _require_registered_services(
    runtime: ServiceRuntime,
    *,
    parent_build: str,
    uid: int,
) -> None:
    processes = _processes(runtime)
    _require_no_host_or_tunnel_process(processes)
    login_uids = {
        process["uid"]
        for process in processes
        if process["uid"] > 0
        and process["path"].endswith(
            "/loginwindow.app/Contents/MacOS/loginwindow"
        )
    }
    if login_uids != {uid}:
        raise install.InstallError(
            "service_multi_user_session",
            "service maintenance requires exactly one active GUI login owner",
        )
    proxy_domain = PROXY_DOMAIN_TEMPLATE.format(uid=uid)
    proxy_pid = _registered_job_pid(
        _launchctl_domain(runtime, proxy_domain),
        domain=proxy_domain,
        program=PROXY_PROGRAM,
        parent_build=parent_build,
        signing_identifier="com.bill.clashformac.proxy-agent",
    )
    authority_pid = _registered_job_pid(
        _launchctl_domain(runtime, AUTHORITY_DOMAIN),
        domain=AUTHORITY_DOMAIN,
        program=AUTHORITY_PROGRAM,
        parent_build=parent_build,
        signing_identifier="com.bill.clashformac.global-authority",
    )
    expected = {
        proxy_pid: (
            uid,
            f"/Applications/{install.TARGET_NAME}/{PROXY_PROGRAM}",
        ),
        authority_pid: (
            0,
            f"/Applications/{install.TARGET_NAME}/{AUTHORITY_PROGRAM}",
        ),
    }
    observed_helper_pids = {
        process["pid"]
        for process in processes
        if any(
            process["path"].endswith(suffix)
            for suffix in install.CFM_PROCESS_SUFFIXES
        )
    }
    if observed_helper_pids != set(expected):
        raise install.InstallError(
            "service_process_identity_invalid",
            "Clash for Mac process inventory differs from the registered jobs",
        )
    for pid, (expected_uid, expected_path) in expected.items():
        matches = [process for process in processes if process["pid"] == pid]
        if (
            len(matches) != 1
            or matches[0]["uid"] != expected_uid
            or _absolute_process_path(pid) != expected_path
        ):
            raise install.InstallError(
                "service_process_identity_invalid",
                "current service process identity differs from its launchd job",
            )
    repeated_proxy_pid = _registered_job_pid(
        _launchctl_domain(runtime, proxy_domain),
        domain=proxy_domain,
        program=PROXY_PROGRAM,
        parent_build=parent_build,
        signing_identifier="com.bill.clashformac.proxy-agent",
    )
    repeated_authority_pid = _registered_job_pid(
        _launchctl_domain(runtime, AUTHORITY_DOMAIN),
        domain=AUTHORITY_DOMAIN,
        program=AUTHORITY_PROGRAM,
        parent_build=parent_build,
        signing_identifier="com.bill.clashformac.global-authority",
    )
    repeated_processes = _processes(runtime)
    for pid, repeated_pid in (
        (proxy_pid, repeated_proxy_pid),
        (authority_pid, repeated_authority_pid),
    ):
        before = [process for process in processes if process["pid"] == pid]
        after = [process for process in repeated_processes if process["pid"] == pid]
        if repeated_pid != pid or len(before) != 1 or after != before:
            raise install.InstallError(
                "service_process_identity_invalid",
                "service job or process identity changed during observation",
            )


def _require_tombstone_and_no_system_extension(runtime: ServiceRuntime) -> None:
    install._require_legacy_tombstone_absent_or_inactive(
        _launchctl_domain(runtime, TOMBSTONE_DOMAIN)
    )
    extensions = runtime.runner(("/usr/bin/systemextensionsctl", "list"))
    if extensions.returncode != 0 or extensions.stderr:
        raise install.InstallError(
            "service_system_extension_observation_failed",
            "cannot prove Packet Tunnel system extension absence",
        )
    if install.CFM_SYSTEM_EXTENSION_IDENTITY in install._parse_system_extension_identities(
        extensions.stdout
    ):
        raise install.InstallError(
            "service_system_extension_registered",
            "Packet Tunnel system extension must be deactivated before service maintenance",
        )


def _uid_from_guard(guard: dict[str, Any]) -> int:
    processes = guard.get("cfw_processes")
    if not isinstance(processes, list) or not processes:
        raise install.InstallError("cfw_identity_invalid", "CFW guard has no GUI identity")
    uid = processes[0].get("uid")
    if type(uid) is not int or uid <= 0 or uid != os.geteuid():
        raise install.InstallError(
            "service_user_invalid", "maintenance user differs from the CFW GUI owner"
        )
    return uid


def _assert_absent_job(result: install.CommandResult, domain: str) -> None:
    install._require_launchctl_service_absent(result, domain)


def _wait_for_service_absence(
    runtime: ServiceRuntime,
    *,
    domain: str,
    process_suffix: str,
) -> None:
    last_error: install.InstallError | None = None
    for _ in range(POLL_ATTEMPTS):
        try:
            _assert_absent_job(_launchctl_domain(runtime, domain), domain)
            if any(process["path"].endswith(process_suffix) for process in _processes(runtime)):
                raise install.InstallError(
                    "service_process_running", f"service process remains active: {domain}"
                )
            return
        except install.InstallError as error:
            if error.code not in {"cfm_service_registered", "service_process_running"}:
                raise
            last_error = error
            time.sleep(POLL_INTERVAL_SECONDS)
    raise install.InstallError(
        "service_shutdown_timeout", f"service did not become absent: {domain}"
    ) from last_error


class CurrentServiceTransaction:
    def __init__(self, paths: ServicePaths, runtime: ServiceRuntime) -> None:
        self.paths = paths
        self.runtime = runtime

    def _candidate(self) -> install.CandidateIdentity:
        return install.admit_fixed_candidate(self.paths.install_paths, self.runtime.runner)

    def _observe_environment(self) -> dict[str, Any]:
        try:
            return ga_environment.validate_environment(
                self.runtime.observe_environment()
            )
        except ga_environment.GAAcceptanceEnvironmentError as error:
            raise install.InstallError(
                "service_environment_invalid",
                "current GA environment cannot be observed",
            ) from error

    def _require_environment(self, intent: dict[str, Any]) -> dict[str, Any]:
        observed = self._observe_environment()
        try:
            digest = ga_environment.environment_sha256(observed)
        except ga_environment.GAAcceptanceEnvironmentError as error:
            raise install.InstallError(
                "service_environment_invalid",
                "current GA environment is invalid",
            ) from error
        if digest != intent["ga_environment_sha256"]:
            raise install.InstallError(
                "service_environment_drift",
                "current GA environment differs from the service intent",
            )
        return observed

    def _identity_pair(
        self,
    ) -> tuple[install.CandidateIdentity, install.AppIdentity]:
        candidate = self._candidate()
        previous = install.read_app_identity(self.paths.install_paths.target_app)
        install.verify_dormant_bundle(
            self.paths.install_paths.target_app,
            previous,
            self.runtime.runner,
        )
        if int(candidate.app.build_number) <= int(previous.build_number):
            raise install.InstallError(
                "service_candidate_not_newer", "service candidate is not newer than installed app"
            )
        profile = self.paths.install_paths.profile
        if (
            candidate.app.build_number != profile.build_number
            or previous.build_number != profile.previous_build_number
        ):
            raise install.InstallError(
                "service_identity_mismatch",
                "candidate and installed application do not match the fixed GA identity",
            )
        return candidate, previous

    def preflight(
        self,
    ) -> tuple[install.CandidateIdentity, install.AppIdentity, dict[str, Any]]:
        with ServiceEventStore(self.paths) as store:
            store._reject_retired_namespace()
        if (
            self.paths.transaction_directory.exists()
            or self.paths.transaction_directory.is_symlink()
            or self.paths.pending_directory.exists()
            or self.paths.pending_directory.is_symlink()
        ):
            raise install.InstallError(
                "service_journal_exists", "service transaction already exists; use recovery"
            )
        self._observe_environment()
        before = self.runtime.capture_guard()
        uid = _uid_from_guard(before)
        install.require_single_interactive_local_user(self.runtime.runner, uid)
        candidate, previous = self._identity_pair()
        status = _service_receipt(
            self.runtime,
            self.paths.install_paths.candidate_executable,
            "status",
        )
        _require_pair(status, proxy={"enabled"}, authority={"enabled"})
        _require_registered_services(
            self.runtime, parent_build=previous.build_number, uid=uid
        )
        _require_tombstone_and_no_system_extension(self.runtime)
        proof = _service_receipt(
            self.runtime,
            self.paths.install_paths.candidate_executable,
            self.paths.install_paths.profile.prove_off_action,
        )
        _require_pair(proof, proxy={"enabled"}, authority={"enabled"})
        after = self.runtime.capture_guard()
        install._assert_guard_unchanged(before, after)
        return candidate, previous, before

    @staticmethod
    def _require_intent_matches(
        intent: dict[str, Any],
        candidate: install.CandidateIdentity,
        previous: install.AppIdentity,
    ) -> None:
        if intent["candidate"] != candidate.document() or intent["previous"] != previous.document():
            raise install.InstallError(
                "service_identity_drift", "service transaction app identity changed"
            )

    def _step(
        self,
        store: ServiceEventStore,
        events: list[dict[str, Any]],
        *,
        intent: dict[str, Any],
        phase: str,
        action: str,
        executable: Path,
        expected_proxy: set[str],
        expected_authority: set[str],
        after_action: Callable[[], None] | None = None,
    ) -> None:
        self._require_environment(intent)
        baseline = events[0]["guard_after"]
        before = self.runtime.capture_guard()
        install._assert_guard_unchanged(baseline, before)
        receipt = _service_receipt(self.runtime, executable, action)
        _require_pair(
            receipt,
            proxy=expected_proxy,
            authority=expected_authority,
        )
        if after_action is not None:
            after_action()
        self._require_environment(intent)
        after = self.runtime.capture_guard()
        install._assert_guard_unchanged(before, after)
        events.append(
            store.append(
                events,
                phase=phase,
                action=action,
                guard=after,
                off_proof_profile=receipt["off_proof_profile"],
            )
        )

    def _prove_decommissioned(
        self,
        intent: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        self._require_environment(intent)
        baseline = events[0]["guard_after"]
        before = self.runtime.capture_guard()
        install._assert_guard_unchanged(baseline, before)
        install.require_cfm_dormant(
            before,
            self.runtime.runner,
            executable=self.paths.install_paths.candidate_executable,
        )
        after = self.runtime.capture_guard()
        install._assert_guard_unchanged(before, after)
        self._require_environment(intent)
        return after

    def _prove_recommissioned(
        self,
        intent: dict[str, Any],
        events: list[dict[str, Any]],
        *,
        executable: Path,
        installed: install.AppIdentity,
        uid: int,
    ) -> dict[str, Any]:
        self._require_environment(intent)
        baseline = events[0]["guard_after"]
        before = self.runtime.capture_guard()
        install._assert_guard_unchanged(baseline, before)
        proof = _service_receipt(self.runtime, executable, "prove-off")
        _require_pair(proof, proxy={"enabled"}, authority={"enabled"})
        _require_registered_services(
            self.runtime, parent_build=installed.build_number, uid=uid
        )
        _require_tombstone_and_no_system_extension(self.runtime)
        after = self.runtime.capture_guard()
        install._assert_guard_unchanged(before, after)
        self._require_environment(intent)
        return after

    def decommission(self) -> dict[str, Any]:
        with ServiceEventStore(self.paths) as store:
            with store.locked():
                loaded = store.load()
                if loaded is None:
                    candidate, previous, guard = self.preflight()
                    environment = self._observe_environment()
                    # Recheck the CFW projection at the actual durable intent boundary.
                    adjacent = self.runtime.capture_guard()
                    install._assert_guard_unchanged(guard, adjacent)
                    intent, events = store.create(
                        candidate,
                        previous,
                        adjacent,
                        environment,
                    )
                else:
                    intent, events = loaded
                    candidate, previous = self._identity_pair()
                    self._require_intent_matches(intent, candidate, previous)
                self._require_environment(intent)
                uid = _uid_from_guard(events[-1]["guard_after"])
                phase = events[-1]["phase"]
                decommission_proven = False
                executable = self.paths.install_paths.candidate_executable
                if phase == "prepared":
                    self._step(
                        store,
                        events,
                        intent=intent,
                        phase="proxy_unregistered",
                        action=(
                            self.paths.install_paths.profile.unregister_proxy_action
                        ),
                        executable=executable,
                        expected_proxy={"not_registered"},
                        expected_authority={"enabled"},
                        after_action=lambda: _wait_for_service_absence(
                            self.runtime,
                            domain=PROXY_DOMAIN_TEMPLATE.format(uid=uid),
                            process_suffix=PROXY_PROCESS_SUFFIX,
                        ),
                    )
                    phase = events[-1]["phase"]
                if phase == "proxy_unregistered":
                    if (
                        self.paths.install_paths.profile.unregister_authority_action
                        == "unregister-installed-40019-global-authority"
                    ):
                        recovery_prepared = store.authority_recovery_prepared(
                            intent, events
                        )
                        status = _service_receipt(
                            self.runtime,
                            executable,
                            "status",
                        )
                        _require_pair(
                            status,
                            proxy={"not_registered"},
                            authority={"enabled", "not_registered"},
                        )
                        if recovery_prepared:
                            authority_action = (
                                install.INSTALLED_40019_RECOVERY_ACTION
                            )
                        elif status["global_authority"] == "not_registered":
                            recovery_guard = self.runtime.capture_guard()
                            install._assert_guard_unchanged(
                                events[0]["guard_after"], recovery_guard
                            )
                            store.prepare_authority_recovery(
                                intent, events, recovery_guard
                            )
                            self._require_environment(intent)
                            adjacent = self.runtime.capture_guard()
                            install._assert_guard_unchanged(
                                recovery_guard, adjacent
                            )
                            authority_action = (
                                install.INSTALLED_40019_RECOVERY_ACTION
                            )
                        else:
                            authority_action = (
                                self.paths.install_paths.profile.unregister_authority_action
                            )
                    else:
                        authority_action = (
                            self.paths.install_paths.profile.unregister_authority_action
                        )
                    self._step(
                        store,
                        events,
                        intent=intent,
                        phase="authority_unregistered",
                        action=authority_action,
                        executable=executable,
                        expected_proxy={"not_registered"},
                        expected_authority={"not_registered"},
                        after_action=lambda: _wait_for_service_absence(
                            self.runtime,
                            domain=AUTHORITY_DOMAIN,
                            process_suffix=AUTHORITY_PROCESS_SUFFIX,
                        ),
                    )
                    phase = events[-1]["phase"]
                if phase == "authority_unregistered":
                    guard = self._prove_decommissioned(intent, events)
                    decommission_proven = True
                    events.append(
                        store.append(
                            events,
                            phase="decommissioned",
                            action="verify-dormant",
                            guard=guard,
                        )
                    )
                    phase = events[-1]["phase"]
                if phase != "decommissioned":
                    raise install.InstallError(
                        "service_journal_transition_invalid",
                        "service decommission did not reach a stable phase",
                    )
                if not decommission_proven:
                    self._prove_decommissioned(intent, events)
                return {"intent": intent, "event": events[-1]}

    def _require_installed_candidate(
        self,
        intent: dict[str, Any],
    ) -> install.AppIdentity:
        actual = install.read_app_identity(self.paths.install_paths.target_app)
        expected = install.AppIdentity(
            intent["candidate"]["version"],
            intent["candidate"]["build_number"],
            intent["candidate"]["tree_sha256"],
        )
        if actual != expected:
            raise install.InstallError(
                "service_target_invalid", "installed app is not the journal-bound candidate"
            )
        install.verify_dormant_bundle(
            self.paths.install_paths.target_app,
            actual,
            self.runtime.runner,
        )
        with install.JournalStore(self.paths.install_paths) as store:
            with store.locked():
                installation = store.load()
        if (
            installation is None
            or installation["phase"] != "installed"
            or installation["candidate"] != intent["candidate"]
            or installation["previous"] != intent["previous"]
            or installation["ga_environment_sha256"]
            != intent["ga_environment_sha256"]
        ):
            raise install.InstallError(
                "service_install_evidence_invalid",
                "dormant installation journal does not bind the installed candidate",
            )
        return actual

    def recommission(self) -> dict[str, Any]:
        with ServiceEventStore(self.paths) as store:
            with store.locked():
                loaded = store.load()
                if loaded is None:
                    raise install.InstallError(
                        "service_journal_missing", "service decommission transaction is absent"
                    )
                intent, events = loaded
                candidate = self._candidate()
                previous = install.AppIdentity(
                    intent["previous"]["version"],
                    intent["previous"]["build_number"],
                    intent["previous"]["tree_sha256"],
                )
                self._require_intent_matches(intent, candidate, previous)
                self._require_environment(intent)
                installed = self._require_installed_candidate(intent)
                uid = _uid_from_guard(events[-1]["guard_after"])
                phase = events[-1]["phase"]
                recommission_proven = False
                if phase not in {
                    "decommissioned",
                    "authority_registered",
                    "proxy_registered",
                    "recommissioned",
                }:
                    raise install.InstallError(
                        "service_journal_transition_invalid",
                        "service transaction is not ready for recommission",
                    )
                executable = self.paths.target_executable
                if phase == "decommissioned":
                    self._step(
                        store,
                        events,
                        intent=intent,
                        phase="authority_registered",
                        action="register-global-authority",
                        executable=executable,
                        expected_proxy={"not_registered"},
                        expected_authority={"enabled"},
                    )
                    phase = events[-1]["phase"]
                if phase == "authority_registered":
                    self._step(
                        store,
                        events,
                        intent=intent,
                        phase="proxy_registered",
                        action="register-proxy-agent",
                        executable=executable,
                        expected_proxy={"enabled"},
                        expected_authority={"enabled"},
                    )
                    phase = events[-1]["phase"]
                if phase == "proxy_registered":
                    after = self._prove_recommissioned(
                        intent,
                        events,
                        executable=executable,
                        installed=installed,
                        uid=uid,
                    )
                    recommission_proven = True
                    events.append(
                        store.append(
                            events,
                            phase="recommissioned",
                            action="prove-off",
                            guard=after,
                        )
                    )
                    phase = events[-1]["phase"]
                if phase != "recommissioned":
                    raise install.InstallError(
                        "service_journal_transition_invalid",
                        "service recommission did not reach its terminal phase",
                    )
                if not recommission_proven:
                    self._prove_recommissioned(
                        intent,
                        events,
                        executable=executable,
                        installed=installed,
                        uid=uid,
                    )
                return {"intent": intent, "event": events[-1]}

    def recover(self) -> dict[str, Any]:
        with ServiceEventStore(self.paths) as store:
            with store.locked():
                loaded = store.load()
                if loaded is None:
                    raise install.InstallError(
                        "service_journal_missing", "service transaction is absent"
                    )
                intent, events = loaded
                self._require_environment(intent)
                phase = events[-1]["phase"]
                target = install.read_app_identity(self.paths.install_paths.target_app)
                previous = install.AppIdentity(
                    intent["previous"]["version"],
                    intent["previous"]["build_number"],
                    intent["previous"]["tree_sha256"],
                )
                candidate = install.AppIdentity(
                    intent["candidate"]["version"],
                    intent["candidate"]["build_number"],
                    intent["candidate"]["tree_sha256"],
                )
        if target == previous and PHASES.index(phase) <= PHASES.index("decommissioned"):
            return self.decommission()
        if target == candidate and PHASES.index(phase) >= PHASES.index("decommissioned"):
            return self.recommission()
        raise install.InstallError(
            "service_recovery_ambiguous",
            "service transaction phase and installed bundle identity disagree",
        )


def _transaction() -> CurrentServiceTransaction:
    if os.geteuid() == 0:
        raise install.InstallError(
            "root_execution_refused",
            "service maintenance must run as the owning administrator, never through sudo",
        )
    return CurrentServiceTransaction(
        ServicePaths.production(), ServiceRuntime.production()
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--decommission", action="store_true")
    mode.add_argument("--recommission", action="store_true")
    mode.add_argument("--recover", action="store_true")
    if "--final" in sys.argv[1:]:
        parser.error(
            "--final is retired; "
            f"{ACTIVE_RELEASE_IDENTITY.product_version} has exactly one GA build "
            f"({ACTIVE_RELEASE_IDENTITY.ga_build})"
        )
    arguments = parser.parse_args()
    try:
        transaction = _transaction()
        if arguments.preflight:
            candidate, previous, _guard = transaction.preflight()
            print(
                "current-service preflight passed: "
                f"{previous.build_number} -> {candidate.app.build_number}; "
                "no registration or application was changed"
            )
            return
        if arguments.decommission:
            result = transaction.decommission()
        elif arguments.recommission:
            result = transaction.recommission()
        else:
            result = transaction.recover()
    except (install.InstallError, OSError, ValueError) as error:
        code = error.code if isinstance(error, install.InstallError) else "unexpected_service_error"
        raise SystemExit(f"error: {code}: {error}") from error
    print(
        "current-service transaction "
        f"{result['event']['phase']}: {result['intent']['candidate']['build_number']}"
    )


if __name__ == "__main__":
    from release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )

    try:
        require_closed_release_runtime()
    except ReleasePythonRuntimeError as error:
        raise SystemExit(f"error: current-service runtime admission: {error}") from error
    main()
